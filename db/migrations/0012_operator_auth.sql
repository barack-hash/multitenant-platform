-- 0012_operator_auth.sql — table-group 11: real per-operator platform-ops auth (FOUNDATION_10).
-- Closes the group-10 stand-in (single shared x-admin-token) so §12 dual-control becomes a TRUE
-- two-person control: each operator authenticates individually, and the APPROVER is derived from a
-- LIVE operator session inside the dual-control function itself (not a caller-supplied UUID). Class B
-- service-only (svc_ops/svc_authz); NO svc_app grant (DEC-009). The operator-auth read paths run as
-- svc_ops (the only logical role in BOTH the operator-auth and platform_operators/support policies).
-- Depends on 0000-0011 (platform_operators, support_access_requests, the audit chain).

-- ============================= DDL =============================

-- Per-operator credential. The raw API key is PRESENTED at login and hashed server-side; only
-- key_prefix (for lookup) + sha256(key) are stored, so a DB read of secret_hash is not a replayable
-- bearer credential (pass-the-hash needs a preimage). Prod → argon2/hardware-backed keys + MFA.
create table if not exists operator_credentials (
  id            uuid primary key default gen_random_uuid(),
  operator_id   uuid not null references platform_operators(id),
  cred_type     text not null default 'api_key' check (cred_type in ('api_key')),
  key_prefix    text not null,
  secret_hash   text not null,                  -- sha256(api_key) hex, computed server-side at issue/login
  status        text not null default 'active' check (status in ('active','revoked')),
  created_at    timestamptz not null default now(),
  created_by    uuid,                            -- issuing operator (null = seed bootstrap)
  last_used_at  timestamptz,
  expires_at    timestamptz,
  revoked_at    timestamptz,
  revoke_reason text
);
create unique index if not exists ux_operator_cred_prefix on operator_credentials (key_prefix);
create index if not exists ix_operator_cred_operator on operator_credentials (operator_id, status);

-- Operator login session — short-TTL, revocable; the operator token is bound to a live one.
create table if not exists operator_sessions (
  id            uuid primary key default gen_random_uuid(),
  operator_id   uuid not null references platform_operators(id),
  status        text not null default 'active' check (status in ('active','revoked','expired')),
  amr           text,                            -- auth method(s); MFA deferred
  acr           text,                            -- auth context/level; MFA deferred
  issued_at     timestamptz not null default now(),
  expires_at    timestamptz not null,
  last_seen_at  timestamptz,
  revoked_at    timestamptz,
  revoke_reason text,
  constraint ck_operator_session_ttl check (expires_at <= issued_at + interval '1 hour')   -- max 60 min
);
create index if not exists ix_operator_sessions_op on operator_sessions (operator_id, status);

-- ============================= RLS =============================
-- Class B service-only (svc_ops/svc_authz own operator auth). No svc_app grant, FORCE RLS, no BYPASSRLS.
do $$
declare t text;
begin
  foreach t in array array['operator_credentials','operator_sessions'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_ops','svc_authz']))
      with check (app.assert_service_role(array['svc_ops','svc_authz']));$p$, t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;

-- Non-renewable / non-revivable: expires_at can't move later, terminal can't reactivate (mirrors
-- support_sessions; the ≤60min CHECK already bounds abuse, this closes the direct-UPDATE hole).
create or replace function app.forbid_operator_session_extension()
returns trigger language plpgsql as $$
begin
  if new.expires_at is distinct from old.expires_at and new.expires_at > old.expires_at then
    raise exception 'OPERATOR_SESSION_NOT_RENEWABLE: expires_at cannot be extended';
  end if;
  if old.status in ('revoked','expired') and new.status = 'active' then
    raise exception 'OPERATOR_SESSION_NOT_RENEWABLE: a terminal session cannot be reactivated';
  end if;
  return new;
end$$;
create trigger trg_operator_session_non_renewable before update on operator_sessions
  for each row execute function app.forbid_operator_session_extension();

-- ============================= Functions =============================

-- Authenticate by (email, key_prefix, RAW secret). The secret is hashed server-side and compared to the
-- stored hash, so the stored value alone can't be replayed. Returns the operator iff an ACTIVE, unexpired
-- credential belongs to that ACTIVE operator whose email matches. Empty result = auth failure.
create or replace function app.operator_authenticate(p_email citext, p_key_prefix text, p_secret text)
returns table(operator_id uuid, operator_role text) language plpgsql as $$
declare v_op uuid; v_role text; v_cred uuid;
begin
  select po.id, po.operator_role, oc.id
    into v_op, v_role, v_cred
    from operator_credentials oc
    join platform_operators po on po.id = oc.operator_id
   where oc.key_prefix = p_key_prefix
     and oc.secret_hash = encode(sha256(convert_to(p_secret, 'UTF8')), 'hex')
     and oc.status = 'active' and (oc.expires_at is null or oc.expires_at > now())
     and po.status = 'active' and po.email = p_email;
  if v_op is null then return; end if;
  update operator_credentials set last_used_at = now() where id = v_cred;
  operator_id := v_op; operator_role := v_role; return next;
end$$;

-- Start an operator session (TTL clamped server-side to [60, 3600]s) for an ACTIVE operator.
create or replace function app.start_operator_session(p_operator uuid, p_ttl integer default 1800)
returns uuid language plpgsql as $$
declare v_id uuid; v_ttl integer;
begin
  if not exists (select 1 from platform_operators where id = p_operator and status = 'active') then
    raise exception 'OPERATOR_INACTIVE' using errcode = 'P0001';
  end if;
  v_ttl := least(greatest(coalesce(p_ttl, 1800), 60), 3600);
  insert into operator_sessions(operator_id, issued_at, expires_at)
  values (p_operator, now(), now() + make_interval(secs => v_ttl))
  returning id into v_id;
  return v_id;
end$$;

-- A token is honored only while its session is live AND its operator is still active — so disabling an
-- operator (or revoking the session) invalidates the token immediately, not at TTL. Runs as svc_ops
-- (reads both operator_sessions and platform_operators).
create or replace function app.assert_operator_session_live(p_osid uuid)
returns boolean language sql stable as $$
  select exists (
    select 1 from operator_sessions os
      join platform_operators po on po.id = os.operator_id
     where os.id = p_osid and os.status = 'active' and now() < os.expires_at and po.status = 'active');
$$;

-- The authenticated operator behind a live session (null if not live). Used by dual-control.
create or replace function app.operator_of_live_session(p_osid uuid)
returns uuid language sql stable as $$
  select os.operator_id from operator_sessions os
    join platform_operators po on po.id = os.operator_id
   where os.id = p_osid and os.status = 'active' and now() < os.expires_at and po.status = 'active';
$$;

create or replace function app.revoke_operator_session(p_osid uuid, p_reason text default 'logout')
returns integer language plpgsql as $$
declare n integer;
begin
  update operator_sessions set status = 'revoked', revoked_at = now(), revoke_reason = p_reason
   where id = p_osid and status = 'active';
  get diagnostics n = row_count;
  return n;
end$$;

create or replace function app.expire_operator_sessions()
returns integer language plpgsql as $$
declare n integer;
begin
  update operator_sessions set status = 'expired'
   where status = 'active' and now() >= expires_at;
  get diagnostics n = row_count;
  return n;
end$$;

-- Disable an operator and IMMEDIATELY revoke their live sessions (a compromised/offboarded operator
-- loses access at once, not after ≤60 min). Runs as svc_ops.
create or replace function app.disable_operator(p_operator uuid, p_reason text default 'disabled')
returns integer language plpgsql as $$
declare n integer;
begin
  update platform_operators set status = 'disabled', disabled_at = now()
   where id = p_operator and status = 'active';
  update operator_sessions set status = 'revoked', revoked_at = now(), revoke_reason = p_reason
   where operator_id = p_operator and status = 'active';
  get diagnostics n = row_count;
  return n;
end$$;

create or replace function app.operator_has_role(p_operator uuid, p_allowed text[])
returns boolean language sql stable as $$
  select exists (select 1 from platform_operators
                  where id = p_operator and status = 'active' and operator_role = any(p_allowed));
$$;

-- ---- Bind §12 dual-control to authenticated sessions (redefines the group-10 function) ----
-- The approver is now derived from a LIVE operator SESSION, not a caller-supplied UUID: the DB itself
-- proves a second, distinct, authenticated operator approved. Must run as svc_ops (reads support_access_
-- requests + operator_sessions + platform_operators). The second arg is now an operator_session id;
-- the parameter is renamed, so we DROP the 0011 definition (and re-GRANT below) rather than REPLACE.
drop function if exists app.approve_support_request(uuid, uuid);
create or replace function app.approve_support_request(p_request uuid, p_approver_session uuid)
returns text language plpgsql as $$
declare v record; v_approver uuid;
begin
  select * into v from support_access_requests where id = p_request for update;
  if not found then raise exception 'SUPPORT_REQUEST_NOT_FOUND' using errcode = 'P0002'; end if;
  if v.status <> 'pending' then raise exception 'SUPPORT_REQUEST_NOT_PENDING: %', v.status using errcode = 'P0001'; end if;
  v_approver := app.operator_of_live_session(p_approver_session);
  if v_approver is null then raise exception 'SUPPORT_APPROVER_SESSION_INVALID' using errcode = 'P0001'; end if;
  if v_approver = v.requested_by then raise exception 'SUPPORT_SELF_APPROVAL_DENIED' using errcode = 'P0001'; end if;
  update support_access_requests
     set status = 'approved', approved_by = v_approver, approved_at = now(),
         approval_expires_at = now() + interval '1 hour'
   where id = p_request;
  return 'approved';
end$$;

-- DEC-009 hardening: deny PUBLIC (svc_app) EXECUTE on the operator-auth functions (mutating AND the
-- SELECT-only helpers, for consistency); only the worker pool may call them.
revoke all on function
  app.operator_authenticate(citext, text, text),
  app.start_operator_session(uuid, integer),
  app.assert_operator_session_live(uuid),
  app.operator_of_live_session(uuid),
  app.revoke_operator_session(uuid, text),
  app.expire_operator_sessions(),
  app.disable_operator(uuid, text),
  app.operator_has_role(uuid, text[]),
  app.approve_support_request(uuid, uuid)   -- re-hardened after the DROP+recreate above
from public;
grant execute on function
  app.operator_authenticate(citext, text, text),
  app.start_operator_session(uuid, integer),
  app.assert_operator_session_live(uuid),
  app.operator_of_live_session(uuid),
  app.revoke_operator_session(uuid, text),
  app.expire_operator_sessions(),
  app.disable_operator(uuid, text),
  app.operator_has_role(uuid, text[]),
  app.approve_support_request(uuid, uuid)
to svc_worker;
