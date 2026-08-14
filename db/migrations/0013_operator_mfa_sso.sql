-- 0013_operator_mfa_sso.sql — table-group 12: operator MFA (TOTP) + SSO federation (FOUNDATION_11).
-- Raises the assurance level of the operator trust plane: a second factor for high-privilege actions
-- (step-up) and a federation seam. Class B service-only (svc_ops/svc_authz); NO svc_app grant (DEC-009).
-- TOTP verification is app-layer (src/mfa.js); the DB stores state + serves service functions.
-- Depends on 0000-0012 (platform_operators, operator_sessions with amr/acr, the audit chain).

-- ============================= DDL =============================

-- One TOTP enrollment per operator. The base32 secret is recoverable by nature (needed to verify codes)
-- → encrypt-at-rest via KMS in prod; MVP stores it. Lockout via failed_attempts/locked_until.
create table if not exists operator_mfa (
  id              uuid primary key default gen_random_uuid(),
  operator_id     uuid not null references platform_operators(id),
  mfa_type        text not null default 'totp' check (mfa_type in ('totp')),
  secret          text not null,
  status          text not null default 'pending' check (status in ('pending','active','disabled')),
  failed_attempts integer not null default 0,
  locked_until    timestamptz,
  enrolled_at     timestamptz not null default now(),
  confirmed_at    timestamptz,
  last_used_at    timestamptz,
  disabled_at     timestamptz
);
-- At most one non-disabled enrollment per operator (re-enroll allowed after a reset/disable).
create unique index if not exists ux_operator_mfa_live on operator_mfa (operator_id) where status <> 'disabled';

-- One-time backup codes (stored hashed).
create table if not exists operator_recovery_codes (
  id           uuid primary key default gen_random_uuid(),
  operator_id  uuid not null references platform_operators(id),
  code_hash    text not null,                 -- sha256(recovery_code)
  used_at      timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists ix_operator_recovery_unused on operator_recovery_codes (operator_id) where used_at is null;

-- SSO provider registry (federation seam). MVP verifies an HMAC-signed assertion; prod = OIDC JWKS / SAML.
create table if not exists operator_idp (
  id               uuid primary key default gen_random_uuid(),
  idp_key          text not null unique,
  display_name     text not null,
  protocol         text not null check (protocol in ('oidc','saml')),
  issuer           text not null,
  audience         text not null,
  signing_secret   text not null,             -- HMAC secret (MVP); prod = JWKS/x509 ref (encrypt-at-rest)
  default_role     text not null default 'support' check (default_role in ('support','ops','admin')),
  allowed_domain   text,                       -- JIT provisioning restricted to this email domain
  jit_provisioning boolean not null default false,
  status           text not null default 'active' check (status in ('active','disabled')),
  created_at       timestamptz not null default now()
);

create table if not exists operator_federated_identities (
  id               uuid primary key default gen_random_uuid(),
  operator_id      uuid not null references platform_operators(id),
  idp_id           uuid not null references operator_idp(id),
  external_subject text not null,
  linked_at        timestamptz not null default now(),
  last_login_at    timestamptz,
  unique (idp_id, external_subject)
);

-- An operator can be required to carry a second factor.
alter table platform_operators add column if not exists mfa_required boolean not null default false;

-- ============================= RLS =============================
do $$
declare t text;
begin
  foreach t in array array['operator_mfa','operator_recovery_codes','operator_idp','operator_federated_identities'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_ops','svc_authz']))
      with check (app.assert_service_role(array['svc_ops','svc_authz']));$p$, t);
    execute format('grant select, insert, update, delete on %I to svc_worker;', t);
  end loop;
end$$;

-- ============================= Functions =============================

-- ---- MFA state (TOTP math is app-side; these manage rows) ----

-- Begin (or restart) enrollment: disable any live enrollment, insert a fresh pending one.
create or replace function app.operator_mfa_begin_enroll(p_operator uuid, p_secret text)
returns uuid language plpgsql as $$
declare v_id uuid;
begin
  update operator_mfa set status = 'disabled', disabled_at = now() where operator_id = p_operator and status <> 'disabled';
  delete from operator_recovery_codes where operator_id = p_operator and used_at is null;
  insert into operator_mfa(operator_id, secret, status) values (p_operator, p_secret, 'pending') returning id into v_id;
  return v_id;
end$$;

-- Activate the pending enrollment (the app has verified a live code first).
create or replace function app.operator_mfa_activate(p_operator uuid)
returns boolean language plpgsql as $$
declare n integer;
begin
  update operator_mfa set status = 'active', confirmed_at = now(), failed_attempts = 0, locked_until = null
   where operator_id = p_operator and status = 'pending';
  get diagnostics n = row_count;
  return n > 0;
end$$;

-- The active/pending enrollment (secret + lock state) for the app to verify a code against. Null if none.
create or replace function app.operator_mfa_get(p_operator uuid)
returns table(secret text, status text, locked boolean) language sql stable as $$
  select m.secret, m.status, (m.locked_until is not null and m.locked_until > now())
    from operator_mfa m where m.operator_id = p_operator and m.status <> 'disabled' limit 1;
$$;

-- Record an MFA verification outcome: success resets the counter; failure increments and locks after 5.
create or replace function app.operator_mfa_record(p_operator uuid, p_ok boolean)
returns boolean language plpgsql as $$
declare v_locked boolean := false;
begin
  if p_ok then
    update operator_mfa set failed_attempts = 0, locked_until = null, last_used_at = now()
     where operator_id = p_operator and status <> 'disabled';
  else
    update operator_mfa set failed_attempts = failed_attempts + 1,
           locked_until = case when failed_attempts + 1 >= 5 then now() + interval '15 minutes' else locked_until end
     where operator_id = p_operator and status <> 'disabled'
     returning (locked_until is not null and locked_until > now()) into v_locked;
  end if;
  return coalesce(v_locked, false);
end$$;

create or replace function app.operator_has_active_mfa(p_operator uuid)
returns boolean language sql stable as $$
  select exists (select 1 from operator_mfa where operator_id = p_operator and status = 'active');
$$;

-- Admin reset: disable MFA + clear unused recovery codes (the §12 sensitive operation).
create or replace function app.operator_reset_mfa(p_operator uuid, p_reason text default 'admin_reset')
returns integer language plpgsql as $$
declare n integer;
begin
  update operator_mfa set status = 'disabled', disabled_at = now() where operator_id = p_operator and status <> 'disabled';
  get diagnostics n = row_count;
  delete from operator_recovery_codes where operator_id = p_operator and used_at is null;
  update platform_operators set mfa_required = false where id = p_operator;
  return n;
end$$;

create or replace function app.operator_add_recovery_codes(p_operator uuid, p_hashes text[])
returns integer language plpgsql as $$
declare h text; n integer := 0;
begin
  foreach h in array p_hashes loop
    insert into operator_recovery_codes(operator_id, code_hash) values (p_operator, h);
    n := n + 1;
  end loop;
  return n;
end$$;

-- Consume a recovery code (single-use): mark the first unused matching row used; true iff one was consumed.
create or replace function app.operator_consume_recovery_code(p_operator uuid, p_hash text)
returns boolean language plpgsql as $$
declare v_id uuid;
begin
  select id into v_id from operator_recovery_codes
   where operator_id = p_operator and code_hash = p_hash and used_at is null limit 1 for update;
  if v_id is null then return false; end if;
  update operator_recovery_codes set used_at = now() where id = v_id;
  return true;
end$$;

-- ---- SSO: resolve a federated identity to an operator, JIT-provisioning if the IdP allows it ----
-- Hardening: the JIT role and allowed email domain are read FROM the IdP row (never a caller argument),
-- so the app cannot request an elevated role or provision outside the domain. The app still verifies the
-- assertion's signature/issuer/audience/exp before calling this (app-layer, like the webhook HMAC).
create or replace function app.operator_sso_login(p_idp uuid, p_external_subject text, p_email citext)
returns table(operator_id uuid, operator_role text, jit boolean) language plpgsql as $$
declare v_op uuid; v_role text; v_new boolean := false; v_idp record;
begin
  select * into v_idp from operator_idp where id = p_idp and status = 'active';
  if v_idp is null then raise exception 'SSO_IDP_UNKNOWN' using errcode = 'P0001'; end if;
  select fi.operator_id, po.operator_role into v_op, v_role
    from operator_federated_identities fi join platform_operators po on po.id = fi.operator_id
   where fi.idp_id = p_idp and fi.external_subject = p_external_subject and po.status = 'active';
  if v_op is null and v_idp.jit_provisioning then
    -- JIT ONLY within the IdP's allowed_domain, and ONLY at the IdP's default_role.
    if v_idp.allowed_domain is null
       or lower(split_part(p_email::text, '@', 2)) <> lower(v_idp.allowed_domain) then
      raise exception 'SSO_DOMAIN_NOT_ALLOWED' using errcode = 'P0001';
    end if;
    insert into platform_operators(email, display_name, operator_role)
      values (p_email, 'SSO ' || p_email, v_idp.default_role)
      returning platform_operators.id, platform_operators.operator_role into v_op, v_role;
    insert into operator_federated_identities(operator_id, idp_id, external_subject)
      values (v_op, p_idp, p_external_subject);
    v_new := true;
  end if;
  if v_op is null then return; end if;
  update operator_federated_identities set last_login_at = now()
   where idp_id = p_idp and external_subject = p_external_subject;
  operator_id := v_op; operator_role := v_role; jit := v_new; return next;
end$$;

-- ---- Sessions now record amr/acr (redefine group-11 start_operator_session; DROP+recreate to add params) ----
drop function if exists app.start_operator_session(uuid, integer);
create or replace function app.start_operator_session(
  p_operator uuid, p_ttl integer default 1800, p_amr text default 'pwd', p_acr text default 'pwd')
returns uuid language plpgsql as $$
declare v_id uuid; v_ttl integer;
begin
  if not exists (select 1 from platform_operators where id = p_operator and status = 'active') then
    raise exception 'OPERATOR_INACTIVE' using errcode = 'P0001';
  end if;
  v_ttl := least(greatest(coalesce(p_ttl, 1800), 60), 3600);
  insert into operator_sessions(operator_id, issued_at, expires_at, amr, acr)
  values (p_operator, now(), now() + make_interval(secs => v_ttl), p_amr, p_acr)
  returning id into v_id;
  return v_id;
end$$;

-- DEC-009 hardening: deny PUBLIC (svc_app) EXECUTE on the operator MFA/SSO/session functions.
revoke all on function
  app.operator_mfa_begin_enroll(uuid, text), app.operator_mfa_activate(uuid), app.operator_mfa_get(uuid),
  app.operator_mfa_record(uuid, boolean), app.operator_has_active_mfa(uuid), app.operator_reset_mfa(uuid, text),
  app.operator_add_recovery_codes(uuid, text[]), app.operator_consume_recovery_code(uuid, text),
  app.operator_sso_login(uuid, text, citext), app.start_operator_session(uuid, integer, text, text)
from public;
grant execute on function
  app.operator_mfa_begin_enroll(uuid, text), app.operator_mfa_activate(uuid), app.operator_mfa_get(uuid),
  app.operator_mfa_record(uuid, boolean), app.operator_has_active_mfa(uuid), app.operator_reset_mfa(uuid, text),
  app.operator_add_recovery_codes(uuid, text[]), app.operator_consume_recovery_code(uuid, text),
  app.operator_sso_login(uuid, text, citext), app.start_operator_session(uuid, integer, text, text)
to svc_worker;
