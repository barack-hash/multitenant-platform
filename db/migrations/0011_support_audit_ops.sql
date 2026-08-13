-- 0011_support_audit_ops.sql — table-group 10: support/impersonation + platform-ops + Tier-A audit.
-- FOUNDATION_09. Depends on 0000-0010. All Class B/C/D service-owned; NO svc_app grant (DEC-009:
-- svc_app gets nothing on support/audit internals). Logical roles svc_support / svc_audit / svc_ops
-- ride the single svc_worker physical login via withServiceContext (add no new DB roles).
--
-- Three sub-domains:
--   1. AUDIT (Tier A, DEC-015/§16): append-only hash-chained governance ledger + external anchors.
--   2. SUPPORT/IMPERSONATION (§12): dual-control, ≤30-min non-renewable TTL, one-active, banner,
--      prohibited-action hard-deny, every denial audited.
--   3. PLATFORM-OPS registries (§2 Support and Operations): rate limits, deployments, migrations, promotions.

-- ============================================================================
-- 1. AUDIT — Tier A immutable hash-chained ledger (DEC-015, §16, §6 never-hard-delete)
-- ============================================================================

-- The ledger. chain_id groups an ordered cryptographic chain: a tenant's uuid text, or 'platform'
-- for cross-tenant/operator/seed events (so a tenant purge never severs another chain). PII stays OUT
-- of the hashed tuple — only surrogate refs/tokens are recorded, so subject erasure (group 8) can't
-- break the chain. `meta` is non-PII and IS hashed.
create table if not exists audit_events (
  id              uuid primary key default gen_random_uuid(),
  chain_id        text        not null,               -- tenant_id::text or 'platform'
  chain_seq       bigint      not null,               -- strictly increasing, gap-free, per chain_id
  tenant_id       uuid        references tenants(id),  -- null for platform scope
  occurred_at     timestamptz not null default now(),
  recorded_at     timestamptz not null default now(),
  actor_type      text        not null,               -- 'user'|'service'|'system'|'support'
  actor_ref       text,                               -- surrogate id/token, NEVER raw PII
  source_svc_role text,                               -- app.svc_role GUC at write time
  action          text        not null,               -- e.g. 'support.impersonation.granted'
  resource_type   text,
  resource_ref    text,                               -- surrogate id, NEVER raw PII
  subject_token   text,                               -- tokenized data subject (survives erasure)
  outcome         text        not null default 'success' check (outcome in ('success','failure','denied')),
  reason_code     text,
  correlation_id  text,
  support_session_id uuid,                            -- set when the action ran under impersonation
  meta            jsonb       not null default '{}'::jsonb,  -- NON-PII only; part of the hash
  hash_alg        text        not null default 'sha256',
  prev_hash       text        not null,               -- prior row's row_hash (genesis = 64 zeros)
  row_hash        text        not null,               -- sha256(prev_hash || '|' || canonical(fields))
  constraint ux_audit_events_chain unique (chain_id, chain_seq),
  constraint ux_audit_events_rowhash unique (chain_id, row_hash)
);
create index if not exists ix_audit_events_tenant_time on audit_events (tenant_id, occurred_at desc);
create index if not exists ix_audit_events_subject on audit_events (subject_token) where subject_token is not null;
create index if not exists ix_audit_events_support on audit_events (support_session_id) where support_session_id is not null;

-- Periodic external anchoring of a chain head (§16 Tier A: "periodically anchor the hash-chain head
-- externally"). Insert-once evidence; the external sink (WORM/notary) is a deferred Tier-B concern.
create table if not exists audit_anchor_points (
  id           uuid primary key default gen_random_uuid(),
  chain_id     text not null,
  chain_seq    bigint not null,
  row_hash     text not null,
  hash_alg     text not null default 'sha256',
  anchored_at  timestamptz not null default now(),
  external_ref text,
  constraint ux_audit_anchor unique (chain_id, chain_seq)
);

alter table audit_events enable row level security;
alter table audit_events force  row level security;
-- Any legit SERVICE may APPEND its own actions (cross-cutting governance ledger); NO client (svc_app).
create policy p_audit_events_append on audit_events
  for insert with check (app.assert_service_role(
    array['svc_audit','svc_support','svc_ops','svc_lifecycle','svc_billing','svc_entitlement',
          'svc_session','svc_authz','svc_identity','svc_events','svc_file']));
-- Any legit SERVICE may READ the ledger (never a client — §8). The write path app.audit_append reads
-- the chain head to compute the next chain_seq, so EVERY writer role must also satisfy this SELECT
-- policy (else RLS hides the head and the chain forks to seq=1 → unique violation). No svc_app.
create policy p_audit_events_select on audit_events
  for select using (app.assert_service_role(
    array['svc_audit','svc_ops','svc_support','svc_lifecycle','svc_billing','svc_entitlement',
          'svc_session','svc_authz','svc_identity','svc_events','svc_file']));
grant select, insert on audit_events to svc_worker;   -- NO update/delete (append-only)
revoke update, delete, truncate on audit_events from svc_worker;

-- Append-only enforced even against the table owner / a buggy path (row + statement level).
create or replace function app.forbid_audit_mutation()
returns trigger language plpgsql as $$
begin
  raise exception 'audit_events is append-only (Tier A, DEC-015): % denied', tg_op;
end$$;
create trigger trg_audit_events_immutable before update or delete on audit_events
  for each row execute function app.forbid_audit_mutation();
create trigger trg_audit_events_no_truncate before truncate on audit_events
  for each statement execute function app.forbid_audit_mutation();

alter table audit_anchor_points enable row level security;
alter table audit_anchor_points force  row level security;
create policy p_audit_anchor_service on audit_anchor_points
  for all using (app.assert_service_role(array['svc_audit','svc_ops']))
  with check (app.assert_service_role(array['svc_audit','svc_ops']));
grant select, insert on audit_anchor_points to svc_worker;

-- ============================================================================
-- 2. PLATFORM OPERATORS + SUPPORT / IMPERSONATION (§12 hard controls)
-- ============================================================================

-- Platform staff directory — operators are NOT tenant users (distinct trust boundary).
create table if not exists platform_operators (
  id           uuid primary key default gen_random_uuid(),
  email        citext not null unique,
  display_name text not null,
  operator_role text not null default 'support' check (operator_role in ('support','ops','admin')),
  status       text not null default 'active' check (status in ('active','disabled')),
  created_at   timestamptz not null default now(),
  disabled_at  timestamptz
);

-- The dual-control approval workflow. CHECK enforces requester≠approver at the row level (C1); the
-- approve function enforces the transition. ttl_seconds capped at 30 min (C2) drives the session TTL.
create table if not exists support_access_requests (
  id                  uuid primary key default gen_random_uuid(),
  tenant_id           uuid not null references tenants(id),
  requested_by        uuid not null references platform_operators(id),
  target_user_id      uuid references user_identities(id),   -- the user to impersonate (null = tenant-scoped)
  reason              text not null,
  ticket_ref          text,
  mode                text not null default 'read_only' check (mode in ('read_only','read_write')),
  ttl_seconds         integer not null default 1800 check (ttl_seconds > 0 and ttl_seconds <= 1800),
  status              text not null default 'pending'
                        check (status in ('pending','approved','denied','consumed','expired')),
  approved_by         uuid references platform_operators(id),
  approval_expires_at timestamptz,
  requested_at        timestamptz not null default now(),
  approved_at         timestamptz,
  denied_at           timestamptz,
  deny_reason         text,
  consumed_at         timestamptz,
  constraint ck_support_dual_control check (approved_by is null or approved_by <> requested_by)
);
create index if not exists ix_support_requests_tenant on support_access_requests (tenant_id, status);

-- The active impersonation session. Separate from group-5 `sessions` (which it references) so that
-- table's invariants stay intact. Non-renewable + one-active enforced by trigger + partial unique index.
create table if not exists support_sessions (
  id                     uuid primary key default gen_random_uuid(),
  access_request_id      uuid not null references support_access_requests(id),
  tenant_id              uuid not null references tenants(id),
  support_operator_id    uuid not null references platform_operators(id),
  target_user_id         uuid references user_identities(id),
  impersonated_session_id uuid references sessions(id),   -- the group-5 session minted for the view
  mode                   text not null default 'read_only' check (mode in ('read_only','read_write')),
  banner_required        boolean not null default true,   -- C5: the UI MUST render the banner
  status                 text not null default 'active' check (status in ('active','ended','revoked','expired')),
  started_at             timestamptz not null default now(),
  expires_at             timestamptz not null,
  ended_at               timestamptz,
  revoke_reason          text,
  constraint ck_support_ttl_30min check (expires_at <= started_at + interval '30 minutes')  -- C2
);
-- C4: at most one ACTIVE session per (operator, tenant) — race-safe (DB serializes).
create unique index if not exists ux_support_sessions_one_active
  on support_sessions (support_operator_id, tenant_id) where status = 'active';
create index if not exists ix_support_sessions_tenant on support_sessions (tenant_id, status);

alter table support_access_requests enable row level security;
alter table support_access_requests force  row level security;
create policy p_support_requests_service on support_access_requests
  for all using (app.assert_service_role(array['svc_support','svc_ops']))
  with check (app.assert_service_role(array['svc_support','svc_ops']));
grant select, insert, update on support_access_requests to svc_worker;
create trigger trg_no_reassign_support_requests before update on support_access_requests
  for each row execute function app.forbid_tenant_reassignment();

alter table support_sessions enable row level security;
alter table support_sessions force  row level security;
create policy p_support_sessions_service on support_sessions
  for all using (app.assert_service_role(array['svc_support','svc_ops']))
  with check (app.assert_service_role(array['svc_support','svc_ops']));
grant select, insert, update on support_sessions to svc_worker;
create trigger trg_no_reassign_support_sessions before update on support_sessions
  for each row execute function app.forbid_tenant_reassignment();

-- C3 non-renewable: expires_at can never move later, and a terminal session can never reactivate.
create or replace function app.forbid_support_session_extension()
returns trigger language plpgsql as $$
begin
  if new.expires_at is distinct from old.expires_at and new.expires_at > old.expires_at then
    raise exception 'SUPPORT_SESSION_NOT_RENEWABLE: expires_at cannot be extended';
  end if;
  if old.status in ('ended','revoked','expired') and new.status = 'active' then
    raise exception 'SUPPORT_SESSION_NOT_RENEWABLE: a terminal session cannot be reactivated';
  end if;
  return new;
end$$;
create trigger trg_support_session_non_renewable before update on support_sessions
  for each row execute function app.forbid_support_session_extension();

-- platform_operators: Class B service-only (svc_support/svc_ops own the staff directory).
alter table platform_operators enable row level security;
alter table platform_operators force  row level security;
create policy p_platform_operators_service on platform_operators
  for all using (app.assert_service_role(array['svc_support','svc_ops']))
  with check (app.assert_service_role(array['svc_support','svc_ops']));
grant select, insert, update on platform_operators to svc_worker;

-- ============================================================================
-- 3. PLATFORM-OPS REGISTRIES (§2 Support and Operations)
-- ============================================================================

-- Rate-limit policy catalog (Class C global reference; §17 requires seed_rate_limit_policies).
create table if not exists rate_limit_policies (
  id            uuid primary key default gen_random_uuid(),
  policy_key    text not null unique,
  scope         text not null check (scope in ('global','tenant','app','endpoint')),
  limit_per_window integer not null check (limit_per_window > 0),
  window_seconds integer not null check (window_seconds > 0),
  burst         integer not null default 0,
  description   text not null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
alter table rate_limit_policies enable row level security;
alter table rate_limit_policies force  row level security;
create policy p_rate_limit_policies_read on rate_limit_policies
  for select using (app.current_actor_id() is not null or app.current_actor_type() = 'service');
create policy p_rate_limit_policies_write on rate_limit_policies
  for all using (app.assert_service_role(array['svc_ops']))
  with check (app.assert_service_role(array['svc_ops']));
grant select on rate_limit_policies to svc_app;
grant select, insert, update on rate_limit_policies to svc_worker;

-- Per-tenant override (Class A tenant-read; service-write). A tenant may see its own limits.
create table if not exists tenant_rate_limit_overrides (
  id               uuid primary key default gen_random_uuid(),
  tenant_id        uuid not null references tenants(id),
  policy_key       text not null,
  limit_per_window integer not null check (limit_per_window > 0),
  window_seconds   integer not null check (window_seconds > 0),
  reason           text,
  created_by       uuid,
  created_at       timestamptz not null default now()
);
create index if not exists ix_rate_overrides_tenant on tenant_rate_limit_overrides (tenant_id, policy_key);
alter table tenant_rate_limit_overrides enable row level security;
alter table tenant_rate_limit_overrides force  row level security;
create policy p_rate_overrides_tenant_select on tenant_rate_limit_overrides
  for select using (app.assert_tenant_context() and tenant_id = app.current_tenant_id() and app.assert_membership_active());
create policy p_rate_overrides_service on tenant_rate_limit_overrides
  for all using (app.assert_service_role(array['svc_ops']))
  with check (app.assert_service_role(array['svc_ops']));
grant select on tenant_rate_limit_overrides to svc_app;
grant select, insert, update on tenant_rate_limit_overrides to svc_worker;
create trigger trg_no_reassign_rate_overrides before update on tenant_rate_limit_overrides
  for each row execute function app.forbid_tenant_reassignment();

-- Deployment / migration / promotion operator logs (Class B service-only, svc_ops).
create table if not exists platform_deployments (
  id           uuid primary key default gen_random_uuid(),
  environment  text not null check (environment in ('local','staging','production')),
  service_name text not null,
  version      text not null,
  git_sha      text,
  status       text not null default 'pending' check (status in ('pending','active','rolled_back','failed')),
  released_by  uuid,
  released_at  timestamptz not null default now(),
  notes        text
);
create table if not exists schema_migration_runs (
  id             uuid primary key default gen_random_uuid(),
  migration_name text not null,
  checksum       text not null,
  status         text not null default 'applied' check (status in ('applied','failed','rolled_back')),
  applied_by     text,
  applied_at     timestamptz not null default now(),
  duration_ms    integer
);
create index if not exists ix_migration_runs_name on schema_migration_runs (migration_name, applied_at desc);
create table if not exists environment_promotions (
  id           uuid primary key default gen_random_uuid(),
  from_env     text not null,
  to_env       text not null,
  artifact_ref text not null,
  status       text not null default 'pending' check (status in ('pending','promoted','failed','rolled_back')),
  promoted_by  uuid,
  promoted_at  timestamptz not null default now()
);
do $$
declare t text;
begin
  foreach t in array array['platform_deployments','schema_migration_runs','environment_promotions'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_ops']))
      with check (app.assert_service_role(array['svc_ops']));$p$, t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;

-- ============================================================================
-- 4. FUNCTIONS
-- ============================================================================

-- ---- 4a. Impersonation-context helpers (read trusted server-set GUCs, like 0001) ----
create or replace function app.current_support_session_id()
returns uuid language sql stable as $$
  select nullif(current_setting('app.support_session_id', true), '')::uuid;
$$;
create or replace function app.current_impersonator_id()
returns text language sql stable as $$
  select nullif(current_setting('app.impersonator_id', true), '');
$$;
create or replace function app.is_impersonated()
returns boolean language sql stable as $$
  select nullif(current_setting('app.support_session_id', true), '') is not null;
$$;

-- ---- 4b. Audit: the canonical append path + verifier + anchor ----
-- SECURITY INVOKER (portable; prod owner is svc_migrate, not superuser). Serialized per chain by an
-- advisory lock so concurrent appends can't fork the head. PII must never be passed in the hashed args.
create or replace function app.audit_append(
  p_chain_id        text,
  p_tenant_id       uuid,
  p_action          text,
  p_actor_type      text default 'service',
  p_actor_ref       text default null,
  p_resource_type   text default null,
  p_resource_ref    text default null,
  p_subject_token   text default null,
  p_outcome         text default 'success',
  p_reason_code     text default null,
  p_correlation_id  text default null,
  p_support_session_id uuid default null,
  p_meta            jsonb default '{}'::jsonb
) returns uuid language plpgsql as $$
declare
  v_seq  bigint;
  v_prev text;
  v_canon text;
  v_hash text;
  v_id   uuid;
begin
  perform pg_advisory_xact_lock(hashtext('audit:' || p_chain_id));
  select chain_seq, row_hash into v_seq, v_prev
    from audit_events where chain_id = p_chain_id order by chain_seq desc limit 1;
  if v_seq is null then v_seq := 0; v_prev := repeat('0', 64); end if;
  v_seq := v_seq + 1;
  v_canon := concat_ws('|',
    p_chain_id, v_seq::text, coalesce(p_tenant_id::text, ''),
    coalesce(p_actor_type, ''), coalesce(p_actor_ref, ''), coalesce(app.current_svc_role(), ''),
    p_action, coalesce(p_resource_type, ''), coalesce(p_resource_ref, ''), coalesce(p_subject_token, ''),
    p_outcome, coalesce(p_reason_code, ''), coalesce(p_correlation_id, ''),
    coalesce(p_meta::text, '{}'));
  v_hash := encode(sha256(convert_to(v_prev || '|' || v_canon, 'UTF8')), 'hex');
  insert into audit_events(chain_id, chain_seq, tenant_id, actor_type, actor_ref, source_svc_role,
      action, resource_type, resource_ref, subject_token, outcome, reason_code, correlation_id,
      support_session_id, meta, prev_hash, row_hash)
  values (p_chain_id, v_seq, p_tenant_id, p_actor_type, p_actor_ref, app.current_svc_role(),
      p_action, p_resource_type, p_resource_ref, p_subject_token, p_outcome, p_reason_code, p_correlation_id,
      p_support_session_id, coalesce(p_meta, '{}'::jsonb), v_prev, v_hash)
  returning id into v_id;
  return v_id;
end$$;

-- Recompute the chain and report the first tampered/reordered/missing row (null failure_kind = clean).
create or replace function app.audit_verify_chain(p_chain_id text)
returns table (ok boolean, checked bigint, first_bad_seq bigint, failure_kind text)
language plpgsql stable as $$
declare
  r record;
  v_prev text := repeat('0', 64);
  v_expected_seq bigint := 1;
  v_canon text; v_hash text; v_n bigint := 0;
begin
  ok := true; first_bad_seq := null; failure_kind := null;
  for r in select * from audit_events where chain_id = p_chain_id order by chain_seq asc loop
    v_n := v_n + 1;
    if r.chain_seq <> v_expected_seq then
      ok := false; first_bad_seq := r.chain_seq; failure_kind := 'seq_gap'; checked := v_n; return next; return;
    end if;
    if r.prev_hash <> v_prev then
      ok := false; first_bad_seq := r.chain_seq; failure_kind := 'prev_hash_mismatch'; checked := v_n; return next; return;
    end if;
    v_canon := concat_ws('|',
      r.chain_id, r.chain_seq::text, coalesce(r.tenant_id::text, ''),
      coalesce(r.actor_type, ''), coalesce(r.actor_ref, ''), coalesce(r.source_svc_role, ''),
      r.action, coalesce(r.resource_type, ''), coalesce(r.resource_ref, ''), coalesce(r.subject_token, ''),
      r.outcome, coalesce(r.reason_code, ''), coalesce(r.correlation_id, ''),
      coalesce(r.meta::text, '{}'));
    v_hash := encode(sha256(convert_to(r.prev_hash || '|' || v_canon, 'UTF8')), 'hex');
    if v_hash <> r.row_hash then
      ok := false; first_bad_seq := r.chain_seq; failure_kind := 'row_hash_mismatch'; checked := v_n; return next; return;
    end if;
    v_prev := r.row_hash;
    v_expected_seq := v_expected_seq + 1;
  end loop;
  checked := v_n;
  return next;
end$$;

-- Record the current chain head as an anchor point (external WORM sink deferred, Tier B). The anchor
-- lives ONLY in audit_anchor_points (an insert-once table) — audit_events itself is never mutated, so
-- this honors DEC-015's "REVOKE UPDATE on the ledger". "Which rows are anchored" is derivable: seq S on
-- chain C is anchored iff an anchor_point exists for C with chain_seq >= S.
create or replace function app.audit_anchor(p_chain_id text, p_external_ref text default null)
returns uuid language plpgsql as $$
declare v_seq bigint; v_hash text; v_id uuid;
begin
  select chain_seq, row_hash into v_seq, v_hash
    from audit_events where chain_id = p_chain_id order by chain_seq desc limit 1;
  if v_seq is null then raise exception 'AUDIT_CHAIN_EMPTY: %', p_chain_id using errcode = 'P0002'; end if;
  insert into audit_anchor_points(chain_id, chain_seq, row_hash, external_ref)
  values (p_chain_id, v_seq, v_hash, p_external_ref)
  on conflict (chain_id, chain_seq) do nothing
  returning id into v_id;
  -- v_id is null on a re-anchor of the same head (idempotent); fetch the existing anchor's id.
  if v_id is null then
    select id into v_id from audit_anchor_points where chain_id = p_chain_id and chain_seq = v_seq;
  end if;
  return v_id;
end$$;

-- ---- 4c. Support impersonation: dual-control approval, session start, prohibited-action gate ----

-- C1 dual-control: approver must differ from requester; only a pending request can be approved.
create or replace function app.approve_support_request(p_request uuid, p_approver uuid)
returns text language plpgsql as $$
declare v record;
begin
  select * into v from support_access_requests where id = p_request for update;
  if not found then raise exception 'SUPPORT_REQUEST_NOT_FOUND' using errcode = 'P0002'; end if;
  if v.status <> 'pending' then raise exception 'SUPPORT_REQUEST_NOT_PENDING: %', v.status using errcode = 'P0001'; end if;
  if p_approver = v.requested_by then raise exception 'SUPPORT_SELF_APPROVAL_DENIED' using errcode = 'P0001'; end if;
  -- The approver must be a real, ACTIVE operator (a disabled operator can't grant dual-control approval).
  if not exists (select 1 from platform_operators where id = p_approver and status = 'active') then
    raise exception 'SUPPORT_APPROVER_INVALID: approver must be an active operator' using errcode = 'P0001';
  end if;
  update support_access_requests
     set status = 'approved', approved_by = p_approver, approved_at = now(),
         approval_expires_at = now() + interval '1 hour'
   where id = p_request;
  return 'approved';
end$$;

-- Start the impersonation session from an approved request. C2 TTL (≤30min) + C4 one-active (partial
-- unique index) + C5 banner_required. Consumes the request (one session per approval).
create or replace function app.start_support_session(p_request uuid, p_impersonated_session uuid default null)
returns uuid language plpgsql as $$
declare v record; v_id uuid; v_ttl integer;
begin
  select * into v from support_access_requests where id = p_request for update;
  if not found then raise exception 'SUPPORT_REQUEST_NOT_FOUND' using errcode = 'P0002'; end if;
  if v.status <> 'approved' then raise exception 'SUPPORT_REQUEST_NOT_APPROVED: %', v.status using errcode = 'P0001'; end if;
  if v.approval_expires_at is not null and now() > v.approval_expires_at then
    raise exception 'SUPPORT_APPROVAL_EXPIRED' using errcode = 'P0001';
  end if;
  -- Free the one-active slot if a prior session for this (operator, tenant) passed its TTL but was never
  -- swept to 'expired' — the partial unique index only excludes non-'active' rows, so a stale row would
  -- otherwise block a legitimate new session (C4 must not become a denial-of-service on the operator).
  update support_sessions set status = 'expired', ended_at = now()
   where support_operator_id = v.requested_by and tenant_id = v.tenant_id
     and status = 'active' and now() >= expires_at;
  v_ttl := least(coalesce(v.ttl_seconds, 1800), 1800);
  insert into support_sessions(access_request_id, tenant_id, support_operator_id, target_user_id, mode,
      impersonated_session_id, banner_required, started_at, expires_at, status)
  values (p_request, v.tenant_id, v.requested_by, v.target_user_id, v.mode,
      p_impersonated_session, true, now(), now() + make_interval(secs => v_ttl), 'active')
  returning id into v_id;
  update support_access_requests set status = 'consumed', consumed_at = now() where id = p_request;
  return v_id;
end$$;

-- The five §12 prohibited action classes (pure predicate).
create or replace function app.support_action_prohibited(p_action_class text)
returns boolean language sql immutable as $$
  select p_action_class in ('billing','identity_secret','lifecycle_destructive','role_privilege','infra_secret');
$$;

-- Hard-deny gate: raises for an expired/terminal session (C2a) or a prohibited action class (P1-P5).
-- Callers audit the denial in a SEPARATE committed tx (Postgres has no autonomous tx) then reject.
create or replace function app.assert_support_action_allowed(p_session uuid, p_action_class text)
returns boolean language plpgsql stable as $$
declare v record;
begin
  select * into v from support_sessions where id = p_session;
  if not found then raise exception 'SUPPORT_SESSION_NOT_FOUND' using errcode = 'P0002'; end if;
  if v.status <> 'active' or now() >= v.expires_at then
    raise exception 'SUPPORT_SESSION_EXPIRED' using errcode = 'P0001';
  end if;
  if app.support_action_prohibited(p_action_class) then
    raise exception 'SUPPORT_ACTION_PROHIBITED: %', p_action_class using errcode = 'P0001';
  end if;
  return true;
end$$;

-- End / revoke an impersonation session (the group-5 cascade revokes the underlying session).
create or replace function app.end_support_session(p_session uuid, p_reason text default 'ended')
returns integer language plpgsql as $$
declare v record; n integer := 0;
begin
  select * into v from support_sessions where id = p_session for update;
  if not found then raise exception 'SUPPORT_SESSION_NOT_FOUND' using errcode = 'P0002'; end if;
  if v.status = 'active' then
    update support_sessions set status = 'ended', ended_at = now(), revoke_reason = p_reason where id = p_session;
    if v.impersonated_session_id is not null then
      n := app.revoke_session_cascade(v.impersonated_session_id, 'support_session_ended', null);
    end if;
  end if;
  return n;
end$$;

-- Scheduled sweep: flip every past-TTL 'active' session to 'expired' (frees the one-active slot; a real
-- deployment runs this on a short timer). Idempotent; returns the number swept. The non-renewable
-- trigger allows active→expired; the partial unique index drops the row once it leaves 'active'.
create or replace function app.expire_support_sessions()
returns integer language plpgsql as $$
declare n integer;
begin
  update support_sessions set status = 'expired', ended_at = now()
   where status = 'active' and now() >= expires_at;
  get diagnostics n = row_count;
  return n;
end$$;

-- DEC-009 hardening: deny PUBLIC (svc_app) EXECUTE on the mutating support/audit functions; only the
-- worker pool may call them.
revoke all on function
  app.audit_append(text, uuid, text, text, text, text, text, text, text, text, text, uuid, jsonb),
  app.audit_anchor(text, text),
  app.approve_support_request(uuid, uuid),
  app.start_support_session(uuid, uuid),
  app.end_support_session(uuid, text),
  app.expire_support_sessions()
from public;
grant execute on function
  app.audit_append(text, uuid, text, text, text, text, text, text, text, text, text, uuid, jsonb),
  app.audit_anchor(text, text),
  app.approve_support_request(uuid, uuid),
  app.start_support_session(uuid, uuid),
  app.end_support_session(uuid, text),
  app.expire_support_sessions()
to svc_worker;
