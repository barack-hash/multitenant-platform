-- 0006_sessions_launch.sql — table-group 5: sessions + 4-token launch/exchange (FOUNDATION_05).
-- Class B service-only (§8). Managed by svc_session. Depends on 0000-0005.

-- Sessions: hub (root) + spoke, with lineage (§4 required columns).
create table if not exists sessions (
  id                            uuid primary key default gen_random_uuid(),
  tenant_id                     uuid not null references tenants(id),
  user_id                       uuid not null references user_identities(id),
  membership_id                 uuid references tenant_memberships(id),
  kind                          text not null default 'hub' check (kind in ('hub','spoke')),
  app_id                        uuid references apps(id),
  root_session_id               uuid not null,
  parent_session_id             uuid,
  entitlement_snapshot_version  bigint not null default 0,
  status                        text not null default 'active' check (status in ('active','revoked','expired')),
  issued_at                     timestamptz not null default now(),
  expires_at                    timestamptz not null,
  revoked_at                    timestamptz,
  revoke_reason                 text
);
create index if not exists ix_sessions_root on sessions (root_session_id);
create index if not exists ix_sessions_tenant_user on sessions (tenant_id, user_id);

-- Launch tokens: 60s, one-time, nonce-bound (§4 required columns).
create table if not exists launch_tokens (
  id                            uuid primary key default gen_random_uuid(),
  jti                           uuid not null unique,
  tenant_id                     uuid not null references tenants(id),
  session_id                    uuid not null references sessions(id),
  root_session_id               uuid not null,
  parent_session_id             uuid,
  app_id                        uuid not null references apps(id),
  nonce_hash                    text not null,
  entitlement_snapshot_version  bigint not null default 0,
  status                        text not null default 'issued' check (status in ('issued','consumed','expired','revoked')),
  issued_at                     timestamptz not null default now(),
  expires_at                    timestamptz not null,
  consumed_at                   timestamptz
);
create index if not exists ix_launch_tokens_session on launch_tokens (session_id);

create table if not exists session_revocations (
  id               uuid primary key default gen_random_uuid(),
  session_id       uuid not null,
  root_session_id  uuid not null,
  tenant_id        uuid,
  reason           text,
  revoked_by       uuid,
  revoked_at       timestamptz not null default now()
);

-- ===== RLS: all Class B service-only (svc_session owns; no svc_app grant) =====
do $$
declare t text;
begin
  foreach t in array array['sessions','launch_tokens','session_revocations'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_session','svc_authz','svc_ops']))
      with check (app.assert_service_role(array['svc_session','svc_authz','svc_ops']));$p$, t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;
create trigger trg_no_reassign_sessions before update on sessions
  for each row execute function app.forbid_tenant_reassignment();

-- ===== Revocation cascade: revoke every session in the root's tree =====
create or replace function app.revoke_session_cascade(p_root uuid, p_reason text default 'revoked', p_actor uuid default null)
returns integer language plpgsql as $$
declare n integer;
begin
  update sessions set status = 'revoked', revoked_at = now(), revoke_reason = p_reason
   where root_session_id = p_root and status = 'active';
  get diagnostics n = row_count;
  insert into session_revocations(session_id, root_session_id, reason, revoked_by)
  values (p_root, p_root, p_reason, p_actor);
  return n;
end$$;
