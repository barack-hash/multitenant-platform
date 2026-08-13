-- 0002_identity_tenancy.sql — table-group-1 DDL + RLS + projections (FOUNDATION_01 §4-6)
-- Requires PostgreSQL >= 15 (security_invoker views) and core gen_random_uuid() (PG13+).

create extension if not exists citext;

-- ============================= DDL =============================

create table if not exists tenants (
  id                            uuid primary key default gen_random_uuid(),
  slug                          citext not null unique,
  name                          text not null,
  status                        text not null default 'active'
                                  check (status in ('active','frozen','suspended','offboarding','deleted')),
  billing_status                text not null default 'trialing'
                                  check (billing_status in ('trialing','active','past_due','grace','locked','canceled')),
  deployment_tier               text not null default 'shared'
                                  check (deployment_tier in ('shared','dedicated')),
  region                        text,
  audit_tier                    text not null default 'A' check (audit_tier in ('A','B','C')),
  entitlement_snapshot_version  bigint not null default 0,
  version                       bigint not null default 1,
  created_at                    timestamptz not null default now(),
  updated_at                    timestamptz not null default now(),
  deleted_at                    timestamptz,
  deleted_by                    uuid,
  delete_reason                 text
);

create table if not exists user_identities (
  id             uuid primary key default gen_random_uuid(),
  auth_provider  text not null default 'supabase',
  auth_subject   text not null,
  primary_email  citext,
  display_name   text,
  status         text not null default 'active' check (status in ('active','disabled','deleted')),
  version        bigint not null default 1,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  deleted_at     timestamptz,
  deleted_by     uuid,
  delete_reason  text,
  unique (auth_provider, auth_subject)
);
create unique index if not exists ux_user_identities_email
  on user_identities (primary_email) where primary_email is not null and deleted_at is null;

create table if not exists tenant_memberships (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id),
  user_id       uuid not null references user_identities(id),
  status        text not null default 'invited' check (status in ('invited','active','suspended','revoked')),
  invited_by    uuid,
  invited_at    timestamptz,
  activated_at  timestamptz,
  version       bigint not null default 1,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  deleted_at    timestamptz,
  deleted_by    uuid,
  delete_reason text,
  unique (tenant_id, id)   -- FK target so child rows can be pinned to the same tenant
);
create unique index if not exists ux_tenant_memberships_tenant_user
  on tenant_memberships (tenant_id, user_id) where deleted_at is null;
create index if not exists ix_tenant_memberships_user on tenant_memberships (user_id);

create table if not exists roles (
  id          uuid primary key default gen_random_uuid(),
  role_key    text not null unique,
  name        text not null,
  description text,
  scope       text not null default 'tenant' check (scope in ('platform','tenant')),
  is_system   boolean not null default false,
  version     bigint not null default 1,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists permissions (
  id              uuid primary key default gen_random_uuid(),
  permission_key  text not null unique,
  resource        text not null,
  action          text not null,
  description     text,
  version         bigint not null default 1,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create table if not exists role_permissions (
  role_id        uuid not null references roles(id) on delete cascade,
  permission_id  uuid not null references permissions(id) on delete cascade,
  primary key (role_id, permission_id)
);

create table if not exists tenant_user_roles (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references tenants(id),
  membership_id  uuid not null,
  role_id        uuid not null references roles(id),
  -- composite FK: the assigned membership MUST belong to the row's tenant (blocks cross-tenant assignment)
  foreign key (tenant_id, membership_id) references tenant_memberships (tenant_id, id),
  granted_by     uuid,
  granted_at     timestamptz not null default now(),
  version        bigint not null default 1,
  updated_at     timestamptz not null default now(),
  deleted_at     timestamptz,
  deleted_by     uuid,
  delete_reason  text
);
create unique index if not exists ux_tenant_user_roles_unique
  on tenant_user_roles (tenant_id, membership_id, role_id) where deleted_at is null;

-- ============================= RLS =============================

-- tenants: own-row read (curated) + service read + service write
alter table tenants enable row level security;
alter table tenants force  row level security;
create policy p_tenants_self_select on tenants
  for select using (
    app.assert_tenant_context() and id = app.current_tenant_id()
    and app.assert_membership_active() and deleted_at is null);
create policy p_tenants_service_read on tenants
  for select using (app.assert_service_role(
    array['svc_ops','svc_lifecycle','svc_billing','svc_entitlement','svc_session','svc_authz','svc_identity']));
create policy p_tenants_service_write on tenants
  for all
  using (app.assert_service_role(array['svc_ops','svc_lifecycle','svc_billing']))
  with check (app.assert_service_role(array['svc_ops','svc_lifecycle','svc_billing']));
grant select on tenants to svc_app;
grant select, insert, update on tenants to svc_worker;

-- user_identities: service-only + own-row read (for the v_me projection)
alter table user_identities enable row level security;
alter table user_identities force  row level security;
create policy p_user_identities_service on user_identities
  for all
  using (app.assert_service_role(array['svc_identity','svc_ops']))
  with check (app.assert_service_role(array['svc_identity','svc_ops']));
create policy p_user_identities_self_select on user_identities
  for select using (id = app.current_actor_id() and deleted_at is null);
revoke all on user_identities from svc_app;
-- deleted_at is included because the v_me projection filters on it (security_invoker checks base columns).
grant select (id, primary_email, display_name, status, deleted_at) on user_identities to svc_app;
grant select, insert, update on user_identities to svc_worker;

-- tenant_memberships: Class A, self-scoped read
alter table tenant_memberships enable row level security;
alter table tenant_memberships force  row level security;
create policy p_memberships_self_select on tenant_memberships
  for select using (
    app.assert_tenant_context() and tenant_id = app.current_tenant_id() and deleted_at is null
    and (user_id = app.current_actor_id() or app.assert_permission('memberships.read')));
create policy p_memberships_service on tenant_memberships
  for all
  using (app.assert_service_role(array['svc_identity','svc_authz','svc_ops']))
  with check (app.assert_service_role(array['svc_identity','svc_authz','svc_ops']));
grant select on tenant_memberships to svc_app;
grant select, insert, update on tenant_memberships to svc_worker;
create trigger trg_no_reassign_memberships before update on tenant_memberships
  for each row execute function app.forbid_tenant_reassignment();

-- roles / permissions / role_permissions: Class C global reference
do $$
declare t text;
begin
  foreach t in array array['roles','permissions','role_permissions'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_ref_read on %1$s
      for select using (app.current_actor_id() is not null);$p$, t);
    execute format($p$create policy p_%1$s_ref_write on %1$s
      for all
      using (app.assert_service_role(array['svc_authz','svc_ops']))
      with check (app.assert_service_role(array['svc_authz','svc_ops']));$p$, t);
    execute format('grant select on %I to svc_app;',  t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;

-- tenant_user_roles: Class A tenant-scoped
alter table tenant_user_roles enable row level security;
alter table tenant_user_roles force  row level security;
create policy p_tur_tenant_select on tenant_user_roles
  for select using (
    app.assert_tenant_context() and tenant_id = app.current_tenant_id()
    and app.assert_membership_active() and deleted_at is null);
create policy p_tur_tenant_insert on tenant_user_roles
  for insert with check (
    app.assert_tenant_context() and tenant_id = app.current_tenant_id()
    and app.assert_permission('roles.assign') and app.assert_tenant_mutation_allowed());
create policy p_tur_tenant_update on tenant_user_roles
  for update using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id()
    and app.assert_permission('roles.assign') and app.assert_tenant_mutation_allowed());
create policy p_tur_service on tenant_user_roles
  for all
  using (app.assert_service_role(array['svc_authz','svc_ops']))
  with check (app.assert_service_role(array['svc_authz','svc_ops']));
grant select, insert, update on tenant_user_roles to svc_app;
grant select, insert, update on tenant_user_roles to svc_worker;
create trigger trg_no_reassign_tur before update on tenant_user_roles
  for each row execute function app.forbid_tenant_reassignment();

-- ============================= Projections (DEC-010) =============================
create or replace view app.v_me
  with (security_invoker = true) as
  select id as user_id, primary_email, display_name, status
  from user_identities
  where id = app.current_actor_id() and deleted_at is null;

create or replace view app.v_my_memberships
  with (security_invoker = true) as
  select m.id as membership_id, m.tenant_id, m.status, m.activated_at
  from tenant_memberships m
  where m.tenant_id = app.current_tenant_id()
    and m.user_id  = app.current_actor_id()
    and m.deleted_at is null;

grant select on app.v_me, app.v_my_memberships to svc_app;
