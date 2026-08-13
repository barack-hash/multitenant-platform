-- 0003_app_registry.sql — table-group 2: app registry + tenant-app activation (FOUNDATION_02).
-- Depends on 0000-0002 (roles, app.* helpers, group-1 tables).

-- Global app catalog (Class C reference; not tenant data)
create table if not exists apps (
  id          uuid primary key default gen_random_uuid(),
  app_key     text not null unique,
  name        text not null,
  description text,
  category    text,
  status      text not null default 'active' check (status in ('active','deprecated','disabled')),
  is_system   boolean not null default false,
  version     bigint not null default 1,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Per-tenant activation (Class A read, service-managed writes). §4 required columns included.
create table if not exists tenant_apps (
  id                                uuid primary key default gen_random_uuid(),
  tenant_id                         uuid not null references tenants(id),
  app_id                            uuid not null references apps(id),
  status                            text not null default 'pending_setup'
                                      check (status in ('pending_setup','active','limited','locked','disabled','suspended')),
  last_entitlement_snapshot_version bigint not null default 0,
  lock_reason                       text,
  activated_at                      timestamptz,
  version                           bigint not null default 1,
  created_at                        timestamptz not null default now(),
  updated_at                        timestamptz not null default now(),
  deleted_at                        timestamptz,
  deleted_by                        uuid,
  delete_reason                     text
);
create unique index if not exists ux_tenant_apps_tenant_app
  on tenant_apps (tenant_id, app_id) where deleted_at is null;
create index if not exists ix_tenant_apps_tenant_status on tenant_apps (tenant_id, status);

-- ===== RLS: apps (Class C global reference) =====
alter table apps enable row level security;
alter table apps force  row level security;
-- Global catalog: readable by any authenticated user OR any service (e.g. recompute joins apps).
create policy p_apps_ref_read on apps
  for select using (app.current_actor_id() is not null or app.current_actor_type() = 'service');
create policy p_apps_ref_write on apps
  for all
  using (app.assert_service_role(array['svc_app_registry','svc_ops']))
  with check (app.assert_service_role(array['svc_app_registry','svc_ops']));
grant select on apps to svc_app;
grant select, insert, update on apps to svc_worker;

-- ===== RLS: tenant_apps (Class A read, service write) =====
alter table tenant_apps enable row level security;
alter table tenant_apps force  row level security;
create policy p_tenant_apps_tenant_select on tenant_apps
  for select using (
    app.assert_tenant_context() and tenant_id = app.current_tenant_id()
    and app.assert_membership_active() and deleted_at is null);
create policy p_tenant_apps_service on tenant_apps
  for all
  using (app.assert_service_role(array['svc_app_registry','svc_billing','svc_entitlement','svc_lifecycle','svc_ops']))
  with check (app.assert_service_role(array['svc_app_registry','svc_billing','svc_entitlement','svc_lifecycle','svc_ops']));
grant select on tenant_apps to svc_app;                     -- read only; activation is service-managed
grant select, insert, update on tenant_apps to svc_worker;
create trigger trg_no_reassign_tenant_apps before update on tenant_apps
  for each row execute function app.forbid_tenant_reassignment();

-- ===== Projection: the tenant's activated apps + launch-eligibility =====
create or replace view app.v_my_apps
  with (security_invoker = true) as
  select a.app_key, a.name, a.category,
         ta.status,
         (ta.status = 'active') as launchable,
         ta.lock_reason
  from tenant_apps ta
  join apps a on a.id = ta.app_id
  where ta.tenant_id = app.current_tenant_id()
    and ta.deleted_at is null
    and a.status <> 'disabled';
grant select on app.v_my_apps to svc_app;
