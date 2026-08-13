-- 0004_billing_entitlements.sql — table-group 3: plans, subscriptions, entitlements (FOUNDATION_03).
-- Depends on 0000-0003. entitlement_snapshots is the internal authority; ent_v gates paid writes/launches.

-- ============================= DDL =============================

-- plans + plan_app_entitlements: global catalog (Class C). Pricing lives in Stripe (DEC-033).
create table if not exists plans (
  id          uuid primary key default gen_random_uuid(),
  plan_key    text not null unique,
  name        text not null,
  description text,
  tier        text,
  status      text not null default 'active' check (status in ('active','deprecated')),
  version     bigint not null default 1,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists plan_app_entitlements (
  id           uuid primary key default gen_random_uuid(),
  plan_id      uuid not null references plans(id) on delete cascade,
  app_id       uuid not null references apps(id),
  entitlements jsonb not null default '{}'::jsonb,
  limits       jsonb not null default '{}'::jsonb,
  created_at   timestamptz not null default now(),
  unique (plan_id, app_id)
);

-- billing internals (Class B service-only; §8 direct-client-denied)
create table if not exists billing_customers (
  id                   uuid primary key default gen_random_uuid(),
  tenant_id            uuid not null references tenants(id),
  provider             text not null default 'stripe',
  provider_customer_id text,
  status               text not null default 'active' check (status in ('active','delinquent','disabled')),
  version              bigint not null default 1,
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now(),
  unique (tenant_id, provider),
  unique (tenant_id, id)                         -- composite-FK target for subscriptions
);

create table if not exists subscriptions (
  id                      uuid primary key default gen_random_uuid(),
  tenant_id               uuid not null references tenants(id),
  billing_customer_id     uuid not null,
  plan_id                 uuid not null references plans(id),
  provider_subscription_id text,
  status                  text not null default 'trialing'
                            check (status in ('trialing','active','past_due','grace','locked','canceled')),
  current_period_end      timestamptz,
  version                 bigint not null default 1,
  created_at              timestamptz not null default now(),
  updated_at              timestamptz not null default now(),
  -- the billing customer must belong to the same tenant
  foreign key (tenant_id, billing_customer_id) references billing_customers (tenant_id, id)
);
create index if not exists ix_subscriptions_tenant on subscriptions (tenant_id, created_at desc);

create table if not exists subscription_items (
  id                       uuid primary key default gen_random_uuid(),
  subscription_id          uuid not null references subscriptions(id) on delete cascade,
  plan_app_entitlement_id  uuid not null references plan_app_entitlements(id),
  quantity                 integer not null default 1,
  created_at               timestamptz not null default now()
);

-- entitlement authority (Class A read of own tenant, service write)
create table if not exists entitlement_snapshots (
  id               uuid primary key default gen_random_uuid(),
  tenant_id        uuid not null references tenants(id),
  snapshot_version bigint not null,
  billing_status   text not null,
  effective_at     timestamptz not null default now(),
  entitlements     jsonb not null default '{}'::jsonb,
  limits           jsonb not null default '{}'::jsonb,
  created_at       timestamptz not null default now(),
  unique (tenant_id, snapshot_version)
);

-- append-only change log (Class D)
create table if not exists entitlement_changes (
  id               uuid primary key default gen_random_uuid(),
  tenant_id        uuid not null references tenants(id),
  snapshot_version bigint not null,
  change_type      text not null,
  detail           jsonb not null default '{}'::jsonb,
  occurred_at      timestamptz not null default now()
);
create index if not exists ix_entitlement_changes_tenant on entitlement_changes (tenant_id, occurred_at desc);

-- ============================= RLS =============================

-- plans / plan_app_entitlements: Class C global reference
do $$
declare t text;
begin
  foreach t in array array['plans','plan_app_entitlements'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_ref_read on %1$s
      for select using (app.current_actor_id() is not null);$p$, t);
    execute format($p$create policy p_%1$s_ref_write on %1$s
      for all using (app.assert_service_role(array['svc_billing','svc_ops']))
      with check (app.assert_service_role(array['svc_billing','svc_ops']));$p$, t);
    execute format('grant select on %I to svc_app;', t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;

-- billing_customers / subscriptions / subscription_items: Class B service-only (NO svc_app grant)
do $$
declare t text;
begin
  foreach t in array array['billing_customers','subscriptions','subscription_items'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_billing','svc_ops']))
      with check (app.assert_service_role(array['svc_billing','svc_ops']));$p$, t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;
create trigger trg_no_reassign_billing_customers before update on billing_customers
  for each row execute function app.forbid_tenant_reassignment();
create trigger trg_no_reassign_subscriptions before update on subscriptions
  for each row execute function app.forbid_tenant_reassignment();

-- entitlement_snapshots: Class A tenant read + service write
alter table entitlement_snapshots enable row level security;
alter table entitlement_snapshots force  row level security;
create policy p_entitlement_snapshots_tenant_select on entitlement_snapshots
  for select using (
    app.assert_tenant_context() and tenant_id = app.current_tenant_id() and app.assert_membership_active());
create policy p_entitlement_snapshots_service on entitlement_snapshots
  for all
  using (app.assert_service_role(array['svc_billing','svc_entitlement','svc_ops']))
  with check (app.assert_service_role(array['svc_billing','svc_entitlement','svc_ops']));
grant select on entitlement_snapshots to svc_app;
grant select, insert on entitlement_snapshots to svc_worker;

-- entitlement_changes: Class D append-only (service insert; tenant/operator read; no update/delete)
alter table entitlement_changes enable row level security;
alter table entitlement_changes force  row level security;
create policy p_entitlement_changes_insert on entitlement_changes
  for insert with check (app.assert_service_role(array['svc_billing','svc_entitlement','svc_ops']));
create policy p_entitlement_changes_select on entitlement_changes
  for select using (
    (app.assert_tenant_context() and tenant_id = app.current_tenant_id() and app.assert_membership_active())
    or app.assert_service_role(array['svc_ops','svc_audit']));
grant select on entitlement_changes to svc_app;
grant select, insert on entitlement_changes to svc_worker;

-- ============================= Recompute loop =============================
-- Runs in a svc_billing service context. Writes tenants/entitlement_snapshots/tenant_apps/
-- entitlement_changes — all authorized for svc_billing by existing policies.
create or replace function app.recompute_entitlements(p_tenant uuid)
returns bigint language plpgsql as $$
declare
  v_sub record;
  v_new_version bigint;
  v_entitlements jsonb;
  v_limits jsonb;
  v_billing_status text;
begin
  select s.plan_id, s.status, pl.plan_key, pl.name as plan_name
    into v_sub
  from subscriptions s join plans pl on pl.id = s.plan_id
  where s.tenant_id = p_tenant
  order by s.created_at desc
  limit 1;

  if not found then
    v_billing_status := 'none';
    v_entitlements := jsonb_build_object('plan_key', null, 'app_keys', '[]'::jsonb);
    v_limits := '{}'::jsonb;
  else
    v_billing_status := v_sub.status;
    with pae_apps as (
      select a.app_key, pae.limits
      from plan_app_entitlements pae join apps a on a.id = pae.app_id
      where pae.plan_id = v_sub.plan_id
    )
    select
      jsonb_build_object(
        'plan_key', v_sub.plan_key, 'plan_name', v_sub.plan_name,
        'app_keys', coalesce((select jsonb_agg(app_key order by app_key) from pae_apps), '[]'::jsonb)),
      coalesce((select jsonb_object_agg(app_key, limits) from pae_apps), '{}'::jsonb)
    into v_entitlements, v_limits;
  end if;

  select entitlement_snapshot_version + 1 into v_new_version from tenants where id = p_tenant;

  insert into entitlement_snapshots(tenant_id, snapshot_version, billing_status, entitlements, limits)
  values (p_tenant, v_new_version, v_billing_status, v_entitlements, coalesce(v_limits, '{}'::jsonb));

  update tenants
     set entitlement_snapshot_version = v_new_version,
         billing_status = case
           when v_billing_status in ('active','trialing','past_due','grace','locked','canceled') then v_billing_status
           else billing_status end,
         updated_at = now()
   where id = p_tenant;

  -- mark all of the tenant's apps refreshed; activate entitled pending_setup apps
  update tenant_apps
     set last_entitlement_snapshot_version = v_new_version, updated_at = now()
   where tenant_id = p_tenant and deleted_at is null;
  if found or v_sub.plan_id is not null then
    update tenant_apps
       set status = 'active', activated_at = coalesce(activated_at, now())
     where tenant_id = p_tenant and deleted_at is null and status = 'pending_setup'
       and app_id in (select app_id from plan_app_entitlements where plan_id = v_sub.plan_id);
  end if;

  insert into entitlement_changes(tenant_id, snapshot_version, change_type, detail)
  values (p_tenant, v_new_version, 'recompute', jsonb_build_object('billing_status', v_billing_status));

  return v_new_version;
end$$;

-- ============================= Projection =============================
-- The tenant's CURRENT entitlement snapshot (highest version).
create or replace view app.v_my_entitlements
  with (security_invoker = true) as
  select snapshot_version, billing_status, effective_at, entitlements, limits
  from entitlement_snapshots
  where tenant_id = app.current_tenant_id()
  order by snapshot_version desc
  limit 1;
grant select on app.v_my_entitlements to svc_app;
