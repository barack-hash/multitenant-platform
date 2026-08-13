-- 0003_billing.sql — group-3 seed: plan, entitlements, subscriptions, initial snapshots.
-- Superuser (bypasses RLS). Standard plan grants ONLY hifz-lms, so tenant-one's directory stays locked.

-- billing.manage permission for admins (lets tenant_admin trigger recompute)
insert into permissions (id, permission_key, resource, action) values
  ('e0000000-0000-0000-0000-000000000004','billing.manage','billing','manage')
on conflict (id) do nothing;
insert into role_permissions (role_id, permission_id) values
  ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000004')  -- tenant_admin
on conflict do nothing;

-- Plan catalog
insert into plans (id, plan_key, name, tier) values
  ('d1000000-0000-0000-0000-000000000001','standard','Standard','standard')
on conflict (id) do nothing;
insert into plan_app_entitlements (id, plan_id, app_id, limits) values
  ('d2000000-0000-0000-0000-000000000001','d1000000-0000-0000-0000-000000000001',
   'c1000000-0000-0000-0000-000000000001', '{"students": 100}'::jsonb)   -- hifz-lms
on conflict (id) do nothing;

-- Billing customers + subscriptions for both tenants
insert into billing_customers (id, tenant_id, provider, provider_customer_id) values
  ('d3000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','stripe','cus_t1'),
  ('d3000000-0000-0000-0000-000000000002','22222222-2222-2222-2222-222222222222','stripe','cus_t2')
on conflict (id) do nothing;

insert into subscriptions (id, tenant_id, billing_customer_id, plan_id, provider_subscription_id, status) values
  ('d4000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','d3000000-0000-0000-0000-000000000001','d1000000-0000-0000-0000-000000000001','sub_t1','active'),
  ('d4000000-0000-0000-0000-000000000002','22222222-2222-2222-2222-222222222222','d3000000-0000-0000-0000-000000000002','d1000000-0000-0000-0000-000000000001','sub_t2','active')
on conflict (id) do nothing;

insert into subscription_items (id, subscription_id, plan_app_entitlement_id) values
  ('d5000000-0000-0000-0000-000000000001','d4000000-0000-0000-0000-000000000001','d2000000-0000-0000-0000-000000000001'),
  ('d5000000-0000-0000-0000-000000000002','d4000000-0000-0000-0000-000000000002','d2000000-0000-0000-0000-000000000001')
on conflict (id) do nothing;

-- Compute the initial entitlement snapshots (ent_v -> 1 for each tenant).
select app.recompute_entitlements('11111111-1111-1111-1111-111111111111');
select app.recompute_entitlements('22222222-2222-2222-2222-222222222222');
