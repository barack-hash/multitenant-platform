-- 0011_rate_limits.sql — group 15 seed (§17 seed_rate_limit_policies, extended). Idempotent.
-- api_default + auth_login already exist (0007_support). Group 15 adds the tenant-aggregate bucket
-- (noisy-neighbor protection — what tenant_rate_limit_overrides actually tune) and webhook ingress
-- (DEPLOYMENT_ARCHITECTURE §3.1: "IP throttling for auth and webhook ingress").
insert into rate_limit_policies (id, policy_key, scope, limit_per_window, window_seconds, burst, description) values
  ('0c000000-0000-0000-0000-000000000003','api_tenant','tenant',3000,60,300,'Aggregate API rate for one tenant (all its principals)'),
  ('0c000000-0000-0000-0000-000000000004','webhook_ingress','endpoint',600,60,60,'Webhook deliveries per source IP')
on conflict (id) do nothing;
