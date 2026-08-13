-- 0007_support.sql — group 10 seed: platform operators, rate-limit policy catalog, and a bootstrap
-- audit row on the 'platform' chain (§17: seed writes are audited). Superuser (bypasses RLS).

-- Platform staff (NOT tenant users). op1 requests, op2 approves (dual-control), op3 is ops.
insert into platform_operators (id, email, display_name, operator_role) values
  ('0b000000-0000-0000-0000-000000000001','support1@platform.example','Support One','support'),
  ('0b000000-0000-0000-0000-000000000002','support2@platform.example','Support Two','support'),
  ('0b000000-0000-0000-0000-000000000003','ops1@platform.example','Ops One','ops')
on conflict (id) do nothing;

-- Rate-limit policy catalog (§17 seed_rate_limit_policies).
insert into rate_limit_policies (id, policy_key, scope, limit_per_window, window_seconds, burst, description) values
  ('0c000000-0000-0000-0000-000000000001','api_default','global',1000,60,100,'Default per-principal API rate limit'),
  ('0c000000-0000-0000-0000-000000000002','auth_login','endpoint',10,60,0,'Login attempts per window')
on conflict (id) do nothing;

-- Bootstrap the 'platform' audit chain (genesis is written by app.audit_append itself).
select app.audit_append('platform', null, 'platform.bootstrap', 'system', 'seed', 'seed_run', null, null,
  'success', null, null, null, '{"seed":"0007_support"}'::jsonb);
