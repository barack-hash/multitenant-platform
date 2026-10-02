-- 0010_feature_flags.sql — group 14 seed (MASTER_PLAN §11; DATABASE_SCHEMA_FINAL §7 seed_feature_flags).
-- Superuser (bypasses RLS) but NOT the triggers: every row still passes the type/target guards and is
-- written to feature_flag_audit_events, attributed to the bootstrap admin (op4). Idempotent.

do $$ begin perform set_config('app.flag_actor', '0b000000-0000-0000-0000-000000000004', false); end $$;

insert into feature_flag_definitions (id, flag_key, description, flag_type, owner_team, risk_level, status, variants, off_value) values
  ('f1000000-0000-0000-0000-000000000001','hifz.progress_v2','New Hifz progress view','boolean','vertical-hifz','low','active',null,'false'),
  ('f1000000-0000-0000-0000-000000000002','billing.checkout_variant','Checkout flow experiment','multivariate','platform-billing','medium','active',array['control','compact','wizard'],'"control"'),
  ('f1000000-0000-0000-0000-000000000003','platform.read_only_mode','Circuit breaker: refuse tenant writes platform-wide','kill_switch','platform-ops','high','active',null,'false')
on conflict (id) do nothing;

insert into feature_flag_environments (flag_id, environment, default_value, updated_by)
select f.id, e.env, f.off_value, '0b000000-0000-0000-0000-000000000004'
  from feature_flag_definitions f cross join (values ('dev'),('staging'),('prod')) e(env)
 where f.id in ('f1000000-0000-0000-0000-000000000001','f1000000-0000-0000-0000-000000000002','f1000000-0000-0000-0000-000000000003')
on conflict (flag_id, environment) do nothing;

-- One live rule so the tenant read path has something to resolve: tenant-one previews progress_v2 in dev.
insert into feature_flag_rollouts (id, flag_id, environment, target_type, target_ref, value, priority, status, created_by) values
  ('f2000000-0000-0000-0000-000000000001','f1000000-0000-0000-0000-000000000001','dev','tenant',
   '11111111-1111-1111-1111-111111111111','true',100,'active','0b000000-0000-0000-0000-000000000004')
on conflict (id) do nothing;
