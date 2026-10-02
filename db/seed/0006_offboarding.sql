-- 0006_offboarding.sql — group 9 seed (tenant-level offboarding lifecycle).
-- Superuser (bypasses RLS). Adds a DEDICATED tenant-three + admin (u4) so the destructive
-- offboarding/purge/tombstone demo never perturbs the tenant-one/two isolation fixtures.

-- A retention policy for offboarding with an immediate purge window (retention_days=0) so the
-- happy-path demo flows straight through; the retention GATE is proven separately by moving the
-- job's scheduled_purge_after into the future.
insert into retention_policies (id, policy_key, retention_class, retention_days, purge_mode, description) values
  ('f3000000-0000-0000-0000-000000000003','offboarding-default','C2',0,'tombstone','Tenant offboarding — immediate purge window for MVP demo')
on conflict (id) do nothing;

-- Dedicated tenant + admin used ONLY for lifecycle demos.
insert into tenants (id, slug, name) values
  ('33333333-3333-3333-3333-333333333333','tenant-three','Tenant Three (offboarding demo)')
on conflict (id) do nothing;

insert into user_identities (id, auth_provider, auth_subject, primary_email, display_name) values
  ('44444444-4444-4444-4444-444444444444','supabase','5b000000-0000-4000-8000-000000000004','u4@example.com','User Four (T3 admin)')
on conflict (id) do nothing;

insert into tenant_memberships (id, tenant_id, user_id, status, activated_at) values
  ('dddddddd-dddd-dddd-dddd-ddddddddddd4','33333333-3333-3333-3333-333333333333','44444444-4444-4444-4444-444444444444','active', now())
on conflict (id) do nothing;

-- u4 is tenant_admin of tenant-three (so a normal tenant write exists to be DENIED once frozen).
insert into tenant_user_roles (id, tenant_id, membership_id, role_id) values
  ('a1000000-0000-0000-0000-000000000004','33333333-3333-3333-3333-333333333333','dddddddd-dddd-dddd-dddd-ddddddddddd4','f0000000-0000-0000-0000-000000000001')
on conflict (id) do nothing;
