-- 0005_minors.sql — group 7-8 seed: retention policies, student-data permissions, a demo minor.
-- Superuser (bypasses RLS). No consent is seeded → the demo starts at "consent required".

insert into retention_policies (id, policy_key, retention_class, retention_days, purge_mode, description) values
  ('f3000000-0000-0000-0000-000000000001','minors','C3',2555,'tombstone','Sensitive minor identity data — strict retention'),
  ('f3000000-0000-0000-0000-000000000002','default','C1',365,'soft_delete','Default internal retention')
on conflict (id) do nothing;

insert into permissions (id, permission_key, resource, action) values
  ('e0000000-0000-0000-0000-000000000005','students.read','students','read'),
  ('e0000000-0000-0000-0000-000000000006','students.manage','students','manage'),
  ('e0000000-0000-0000-0000-000000000007','consents.manage','consents','manage')
on conflict (id) do nothing;

insert into role_permissions (role_id, permission_id) values
  ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000005'),
  ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000006'),
  ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000007')
on conflict do nothing;

insert into students (id, tenant_id, app_id, full_name, date_of_birth, is_minor, retention_policy_id) values
  ('f1000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111',
   'c1000000-0000-0000-0000-000000000001','Amina Yusuf','2015-05-01', true, 'f3000000-0000-0000-0000-000000000001')
on conflict (id) do nothing;

insert into guardians (id, tenant_id, student_id, full_name, contact_email, relationship) values
  ('f2000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111',
   'f1000000-0000-0000-0000-000000000001','Yusuf (parent)','parent@example.com','parent')
on conflict (id) do nothing;
