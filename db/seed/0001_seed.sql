-- 0001_seed.sql — deterministic seed for isolation tests. Run as superuser (bypasses RLS).
-- Two tenants, three users, RBAC catalog.

-- Tenants
insert into tenants (id, slug, name) values
  ('11111111-1111-1111-1111-111111111111','tenant-one','Tenant One'),
  ('22222222-2222-2222-2222-222222222222','tenant-two','Tenant Two')
on conflict (id) do nothing;

-- Users (identity principals)
insert into user_identities (id, auth_provider, auth_subject, primary_email, display_name) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','supabase','sub-u1','u1@example.com','User One (T1 member)'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','supabase','sub-u2','u2@example.com','User Two (T2 member)'),
  ('cccccccc-cccc-cccc-cccc-cccccccccccc','supabase','sub-u3','u3@example.com','User Three (T1 admin)')
on conflict (id) do nothing;

-- Memberships (id == membership_id)
insert into tenant_memberships (id, tenant_id, user_id, status, activated_at) values
  ('dddddddd-dddd-dddd-dddd-ddddddddddd1','11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','active', now()),
  ('dddddddd-dddd-dddd-dddd-ddddddddddd2','22222222-2222-2222-2222-222222222222','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','active', now()),
  ('dddddddd-dddd-dddd-dddd-ddddddddddd3','11111111-1111-1111-1111-111111111111','cccccccc-cccc-cccc-cccc-cccccccccccc','active', now())
on conflict (id) do nothing;

-- Permission catalog
insert into permissions (id, permission_key, resource, action) values
  ('e0000000-0000-0000-0000-000000000001','memberships.read','memberships','read'),
  ('e0000000-0000-0000-0000-000000000002','memberships.manage','memberships','manage'),
  ('e0000000-0000-0000-0000-000000000003','roles.assign','roles','assign')
on conflict (id) do nothing;

-- Roles
insert into roles (id, role_key, name, scope, is_system) values
  ('f0000000-0000-0000-0000-000000000001','tenant_admin','Tenant Admin','tenant', true),
  ('f0000000-0000-0000-0000-000000000002','member','Member','tenant', true)
on conflict (id) do nothing;

-- tenant_admin gets all three permissions; member gets none of these
insert into role_permissions (role_id, permission_id) values
  ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000001'),
  ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000002'),
  ('f0000000-0000-0000-0000-000000000001','e0000000-0000-0000-0000-000000000003')
on conflict do nothing;

-- Existing role assignments: U3 is admin of T1, U1 is member of T1, U2 is member of T2
insert into tenant_user_roles (id, tenant_id, membership_id, role_id) values
  ('a1000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','dddddddd-dddd-dddd-dddd-ddddddddddd3','f0000000-0000-0000-0000-000000000001'),
  ('a1000000-0000-0000-0000-000000000002','11111111-1111-1111-1111-111111111111','dddddddd-dddd-dddd-dddd-ddddddddddd1','f0000000-0000-0000-0000-000000000002'),
  ('a1000000-0000-0000-0000-000000000003','22222222-2222-2222-2222-222222222222','dddddddd-dddd-dddd-dddd-ddddddddddd2','f0000000-0000-0000-0000-000000000002')
on conflict (id) do nothing;
