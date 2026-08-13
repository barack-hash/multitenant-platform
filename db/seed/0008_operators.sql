-- 0008_operators.sql — group 11 seed (bootstrap_platform_admins, §17): operator credentials so
-- operators exist from seed (no chicken-and-egg), plus an admin operator and a credential-less
-- break-glass identity. Superuser (bypasses RLS). Seed writes audited below.
--
-- DEV KEYS (local only; prod issues real high-entropy keys via /admin/operators/:id/credential):
--   op1 support : opk_op1_key_aaaaaaaa    op2 support : opk_op2_key_bbbbbbbb
--   op3 ops     : opk_op3_key_cccccccc    op4 admin   : opk_op4_key_dddddddd

-- An admin operator (for operator management) + a credential-less break-glass identity (only reachable
-- via the env-gated x-admin-token, never via login).
insert into platform_operators (id, email, display_name, operator_role) values
  ('0b000000-0000-0000-0000-000000000004','admin1@platform.example','Admin One','admin'),
  ('0b000000-0000-0000-0000-0000000000ff','breakglass@platform.example','Break-Glass','admin')
on conflict (id) do nothing;

-- Per-operator credentials. key_prefix = left(key,12); secret_hash = sha256(key) (hashed the same way
-- app.operator_authenticate hashes the presented key). No credential for the break-glass identity.
insert into operator_credentials (id, operator_id, key_prefix, secret_hash) values
  ('0d000000-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001',
     left('opk_op1_key_aaaaaaaa',12), encode(sha256(convert_to('opk_op1_key_aaaaaaaa','UTF8')),'hex')),
  ('0d000000-0000-0000-0000-000000000002','0b000000-0000-0000-0000-000000000002',
     left('opk_op2_key_bbbbbbbb',12), encode(sha256(convert_to('opk_op2_key_bbbbbbbb','UTF8')),'hex')),
  ('0d000000-0000-0000-0000-000000000003','0b000000-0000-0000-0000-000000000003',
     left('opk_op3_key_cccccccc',12), encode(sha256(convert_to('opk_op3_key_cccccccc','UTF8')),'hex')),
  ('0d000000-0000-0000-0000-000000000004','0b000000-0000-0000-0000-000000000004',
     left('opk_op4_key_dddddddd',12), encode(sha256(convert_to('opk_op4_key_dddddddd','UTF8')),'hex'))
on conflict (id) do nothing;

-- §17: seed writes are audited (platform chain).
select app.audit_append('platform', null, 'platform.operators.bootstrap', 'system', 'seed', 'operator_credential',
  null, null, 'success', null, null, null, '{"seed":"0008_operators","operators":4}'::jsonb);
