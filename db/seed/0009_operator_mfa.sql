-- 0009_operator_mfa.sql — group 12 seed: MFA enrollments + an SSO IdP + a federated identity.
-- Superuser (bypasses RLS). Dev TOTP secrets are LOCAL-ONLY (prod enrolls per-operator + encrypts at rest).
--   op3 (ops)   TOTP secret: JBSWY3DPEHPK3PXP     op4 (admin) TOTP secret: KRSXG5CTMVRXEZLU
--   op5 (ops, NO MFA) api_key: opk_op5_key_eeeeeeee   (used to prove step-up denial)
--   SSO idp 'demo-oidc' signing_secret: sso-demo-secret-key ; linked external_subject 'ext-op1' -> op1

-- A second ops operator with NO MFA (logs in password-only → must be denied step-up actions).
insert into platform_operators (id, email, display_name, operator_role) values
  ('0b000000-0000-0000-0000-000000000005','ops2@platform.example','Ops Two','ops')
on conflict (id) do nothing;
insert into operator_credentials (id, operator_id, key_prefix, secret_hash) values
  ('0d000000-0000-0000-0000-000000000005','0b000000-0000-0000-0000-000000000005',
     left('opk_op5_key_eeeeeeee',12), encode(sha256(convert_to('opk_op5_key_eeeeeeee','UTF8')),'hex'))
on conflict (id) do nothing;

-- Active TOTP enrollments for op3 (ops) and op4 (admin); they must step up to run destructive/admin ops.
insert into operator_mfa (id, operator_id, secret, status, confirmed_at) values
  ('0f000000-0000-0000-0000-000000000003','0b000000-0000-0000-0000-000000000003','JBSWY3DPEHPK3PXP','active', now()),
  ('0f000000-0000-0000-0000-000000000004','0b000000-0000-0000-0000-000000000004','KRSXG5CTMVRXEZLU','active', now())
on conflict (id) do nothing;
update platform_operators set mfa_required = true
  where id in ('0b000000-0000-0000-0000-000000000003','0b000000-0000-0000-0000-000000000004');

-- A known recovery code for op3 (for the recovery-login test): rc_known_op3_001
insert into operator_recovery_codes (id, operator_id, code_hash) values
  ('11000000-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000003',
     encode(sha256(convert_to('rc_known_op3_001','UTF8')),'hex'))
on conflict (id) do nothing;

-- SSO provider (federation seam) + a linked federated identity for op1.
insert into operator_idp (id, idp_key, display_name, protocol, issuer, audience, signing_secret, default_role, allowed_domain, jit_provisioning) values
  ('0e000000-0000-0000-0000-000000000001','demo-oidc','Demo OIDC','oidc','https://idp.example','hub-operators','sso-demo-secret-key','support','partner.example', true)
on conflict (id) do nothing;
insert into operator_federated_identities (id, operator_id, idp_id, external_subject) values
  ('10000000-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','0e000000-0000-0000-0000-000000000001','ext-op1')
on conflict (id) do nothing;

-- §17: seed writes audited (platform chain).
select app.audit_append('platform', null, 'platform.mfa_sso.bootstrap', 'system', 'seed', 'operator_mfa',
  null, null, 'success', null, null, null, '{"seed":"0009_operator_mfa"}'::jsonb);
