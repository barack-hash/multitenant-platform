// Runtime config. In production these come from the secret manager (DEC-013); dev defaults here.
export const cfg = {
  // The app connects as least-privilege roles — NOT as postgres. RLS is enforced beneath it.
  appUrl:    process.env.APP_DATABASE_URL    || 'postgres://svc_app@localhost:55432/postgres',
  workerUrl: process.env.WORKER_DATABASE_URL || 'postgres://svc_worker@localhost:55432/postgres',
  // Hub token signing. MVP uses HS256 + a shared secret; production uses RS256/JWKS (SYSTEM_ARCHITECTURE §3).
  jwtSecret: process.env.HUB_JWT_SECRET || 'dev-only-secret-change-me',
  iss: 'hub',
  aud: 'platform',
  accessTtlSec: 900, // MASTER_PLAN §5: hub access token max TTL 900s
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET || 'whsec_dev',
  // Group 11: per-operator platform-ops auth. The operator token is aud='operator', bound to a live
  // operator_session. The shared adminToken is now ONLY a break-glass fallback, env-gated + audited.
  operatorTokenTtlSec: Number(process.env.OPERATOR_TOKEN_TTL || 1800),
  // Group 12: operator MFA (TOTP) + SSO. The pending-MFA token is short-lived (login step 1 → step 2).
  operatorMfaTtlSec: Number(process.env.OPERATOR_MFA_TTL || 300),
  mfaIssuer: process.env.MFA_ISSUER || 'hub-operators',
  // Group 13: WebAuthn / passkeys. rpId = the registrable domain; origin = the exact page origin.
  webauthnRpId: process.env.WEBAUTHN_RP_ID || 'localhost',
  webauthnRpName: process.env.WEBAUTHN_RP_NAME || 'MultiTenant Hub Operators',
  webauthnOrigin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3939',
  adminToken: process.env.ADMIN_API_TOKEN || 'dev-admin-token',
  breakGlassEnabled: ['1', 'true', 'yes'].includes(String(process.env.BREAKGLASS_ENABLED || '').toLowerCase()),
  port: Number(process.env.PORT || 3000),
};
