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
  // Platform-operator token gating the /admin/* lifecycle surface (a stand-in for the future
  // dual-control platform-ops auth). Out-of-band from tenant JWTs — tenant users can't offboard tenants.
  adminToken: process.env.ADMIN_API_TOKEN || 'dev-admin-token',
  port: Number(process.env.PORT || 3000),
};
