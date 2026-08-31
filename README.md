# MultiTenant-Platform

A reusable, **business-agnostic multi-tenant SaaS platform** built as a modular monolith, where
**tenant isolation is enforced in Postgres by Row-Level Security** — beneath the application — so a bug
in a request handler still cannot cross a tenant boundary.

Thirteen foundation groups plus a real Next.js operator console are built and proven end-to-end
(database + HTTP + browser), with **173 automated checks** that run in one command against a disposable
local Postgres.

## Security model (the load-bearing idea)

The Hub connects to Postgres only as **least-privilege roles** (`svc_app` for tenant-request handling,
`svc_worker` for privileged/cross-tenant service work) — **never as a superuser, none with `BYPASSRLS`**.
Every table has `FORCE ROW LEVEL SECURITY`. Each request runs in a transaction whose trust context is
set with `SET LOCAL` GUCs; the RLS policies read *only* those server-set GUCs, never client-supplied JWT
claims. Policies fall into four canonical classes:

- **A — tenant-scoped**: `tenant_id = current` + active membership + permission check + write-gate
- **B — service-only**: only a named logical service role (bound to the physical `svc_worker` login) passes
- **C — global reference**: readable to any authenticated actor, written by ops services
- **D — append-only**: insert-only ledgers (events, audit)

A logical-vs-physical role split (a trusted `app.svc_role` GUC checked against `current_user='svc_worker'`)
means a compromised `svc_app` path can never satisfy a service policy by spoofing context.

## The thirteen foundation groups

| # | Group | What it proves |
|---|-------|----------------|
| 1 | Identity / tenancy / RBAC | RLS tenant isolation, `app.*` helpers, 3-role grant model |
| 2 | App registry + activation | per-tenant app enablement gates launch |
| 3 | Billing + entitlements | subscription → entitlement snapshot → `ent_v` version, staleness gate |
| 4 | Events + workers | transactional outbox → relay → inbox (exactly-once) → dead-letter |
| 5 | Sessions + 4-token launch | hub→launch→exchange→spoke session lineage + revocation cascade |
| 6 | Stripe webhooks | HMAC verify + dedupe → billing lock/unlock of apps |
| 7 | Files / storage | brokered signed URLs, quarantine-first upload, download only when clean |
| 8 | Minor-data protection | students as data subjects, parental-consent gate, subject-level erasure |
| 9 | Tenant offboarding lifecycle | freeze → export → retention → purge → tombstone, legal-hold- and receipt-gated |
| 10 | Support / impersonation + Tier-A audit | dual-control impersonation, prohibited-action hard-deny, tamper-evident hash-chained audit ledger |
| 11 | Per-operator platform-ops auth | per-operator API keys + live operator sessions; the DB derives the approver from the approving operator's session, so dual control is a true two-person control |
| 12 | Operator MFA + SSO | TOTP (pure-Node RFC 6238) + recovery codes + HMAC-signed IdP assertions; `acr=mfa` **step-up** gates the destructive surfaces |
| 13 | WebAuthn / passkeys | real ES256 assertion verification (no deps): origin + RP-ID binding, user verification, sign-count clone detection |

The whole thing converges into one loop: **Stripe webhook → billing → entitlements → app lock/unlock →
4-token spoke launch → revocation cascade**, on a transactional-outbox event backbone, with brokered
files, consent-gated minor data, a gated tenant-purge state machine, and an immutable audit chain.

## Layout
```
db/migrations/  0000 roles … 0014 operator webauthn   (append-only, numbered)
db/seed/        deterministic fixtures (tenants, users, RBAC, apps, plans, operators)
src/            modular-monolith Hub runtime (Fastify): config · db · tokens · mfa · webauthn · server
test/           isolation.mjs + one *.test.mjs per group + api.test.mjs (HTTP end-to-end)
console/        Next.js/Vercel operator console (BFF over the Hub) — see console/README.md
scripts/run-local.sh   one-command reproduce (no Docker required)
```

## Operator console (`console/`)
A Next.js (App Router) app — the operator-facing UI, deployed on Vercel (DEC-013). It drives the operator
auth ladder (password → TOTP MFA + step-up → SSO → WebAuthn passkeys) and the operator surfaces:
**support access & impersonation** (`/support`), **tenant offboarding** (`/offboarding`), the Tier-A audit
chain (`/audit`) and passkey management (`/passkeys`). It uses a **BFF**: the browser talks only to the
console's own route handlers, which keep every bearer credential — the operator token *and* the
impersonation support token — in httpOnly cookies and proxy to the Hub (no token in client JS, no CORS).
Each page inherits the Hub's own gate: `/support` is `support|ops|admin`, `/offboarding` additionally
requires step-up (`acr=mfa`). See [`console/README.md`](console/README.md).

## Run it
Uses a disposable Homebrew `postgresql@16` cluster in `.localpg/` (own port, nothing system-wide);
runs migrate → seed → the full gate, then stops.
```bash
npm install
./scripts/run-local.sh
```
Expected: **173/173 passing** — 98 database isolation/behaviour checks + 75 HTTP end-to-end checks,
against Postgres 16.

## Notes
- **Dev credentials are placeholders.** The HS256 shared JWT secret, the `whsec_dev` webhook secret, and
  the `dev-admin-token` operator token are local-development defaults (`process.env.X || 'dev-…'`);
  production supplies real values via a secret manager and moves signing to RS256/JWKS.
- Architecture and decision records are maintained in a separate (private) planning repository; this
  repository is the buildable implementation.
