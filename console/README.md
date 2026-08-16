# HubOps Console

The **operator console** for the MultiTenant platform — a Next.js (App Router) app deployed on Vercel
(DEC-013). It drives the operator authentication ladder (password → TOTP MFA + step-up → SSO → WebAuthn
passkeys) and the operator surfaces (audit chain, passkey management, and — via the same proxy — support
and offboarding), talking to the Fastify **Hub** API.

## Architecture — BFF (backend-for-frontend)
The browser never sees the operator token. It talks only to this app's Route Handlers under `app/api/*`,
which store the operator session in an **httpOnly cookie** and attach it as a `Bearer` token when they
proxy to the Hub (`lib/hub.ts`). This keeps tokens out of client JS and avoids CORS.

```
browser ──(httpOnly cookie)──▶ Next.js route handlers ──(Bearer op_token)──▶ Hub API
```

- `app/api/login` · `mfa/verify` · `sso` · `webauthn/*` — auth ceremonies (set the session cookie)
- `app/api/hub/[...path]` — a guarded proxy for `/admin/*` and `/operator/*` reads + actions
- WebAuthn client (`lib/webauthn-client.ts`) uses the real `navigator.credentials` API

## Run it locally
Start the Hub first (from the repo root), pointing WebAuthn at this console's origin:
```bash
# terminal 1 — the Hub (see the repo README for the local Postgres setup)
WEBAUTHN_ORIGIN=http://localhost:3001 PORT=3939 node src/server.js
```
```bash
# terminal 2 — the console
cd console
npm install
HUB_URL=http://localhost:3939 npm run dev   # http://localhost:3001
```
Sign in with a seeded operator, e.g. `ops1@platform.example` + `opk_op3_key_cccccccc` (→ TOTP step-up),
or `support1@platform.example` + `opk_op1_key_aaaaaaaa` (password-only). Register a passkey on the
Passkeys page, then use “Sign in with a passkey”.

## Deploy to Vercel
1. Import the repo in Vercel and set the **Root Directory** to `console/`.
2. Set the env var **`HUB_URL`** to your deployed Hub's URL.
3. Set the Hub's **`WEBAUTHN_ORIGIN`** and **`WEBAUTHN_RP_ID`** to the console's deployed origin/domain
   (passkeys are origin-bound).
4. Deploy — Vercel auto-detects Next.js.

> Note: passkeys require a real authenticator (Touch ID / security key) and SSO a real IdP redirect; the
> client integration is complete, and those flows run in a real browser. Password + MFA work everywhere.
