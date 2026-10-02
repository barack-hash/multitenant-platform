// End-to-end API gate: HTTP -> Hub token -> context GUCs -> RLS. Proves the request path
// enforces the same isolation the DB gate proves, through real login and endpoints.
import { buildServer } from '../src/server.js';
import { closePools } from '../src/db.js';
import { createHmac, randomUUID, generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { totp } from '../src/mfa.js';
import { makeCredential } from '../src/webauthn.js';
import { cfg } from '../src/config.js';

function signedEvent(body) {
  const raw = JSON.stringify(body);
  const t = 1700000000;
  const v1 = createHmac('sha256', 'whsec_dev').update(`${t}.${raw}`).digest('hex');
  return { raw, headers: { 'stripe-signature': `t=${t},v1=${v1}`, 'content-type': 'application/json' } };
}

const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1'; // U1's membership (tenant one)
const M2 = 'dddddddd-dddd-dddd-dddd-ddddddddddd2'; // U2's membership (tenant two)
const M3 = 'dddddddd-dddd-dddd-dddd-ddddddddddd3'; // U3's membership (tenant one, admin)
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const U2 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const ROLE_MEMBER = 'f0000000-0000-0000-0000-000000000002';
const ROLE_ADMIN = 'f0000000-0000-0000-0000-000000000001';

// ---- Supabase stand-in (group 16). Tokens are signed exactly as a local `supabase start` signs them
// (HS256, project secret, iss <url>/auth/v1, aud/role authenticated). The Admin API (used only when a new
// Supabase user CLAIMS an invitation) and the JWKS endpoint are served by this fake fetch.
const SUBS = { 'u1@example.com': '5b000000-0000-4000-8000-000000000001', 'u2@example.com': '5b000000-0000-4000-8000-000000000002',
  'u3@example.com': '5b000000-0000-4000-8000-000000000003', 'u4@example.com': '5b000000-0000-4000-8000-000000000004' };
const ISS = `${cfg.supabaseUrl}/auth/v1`;
const supaUsers = new Map();            // sub -> { email, email_confirmed_at }
const jwksKeys = [];
const supaToken = (email, { sub, claims = {}, secret = cfg.supabaseJwtSecret, opts = {} } = {}) => jwt.sign(
  { sub: sub || SUBS[email] || randomUUID(), email, role: 'authenticated', aud: 'authenticated', ...claims },
  secret, { algorithm: 'HS256', issuer: ISS, expiresIn: 3600, ...opts });
const fakeRes = (status, body) => ({ ok: status < 300, status, json: async () => body });
const supabaseFetch = async (url, init = {}) => {
  const m = /\/auth\/v1\/admin\/users\/([0-9a-f-]+)$/.exec(url);
  if (m) {
    if (init.headers?.authorization !== 'Bearer test-service-role') return fakeRes(401, { msg: 'bad key' });
    const u = supaUsers.get(m[1]);
    return u ? fakeRes(200, { id: m[1], ...u }) : fakeRes(404, {});
  }
  if (url === `${ISS}/.well-known/jwks.json`) return fakeRes(200, { keys: jwksKeys });
  return fakeRes(404, {});
};
const app = buildServer({ supabaseFetch, supabaseServiceRoleKey: 'test-service-role' });
// Rate limiting is ON in the gate. The suite makes ~150 requests, including dozens of logins, which from
// one address would rightly trip auth_login (10/min). So each injected request comes from its own client
// address unless a test pins one with `remoteAddress` — the rate-limit tests below do exactly that.
let ipSeq = 0;
const rawInject = app.inject.bind(app);
app.inject = (opts) => rawInject({ remoteAddress: `10.77.${(ipSeq >> 8) & 255}.${ipSeq++ & 255}`, ...opts });
const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };
const login = (email, tenant) => app.inject({ method: 'POST', url: '/auth/login', payload: { access_token: supaToken(email), tenant } });
const bearer = (t) => ({ authorization: `Bearer ${t}` });

let token1, token2, token3;

test('login: member of tenant-one issues a token', async () => {
  const r = await login('u1@example.com', 'tenant-one');
  eq(r.statusCode, 200, 'login status'); token1 = r.json().token;
  if (!token1) throw new Error('no token returned');
});
test('login: admin of tenant-one', async () => {
  const r = await login('u3@example.com', 'tenant-one'); eq(r.statusCode, 200, 'admin login'); token3 = r.json().token;
});
test('login: member of tenant-two', async () => {
  const r = await login('u2@example.com', 'tenant-two'); eq(r.statusCode, 200, 'T2 login'); token2 = r.json().token;
});
test('login denied: user with no membership in that tenant', async () => {
  const r = await login('u1@example.com', 'tenant-two'); eq(r.statusCode, 401, 'cross-tenant login must fail');
});
test('login denied: unknown user', async () => {
  const r = await login('nobody@example.com', 'tenant-one'); eq(r.statusCode, 401, 'unknown-user login');
});

test('/me returns the caller identity (RLS v_me)', async () => {
  const r = await app.inject({ method: 'GET', url: '/me', headers: bearer(token1) });
  eq(r.statusCode, 200, '/me status'); eq(r.json().me.user_id, U1, '/me identity');
});
test('/me rejects missing and invalid tokens', async () => {
  eq((await app.inject({ method: 'GET', url: '/me' })).statusCode, 401, 'no token');
  eq((await app.inject({ method: 'GET', url: '/me', headers: bearer('garbage.token.here') })).statusCode, 401, 'bad token');
});

test('/memberships is tenant-scoped per token (isolation)', async () => {
  const a = await app.inject({ method: 'GET', url: '/memberships', headers: bearer(token1) });
  const b = await app.inject({ method: 'GET', url: '/memberships', headers: bearer(token2) });
  eq(a.json().memberships.length, 1, 'T1 membership count');
  eq(b.json().memberships.length, 1, 'T2 membership count');
  eq(a.json().memberships[0].tenant_id, b.json().memberships[0].tenant_id === a.json().memberships[0].tenant_id ? 'same' : a.json().memberships[0].tenant_id, 'tenants differ');
  if (a.json().memberships[0].tenant_id === b.json().memberships[0].tenant_id) throw new Error('two tenants saw the same membership');
});

test('role assign denied for a member (no roles.assign)', async () => {
  const r = await app.inject({ method: 'POST', url: '/roles/assign', headers: bearer(token1), payload: { membership_id: M3, role_id: ROLE_MEMBER } });
  eq(r.statusCode, 403, 'member must be forbidden');
});
test('role assign allowed for an admin', async () => {
  const r = await app.inject({ method: 'POST', url: '/roles/assign', headers: bearer(token3), payload: { membership_id: M3, role_id: ROLE_MEMBER } });
  eq(r.statusCode, 200, 'admin assign');
});
test('role assign to a cross-tenant membership is rejected (composite FK)', async () => {
  const r = await app.inject({ method: 'POST', url: '/roles/assign', headers: bearer(token3), payload: { membership_id: M2, role_id: ROLE_MEMBER } });
  eq(r.statusCode, 400, 'cross-tenant membership assignment must fail');
});

// ---- group 3: entitlements + ent_v staleness gate ----
test('/my-entitlements shows the current plan (group 3)', async () => {
  const r = await app.inject({ method: 'GET', url: '/my-entitlements', headers: bearer(token1) });
  eq(r.statusCode, 200, '/my-entitlements status');
  eq(r.json().entitlements.entitlements.plan_key, 'standard', 'plan_key');
});
test('non-admin cannot recompute entitlements', async () => {
  const r = await app.inject({ method: 'POST', url: '/billing/recompute', headers: bearer(token1) });
  eq(r.statusCode, 403, 'member recompute must be forbidden');
});
test('admin recompute bumps ent_v', async () => {
  const r = await app.inject({ method: 'POST', url: '/billing/recompute', headers: bearer(token3) });
  eq(r.statusCode, 200, 'recompute status');
  if (!(r.json().ent_v > 1)) throw new Error(`expected ent_v > 1, got ${r.json().ent_v}`);
});
test('stale token guarded write is rejected (409 STALE_ENTITLEMENT_VERSION)', async () => {
  // token3 was minted before the recompute above, so its ent_v is now behind.
  const r = await app.inject({ method: 'POST', url: '/roles/assign', headers: bearer(token3), payload: { membership_id: M1, role_id: ROLE_ADMIN } });
  eq(r.statusCode, 409, 'stale write status');
  eq(r.json().error, 'STALE_ENTITLEMENT_VERSION', 'stale error code');
});
test('re-login refreshes ent_v and the same write succeeds', async () => {
  const fresh = (await login('u3@example.com', 'tenant-one')).json().token;
  const r = await app.inject({ method: 'POST', url: '/roles/assign', headers: bearer(fresh), payload: { membership_id: M1, role_id: ROLE_ADMIN } });
  eq(r.statusCode, 200, 'refreshed write should succeed');
});

// ---- group 4: events ----
test('/my-events shows the tenant event stream (seeded history)', async () => {
  const r = await app.inject({ method: 'GET', url: '/my-events', headers: bearer(token2) });
  eq(r.statusCode, 200, '/my-events status');
  if (!r.json().events.length) throw new Error('expected seeded events for tenant-two');
});
test('recompute emitted an entitlements.recomputed event (transactional outbox -> relay)', async () => {
  const fresh = (await login('u3@example.com', 'tenant-one')).json().token;
  const r = await app.inject({ method: 'GET', url: '/my-events', headers: bearer(fresh) });
  if (!r.json().events.some((e) => e.event_type === 'entitlements.recomputed'))
    throw new Error('recompute event not found in /my-events');
});

// ---- group 5: 4-token launch/exchange + revocation cascade ----
let hubFresh, launchTok, launchNonce, spokeTok;
test('launch: fresh hub session (current ent_v)', async () => {
  hubFresh = (await login('u3@example.com', 'tenant-one')).json().token;
  if (!hubFresh) throw new Error('no fresh token');
});
test('launch: a locked app is rejected (423 TENANT_LOCKED)', async () => {
  const r = await app.inject({ method: 'POST', url: '/launch', headers: bearer(hubFresh), payload: { app_key: 'directory' } });
  eq(r.statusCode, 423, 'locked app launch');
});
test('launch: a launchable app issues a 60s launch token', async () => {
  const r = await app.inject({ method: 'POST', url: '/launch', headers: bearer(hubFresh), payload: { app_key: 'hifz-lms' } });
  eq(r.statusCode, 200, 'launch status');
  launchTok = r.json().launch_token; launchNonce = r.json().nonce;
  if (!launchTok || !launchNonce) throw new Error('no launch token/nonce');
});
test('exchange: launch token + nonce yields a spoke session', async () => {
  const r = await app.inject({ method: 'POST', url: '/token/exchange', payload: { launch_token: launchTok, nonce: launchNonce } });
  eq(r.statusCode, 200, 'exchange status');
  spokeTok = r.json().spoke_session_token;
  if (!spokeTok) throw new Error('no spoke token');
});
test('exchange: a replayed launch token is rejected (one-time)', async () => {
  const r = await app.inject({ method: 'POST', url: '/token/exchange', payload: { launch_token: launchTok, nonce: launchNonce } });
  eq(r.statusCode, 401, 'replay status'); eq(r.json().error, 'LAUNCH_INVALID', 'replay error');
});
test('spoke: the spoke session token works', async () => {
  const r = await app.inject({ method: 'GET', url: '/spoke/context', headers: bearer(spokeTok) });
  eq(r.statusCode, 200, 'spoke status'); eq(r.json().active, true, 'spoke active');
});
test('revoke: revoking the root session cascades to the spoke (401 SESSION_REVOKED)', async () => {
  const rev = await app.inject({ method: 'POST', url: '/sessions/revoke', headers: bearer(hubFresh) });
  if (!(rev.json().revoked >= 1)) throw new Error('expected >=1 revoked');
  const r = await app.inject({ method: 'GET', url: '/spoke/context', headers: bearer(spokeTok) });
  eq(r.statusCode, 401, 'post-revoke spoke status'); eq(r.json().error, 'SESSION_REVOKED', 'cascade');
});

// ---- group 6: Stripe webhook ingestion -> billing loop ----
const PD = { id: 'evt_pd', type: 'customer.subscription.updated', created: 1700000000, data: { object: { customer: 'cus_t1', status: 'past_due' } } };
const PD_CONFLICT = { id: 'evt_pd', type: 'customer.subscription.updated', created: 1700000000, data: { object: { customer: 'cus_t1', status: 'active' } } };
const ACT = { id: 'evt_act', type: 'customer.subscription.updated', created: 1700000010, data: { object: { customer: 'cus_t1', status: 'active' } } };

test('webhook: an invalid signature is rejected (401)', async () => {
  const r = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: { 'stripe-signature': 't=1,v1=deadbeef', 'content-type': 'application/json' }, payload: JSON.stringify(PD) });
  eq(r.statusCode, 401, 'bad signature');
});
test('webhook: subscription past_due processes and LOCKS the app', async () => {
  const e = signedEvent(PD);
  const r = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: e.headers, payload: e.raw });
  eq(r.statusCode, 200, 'processed'); eq(r.json().status, 'processed', 'result');
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  const apps = await app.inject({ method: 'GET', url: '/my-apps', headers: bearer(tok) });
  eq(apps.json().apps.find((a) => a.app_key === 'hifz-lms').launchable, false, 'hifz locked after past_due');
  const launch = await app.inject({ method: 'POST', url: '/launch', headers: bearer(tok), payload: { app_key: 'hifz-lms' } });
  eq(launch.statusCode, 423, 'launch denied for the now-locked app');
});
test('webhook: replaying the same event is deduped (200 duplicate)', async () => {
  const e = signedEvent(PD);
  const r = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: e.headers, payload: e.raw });
  eq(r.statusCode, 200, 'replay status'); eq(r.json().status, 'duplicate', 'deduped');
});
test('webhook: same event id + different payload is a conflict (409 WEBHOOK_CONFLICT)', async () => {
  const e = signedEvent(PD_CONFLICT);
  const r = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: e.headers, payload: e.raw });
  eq(r.statusCode, 409, 'conflict status'); eq(r.json().error, 'WEBHOOK_CONFLICT', 'conflict code');
});
test('webhook: subscription active RE-ACTIVATES the app', async () => {
  const e = signedEvent(ACT);
  const r = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: e.headers, payload: e.raw });
  eq(r.statusCode, 200, 'processed');
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  const apps = await app.inject({ method: 'GET', url: '/my-apps', headers: bearer(tok) });
  eq(apps.json().apps.find((a) => a.app_key === 'hifz-lms').launchable, true, 'hifz re-activated');
});

// ---- group 7: files (brokered, quarantine-first) ----
const S1 = 'f1000000-0000-0000-0000-000000000001'; // seeded minor
let fileId, studentFileId;
test('file: an upload is quarantined and download-before-scan is 423 FILE_NOT_CLEAN', async () => {
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  const up = await app.inject({ method: 'POST', url: '/files', headers: bearer(tok), payload: { filename: 'note.txt', content_type: 'text/plain', size_bytes: 12 } });
  eq(up.statusCode, 200, 'upload'); eq(up.json().status, 'quarantined', 'quarantined'); fileId = up.json().file_id;
  const dl = await app.inject({ method: 'GET', url: `/files/${fileId}/download`, headers: bearer(tok) });
  eq(dl.statusCode, 423, 'download denied before clean'); eq(dl.json().error, 'FILE_NOT_CLEAN', 'code');
});
test('file: after a clean scan, download returns a brokered URL (200)', async () => {
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  await app.inject({ method: 'POST', url: `/files/${fileId}/scan`, headers: bearer(tok), payload: { status: 'clean' } });
  const dl = await app.inject({ method: 'GET', url: `/files/${fileId}/download`, headers: bearer(tok) });
  eq(dl.statusCode, 200, 'download after clean'); if (!dl.json().download_url) throw new Error('no brokered url');
});

// ---- group 8: minor-data consent gate + subject erasure (OQ-034) ----
test('minor: reading a student WITHOUT consent is 403 CONSENT_REQUIRED', async () => {
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  const r = await app.inject({ method: 'GET', url: `/students/${S1}`, headers: bearer(tok) });
  eq(r.statusCode, 403, 'no consent'); eq(r.json().error, 'CONSENT_REQUIRED', 'code');
});
test('minor: granting parental consent unlocks reading the student', async () => {
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  eq((await app.inject({ method: 'POST', url: `/students/${S1}/consent`, headers: bearer(tok), payload: { granted: true } })).statusCode, 200, 'grant');
  const r = await app.inject({ method: 'GET', url: `/students/${S1}`, headers: bearer(tok) });
  eq(r.statusCode, 200, 'read after consent'); if (!r.json().student) throw new Error('no student returned');
});
test('minor: a student file needs consent — allowed while granted, denied after revoke', async () => {
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  const up = await app.inject({ method: 'POST', url: '/files', headers: bearer(tok), payload: { filename: 'recitation.m4a', subject_ref: S1 } });
  studentFileId = up.json().file_id;
  await app.inject({ method: 'POST', url: `/files/${studentFileId}/scan`, headers: bearer(tok), payload: { status: 'clean' } });
  eq((await app.inject({ method: 'GET', url: `/files/${studentFileId}/download`, headers: bearer(tok) })).statusCode, 200, 'download while consent granted');
  await app.inject({ method: 'POST', url: `/students/${S1}/consent`, headers: bearer(tok), payload: { granted: false } });
  const dl = await app.inject({ method: 'GET', url: `/files/${studentFileId}/download`, headers: bearer(tok) });
  eq(dl.statusCode, 403, 'download denied after revoke'); eq(dl.json().error, 'CONSENT_REQUIRED', 'code');
});
test('minor: subject-level erasure removes the student + their files (tenant intact)', async () => {
  const tok = (await login('u3@example.com', 'tenant-one')).json().token;
  const e = await app.inject({ method: 'POST', url: `/students/${S1}/erase`, headers: bearer(tok) });
  if (!(e.json().erased >= 1)) throw new Error('expected erasure');
  await app.inject({ method: 'POST', url: `/students/${S1}/consent`, headers: bearer(tok), payload: { granted: true } }); // consent gate passes...
  const r = await app.inject({ method: 'GET', url: `/students/${S1}`, headers: bearer(tok) });
  eq(r.statusCode, 404, '...but the erased student is gone');
});

// ---- group 11/12 setup: log in DISTINCT operators; ops/admin step up through MFA (group 12) ----
const loginOp = (email, api_key) => app.inject({ method: 'POST', url: '/operator/login', payload: { email, api_key } }).then((r) => r.json().operator_token);
async function loginOpMfa(email, api_key, secret) {
  const r1 = (await app.inject({ method: 'POST', url: '/operator/login', payload: { email, api_key } })).json();
  if (!r1.mfa_required) return r1.operator_token;
  return (await app.inject({ method: 'POST', url: '/operator/mfa/verify', payload: { mfa_token: r1.mfa_token, code: totp(secret) } })).json().operator_token;
}
const opsTok = await loginOpMfa('ops1@platform.example', 'opk_op3_key_cccccccc', 'JBSWY3DPEHPK3PXP');    // ops + MFA
const adminTok = await loginOpMfa('admin1@platform.example', 'opk_op4_key_dddddddd', 'KRSXG5CTMVRXEZLU'); // admin + MFA
const supTokA = await loginOp('support1@platform.example', 'opk_op1_key_aaaaaaaa');   // support (password-only)
const supTokB = await loginOp('support2@platform.example', 'opk_op2_key_bbbbbbbb');   // support (password-only)

// ---- group 9: TENANT-level offboarding lifecycle (operator-gated, ops role; dedicated tenant-three) ----
const adminHdr = bearer(opsTok);
const advance = (id, to) => app.inject({ method: 'POST', url: `/admin/offboarding/${id}/advance`, headers: adminHdr, payload: { to } });
let obJobId;

test('offboarding: the /admin surface rejects a missing/invalid operator token (401)', async () => {
  eq((await app.inject({ method: 'POST', url: '/admin/offboarding/start', payload: { tenant: 'tenant-three' } })).statusCode, 401, 'no operator token');
  eq((await app.inject({ method: 'POST', url: '/admin/offboarding/start', headers: bearer('garbage.token'), payload: { tenant: 'tenant-three' } })).statusCode, 401, 'invalid operator token');
});

test('offboarding: start creates a requested job for the tenant', async () => {
  const r = await app.inject({ method: 'POST', url: '/admin/offboarding/start', headers: adminHdr, payload: { tenant: 'tenant-three', reason: 'customer_churn' } });
  eq(r.statusCode, 200, 'start status'); obJobId = r.json().offboarding_job_id;
  eq(r.json().phase, 'requested', 'starts at requested'); if (!obJobId) throw new Error('no job id');
});

test('offboarding: the job LIST carries gate status and inherits the role + step-up gate', async () => {
  const l = await app.inject({ method: 'GET', url: '/admin/offboarding?tenant=tenant-three', headers: adminHdr });
  eq(l.statusCode, 200, 'list status');
  const row = (l.json().jobs || []).find((j) => j.id === obJobId);
  if (!row) throw new Error('the live job is missing from the list');
  eq(row.phase, 'requested', 'listed phase'); eq(row.tenant_slug, 'tenant-three', 'tenant slug joined');
  eq(row.retention_policy_key, 'offboarding-default', 'retention policy joined');
  eq(row.legal_hold_active, false, 'no hold yet'); eq(row.completion_ready, false, 'no receipts yet');
  // A list may never be a way around the gate its actions carry.
  const bySupport = await app.inject({ method: 'GET', url: '/admin/offboarding', headers: bearer(supTokA) });
  eq(bySupport.statusCode, 403, 'support role denied'); eq(bySupport.json().error, 'OPERATOR_ROLE_REQUIRED', 'code');
  const pwdOnlyOps = await loginOp('ops2@platform.example', 'opk_op5_key_eeeeeeee');
  const noStepUp = await app.inject({ method: 'GET', url: '/admin/offboarding', headers: bearer(pwdOnlyOps) });
  eq(noStepUp.statusCode, 403, 'pwd-only ops denied'); eq(noStepUp.json().error, 'MFA_REQUIRED', 'code');
});

test('offboarding: /admin/tenants flags the tenant that already has a live lifecycle job', async () => {
  const r = await app.inject({ method: 'GET', url: '/admin/tenants', headers: adminHdr });
  eq(r.statusCode, 200, 'tenants status');
  const t3 = (r.json().tenants || []).find((t) => t.slug === 'tenant-three');
  if (!t3) throw new Error('tenant-three missing'); eq(t3.live_offboarding_job_id, obJobId, 'live job surfaced');
  const t1 = (r.json().tenants || []).find((t) => t.slug === 'tenant-one');
  if (t1.live_offboarding_job_id) throw new Error('tenant-one should have no live job');
  // The support panel needs the same picker, so support may read it (no step-up either).
  eq((await app.inject({ method: 'GET', url: '/admin/tenants', headers: bearer(supTokA) })).statusCode, 200, 'support may list tenants');
});

test('offboarding: /admin/retention-policies exposes the §15 catalog the start form needs', async () => {
  const r = await app.inject({ method: 'GET', url: '/admin/retention-policies', headers: adminHdr });
  eq(r.statusCode, 200, 'policies status');
  const p = (r.json().policies || []).find((x) => x.policy_key === 'offboarding-default');
  if (!p) throw new Error('offboarding-default policy missing'); eq(p.retention_days, 0, 'retention days');
  eq((await app.inject({ method: 'GET', url: '/admin/retention-policies', headers: bearer(supTokA) })).statusCode, 403, 'support role denied the lifecycle catalog');
});

test('offboarding: a tenant write works while ACTIVE (baseline before freeze)', async () => {
  const tok = (await login('u4@example.com', 'tenant-three')).json().token;
  const r = await app.inject({ method: 'POST', url: '/students', headers: bearer(tok), payload: { full_name: 'T3 Pupil' } });
  eq(r.statusCode, 200, 'admin can write while tenant is active');
});

test('offboarding: freeze denies tenant WRITES but still allows READS (reuses tenant_writes_allowed)', async () => {
  eq((await advance(obJobId, 'approved')).json().phase, 'approved', 'approved');
  eq((await advance(obJobId, 'freeze_started')).json().phase, 'freeze_started', 'freeze_started');
  // A token minted AFTER freeze carries tw=false (login computes it from tenants.status).
  const tok = (await login('u4@example.com', 'tenant-three')).json().token;
  const w = await app.inject({ method: 'POST', url: '/students', headers: bearer(tok), payload: { full_name: 'Blocked Pupil' } });
  eq(w.statusCode, 403, 'frozen tenant denies writes');
  eq((await app.inject({ method: 'GET', url: '/my-apps', headers: bearer(tok) })).statusCode, 200, 'reads still allowed while frozen');
});

test('offboarding: export completion is gated on a verification receipt', async () => {
  await advance(obJobId, 'freeze_completed');
  await advance(obJobId, 'export_started');
  const blocked = await advance(obJobId, 'export_completed');
  eq(blocked.statusCode, 409, 'no receipt blocks'); eq(blocked.json().error, 'EXPORT_RECEIPT_REQUIRED', 'code');
  eq((await app.inject({ method: 'POST', url: `/admin/offboarding/${obJobId}/export-verify`, headers: adminHdr, payload: {} })).statusCode, 200, 'verify export');
  eq((await advance(obJobId, 'export_completed')).json().phase, 'export_completed', 'unblocked after receipt');
  await advance(obJobId, 'retention_wait');
});

test('offboarding: an active legal hold BLOCKS purge; releasing it unblocks (§13)', async () => {
  const h = await app.inject({ method: 'POST', url: '/admin/legal-hold', headers: adminHdr, payload: { tenant: 'tenant-three', reason: 'litigation' } });
  eq(h.statusCode, 200, 'place hold'); const holdId = h.json().legal_hold_id;
  const blocked = await advance(obJobId, 'purge_started');
  eq(blocked.statusCode, 409, 'hold blocks purge'); eq(blocked.json().error, 'LEGAL_HOLD_ACTIVE', 'code');
  eq((await app.inject({ method: 'POST', url: `/admin/legal-hold/${holdId}/release`, headers: adminHdr })).json().released, 1, 'release hold');
  eq((await advance(obJobId, 'purge_started')).json().phase, 'purge_started', 'purge starts after release');
});

test('offboarding: completion needs cache+search receipts; then tombstone deletes the tenant', async () => {
  const blocked = await advance(obJobId, 'purge_completed');
  eq(blocked.statusCode, 409, 'no purge receipts blocks completion'); eq(blocked.json().error, 'PURGE_RECEIPTS_REQUIRED', 'code');
  const p = await app.inject({ method: 'POST', url: `/admin/offboarding/${obJobId}/purge`, headers: adminHdr });
  eq(p.statusCode, 200, 'run purge'); if (!p.json().purge_job_id) throw new Error('no purge job');
  eq((await advance(obJobId, 'purge_completed')).json().phase, 'purge_completed', 'complete after receipts');
  eq((await advance(obJobId, 'tombstoned')).json().phase, 'tombstoned', 'tombstoned');
  const g = await app.inject({ method: 'GET', url: `/admin/offboarding/${obJobId}`, headers: adminHdr });
  eq(g.json().job.phase, 'tombstoned', 'inspect shows tombstoned'); eq(g.json().completion_ready, true, 'all receipts present');
  // The tenant is now deleted — it can no longer be logged into.
  eq((await login('u4@example.com', 'tenant-three')).statusCode, 401, 'deleted tenant rejects login');
});

test('offboarding: job detail carries the tenant, the retention policy and the HOLD IDS a console needs', async () => {
  const g = await app.inject({ method: 'GET', url: `/admin/offboarding/${obJobId}`, headers: adminHdr });
  eq(g.statusCode, 200, 'detail status');
  eq(g.json().tenant_slug, 'tenant-three', 'tenant slug'); eq(g.json().tenant_status, 'deleted', 'tenant status after tombstone');
  eq(g.json().retention_policy.policy_key, 'offboarding-default', 'policy joined');
  // Releasing a hold needs its id; before this it was only ever returned once, at placement time.
  const holds = g.json().legal_holds || [];
  if (!holds.length) throw new Error('the placed+released hold is missing from the detail');
  eq(holds[0].status, 'released', 'the demo hold was released'); if (!holds[0].id) throw new Error('hold id missing');
});

test('offboarding: blast radius is one tenant — tenant-one is unaffected', async () => {
  eq((await login('u3@example.com', 'tenant-one')).statusCode, 200, 'tenant-one still operational after tenant-three offboarding');
});

// ---- group 10: support/impersonation + platform-ops + Tier-A audit (operator-gated) ----
const OP1 = '0b000000-0000-0000-0000-000000000001'; // requester operator
const OP2 = '0b000000-0000-0000-0000-000000000002'; // approver operator
const sreq = (body) => app.inject({ method: 'POST', url: '/admin/support/request', headers: bearer(supTokA), payload: body });
let supTok;

test('support: /admin surface rejects a missing operator token (401)', async () => {
  eq((await app.inject({ method: 'POST', url: '/admin/support/request', payload: { tenant: 'tenant-one', reason: 'x' } })).statusCode, 401, 'no operator token');
});

test('support: dual-control — an operator cannot approve their OWN request (409)', async () => {
  const id = (await sreq({ tenant: 'tenant-one', target_email: 'u3@example.com', reason: 'debug' })).json().support_access_request_id;
  // Approve with the SAME operator's token → the approver is derived as op1 == requester → self-approval.
  const r = await app.inject({ method: 'POST', url: `/admin/support/request/${id}/approve`, headers: bearer(supTokA) });
  eq(r.statusCode, 409, 'self-approval blocked'); eq(r.json().error, 'SELF_APPROVAL_DENIED', 'code');
});

test('support: cannot impersonate an un-approved request (409, audited denial)', async () => {
  const id = (await sreq({ tenant: 'tenant-one', target_email: 'u3@example.com', reason: 'debug' })).json().support_access_request_id;
  const r = await app.inject({ method: 'POST', url: '/admin/support/impersonate', headers: bearer(supTokB), payload: { request_id: id } });
  eq(r.statusCode, 409, 'not approved'); eq(r.json().error, 'SUPPORT_REQUEST_NOT_APPROVED', 'code');
});

test('support: approve (by a DISTINCT operator) → impersonate issues a READ-ONLY token + banner', async () => {
  const id = (await sreq({ tenant: 'tenant-one', target_email: 'u3@example.com', reason: 'debug', ttl_seconds: 900 })).json().support_access_request_id;
  // op2's token approves op1's request — a genuine second authenticated human.
  eq((await app.inject({ method: 'POST', url: `/admin/support/request/${id}/approve`, headers: bearer(supTokB) })).statusCode, 200, 'approved by a distinct operator');
  const imp = await app.inject({ method: 'POST', url: '/admin/support/impersonate', headers: bearer(supTokB), payload: { request_id: id } });
  eq(imp.statusCode, 200, 'impersonate'); supTok = imp.json().support_token;
  eq(imp.json().banner_required, true, 'banner required');
  const ctx = await app.inject({ method: 'GET', url: '/support/session', headers: bearer(supTok) });
  eq(ctx.statusCode, 200, 'context'); eq(ctx.json().impersonating, true, 'impersonating'); eq(ctx.json().operator, OP1, 'requester operator carried');
});

test('support: impersonation is READ-ONLY — reads work, writes are denied even with the permission', async () => {
  eq((await app.inject({ method: 'GET', url: '/me', headers: bearer(supTok) })).statusCode, 200, 'read (/me) works under impersonation');
  // u3 HAS students.manage, but the support token is tw=false → the write is still denied.
  const w = await app.inject({ method: 'POST', url: '/students', headers: bearer(supTok), payload: { full_name: 'Should Fail' } });
  eq(w.statusCode, 403, 'impersonated write denied (read-only)');
});

test('support: a prohibited action class hard-denies (403) and is audited; benign passes', async () => {
  const bad = await app.inject({ method: 'POST', url: '/support/attempt', headers: bearer(supTok), payload: { action_class: 'billing' } });
  eq(bad.statusCode, 403, 'billing prohibited'); eq(bad.json().error, 'SUPPORT_ACTION_PROHIBITED', 'code');
  eq((await app.inject({ method: 'POST', url: '/support/attempt', headers: bearer(supTok), payload: { action_class: 'view_reports' } })).statusCode, 200, 'benign allowed');
});

test('support: the tenant audit chain records the flow and verifies intact', async () => {
  const v = await app.inject({ method: 'GET', url: '/admin/audit/verify?chain=tenant-one', headers: adminHdr });
  eq(v.statusCode, 200, 'verify'); eq(v.json().ok, true, 'chain intact');
  if (!(Number(v.json().checked) >= 5)) throw new Error(`expected the flow to have logged >=5 audit rows, got ${v.json().checked}`);
  const tail = await app.inject({ method: 'GET', url: '/admin/audit/tail?chain=tenant-one', headers: adminHdr });
  const actions = tail.json().events.map((e) => e.action);
  if (!actions.includes('support.impersonation.granted')) throw new Error('grant not in audit tail');
  if (!tail.json().events.some((e) => e.outcome === 'denied')) throw new Error('prohibited denial not audited');
});

test('support: the session LIST surfaces the live impersonation so it survives a console reload', async () => {
  const ctx = await app.inject({ method: 'GET', url: '/support/session', headers: bearer(supTok) });
  const ssid = ctx.json().support_session_id;
  const l = await app.inject({ method: 'GET', url: '/admin/support/sessions?status=active', headers: bearer(supTokB) });
  eq(l.statusCode, 200, 'sessions status');
  const row = (l.json().sessions || []).find((s) => s.id === ssid);
  if (!row) throw new Error('the active support session is missing from the list');
  eq(row.tenant_slug, 'tenant-one', 'tenant joined'); eq(row.mode, 'read_only', 'MVP mode');
  eq(row.banner_required, true, 'C5 banner signal'); eq(row.past_ttl, false, 'still inside its TTL');
});

test('support: ending the impersonation session revokes the underlying session', async () => {
  const tail = await app.inject({ method: 'GET', url: '/admin/audit/tail?chain=tenant-one', headers: adminHdr });
  // find the active support session via a fresh impersonation is overkill; end via the operator surface using the session id from context
  const ctx = await app.inject({ method: 'GET', url: '/support/session', headers: bearer(supTok) });
  const ssid = ctx.json().support_session_id;
  const e = await app.inject({ method: 'POST', url: `/admin/support/session/${ssid}/end`, headers: adminHdr });
  eq(e.statusCode, 200, 'end session'); if (!(Number(e.json().revoked) >= 1)) throw new Error('expected the underlying session revoked');
});

test('support: the request LIST carries BOTH sides of dual control (requester and approver)', async () => {
  const l = await app.inject({ method: 'GET', url: '/admin/support/requests?tenant=tenant-one', headers: bearer(supTokA) });
  eq(l.statusCode, 200, 'requests status');
  const rows = l.json().requests || [];
  if (!rows.length) throw new Error('no support requests listed');
  for (const r of rows) eq(r.requested_by_email, 'support1@platform.example', 'requester identity joined');
  const approved = rows.filter((r) => r.approved_by);
  if (!approved.length) throw new Error('no approved request listed');
  eq(approved[0].approved_by_email, 'support2@platform.example', 'approver identity joined');
  if (approved[0].approved_by === approved[0].requested_by) throw new Error('dual control violated in the projection');
});

test('support: creating a request reports whether target_email actually resolved to a user', async () => {
  const ok = await sreq({ tenant: 'tenant-one', target_email: 'u3@example.com', reason: 'resolvable' });
  eq(ok.json().target_resolved, true, 'known email resolves');
  const miss = await sreq({ tenant: 'tenant-one', target_email: 'ghost@example.com', reason: 'unresolvable' });
  eq(miss.statusCode, 200, 'request still created'); eq(miss.json().target_resolved, false, 'unknown email flagged at create time');
  // ...and that unresolved request is exactly the one impersonation would refuse three steps later.
  const id = miss.json().support_access_request_id;
  eq((await app.inject({ method: 'POST', url: `/admin/support/request/${id}/approve`, headers: bearer(supTokB) })).statusCode, 200, 'approved');
  eq((await app.inject({ method: 'POST', url: '/admin/support/impersonate', headers: bearer(supTokB), payload: { request_id: id } })).statusCode, 400, 'no target to impersonate');
});

test('support: read_write impersonation is rejected in MVP (mode never diverges from enforcement)', async () => {
  const r = await sreq({ tenant: 'tenant-one', target_email: 'u3@example.com', reason: 'debug', mode: 'read_write' });
  eq(r.statusCode, 400, 'read_write rejected'); eq(r.json().error, 'MODE_UNSUPPORTED', 'code');
});

test('support: impersonating a user with no membership in the tenant is denied AND audited (§12)', async () => {
  // u2 belongs to tenant-two only → no active membership in tenant-one.
  const id = (await sreq({ tenant: 'tenant-one', target_email: 'u2@example.com', reason: 'debug' })).json().support_access_request_id;
  eq((await app.inject({ method: 'POST', url: `/admin/support/request/${id}/approve`, headers: bearer(supTokB) })).statusCode, 200, 'approved');
  const imp = await app.inject({ method: 'POST', url: '/admin/support/impersonate', headers: bearer(supTokB), payload: { request_id: id } });
  eq(imp.statusCode, 404, 'no-membership impersonation denied');
  const tail = await app.inject({ method: 'GET', url: '/admin/audit/tail?chain=tenant-one', headers: adminHdr });
  if (!tail.json().events.some((e) => e.reason_code === 'NO_ACTIVE_MEMBERSHIP')) throw new Error('the denied attempt was not audited');
});

test('support: an operator can anchor a chain head (§16 Tier-A periodic anchoring), idempotently', async () => {
  const a1 = await app.inject({ method: 'POST', url: '/admin/audit/anchor', headers: adminHdr, payload: { chain: 'tenant-one', external_ref: 'notary-1' } });
  eq(a1.statusCode, 200, 'anchor ok'); if (!a1.json().anchor_id) throw new Error('no anchor id');
  const a2 = await app.inject({ method: 'POST', url: '/admin/audit/anchor', headers: adminHdr, payload: { chain: 'tenant-one' } });
  eq(a2.json().anchor_id, a1.json().anchor_id, 're-anchoring the same head is idempotent');
  // anchoring did not mutate the ledger — the chain still verifies clean.
  eq((await app.inject({ method: 'GET', url: '/admin/audit/verify?chain=tenant-one', headers: adminHdr })).json().ok, true, 'chain still verifies after anchor');
});

// ---- group 11: per-operator platform-ops auth ----
test('operator: bad key is 401 (audited); good key issues an operator token with its role', async () => {
  // ops2 (op5) has no MFA, so its login returns a full token directly (op3/op4 now step up via MFA).
  eq((await app.inject({ method: 'POST', url: '/operator/login', payload: { email: 'ops2@platform.example', api_key: 'opk_op5_key_WRONGXX' } })).statusCode, 401, 'bad key rejected');
  const good = await app.inject({ method: 'POST', url: '/operator/login', payload: { email: 'ops2@platform.example', api_key: 'opk_op5_key_eeeeeeee' } });
  eq(good.statusCode, 200, 'good key'); eq(good.json().operator_role, 'ops', 'role carried'); if (!good.json().operator_token) throw new Error('no operator token');
});

test('operator: role gating — a SUPPORT operator cannot drive destructive lifecycle (403)', async () => {
  const denied = await app.inject({ method: 'POST', url: '/admin/offboarding/start', headers: bearer(supTokA), payload: { tenant: 'tenant-one' } });
  eq(denied.statusCode, 403, 'support role denied offboarding'); eq(denied.json().error, 'OPERATOR_ROLE_REQUIRED', 'code');
});

test('operator: break-glass is OFF by default → the shared admin token is rejected', async () => {
  eq((await app.inject({ method: 'GET', url: '/admin/audit/verify?chain=platform', headers: { 'x-admin-token': 'dev-admin-token' } })).statusCode, 401, 'shared token rejected when break-glass disabled');
});

test('operator: logout revokes the session → the token is immediately rejected', async () => {
  const tok = await loginOp('support2@platform.example', 'opk_op2_key_bbbbbbbb');
  eq((await app.inject({ method: 'POST', url: '/operator/logout', headers: bearer(tok) })).json().revoked, 1, 'logout revokes the session');
  eq((await app.inject({ method: 'GET', url: '/admin/audit/tail?chain=platform', headers: bearer(tok) })).statusCode, 401, 'revoked token no longer authenticates');
});

// ---- group 12: operator MFA + SSO ----
test('mfa: step-up — an ops operator WITHOUT MFA is denied destructive lifecycle (403 MFA_REQUIRED)', async () => {
  const pwdOps = await loginOp('ops2@platform.example', 'opk_op5_key_eeeeeeee');   // ops, no MFA → acr='pwd'
  const r = await app.inject({ method: 'POST', url: '/admin/offboarding/start', headers: bearer(pwdOps), payload: { tenant: 'tenant-one' } });
  eq(r.statusCode, 403, 'pwd-only ops denied step-up'); eq(r.json().error, 'MFA_REQUIRED', 'code');
});

test('mfa: enroll → activate → two-step login yields an acr=mfa session that clears step-up', async () => {
  const created = await app.inject({ method: 'POST', url: '/admin/operators', headers: bearer(adminTok), payload: { email: 'mfatest@platform.example', display_name: 'MFA Test', operator_role: 'ops' } });
  eq(created.statusCode, 200, 'admin created a fresh ops operator'); const newId = created.json().operator_id;
  const apiKey = (await app.inject({ method: 'POST', url: `/admin/operators/${newId}/credential`, headers: bearer(adminTok) })).json().api_key;
  const tok0 = await loginOp('mfatest@platform.example', apiKey);   // password-only for now
  const enroll = (await app.inject({ method: 'POST', url: '/operator/mfa/enroll', headers: bearer(tok0) })).json();
  if (!enroll.secret) throw new Error('no enroll secret');
  eq((await app.inject({ method: 'POST', url: '/operator/mfa/activate', headers: bearer(tok0), payload: { code: '000000' } })).statusCode, 401, 'wrong activation code rejected');
  const act = await app.inject({ method: 'POST', url: '/operator/mfa/activate', headers: bearer(tok0), payload: { code: totp(enroll.secret) } });
  eq(act.statusCode, 200, 'activate with a live TOTP'); if (!(act.json().recovery_codes || []).length) throw new Error('no recovery codes issued');
  const step1 = (await app.inject({ method: 'POST', url: '/operator/login', payload: { email: 'mfatest@platform.example', api_key: apiKey } })).json();
  eq(step1.mfa_required, true, 'login now demands a second factor');
  eq((await app.inject({ method: 'POST', url: '/operator/mfa/verify', payload: { mfa_token: step1.mfa_token, code: '000000' } })).statusCode, 401, 'wrong TOTP rejected');
  const step2 = await app.inject({ method: 'POST', url: '/operator/mfa/verify', payload: { mfa_token: step1.mfa_token, code: totp(enroll.secret) } });
  eq(step2.statusCode, 200, 'correct TOTP completes login'); eq(step2.json().acr, 'mfa', 'session is acr=mfa');
  eq((await app.inject({ method: 'GET', url: '/admin/offboarding/00000000-0000-0000-0000-0000000000aa', headers: bearer(step2.json().operator_token) })).statusCode, 404, 'MFA ops now passes step-up (404, not 403)');
});

test('mfa: recovery-code login works and the code is single-use', async () => {
  const s1 = (await app.inject({ method: 'POST', url: '/operator/login', payload: { email: 'ops1@platform.example', api_key: 'opk_op3_key_cccccccc' } })).json();
  const r = await app.inject({ method: 'POST', url: '/operator/mfa/verify', payload: { mfa_token: s1.mfa_token, recovery_code: 'rc_known_op3_001' } });
  eq(r.statusCode, 200, 'recovery code logs in'); eq(r.json().acr, 'mfa', 'acr=mfa');
  const s1b = (await app.inject({ method: 'POST', url: '/operator/login', payload: { email: 'ops1@platform.example', api_key: 'opk_op3_key_cccccccc' } })).json();
  eq((await app.inject({ method: 'POST', url: '/operator/mfa/verify', payload: { mfa_token: s1b.mfa_token, recovery_code: 'rc_known_op3_001' } })).statusCode, 401, 'the recovery code is single-use');
});

test('sso: a validly-signed IdP assertion logs the linked operator in; tamper/aud/domain are rejected', async () => {
  const sign = (o) => { const p = Buffer.from(JSON.stringify(o)).toString('base64url'); return `${p}.${createHmac('sha256', 'sso-demo-secret-key').update(p).digest('hex')}`; };
  const exp = Math.floor(Date.now() / 1000) + 300;
  const good = sign({ iss: 'https://idp.example', aud: 'hub-operators', sub: 'ext-op1', email: 'op1@partner.example', exp });
  const r = await app.inject({ method: 'POST', url: '/operator/sso/login', payload: { idp: 'demo-oidc', assertion: good } });
  eq(r.statusCode, 200, 'SSO login ok'); if (!r.json().operator_token) throw new Error('no SSO token');
  eq((await app.inject({ method: 'POST', url: '/operator/sso/login', payload: { idp: 'demo-oidc', assertion: good.slice(0, -4) + 'dead' } })).statusCode, 401, 'tampered signature rejected');
  const badAud = sign({ iss: 'https://idp.example', aud: 'someone-else', sub: 'ext-op1', exp });
  eq((await app.inject({ method: 'POST', url: '/operator/sso/login', payload: { idp: 'demo-oidc', assertion: badAud } })).statusCode, 401, 'wrong audience rejected');
  const badDom = sign({ iss: 'https://idp.example', aud: 'hub-operators', sub: 'ext-evil', email: 'evil@attacker.example', exp });
  eq((await app.inject({ method: 'POST', url: '/operator/sso/login', payload: { idp: 'demo-oidc', assertion: badDom } })).json().error, 'DOMAIN_NOT_ALLOWED', 'JIT is restricted to the IdP allowed_domain');
});

test('mfa: an admin can reset an operator’s MFA (step-up), restoring password-only login', async () => {
  const rst = await app.inject({ method: 'POST', url: '/admin/operators/0b000000-0000-0000-0000-000000000003/mfa/reset', headers: bearer(adminTok) });
  eq(rst.statusCode, 200, 'admin MFA reset ok');
  const after = (await app.inject({ method: 'POST', url: '/operator/login', payload: { email: 'ops1@platform.example', api_key: 'opk_op3_key_cccccccc' } })).json();
  if (!after.operator_token) throw new Error('expected a full token after MFA reset'); eq(after.acr, 'pwd', 'password-only after reset');
});

// ---- group 13: WebAuthn / passkeys (real ES256 ceremonies via src/webauthn.js) ----
const pkEmail = 'pktest@platform.example';
const pkAuthr = makeCredential(cfg.webauthnRpId);   // a simulated authenticator (real P-256 keypair)
let pkCredId;

test('passkey: an operator registers a passkey from an authenticated session', async () => {
  const newId = (await app.inject({ method: 'POST', url: '/admin/operators', headers: bearer(adminTok), payload: { email: pkEmail, display_name: 'PK Test', operator_role: 'ops' } })).json().operator_id;
  const key = (await app.inject({ method: 'POST', url: `/admin/operators/${newId}/credential`, headers: bearer(adminTok) })).json().api_key;
  const tok = await loginOp(pkEmail, key);   // a password session, from which the operator adds a passkey
  const begin = (await app.inject({ method: 'POST', url: '/operator/webauthn/register/begin', headers: bearer(tok) })).json();
  const att = pkAuthr.attestation(begin.challenge, cfg.webauthnOrigin);
  const fin = await app.inject({ method: 'POST', url: '/operator/webauthn/register/finish', headers: bearer(tok), payload: { challenge_id: begin.challenge_id, attestationObject: att.attestationObject, clientDataJSON: att.clientDataJSON, nickname: 'yubikey' } });
  eq(fin.statusCode, 200, 'passkey registered'); pkCredId = fin.json().credential_id; if (!pkCredId) throw new Error('no credential id');
});

test('passkey: passwordless login yields a phishing-resistant session (acr=mfa) that clears step-up', async () => {
  const lb = (await app.inject({ method: 'POST', url: '/operator/webauthn/login/begin', payload: { email: pkEmail } })).json();
  if (!lb.allowCredentials.some((x) => x.id === pkCredId)) throw new Error('registered credential not offered');
  const asr = pkAuthr.assertion(lb.challenge, cfg.webauthnOrigin);
  const lf = await app.inject({ method: 'POST', url: '/operator/webauthn/login/finish', payload: { challenge_id: lb.challenge_id, ...asr } });
  eq(lf.statusCode, 200, 'passwordless login'); eq(lf.json().acr, 'mfa', 'phishing-resistant → acr=mfa'); eq(lf.json().amr[0], 'webauthn', 'amr=webauthn');
  eq((await app.inject({ method: 'GET', url: '/admin/offboarding/00000000-0000-0000-0000-0000000000aa', headers: bearer(lf.json().operator_token) })).statusCode, 404, 'passkey session clears step-up (404, not 403)');
});

test('passkey: origin mismatch, a consumed challenge, and a bad signature are all rejected', async () => {
  const lb1 = (await app.inject({ method: 'POST', url: '/operator/webauthn/login/begin', payload: { email: pkEmail } })).json();
  const badOrigin = pkAuthr.assertion(lb1.challenge, 'https://evil.example');
  eq((await app.inject({ method: 'POST', url: '/operator/webauthn/login/finish', payload: { challenge_id: lb1.challenge_id, ...badOrigin } })).json().error, 'WEBAUTHN_ORIGIN_MISMATCH', 'origin mismatch rejected');
  const reuse = pkAuthr.assertion(lb1.challenge, cfg.webauthnOrigin);
  eq((await app.inject({ method: 'POST', url: '/operator/webauthn/login/finish', payload: { challenge_id: lb1.challenge_id, ...reuse } })).statusCode, 401, 'a consumed challenge cannot be reused (single-use)');
  const lb2 = (await app.inject({ method: 'POST', url: '/operator/webauthn/login/begin', payload: { email: pkEmail } })).json();
  const asr = pkAuthr.assertion(lb2.challenge, cfg.webauthnOrigin);
  eq((await app.inject({ method: 'POST', url: '/operator/webauthn/login/finish', payload: { challenge_id: lb2.challenge_id, ...asr, signature: asr.signature.slice(0, -6) + 'AAAAAA' } })).statusCode, 401, 'a tampered signature is rejected');
});

test('passkey: a regressed sign counter is treated as a cloned authenticator', async () => {
  const lb = (await app.inject({ method: 'POST', url: '/operator/webauthn/login/begin', payload: { email: pkEmail } })).json();
  pkAuthr.setSignCount(0);   // roll the counter BACKWARD (what a cloned authenticator would do)
  const asr = pkAuthr.assertion(lb.challenge, cfg.webauthnOrigin, { bump: false });
  eq((await app.inject({ method: 'POST', url: '/operator/webauthn/login/finish', payload: { challenge_id: lb.challenge_id, ...asr } })).json().error, 'WEBAUTHN_CLONE_DETECTED', 'sign-count regression → clone detected');
});

// ---- group 14: feature-flag governance (MASTER_PLAN §11) ----
const myFlags = async (email, tenant, appKey) => {
  const tok = (await login(email, tenant)).json().token;
  return app.inject({ method: 'GET', url: `/my-flags${appKey ? `?app=${appKey}` : ''}`, headers: bearer(tok) });
};
const flagPost = (tok, url, payload) => app.inject({ method: 'POST', url, headers: bearer(tok), payload });
const QA = 'qa.api_checkout';
let qaRule;

test('flags: /my-flags resolves for the CALLER’s tenant and returns values only — no rules, targets or ids', async () => {
  const a = await myFlags('u1@example.com', 'tenant-one');
  eq(a.statusCode, 200, 'tenant-one /my-flags'); eq(a.json().flags['hifz.progress_v2'], true, 'seeded tenant rule applies to tenant-one');
  eq(a.json().environment, 'dev', 'served environment');
  const b = await myFlags('u2@example.com', 'tenant-two');
  eq(b.json().flags['hifz.progress_v2'], false, 'tenant-two gets the environment default');
  const raw = a.body;
  for (const leak of ['target_ref', 'rule_id', 'tier', '11111111-1111', 'priority']) if (raw.includes(leak)) throw new Error(`tenant payload leaks "${leak}"`);
  eq((await app.inject({ method: 'GET', url: '/my-flags' })).statusCode, 401, 'requires a tenant token');
  // Each app key is a decision subject in a never-deleted log — junk keys must not mint new subjects.
  const junk = await myFlags('u1@example.com', 'tenant-one', 'junk-app-123');
  eq(junk.statusCode, 400, 'unknown app refused'); eq(junk.json().error, 'UNKNOWN_APP', 'code');
});

test('flags: support may read and explain, but not write; password-only ops is refused step-up', async () => {
  const l = await app.inject({ method: 'GET', url: '/admin/flags', headers: bearer(supTokA) });
  eq(l.statusCode, 200, 'support lists flags');
  if (!l.json().flags.find((f) => f.flag_key === 'hifz.progress_v2' && f.environments.dev)) throw new Error('seeded flag missing from list');
  const x = await app.inject({ method: 'GET', url: '/admin/flags/hifz.progress_v2/explain?tenant=tenant-one', headers: bearer(supTokA) });
  eq(x.statusCode, 200, 'support explains'); eq(x.json().decision.tier, 'tenant', 'explained tier');
  eq(x.json().candidates.filter((r) => r.selected).length, 1, 'exactly one rule marked selected');
  const body = { flag_key: 'qa.denied', description: 'x', flag_type: 'boolean', owner_team: 'qa', risk_level: 'low', off_value: false };
  const s = await flagPost(supTokA, '/admin/flags', body);
  eq(s.statusCode, 403, 'support cannot write'); eq(s.json().error, 'OPERATOR_ROLE_REQUIRED', 'role code');
  const p = await flagPost(await loginOp('ops2@platform.example', 'opk_op5_key_eeeeeeee'), '/admin/flags', body);
  eq(p.statusCode, 403, 'pwd-only ops refused'); eq(p.json().error, 'MFA_REQUIRED', 'step-up code');
});

test('flags: create → tenant rule → /my-flags reflects it for that tenant only', async () => {
  const c = await flagPost(opsTok, '/admin/flags', { flag_key: QA, description: 'API checkout experiment', flag_type: 'multivariate',
    owner_team: 'qa', risk_level: 'medium', variants: ['control', 'wizard'], off_value: 'control' });
  eq(c.statusCode, 200, 'MFA ops creates a flag');
  eq((await myFlags('u1@example.com', 'tenant-one')).json().flags[QA], 'control', 'starts at off_value in every environment');
  const r = await flagPost(opsTok, `/admin/flags/${QA}/rollouts`, { environment: 'dev', target_type: 'tenant', tenant: 'tenant-one', value: 'wizard' });
  eq(r.statusCode, 200, 'tenant rule created'); qaRule = r.json().rule_id;
  eq((await myFlags('u1@example.com', 'tenant-one')).json().flags[QA], 'wizard', 'tenant-one sees its override');
  eq((await myFlags('u2@example.com', 'tenant-two')).json().flags[QA], 'control', 'tenant-two is unaffected');
});

test('flags: the kill switch overrides every rule for everyone (reason required); release restores', async () => {
  eq((await flagPost(opsTok, `/admin/flags/${QA}/environments/dev/kill`, { engaged: true })).statusCode, 400, 'no reason → 400');
  eq((await flagPost(opsTok, `/admin/flags/${QA}/environments/dev/kill`, { engaged: true, reason: 'checkout incident' })).statusCode, 200, 'engage');
  eq((await myFlags('u1@example.com', 'tenant-one')).json().flags[QA], 'control', 'tenant rule overridden by the kill switch');
  const x = await app.inject({ method: 'GET', url: `/admin/flags/${QA}/explain?tenant=tenant-one`, headers: bearer(opsTok) });
  eq(x.json().decision.tier, 'kill_switch', 'explain names tier 1');
  eq((await flagPost(opsTok, `/admin/flags/${QA}/environments/dev/kill`, { engaged: false })).statusCode, 200, 'release');
  eq((await myFlags('u1@example.com', 'tenant-one')).json().flags[QA], 'wizard', 'rule applies again');
});

test('flags: bad input surfaces as typed errors, not 500s', async () => {
  const rule = (b) => flagPost(opsTok, `/admin/flags/${QA}/rollouts`, { environment: 'dev', ...b });
  eq((await rule({ target_type: 'tenant', tenant: 'tenant-two', value: 'nope' })).json().error, 'FLAG_VALUE_INVALID', 'undeclared variant');
  eq((await rule({ target_type: 'tenant', tenant: 'no-such-tenant', value: 'wizard' })).statusCode, 404, 'unknown tenant slug');
  eq((await rule({ target_type: 'cohort', percent: 101, value: 'wizard' })).json().error, 'FLAG_TARGET_INVALID', 'cohort > 100');
  eq((await rule({ target_type: 'app', app: 'no-such-app', value: 'wizard' })).json().error, 'FLAG_TARGET_INVALID', 'unknown app');
  eq((await flagPost(opsTok, '/admin/flags', { flag_key: QA, description: 'dup', flag_type: 'boolean', owner_team: 'qa', risk_level: 'low', off_value: false })).json().error, 'FLAG_EXISTS', 'duplicate key');
  eq((await flagPost(opsTok, '/admin/flags/qa.nope/rollouts', { environment: 'dev', target_type: 'app', app: 'hifz-lms', value: true })).statusCode, 404, 'unknown flag');
});

test('flags: rules end but never revive; every change is attributed in the flag history and the platform chain', async () => {
  eq((await flagPost(opsTok, `/admin/flags/${QA}/rollouts/${qaRule}/status`, { status: 'ended' })).statusCode, 200, 'end rule');
  eq((await myFlags('u1@example.com', 'tenant-one')).json().flags[QA], 'control', 'back to the default');
  const rv = await flagPost(opsTok, `/admin/flags/${QA}/rollouts/${qaRule}/status`, { status: 'active' });
  eq(rv.statusCode, 409, 'revive refused'); eq(rv.json().error, 'FLAG_RULE_TERMINAL', 'code');
  const d = (await app.inject({ method: 'GET', url: `/admin/flags/${QA}`, headers: bearer(opsTok) })).json();
  const actions = d.audit.map((a) => a.action);
  for (const a of ['flag.created', 'rule.created', 'kill_switch.engaged', 'kill_switch.released', 'rule.status.ended'])
    if (!actions.includes(a)) throw new Error(`flag history missing ${a}`);
  if (!d.audit.every((a) => a.actor_email === 'ops1@platform.example')) throw new Error('an audit row is not attributed to ops1');
  const tiers = d.decisions.filter((x) => x.tenant_slug === 'tenant-one').map((x) => x.tier);
  for (const t of ['tenant', 'kill_switch', 'default']) if (!tiers.includes(t)) throw new Error(`decision log missing tier ${t}`);
  const tail = (await app.inject({ method: 'GET', url: '/admin/audit/tail?chain=platform', headers: bearer(opsTok) })).json().events.map((e) => e.action);
  if (!tail.includes('flag.kill_switch')) throw new Error('kill switch not on the Tier-A platform chain');
});

test('flags: paused serves off_value; archived disappears from tenants and cannot be revived', async () => {
  await flagPost(opsTok, `/admin/flags/${QA}/rollouts`, { environment: 'dev', target_type: 'tenant', tenant: 'tenant-one', value: 'wizard' });
  eq((await myFlags('u1@example.com', 'tenant-one')).json().flags[QA], 'wizard', 'new rule live');
  eq((await flagPost(opsTok, `/admin/flags/${QA}/status`, { status: 'paused' })).statusCode, 200, 'pause');
  eq((await myFlags('u1@example.com', 'tenant-one')).json().flags[QA], 'control', 'paused → off_value');
  await flagPost(opsTok, `/admin/flags/${QA}/status`, { status: 'archived' });
  if (QA in (await myFlags('u1@example.com', 'tenant-one')).json().flags) throw new Error('archived flag still served');
  eq((await flagPost(opsTok, `/admin/flags/${QA}/status`, { status: 'active' })).json().error, 'FLAG_ARCHIVED', 'archive is terminal');
  eq((await flagPost(opsTok, `/admin/flags/${QA}/rollouts`, { environment: 'dev', target_type: 'app', app: 'hifz-lms', value: 'wizard' })).json().error,
    'FLAG_ARCHIVED', 'no new rules on an archived flag');
});

// ---- group 15: rate-limit enforcement ----
const fromIp = (ip, opts) => app.inject({ ...opts, remoteAddress: ip });

test('ratelimit: login is throttled per client IP — 429 + Retry-After + RateLimit-*; another IP is unaffected', async () => {
  const try1 = () => fromIp('203.0.113.7', { method: 'POST', url: '/auth/login', payload: { access_token: supaToken('nobody@example.com'), tenant: 'tenant-one' } });
  const remaining = [];
  for (let i = 0; i < 10; i++) {
    const r = await try1();
    if (r.statusCode === 429) throw new Error(`throttled too early at attempt ${i + 1}`);
    remaining.push(Number(r.headers['ratelimit-remaining']));
  }
  eq(remaining.join(','), '9,8,7,6,5,4,3,2,1,0', 'RateLimit-Remaining counts down');
  const d = await try1();
  eq(d.statusCode, 429, '11th attempt throttled'); eq(d.json().error, 'RATE_LIMITED', 'code'); eq(d.json().policy, 'auth_login', 'policy');
  if (!(Number(d.headers['retry-after']) >= 1)) throw new Error('Retry-After missing');
  // Failed AND successful attempts both count — otherwise guessing is free. A different client is fine.
  eq((await fromIp('203.0.113.8', { method: 'POST', url: '/auth/login', payload: { access_token: supaToken('u1@example.com'), tenant: 'tenant-one' } })).statusCode, 200, 'other IP unaffected');
  // Operator login shares the auth budget for the same address.
  eq((await fromIp('203.0.113.7', { method: 'POST', url: '/operator/login', payload: { email: 'ops1@platform.example', api_key: 'x' } })).statusCode, 429, 'operator login throttled for that IP too');
});

test('ratelimit: the BFF\u2019s SIGNED client-IP assertion picks the bucket; an unsigned or forged one is ignored', async () => {
  const BFF = '10.1.1.1';   // every operator arrives from the console server's one address
  const signed = (ip, secret = 'dev-bff-secret-change-me') => {
    const ts = String(Date.now());
    return { 'x-client-ip': ip, 'x-client-ip-ts': ts, 'x-client-ip-sig': createHmac('sha256', secret).update(`${ip}|${ts}`).digest('hex') };
  };
  const attempt = (headers) => fromIp(BFF, { method: 'POST', url: '/operator/login', headers, payload: { email: 'nobody@platform.example', api_key: 'x' } });
  for (let i = 0; i < 10; i++) eq((await attempt(signed('198.18.0.1'))).statusCode, 401, `client A attempt ${i + 1} reaches the handler`);
  eq((await attempt(signed('198.18.0.1'))).statusCode, 429, 'client A throttled');
  eq((await attempt(signed('198.18.0.2'))).statusCode, 401, 'client B, same BFF socket, has its own bucket');
  // Forged (wrong secret) and unsigned assertions fall back to the socket address — they cannot select a bucket.
  eq((await attempt(signed('198.18.0.1', 'guess'))).statusCode, 401, 'forged signature ignored (not client A\u2019s exhausted bucket)');
  eq((await attempt({ 'x-client-ip': '198.18.0.1' })).statusCode, 401, 'unsigned assertion ignored');
  const stale = signed('198.18.0.1'); stale['x-client-ip-ts'] = String(Date.now() - 120_000);
  eq((await attempt(stale)).statusCode, 401, 'stale assertion ignored');
});

test('ratelimit: the login throttle cannot be bypassed by spelling the URL differently', async () => {
  // Percent-encoding a letter still routes to the login handler; the throttle must follow the ROUTE.
  for (const url of ['/auth/%6Cogin', '/auth/login?via=query']) {
    const ip = `203.0.113.${url.length}`;
    const tryIt = () => fromIp(ip, { method: 'POST', url, payload: { access_token: supaToken('nobody@example.com'), tenant: 'tenant-one' } });
    for (let i = 0; i < 10; i++) eq((await tryIt()).statusCode, 401, `${url} attempt ${i + 1} reaches the handler`);
    eq((await tryIt()).statusCode, 429, `${url} is throttled like /auth/login`);
  }
});

let t2Bucket;
test('ratelimit: noisy neighbour — a tight override on tenant-two throttles tenant-two only, and is visible to it', async () => {
  const o = await flagPost(opsTok, '/admin/rate-limits/overrides', { tenant: 'tenant-two', policy_key: 'api_tenant', limit_per_window: 3, window_seconds: 60, reason: 'abuse investigation' });
  eq(o.statusCode, 200, 'MFA ops sets an override');
  const t2 = (await login('u2@example.com', 'tenant-two')).json().token;
  const mine = await app.inject({ method: 'GET', url: '/my-rate-limits', headers: bearer(t2) });   // hit 1 of 3
  eq(mine.json().limits.api_tenant.source, 'override', 'tenant sees its own override');
  eq(mine.json().limits.api_tenant.limit_per_window, 3, 'override limit'); eq(mine.json().limits.api_tenant.burst, 0, 'burst scaled down with the override');
  eq((await app.inject({ method: 'GET', url: '/me', headers: bearer(t2) })).statusCode, 200, 'hit 2');
  eq((await app.inject({ method: 'GET', url: '/me', headers: bearer(t2) })).statusCode, 200, 'hit 3');
  const d = await app.inject({ method: 'GET', url: '/me', headers: bearer(t2) });
  eq(d.statusCode, 429, 'tenant-two throttled'); eq(d.json().policy, 'api_tenant', 'by the tenant aggregate');
  const t1 = (await login('u1@example.com', 'tenant-one')).json().token;
  eq((await app.inject({ method: 'GET', url: '/me', headers: bearer(t1) })).statusCode, 200, 'tenant-one unaffected');
  const ops = (await app.inject({ method: 'GET', url: '/admin/rate-limits', headers: bearer(opsTok) })).json();
  const ep = ops.episodes.find((e) => e.tenant_slug === 'tenant-two' && e.policy_key === 'api_tenant');
  if (!ep) throw new Error('throttling episode not recorded'); t2Bucket = ep.bucket_key;
  if (!ops.overrides.find((x) => x.tenant_slug === 'tenant-two' && x.created_by_email === 'ops1@platform.example')) throw new Error('override not attributed');
});

test('ratelimit: an operator can lift the override and clear the bucket (both audited)', async () => {
  eq((await flagPost(opsTok, '/admin/rate-limits/overrides', { tenant: 'tenant-two', policy_key: 'api_tenant', limit_per_window: 3000, window_seconds: 60, reason: 'investigation closed' })).statusCode, 200, 'newer override supersedes');
  eq((await flagPost(opsTok, '/admin/rate-limits/reset', { bucket_key: t2Bucket })).json().cleared, 1, 'bucket cleared');
  const t2 = (await login('u2@example.com', 'tenant-two')).json().token;
  eq((await app.inject({ method: 'GET', url: '/me', headers: bearer(t2) })).statusCode, 200, 'tenant-two served again');
  const tail = (await app.inject({ method: 'GET', url: '/admin/audit/tail?chain=platform', headers: bearer(opsTok) })).json().events.map((e) => e.action);
  for (const a of ['rate_limit.override_set', 'rate_limit.bucket_reset']) if (!tail.includes(a)) throw new Error(`${a} not on the platform chain`);
});

test('ratelimit: policy edits apply at once; writes need ops|admin + step-up; support may read', async () => {
  eq((await app.inject({ method: 'GET', url: '/admin/rate-limits', headers: bearer(supTokA) })).statusCode, 200, 'support reads');
  const body = { limit_per_window: 2, window_seconds: 60, burst: 0 };
  eq((await flagPost(supTokA, '/admin/rate-limits/policies/webhook_ingress', body)).json().error, 'OPERATOR_ROLE_REQUIRED', 'support refused');
  eq((await flagPost(await loginOp('ops2@platform.example', 'opk_op5_key_eeeeeeee'), '/admin/rate-limits/policies/webhook_ingress', body)).json().error, 'MFA_REQUIRED', 'pwd-only ops refused');
  eq((await flagPost(opsTok, '/admin/rate-limits/policies/webhook_ingress', { limit_per_window: 0, window_seconds: 60 })).statusCode, 400, 'invalid limit');
  eq((await flagPost(opsTok, '/admin/rate-limits/policies/nope', body)).statusCode, 404, 'unknown policy');
  eq((await flagPost(opsTok, '/admin/rate-limits/policies/webhook_ingress', body)).statusCode, 200, 'tighten webhook ingress');
  const hook = () => fromIp('198.51.100.9', { method: 'POST', url: '/webhooks/stripe', payload: { id: 'evt_x' }, headers: { 'stripe-signature': 't=1,v1=bad' } });
  eq((await hook()).statusCode, 401, '#1 reaches the handler (bad signature)');
  eq((await hook()).statusCode, 401, '#2 reaches the handler');
  eq((await hook()).statusCode, 429, '#3 stopped before the handler');
  eq((await flagPost(opsTok, '/admin/rate-limits/policies/webhook_ingress', { limit_per_window: 600, window_seconds: 60, burst: 60 })).statusCode, 200, 'restore');
});

test('ratelimit: a limiter-store outage FAILS OPEN and is counted where operators can see it', async () => {
  const broken = { kind: 'broken', hit: async () => { throw new Error('store down'); }, reset: async () => 0, gc: async () => 0 };
  const app2 = buildServer({ rateLimitStore: broken, supabaseFetch, supabaseServiceRoleKey: 'test-service-role' });
  try {
    for (let i = 0; i < 15; i++) {
      const r = await app2.inject({ method: 'POST', url: '/auth/login', remoteAddress: '192.0.2.1', payload: { access_token: supaToken('u1@example.com'), tenant: 'tenant-one' } });
      eq(r.statusCode, 200, `login ${i + 1} served despite the outage`);
    }
    const s = (await app2.inject({ method: 'GET', url: '/admin/rate-limits', headers: bearer(opsTok) })).json().status;
    if (!(s.failed_open >= 15)) throw new Error(`failed_open not counted: ${s.failed_open}`);
    if (!/store down/.test(s.last_error)) throw new Error('last_error not surfaced');
  } finally { await app2.close(); }
});

// ---- group 16: real authentication (Supabase, DEC-012) ----
const exchange = (access_token, tenant = 'tenant-one') => app.inject({ method: 'POST', url: '/auth/login', payload: { access_token, tenant } });

test('auth: the email-only login is gone — naming an email no longer mints a token', async () => {
  const r = await app.inject({ method: 'POST', url: '/auth/login', payload: { email: 'u3@example.com', tenant: 'tenant-one' } });
  eq(r.statusCode, 400, 'email-only request refused'); if (r.json().token) throw new Error('a token was minted');
});

test('auth: only a genuine, current, correctly-addressed Supabase token is accepted', async () => {
  eq((await exchange(supaToken('u1@example.com'))).statusCode, 200, 'valid HS256 token');
  const good = supaToken('u1@example.com');
  const [h, p, sig] = good.split('.');
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), sub: SUBS['u3@example.com'] })).toString('base64url');
  eq((await exchange(`${h}.${forged}.${sig}`)).json().error, 'SUPABASE_TOKEN_INVALID', 'payload swapped to another user (signature no longer matches)');
  eq((await exchange(supaToken('u1@example.com', { secret: 'not-the-project-secret-but-32-chars-long!!' }))).json().error, 'SUPABASE_TOKEN_INVALID', 'wrong signing secret');
  eq((await exchange(supaToken('u1@example.com', { opts: { expiresIn: -120 } }))).json().error, 'SUPABASE_TOKEN_INVALID', 'expired beyond the 60s skew');
  eq((await exchange(supaToken('u1@example.com', { opts: { issuer: 'https://evil.example/auth/v1' } }))).json().error, 'SUPABASE_TOKEN_INVALID', 'another project / issuer');
  eq((await exchange(supaToken('u1@example.com', { claims: { aud: 'other' } }))).json().error, 'SUPABASE_TOKEN_INVALID', 'wrong audience');
  eq((await exchange('not.a.jwt')).statusCode, 401, 'garbage');
});

test('auth: Supabase’s own anon/service_role keys and anonymous users can never log in as a user', async () => {
  for (const role of ['anon', 'service_role'])
    eq((await exchange(supaToken('u1@example.com', { claims: { role } }))).json().error, 'SUPABASE_ROLE_INVALID', `${role} key refused`);
  eq((await exchange(supaToken('u1@example.com', { claims: { is_anonymous: true } }))).json().error, 'SUPABASE_ANONYMOUS_REFUSED', 'anonymous refused');
});

test('auth: asymmetric keys via JWKS work; unknown kid, algorithm confusion and alg=none are refused', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  jwksKeys.push({ ...publicKey.export({ format: 'jwk' }), kid: 'kid-es256-1', alg: 'ES256', use: 'sig' });
  const claims = { sub: SUBS['u1@example.com'], role: 'authenticated', aud: 'authenticated' };
  const es = (kid) => jwt.sign(claims, privateKey, { algorithm: 'ES256', issuer: ISS, expiresIn: 600, keyid: kid });
  eq((await exchange(es('kid-es256-1'))).statusCode, 200, 'ES256 token verified against the JWKS');
  eq((await exchange(es('kid-unknown'))).json().error, 'SUPABASE_UNKNOWN_KEY', 'unknown kid');
  // Algorithm confusion: an HS256 token "signed" with the PUBLIC key must not verify.
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const confused = jwt.sign(claims, pem, { algorithm: 'HS256', issuer: ISS, expiresIn: 600, keyid: 'kid-es256-1' });
  eq((await exchange(confused)).json().error, 'SUPABASE_TOKEN_INVALID', 'HS256-with-public-key refused');
  const none = `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({ ...claims, iss: ISS, exp: Math.floor(Date.now() / 1000) + 600 })).toString('base64url')}.`;
  eq((await exchange(none)).json().error, 'SUPABASE_ALG_NOT_ALLOWED', 'alg=none refused');
});

const NEW_SUB = randomUUID();
test('auth: invite → verified first login CLAIMS the identity and activates the membership', async () => {
  const admin = (await login('u3@example.com', 'tenant-one')).json().token;
  const inv = await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(admin), payload: { email: 'newbie@example.com', role_key: 'member' } });
  eq(inv.statusCode, 200, 'tenant admin invites'); eq(inv.json().status, 'invited', 'invited');
  eq((await exchange(supaToken('newbie@example.com', { sub: NEW_SUB }))).json().error, 'SUPABASE_USER_NOT_FOUND', 'no Supabase user yet → no claim');
  supaUsers.set(NEW_SUB, { email: 'newbie@example.com', email_confirmed_at: new Date().toISOString() });
  const first = await exchange(supaToken('newbie@example.com', { sub: NEW_SUB }));
  eq(first.statusCode, 200, 'first login'); eq(first.json().identity_claimed, true, 'identity claimed'); eq(first.json().membership_activated, true, 'membership activated');
  eq((await app.inject({ method: 'GET', url: '/me', headers: bearer(first.json().token) })).json().me.primary_email, 'newbie@example.com', '/me is the invitee');
  const second = await exchange(supaToken('newbie@example.com', { sub: NEW_SUB }));
  eq(second.statusCode, 200, 'second login via the binding'); eq(second.json().identity_claimed, undefined, 'no second claim');
  eq((await exchange(supaToken('newbie@example.com', { sub: NEW_SUB }), 'tenant-two')).statusCode, 401, 'no membership in another tenant');
});

test('auth: an unverified email cannot claim; a second Supabase account cannot take a claimed identity', async () => {
  const admin = (await login('u3@example.com', 'tenant-one')).json().token;
  await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(admin), payload: { email: 'pending@example.com' } });
  const sub = randomUUID();
  supaUsers.set(sub, { email: 'pending@example.com', email_confirmed_at: null });
  eq((await exchange(supaToken('pending@example.com', { sub }))).json().error, 'EMAIL_NOT_VERIFIED', 'unverified refused');
  supaUsers.set(sub, { email: 'pending@example.com', email_confirmed_at: new Date().toISOString() });
  eq((await exchange(supaToken('pending@example.com', { sub }))).statusCode, 200, 'claims once verified');
  // An attacker who registers a different Supabase account with the victim's email (e.g. after the victim
  // changed theirs) — or presents a token whose email CLAIM says so — gets nothing: the identity is bound.
  const attacker = randomUUID();
  supaUsers.set(attacker, { email: 'newbie@example.com', email_confirmed_at: new Date().toISOString() });
  eq((await exchange(supaToken('newbie@example.com', { sub: attacker }))).json().error, 'IDENTITY_NOT_PROVISIONED', 'claimed identity not re-bindable');
  // The token's own email claim is never trusted for claiming — only the Admin API's record is.
  const liar = randomUUID();
  supaUsers.set(liar, { email: 'liar@example.com', email_confirmed_at: new Date().toISOString() });
  await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(admin), payload: { email: 'target@example.com' } });
  eq((await exchange(supaToken('target@example.com', { sub: liar }))).json().error, 'IDENTITY_NOT_PROVISIONED', 'token email claim ignored');
});

test('auth: inviting needs memberships.manage and a write-eligible token; existing accounts are not revealed', async () => {
  // u2 is a plain member of tenant-two (u1 is promoted to tenant_admin earlier in this suite).
  const member = (await login('u2@example.com', 'tenant-two')).json().token;
  const denied = await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(member), payload: { email: 'x@example.com' } });
  eq(denied.statusCode, 403, 'member cannot invite'); eq(denied.json().error, 'PERMISSION_REQUIRED', 'code');
  const admin = (await login('u3@example.com', 'tenant-one')).json().token;
  const a = await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(admin), payload: { email: 'u2@example.com' } });
  const b = await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(admin), payload: { email: 'brand-new@example.com' } });
  eq(Object.keys(a.json()).sort().join(','), Object.keys(b.json()).sort().join(','), 'same response shape for existing and new emails');
  eq(a.json().status, 'invited', 'existing account invited'); eq(b.json().status, 'invited', 'new email invited');
  eq((await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(admin), payload: { email: 'not-an-email' } })).statusCode, 400, 'bad email');
  eq((await app.inject({ method: 'POST', url: '/tenant/invitations', headers: bearer(admin), payload: { email: 'r@example.com', role_key: 'god' } })).statusCode, 400, 'unknown role');
});

let pass = 0, fail = 0;
for (const t of tests) {
  try { await t.fn(); console.log(`  \x1b[32mPASS\x1b[0m  ${t.name}`); pass++; }
  catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.name}\n        ${e.message}`); fail++; }
}
await app.close(); await closePools();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
