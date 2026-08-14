// End-to-end API gate: HTTP -> Hub token -> context GUCs -> RLS. Proves the request path
// enforces the same isolation the DB gate proves, through real login and endpoints.
import { buildServer } from '../src/server.js';
import { closePools } from '../src/db.js';
import { createHmac } from 'node:crypto';
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

const app = buildServer();
const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };
const login = (email, tenant) => app.inject({ method: 'POST', url: '/auth/login', payload: { email, tenant } });
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

test('support: ending the impersonation session revokes the underlying session', async () => {
  const tail = await app.inject({ method: 'GET', url: '/admin/audit/tail?chain=tenant-one', headers: adminHdr });
  // find the active support session via a fresh impersonation is overkill; end via the operator surface using the session id from context
  const ctx = await app.inject({ method: 'GET', url: '/support/session', headers: bearer(supTok) });
  const ssid = ctx.json().support_session_id;
  const e = await app.inject({ method: 'POST', url: `/admin/support/session/${ssid}/end`, headers: adminHdr });
  eq(e.statusCode, 200, 'end session'); if (!(Number(e.json().revoked) >= 1)) throw new Error('expected the underlying session revoked');
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

let pass = 0, fail = 0;
for (const t of tests) {
  try { await t.fn(); console.log(`  \x1b[32mPASS\x1b[0m  ${t.name}`); pass++; }
  catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.name}\n        ${e.message}`); fail++; }
}
await app.close(); await closePools();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
