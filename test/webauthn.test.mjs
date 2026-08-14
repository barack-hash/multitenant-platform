// Isolation + control gate — table-group 13 (WebAuthn / passkeys, FOUNDATION_12).
// Proves: service-only isolation, single-use/expiry/ceremony challenge store, credential add/get/revoke,
// sign-count clone detection, EXECUTE revoked. (The WebAuthn crypto itself is proven in api.test.mjs.)
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const OP1 = '0b000000-0000-0000-0000-000000000001';
const JWK = '{"kty":"EC","crv":"P-256","x":"AA","y":"BB"}';

const svc = (role) => ({ role: 'svc_worker', gucs: { 'app.actor_type': 'service', 'app.svc_role': role } });
const userGucs = (t, a, m) => ({ 'app.tenant_id': t, 'app.actor_type': 'user', 'app.actor_id': a, 'app.membership_id': m, 'app.permissions': '', 'app.tenant_writes_allowed': 'true' });
async function withCtx(c, { role, gucs = {} }, fn) {
  await c.query('begin');
  try {
    if (role) await c.query(`set local role ${role}`);
    for (const [k, v] of Object.entries(gucs)) await c.query('select set_config($1,$2,true)', [k, v]);
    return await fn();
  } finally { await c.query('rollback').catch(() => {}); }
}
async function expectErr(c, fn, rx, m) {
  await c.query('savepoint sp'); let threw = null;
  try { await fn(); } catch (e) { threw = e; }
  await c.query('rollback to savepoint sp');
  if (!threw) throw new Error(`${m}: expected an error, got none`);
  if (rx && !rx.test(threw.message)) throw new Error(`${m}: wrong error: ${threw.message}`);
}
const tests = [];
const test = (n, f) => tests.push({ n, f });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };
const n = (c, sql, p = []) => c.query(sql, p).then((r) => Number(r.rows[0].n));
const TABLES = ['operator_webauthn_credentials', 'operator_webauthn_challenges'];

test('1  WebAuthn internals are service-only; svc_app denied; FORCE RLS', async (c) => {
  await withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    for (const t of TABLES) await expectErr(c, () => c.query(`select * from ${t}`), /permission denied/, `svc_app read ${t}`);
  });
  const f = await c.query('select bool_and(relforcerowsecurity) ok from pg_class where relname = any($1)', [TABLES]);
  eq(f.rows[0].ok, true, 'force RLS on both');
});

test('2  challenge store: single-use, ceremony-matched, expiry-checked', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const id = (await c.query("select app.webauthn_new_challenge($1,'authentication','chal-abc') id", [OP1])).rows[0].id;
    const r1 = (await c.query("select * from app.webauthn_consume_challenge($1,'authentication')", [id])).rows[0];
    eq(r1.operator_id, OP1, 'consume returns the bound operator'); eq(r1.challenge, 'chal-abc', 'returns the stored challenge value');
    eq(await n(c, "select count(*)::int n from app.webauthn_consume_challenge($1,'authentication')", [id]), 0, 'single-use: a second consume is empty');
    const id2 = (await c.query("select app.webauthn_new_challenge($1,'registration','x') id", [OP1])).rows[0].id;
    eq(await n(c, "select count(*)::int n from app.webauthn_consume_challenge($1,'authentication')", [id2]), 0, 'ceremony mismatch → empty');
    await c.query("insert into operator_webauthn_challenges(id, operator_id, challenge, ceremony, expires_at) values('c1000000-0000-0000-0000-0000000000ee',$1,'old','authentication', now()-interval '1 minute')", [OP1]);
    eq(await n(c, "select count(*)::int n from app.webauthn_consume_challenge('c1000000-0000-0000-0000-0000000000ee','authentication')"), 0, 'expired → empty');
  }));

test('3  credential add / get / revoke', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    await c.query(`select app.webauthn_add_credential($1,'cred-1',$2::jsonb, 0)`, [OP1, JWK]);
    const g = (await c.query("select * from app.webauthn_get_credential('cred-1')")).rows[0];
    eq(g.operator_id, OP1, 'get returns owner'); eq(g.sign_count, 0, 'sign_count 0');
    if (!g.public_key_jwk || g.public_key_jwk.kty !== 'EC') throw new Error('public key jwk not returned');
    eq((await c.query("select app.webauthn_revoke('cred-1',$1) n", [OP1])).rows[0].n, 1, 'revoke');
    eq(await n(c, "select count(*)::int n from app.webauthn_get_credential('cred-1')"), 0, 'a revoked credential is not returned');
  }));

test('4  sign-count clone detection: only a strictly increasing counter advances', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    await c.query(`select app.webauthn_add_credential($1,'cred-2',$2::jsonb, 5)`, [OP1, JWK]);
    eq((await c.query("select app.webauthn_bump_sign_count('cred-2', 6) ok")).rows[0].ok, true, 'monotonic bump accepted');
    eq((await c.query("select app.webauthn_bump_sign_count('cred-2', 6) ok")).rows[0].ok, false, 'non-increasing bump rejected (clone signal)');
    eq((await c.query("select sign_count from operator_webauthn_credentials where credential_id='cred-2'")).rows[0].sign_count, 6, 'counter unchanged after a rejected bump');
    await c.query(`select app.webauthn_add_credential($1,'cred-0',$2::jsonb, 0)`, [OP1, JWK]);
    eq((await c.query("select app.webauthn_bump_sign_count('cred-0', 0) ok")).rows[0].ok, true, 'a 0/0 counter (authenticators without counters) is allowed');
  }));

test('5  svc_app cannot execute the WebAuthn functions (EXECUTE revoked)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    await expectErr(c, () => c.query("select app.webauthn_new_challenge($1,'authentication','x')", [OP1]), /permission denied/, 'new_challenge denied');
    await expectErr(c, () => c.query("select app.webauthn_get_credential('x')"), /permission denied/, 'get_credential denied');
    await expectErr(c, () => c.query("select app.webauthn_bump_sign_count('x',1)"), /permission denied/, 'bump denied');
  }));

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) { try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; } catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; } }
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
