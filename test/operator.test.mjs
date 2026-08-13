// Isolation + control gate — table-group 11 (per-operator platform-ops auth, FOUNDATION_10).
// Proves: service-only isolation, credential auth (right/wrong/disabled), session live/revoked/expired,
// disable-cascades-to-sessions, pass-the-hash resistance, TTL clamp + non-renewable, EXECUTE revoked.
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const OP1 = '0b000000-0000-0000-0000-000000000001'; // support
const OP2 = '0b000000-0000-0000-0000-000000000002'; // support
const OP3 = '0b000000-0000-0000-0000-000000000003'; // ops
const KEY1 = 'opk_op1_key_aaaaaaaa', PREFIX1 = KEY1.slice(0, 12);
const EMAIL1 = 'support1@platform.example';

const svc = (role) => ({ role: 'svc_worker', gucs: { 'app.actor_type': 'service', 'app.svc_role': role } });
const userGucs = (t, a, m, perms = '') => ({
  'app.tenant_id': t, 'app.actor_type': 'user', 'app.actor_id': a, 'app.membership_id': m,
  'app.permissions': perms, 'app.tenant_writes_allowed': 'true',
});
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
const live = (c, osid) => c.query('select app.assert_operator_session_live($1) l', [osid]).then((r) => r.rows[0].l);
const startSess = (c, op, ttl = null) => c.query('select app.start_operator_session($1,$2) id', [op, ttl]).then((r) => r.rows[0].id);

test('1  operator-auth internals are service-only; svc_app denied; FORCE RLS', async (c) => {
  await withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    for (const t of ['operator_credentials', 'operator_sessions'])
      await expectErr(c, () => c.query(`select * from ${t}`), /permission denied/, `svc_app read ${t}`);
  });
  const f = await c.query('select bool_and(relforcerowsecurity) ok from pg_class where relname = any($1)', [['operator_credentials', 'operator_sessions']]);
  eq(f.rows[0].ok, true, 'force RLS on both');
});

test('2  operator_authenticate: right key → operator+role; wrong key / wrong email → none', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const r = (await c.query('select * from app.operator_authenticate($1,$2,$3)', [EMAIL1, PREFIX1, KEY1])).rows[0];
    eq(r.operator_id, OP1, 'right key → op1'); eq(r.operator_role, 'support', 'role carried');
    eq((await c.query('select count(*)::int n from app.operator_authenticate($1,$2,$3)', [EMAIL1, PREFIX1, 'opk_op1_key_WRONGXXX'])).rows[0].n, 0, 'wrong key → none');
    eq((await c.query('select count(*)::int n from app.operator_authenticate($1,$2,$3)', ['support2@platform.example', PREFIX1, KEY1])).rows[0].n, 0, 'wrong email → none');
  }));

test('3  session gate: live, then revoked → not live, and a past-expiry active row → not live', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const s = await startSess(c, OP1, 600);
    eq(await live(c, s), true, 'fresh session is live');
    await c.query('select app.revoke_operator_session($1)', [s]);
    eq(await live(c, s), false, 'revoked → not live');
    const expd = (await c.query(
      `insert into operator_sessions(operator_id, issued_at, expires_at, status)
       values($1, now()-interval '2 hours', now()-interval '90 minutes','active') returning id`, [OP2])).rows[0].id;
    eq(await live(c, expd), false, 'past-expiry active → not live');
  }));

test('4  disabling an operator IMMEDIATELY kills its live token (no ≤60min lingering access)', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const s = await startSess(c, OP3);
    eq(await live(c, s), true, 'live before disable');
    await c.query('select app.disable_operator($1,$2)', [OP3, 'compromised']);
    eq(await live(c, s), false, 'disabling the operator invalidates the token at once');
    eq((await c.query('select app.operator_has_role($1,$2) r', [OP3, ['ops', 'admin']])).rows[0].r, false, 'disabled operator has no role');
  }));

test('5  operator_has_role reflects the staff directory', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    eq((await c.query('select app.operator_has_role($1,$2) r', [OP3, ['ops', 'admin']])).rows[0].r, true, 'op3 is ops');
    eq((await c.query('select app.operator_has_role($1,$2) r', [OP1, ['ops', 'admin']])).rows[0].r, false, 'op1 (support) is not ops/admin');
  }));

test('6  pass-the-hash blocked: presenting the STORED hash does NOT authenticate', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const stored = (await c.query('select secret_hash from operator_credentials where operator_id=$1', [OP1])).rows[0].secret_hash;
    eq((await c.query('select count(*)::int n from app.operator_authenticate($1,$2,$3)', [EMAIL1, PREFIX1, stored])).rows[0].n, 0,
      'the secret is hashed server-side, so a DB-read hash is not replayable');
  }));

test('7  TTL is clamped ≤1h and expires_at cannot be extended (non-renewable)', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const s = await startSess(c, OP1, 999999);   // clamps to 3600
    const secs = Number((await c.query('select extract(epoch from (expires_at - issued_at))::int s from operator_sessions where id=$1', [s])).rows[0].s);
    if (secs > 3600) throw new Error(`TTL not clamped: ${secs}s`);
    await expectErr(c, () => c.query("update operator_sessions set expires_at = expires_at + interval '10 minutes' where id=$1", [s]),
      /OPERATOR_SESSION_NOT_RENEWABLE/, 'extension blocked');
  }));

test('8  svc_app cannot execute the operator-auth functions (EXECUTE revoked)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    await expectErr(c, () => c.query("select app.operator_authenticate('x','y','z')"), /permission denied/, 'authenticate denied');
    await expectErr(c, () => c.query('select app.start_operator_session($1)', [OP1]), /permission denied/, 'start denied');
    await expectErr(c, () => c.query('select app.assert_operator_session_live($1)', ['00000000-0000-0000-0000-0000000000aa']), /permission denied/, 'gate denied');
  }));

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) { try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; } catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; } }
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
