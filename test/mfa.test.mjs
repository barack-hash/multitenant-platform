// Isolation + control gate — table-group 12 (operator MFA + SSO, FOUNDATION_11).
// Proves: service-only isolation, MFA enroll/activate state machine, recovery-code single-use, lockout,
// admin reset, SSO federated-identity resolve + JIT-within-domain guard, EXECUTE revoked from svc_app.
// (TOTP code math is app-layer and is proven in api.test.mjs via src/mfa.js.)
import pg from 'pg';
import { createHash } from 'node:crypto';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const T1 = '11111111-1111-1111-1111-111111111111';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const OP1 = '0b000000-0000-0000-0000-000000000001';
const OP3 = '0b000000-0000-0000-0000-000000000003'; // seeded active MFA
const OP5 = '0b000000-0000-0000-0000-000000000005'; // no MFA
const IDP = '0e000000-0000-0000-0000-000000000001';

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
const OPS_TABLES = ['operator_mfa', 'operator_recovery_codes', 'operator_idp', 'operator_federated_identities'];

test('1  MFA/SSO internals are service-only; svc_app denied; FORCE RLS', async (c) => {
  await withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    for (const t of OPS_TABLES) await expectErr(c, () => c.query(`select * from ${t}`), /permission denied/, `svc_app read ${t}`);
  });
  const f = await c.query('select bool_and(relforcerowsecurity) ok from pg_class where relname = any($1)', [OPS_TABLES]);
  eq(f.rows[0].ok, true, 'force RLS on all four');
});

test('2  MFA enroll → activate state machine', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    await c.query('select app.operator_mfa_begin_enroll($1,$2)', [OP5, 'JBSWY3DPEHPK3PXP']);
    const m = (await c.query('select * from app.operator_mfa_get($1)', [OP5])).rows[0];
    eq(m.status, 'pending', 'pending after enroll'); eq(m.secret, 'JBSWY3DPEHPK3PXP', 'secret stored');
    eq((await c.query('select app.operator_mfa_activate($1) a', [OP5])).rows[0].a, true, 'activate flips to active');
    eq((await c.query('select app.operator_has_active_mfa($1) h', [OP5])).rows[0].h, true, 'now active');
    // re-enroll disables the old and returns to pending (one live enrollment).
    await c.query('select app.operator_mfa_begin_enroll($1,$2)', [OP5, 'KRSXG5CTMVRXEZLU']);
    eq((await c.query('select status from app.operator_mfa_get($1)', [OP5])).rows[0].status, 'pending', 're-enroll → pending');
    eq((await c.query("select count(*)::int n from operator_mfa where operator_id=$1 and status<>'disabled'", [OP5])).rows[0].n, 1, 'exactly one live enrollment');
  }));

test('3  recovery codes are single-use and operator-scoped', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    await c.query('select app.operator_add_recovery_codes($1,$2::text[])', [OP5, [sha256('code1'), sha256('code2')]]);
    eq((await c.query('select app.operator_consume_recovery_code($1,$2) ok', [OP5, sha256('code1')])).rows[0].ok, true, 'first use ok');
    eq((await c.query('select app.operator_consume_recovery_code($1,$2) ok', [OP5, sha256('code1')])).rows[0].ok, false, 'reuse denied');
    eq((await c.query('select app.operator_consume_recovery_code($1,$2) ok', [OP5, sha256('nope')])).rows[0].ok, false, 'unknown code denied');
    eq((await c.query('select app.operator_consume_recovery_code($1,$2) ok', [OP1, sha256('code2')])).rows[0].ok, false, "another operator can't spend op5's code");
  }));

test('4  lockout after repeated failures; a success clears it', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    for (let i = 0; i < 5; i++) await c.query('select app.operator_mfa_record($1,false)', [OP3]);
    eq((await c.query('select locked from app.operator_mfa_get($1)', [OP3])).rows[0].locked, true, 'locked after 5 failures');
    await c.query('select app.operator_mfa_record($1,true)', [OP3]);
    eq((await c.query('select locked from app.operator_mfa_get($1)', [OP3])).rows[0].locked, false, 'a success clears the lock');
  }));

test('5  admin reset disables MFA + clears recovery codes + mfa_required', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    eq((await c.query('select app.operator_has_active_mfa($1) h', [OP3])).rows[0].h, true, 'op3 has MFA (seeded)');
    await c.query('select app.operator_reset_mfa($1,$2)', [OP3, 'test']);
    eq((await c.query('select app.operator_has_active_mfa($1) h', [OP3])).rows[0].h, false, 'reset disables MFA');
    eq((await c.query('select count(*)::int n from operator_recovery_codes where operator_id=$1 and used_at is null', [OP3])).rows[0].n, 0, 'recovery codes cleared');
    eq((await c.query('select mfa_required from platform_operators where id=$1', [OP3])).rows[0].mfa_required, false, 'mfa_required cleared');
  }));

test('6  SSO: linked identity resolves; JIT only within the IdP allowed_domain at the IdP role', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const r = (await c.query('select * from app.operator_sso_login($1,$2,$3)', [IDP, 'ext-op1', 'op1@partner.example'])).rows[0];
    eq(r.operator_id, OP1, 'linked subject → op1'); eq(r.jit, false, 'not JIT');
    const j = (await c.query('select * from app.operator_sso_login($1,$2,$3)', [IDP, 'ext-new', 'newbie@partner.example'])).rows[0];
    if (!j || !j.operator_id) throw new Error('JIT should provision'); eq(j.jit, true, 'JIT provisions'); eq(j.operator_role, 'support', 'JIT at IdP default_role, not caller-chosen');
    await expectErr(c, () => c.query('select * from app.operator_sso_login($1,$2,$3)', [IDP, 'ext-bad', 'x@evil.example']), /SSO_DOMAIN_NOT_ALLOWED/, 'JIT outside allowed_domain refused');
    await expectErr(c, () => c.query('select * from app.operator_sso_login($1,$2,$3)', ['00000000-0000-0000-0000-0000000000aa', 'x', 'y@partner.example']), /SSO_IDP_UNKNOWN/, 'unknown idp raises');
  }));

test('7  svc_app cannot execute the MFA/SSO functions (EXECUTE revoked)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    await expectErr(c, () => c.query('select app.operator_mfa_get($1)', [OP3]), /permission denied/, 'mfa_get denied');
    await expectErr(c, () => c.query('select app.operator_reset_mfa($1)', [OP3]), /permission denied/, 'reset denied');
    await expectErr(c, () => c.query('select app.operator_sso_login($1,$2,$3)', [IDP, 'x', 'y@partner.example']), /permission denied/, 'sso_login denied');
  }));

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) { try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; } catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; } }
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
