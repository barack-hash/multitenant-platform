// Isolation + control gate — table-group 10 (support/impersonation + platform-ops + Tier-A audit).
// Proves: service-only isolation, audit hash-chain integrity + tamper detection + append-only
// immutability + crypto-shred-safety, and the §12 hard controls (dual-control, TTL, non-renewable,
// one-active, prohibited-action hard-deny).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const S1 = 'f1000000-0000-0000-0000-000000000001'; // seeded minor (group 8)
const OP1 = '0b000000-0000-0000-0000-000000000001'; // requester
const OP2 = '0b000000-0000-0000-0000-000000000002'; // approver

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

const OPS_TABLES = ['audit_events', 'audit_anchor_points', 'platform_operators', 'support_access_requests',
  'support_sessions', 'rate_limit_policies', 'tenant_rate_limit_overrides', 'platform_deployments',
  'schema_migration_runs', 'environment_promotions'];

const appendAudit = (c, chain, tenant, action, extra = {}) => c.query(
  'select app.audit_append($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) id',
  [chain, tenant, action, extra.actor_type ?? 'service', extra.actor_ref ?? null, extra.resource_type ?? null,
   extra.resource_ref ?? null, extra.subject_token ?? null, extra.outcome ?? 'success', extra.reason_code ?? null,
   extra.correlation_id ?? null, extra.support_session_id ?? null, JSON.stringify(extra.meta ?? {})]).then((r) => r.rows[0].id);
const verify = (c, chain) => c.query('select * from app.audit_verify_chain($1)', [chain]).then((r) => r.rows[0]);
async function makeActiveSession(c, { requester = OP1, approver = OP2, tenant = T1, target = U1, ttl = 1800 } = {}) {
  const req = (await c.query(
    `insert into support_access_requests(tenant_id, requested_by, target_user_id, reason, ttl_seconds)
     values($1,$2,$3,'t',$4) returning id`, [tenant, requester, target, ttl])).rows[0].id;
  // The approver is derived from a LIVE operator session (group-11 dual-control binding).
  const approverSess = (await c.query('select app.start_operator_session($1) id', [approver])).rows[0].id;
  await c.query('select app.approve_support_request($1,$2)', [req, approverSess]);
  return { req, ss: (await c.query('select app.start_support_session($1,null) id', [req])).rows[0].id };
}

test('1  support/audit internals are service-only; svc_app denied; FORCE RLS on all 10 tables', async (c) => {
  await withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    for (const t of ['audit_events', 'support_access_requests', 'support_sessions', 'platform_operators']) {
      await expectErr(c, () => c.query(`select * from ${t}`), /permission denied/, `svc_app read ${t}`);
    }
  });
  const f = await c.query('select bool_and(relforcerowsecurity) ok from pg_class where relname = any($1)', [OPS_TABLES]);
  eq(f.rows[0].ok, true, 'force RLS on every group-10 table');
  eq((await c.query(`select count(*)::int n from pg_class where relname = any($1) and relkind='r'`, [OPS_TABLES])).rows[0].n, 10, 'all 10 exist');
});

test('2  audit_append builds a gap-free hash chain that verifies clean', async (c) =>
  withCtx(c, svc('svc_audit'), async () => {
    const start = Number((await c.query('select coalesce(max(chain_seq),0)::int m from audit_events where chain_id=$1', [T1])).rows[0].m);
    await appendAudit(c, T1, T1, 'a.one');
    await appendAudit(c, T1, T1, 'a.two');
    await appendAudit(c, T1, T1, 'a.three');
    const seqs = (await c.query('select chain_seq from audit_events where chain_id=$1 and chain_seq > $2 order by chain_seq', [T1, start])).rows.map((r) => Number(r.chain_seq));
    eq(seqs.join(','), `${start + 1},${start + 2},${start + 3}`, 'contiguous chain_seq');
    const v = await verify(c, T1);
    eq(v.ok, true, 'intact chain verifies'); eq(v.first_bad_seq, null, 'no bad row');
  }));

test('3  audit_verify_chain DETECTS a forged/tampered row', async (c) =>
  withCtx(c, svc('svc_audit'), async () => {
    await appendAudit(c, T1, T1, 'a.one');
    const seq2 = Number((await c.query('select max(chain_seq)::int m from audit_events where chain_id=$1', [T1])).rows[0].m) + 1;
    // Forge the next row with a wrong prev_hash (simulating a DB-level tamper that bypassed audit_append).
    await c.query(
      `insert into audit_events(chain_id, chain_seq, tenant_id, actor_type, action, outcome, prev_hash, row_hash)
       values($1, $2, $3::uuid, 'service', 'forged', 'success', $4, $5)`, [T1, seq2, T1, 'f'.repeat(64), 'deadhash']);
    const v = await verify(c, T1);
    eq(v.ok, false, 'tamper detected'); eq(v.first_bad_seq, seq2, 'pinpoints the bad row'); eq(v.failure_kind, 'prev_hash_mismatch', 'kind');
  }));

test('4  audit_events is append-only — update/delete/truncate all raise (even for the owner)', async (c) => {
  await c.query('begin');
  try {
    await appendAudit(c, T1, T1, 'a.one'); // superuser (no role set) — trigger must still fire below
    await c.query('savepoint sp');
    for (const [sql, label] of [
      [`update audit_events set action='x' where chain_id='${T1}'`, 'update'],
      [`delete from audit_events where chain_id='${T1}'`, 'delete'],
      ['truncate audit_events', 'truncate'],
    ]) {
      let threw = null; try { await c.query(sql); } catch (e) { threw = e; }
      await c.query('rollback to savepoint sp');
      if (!threw || !/append-only/.test(threw.message)) throw new Error(`${label} should raise append-only, got ${threw?.message}`);
    }
  } finally { await c.query('rollback').catch(() => {}); }
});

test('5  dual-control: the approver is a LIVE operator session distinct from the requester', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const req = (await c.query(
      `insert into support_access_requests(tenant_id, requested_by, target_user_id, reason) values($1,$2,$3,'t') returning id`, [T1, OP1, U1])).rows[0].id;
    const sessOP1 = (await c.query('select app.start_operator_session($1) id', [OP1])).rows[0].id;
    const sessOP2 = (await c.query('select app.start_operator_session($1) id', [OP2])).rows[0].id;
    // Approving via the REQUESTER's own session is self-approval → denied.
    await expectErr(c, () => c.query('select app.approve_support_request($1,$2)', [req, sessOP1]), /SUPPORT_SELF_APPROVAL_DENIED/, 'self-approval via own session blocked');
    // A bogus/non-live session cannot approve (approver must be a live authenticated operator).
    await expectErr(c, () => c.query('select app.approve_support_request($1,$2)', [req, '00000000-0000-0000-0000-0000000000aa']), /SUPPORT_APPROVER_SESSION_INVALID/, 'non-live session rejected');
    // A DISTINCT operator's live session approves.
    eq((await c.query('select app.approve_support_request($1,$2) r', [req, sessOP2])).rows[0].r, 'approved', 'distinct operator session approves');
    // The row-level CHECK still blocks requester==approver independently.
    await expectErr(c, () => c.query(
      `insert into support_access_requests(tenant_id, requested_by, approved_by, reason) values($1,$2,$2,'t')`, [T1, OP1]),
      /ck_support_dual_control/, 'row CHECK blocks requester==approver');
  }));

test('6  a support session TTL cannot exceed 30 minutes (CHECK)', async (c) =>
  withCtx(c, svc('svc_support'), async () => {
    const req = (await c.query(`insert into support_access_requests(tenant_id, requested_by, reason) values($1,$2,'t') returning id`, [T1, OP1])).rows[0].id;
    await expectErr(c, () => c.query(
      `insert into support_sessions(access_request_id, tenant_id, support_operator_id, started_at, expires_at)
       values($1,$2,$3, now(), now() + interval '31 minutes')`, [req, T1, OP1]),
      /ck_support_ttl_30min/, '>30min window rejected');
  }));

test('7  a support session is non-renewable: expires_at cannot be extended, terminal cannot reactivate', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    const { ss } = await makeActiveSession(c);
    await expectErr(c, () => c.query("update support_sessions set expires_at = expires_at + interval '10 minutes' where id=$1", [ss]),
      /SUPPORT_SESSION_NOT_RENEWABLE/, 'extension blocked');
    await c.query("update support_sessions set status='ended', ended_at=now() where id=$1", [ss]);
    await expectErr(c, () => c.query("update support_sessions set status='active' where id=$1", [ss]),
      /SUPPORT_SESSION_NOT_RENEWABLE/, 'reactivation blocked');
  }));

test('8  only one ACTIVE support session per (operator, tenant)', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    await makeActiveSession(c);
    await expectErr(c, () => makeActiveSession(c), /duplicate key|ux_support_sessions_one_active/, 'second active blocked');
  }));

test('9  prohibited action classes hard-deny; expired session denies too', async (c) =>
  withCtx(c, svc('svc_ops'), async () => {
    for (const k of ['billing', 'identity_secret', 'lifecycle_destructive', 'role_privilege', 'infra_secret'])
      eq((await c.query('select app.support_action_prohibited($1) p', [k])).rows[0].p, true, `${k} prohibited`);
    eq((await c.query("select app.support_action_prohibited('view_dashboard') p")).rows[0].p, false, 'benign allowed');
    const { ss } = await makeActiveSession(c);
    eq((await c.query("select app.assert_support_action_allowed($1,'view_dashboard') ok", [ss])).rows[0].ok, true, 'benign passes gate');
    await expectErr(c, () => c.query("select app.assert_support_action_allowed($1,'billing')", [ss]), /SUPPORT_ACTION_PROHIBITED/, 'billing hard-denied');
    // An expired session denies even a benign action (C2a expiry-on-use).
    const req = (await c.query(`insert into support_access_requests(tenant_id, requested_by, reason) values($1,$2,'t') returning id`, [T1, OP1])).rows[0].id;
    const expired = (await c.query(
      `insert into support_sessions(access_request_id, tenant_id, support_operator_id, started_at, expires_at, status)
       values($1,$2,$3, now() - interval '1 hour', now() - interval '40 minutes','active') returning id`, [req, T1, OP2])).rows[0].id;
    await expectErr(c, () => c.query("select app.assert_support_action_allowed($1,'view_dashboard')", [expired]), /SUPPORT_SESSION_EXPIRED/, 'expired denied');
  }));

test('10  the audit chain survives subject erasure (PII was never in the hash)', async (c) => {
  await c.query('begin');
  try {
    await c.query('set local role svc_worker');
    await c.query("select set_config('app.actor_type','service',true)");
    await c.query("select set_config('app.svc_role','svc_audit',true)");
    await appendAudit(c, T1, T1, 'student.viewed', { subject_token: S1, actor_ref: 'op' });
    eq((await verify(c, T1)).ok, true, 'chain ok before erasure');
    await c.query("select set_config('app.svc_role','svc_lifecycle',true)");
    await c.query('select app.erase_student($1)', [S1]);           // group-8 subject erasure
    await c.query("select set_config('app.svc_role','svc_audit',true)");
    const v = await verify(c, T1);
    eq(v.ok, true, 'chain STILL verifies after the subject is crypto-shredded'); eq(v.first_bad_seq, null, 'no break');
  } finally { await c.query('rollback').catch(() => {}); }
});

test('11  svc_app cannot execute the audit/support functions (EXECUTE revoked)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, async () => {
    await expectErr(c, () => c.query("select app.audit_append('x',null,'a')"), /permission denied/, 'svc_app audit_append denied');
    await expectErr(c, () => c.query('select app.approve_support_request($1,$2)', [T1, T1]), /permission denied/, 'svc_app approve denied');
  }));

test('12  audit_anchor records the head (insert-once, idempotent) WITHOUT mutating the append-only ledger', async (c) =>
  withCtx(c, svc('svc_audit'), async () => {
    await appendAudit(c, T1, T1, 'a.one');
    await appendAudit(c, T1, T1, 'a.two');
    const head = Number((await c.query('select max(chain_seq)::int m from audit_events where chain_id=$1', [T1])).rows[0].m);
    const a1 = (await c.query('select app.audit_anchor($1,$2) id', [T1, 'ext-1'])).rows[0].id;
    if (!a1) throw new Error('anchor returned no id');
    eq(Number((await c.query('select chain_seq from audit_anchor_points where chain_id=$1 order by chain_seq desc limit 1', [T1])).rows[0].chain_seq), head, 'anchor records the head seq');
    const a2 = (await c.query('select app.audit_anchor($1) id', [T1])).rows[0].id;
    eq(a2, a1, 're-anchoring the same head is idempotent (same id, no new row)');
    eq((await c.query('select count(*)::int n from audit_anchor_points where chain_id=$1 and chain_seq=$2', [T1, head])).rows[0].n, 1, 'exactly one anchor for the head');
    await appendAudit(c, T1, T1, 'a.three');            // ledger was not frozen/mutated by anchoring
    eq((await verify(c, T1)).ok, true, 'chain still verifies + extends after anchoring');
    await expectErr(c, () => c.query("select app.audit_anchor('no-such-chain')"), /AUDIT_CHAIN_EMPTY/, 'empty chain raises');
  }));

test('13  a past-TTL active session does NOT wedge the one-active slot (sweep frees it)', async (c) =>
  withCtx(c, svc('svc_support'), async () => {
    const mkApproved = () => c.query(
      `insert into support_access_requests(tenant_id, requested_by, target_user_id, reason, status, approved_by, approved_at)
       values($1,$2,$3,'t','approved',$4, now()) returning id`, [T1, OP1, U1, OP2]).then((r) => r.rows[0].id);
    const req1 = await mkApproved();
    const stale = (await c.query(
      `insert into support_sessions(access_request_id, tenant_id, support_operator_id, target_user_id, started_at, expires_at, status)
       values($1,$2,$3,$4, now()-interval '1 hour', now()-interval '40 minutes','active') returning id`, [req1, T1, OP1, U1])).rows[0].id;
    // A fresh approved request for the SAME (operator, tenant): start must succeed — the stale slot is freed.
    const req2 = await mkApproved();
    const ss2 = (await c.query('select app.start_support_session($1,null) id', [req2])).rows[0].id;
    if (!ss2) throw new Error('a new session should start once the stale one is swept');
    eq((await c.query('select status from support_sessions where id=$1', [stale])).rows[0].status, 'expired', 'the stale session was swept to expired');
    eq((await c.query('select count(*)::int n from support_sessions where support_operator_id=$1 and tenant_id=$2 and status=$3', [OP1, T1, 'active'])).rows[0].n, 1, 'exactly one active session remains');
  }));

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) { try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; } catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; } }
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
