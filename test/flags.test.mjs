// Isolation + resolver gate — table-group 14 (feature-flag governance, MASTER_PLAN §11, FOUNDATION_13).
// Proves: service-only isolation (svc_app nothing, svc_hub read-only), attributed + typed + target-checked
// config, the six-tier §11 precedence, in-tier conflict resolution, window/status filtering,
// deterministic cohorts, decision logging, and append-only evidence. Every test runs as the actual
// logical role it is about, inside its own rolled-back transaction.
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const T3 = '33333333-3333-3333-3333-333333333333';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const OP3 = '0b000000-0000-0000-0000-000000000003';   // ops operator (the acting actor)
const FLAG_TABLES = ['feature_flag_definitions', 'feature_flag_environments', 'feature_flag_rollouts',
  'feature_flag_audit_events', 'feature_flag_decision_log'];

const svc = (role, extra = {}) => ({ role: 'svc_worker', gucs: { 'app.actor_type': 'service', 'app.svc_role': role, ...extra } });
const ops = () => svc('svc_ops', { 'app.flag_actor': OP3 });
const hub = () => svc('svc_hub');
const appUser = () => ({ role: 'svc_app', gucs: {
  'app.tenant_id': T1, 'app.actor_type': 'user', 'app.actor_id': U1, 'app.membership_id': M1,
  'app.permissions': '', 'app.tenant_writes_allowed': 'true' } });

async function withCtx(c, { role, gucs = {} }, fn) {
  await c.query('begin');
  try {
    if (role) await c.query(`set local role ${role}`);
    for (const [k, v] of Object.entries(gucs)) await c.query('select set_config($1,$2,true)', [k, v]);
    return await fn();
  } finally { await c.query('rollback').catch(() => {}); }
}
// Switch logical role mid-transaction (rows written as svc_ops stay visible to the next role).
const become = async (c, { role, gucs }) => {
  await c.query('reset role'); await c.query(`set local role ${role}`);
  await c.query("select set_config('app.flag_actor','',true)");
  for (const [k, v] of Object.entries(gucs)) await c.query('select set_config($1,$2,true)', [k, v]);
};
async function expectErr(c, fn, rx, m) {
  await c.query('savepoint sp');
  let threw = null;
  try { await fn(); } catch (e) { threw = e; }
  await c.query('rollback to savepoint sp');
  if (!threw) throw new Error(`${m}: expected an error, got none`);
  if (rx && !rx.test(threw.message)) throw new Error(`${m}: wrong error: ${threw.message}`);
}

const tests = [];
const test = (n, f) => tests.push({ n, f });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };

// --- fixtures (all written as svc_ops inside the caller's tx) ---
async function mkFlag(c, key, { type = 'multivariate', variants = ['a', 'b', 'c', 'd', 'e', 'off'], off = '"off"', dflt = '"e"' } = {}) {
  const id = (await c.query(
    `insert into feature_flag_definitions(flag_key, description, flag_type, owner_team, risk_level, variants, off_value)
     values($1,'test','${type}','qa','low',$2,$3) returning id`,
    [key, type === 'multivariate' ? variants : null, off])).rows[0].id;
  await c.query(`insert into feature_flag_environments(flag_id, environment, default_value, updated_by) values($1,'dev',$2,$3)`, [id, dflt, OP3]);
  return id;
}
const rule = (c, flag, type, ref, value, extra = {}) => c.query(
  `insert into feature_flag_rollouts(flag_id, environment, target_type, target_ref, value, priority, start_at, end_at, status, created_by, created_at)
   values($1,'dev',$2,$3,$4,$5,$6,$7,$8,$9,coalesce($10, now())) returning id`,
  [flag, type, ref, value, extra.priority ?? 100, extra.start_at ?? null, extra.end_at ?? null,
   extra.status ?? 'active', OP3, extra.created_at ?? null]).then((r) => r.rows[0].id);
const evalf = (c, key, tenant, app = null, log = true) => c.query(
  'select * from app.evaluate_flag($1,$2,$3,$4,$5)', [key, 'dev', tenant, app, log]).then((r) => r.rows[0]);
const endRule = (c, id) => c.query("update feature_flag_rollouts set status='ended' where id=$1", [id]);

// ---------------------------------------------------------------------------------------------------

test('isolation: svc_app can neither read the flag tables nor call the resolver (DEC-009)', async (c) => {
  for (const t of FLAG_TABLES) {
    await withCtx(c, appUser(), () => expectErr(c, () => c.query(`select 1 from ${t} limit 1`), /permission denied/, `svc_app select ${t}`));
  }
  await withCtx(c, appUser(), () => expectErr(c,
    () => c.query("select * from app.evaluate_flag('hifz.progress_v2','dev',$1)", [T1]), /permission denied/, 'svc_app evaluate'));
});

test('isolation: svc_hub (the request path) may READ config but never write it or read the audit history', async (c) => {
  await withCtx(c, hub(), async () => {
    eq((await c.query('select count(*) n from feature_flag_definitions')).rows[0].n >= 3, true, 'hub reads definitions');
    await expectErr(c, () => c.query(
      `insert into feature_flag_rollouts(flag_id, environment, target_type, target_ref, value, status, created_by)
       values('f1000000-0000-0000-0000-000000000001','dev','cohort','pct:50','true','active',$1)`, [OP3]),
      /row-level security/, 'hub cannot create a rule (RLS WITH CHECK)');
    eq((await c.query("update feature_flag_environments set default_value='true' where environment='prod'")).rowCount, 0, 'hub update touches nothing');
    eq((await c.query('select count(*) n from feature_flag_audit_events')).rows[0].n, 0, 'hub cannot see the audit history');
  });
});

test('attribution: a config change with no app.flag_actor is refused, not logged with a placeholder', async (c) => {
  await withCtx(c, svc('svc_ops'), () => expectErr(c, () => c.query(
    `insert into feature_flag_definitions(flag_key, description, flag_type, owner_team, risk_level, off_value)
     values('qa.unattributed','x','boolean','qa','low','false')`), /FLAG_ACTOR_REQUIRED/, 'unattributed insert'));
});

test('typing: values must match the flag type (boolean vs declared multivariate variants)', async (c) => {
  await withCtx(c, ops(), async () => {
    const b = await mkFlag(c, 'qa.bool', { type: 'boolean', off: 'false', dflt: 'false' });
    await expectErr(c, () => c.query("update feature_flag_environments set default_value='\"on\"' where flag_id=$1", [b]), /FLAG_VALUE_INVALID/, 'string into boolean');
    await expectErr(c, () => rule(c, b, 'tenant', T1, '1'), /FLAG_VALUE_INVALID/, 'number into boolean');
    const m = await mkFlag(c, 'qa.multi');
    await expectErr(c, () => rule(c, m, 'tenant', T1, '"zzz"'), /FLAG_VALUE_INVALID/, 'undeclared variant');
    await expectErr(c, () => c.query(
      `insert into feature_flag_definitions(flag_key, description, flag_type, owner_team, risk_level, off_value)
       values('qa.badoff','x','boolean','qa','low','"no"')`), /ck_ff_off_value/, 'mistyped off_value');
  });
});

test('targets: a rule must point at something real (live tenant, known app, pct cohort)', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.targets');
    await expectErr(c, () => rule(c, f, 'tenant', '99999999-9999-9999-9999-999999999999', '"a"'), /FLAG_TARGET_INVALID/, 'unknown tenant');
    await expectErr(c, () => rule(c, f, 'app', 'no-such-app', '"a"'), /FLAG_TARGET_INVALID/, 'unknown app');
    await expectErr(c, () => rule(c, f, 'cohort', 'pct:101', '"a"'), /FLAG_TARGET_INVALID/, 'cohort > 100');
    await expectErr(c, () => rule(c, f, 'tenant_app', `${T1}:nope`, '"a"'), /FLAG_TARGET_INVALID/, 'tenant_app with unknown app');
    await rule(c, f, 'tenant_app', `${T1}:hifz-lms`, '"a"');   // a valid compound target is accepted
  });
});

test('§11 precedence: tenant_app > tenant > app > cohort > environment default', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.precedence');
    const ta = await rule(c, f, 'tenant_app', `${T1}:hifz-lms`, '"a"');
    const tn = await rule(c, f, 'tenant', T1, '"b"');
    const ap = await rule(c, f, 'app', 'hifz-lms', '"c"');
    const co = await rule(c, f, 'cohort', 'pct:100', '"d"');
    const walk = [['tenant_app', 'a', ta], ['tenant', 'b', tn], ['app', 'c', ap], ['cohort', 'd', co]];
    for (const [tier, val, id] of walk) {
      const r = await evalf(c, 'qa.precedence', T1, 'hifz-lms', false);
      eq(r.tier, tier, `tier while ${tier} is live`); eq(r.value, val, `value from ${tier}`); eq(r.rule_id, id, `rule id for ${tier}`);
      await endRule(c, id);
    }
    const d = await evalf(c, 'qa.precedence', T1, 'hifz-lms', false);
    eq(d.tier, 'default', 'falls through to the environment default'); eq(d.value, 'e', 'default value');
  });
});

test('§11 precedence: app-scoped tiers are skipped when the request names no app', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.noapp');
    await rule(c, f, 'tenant_app', `${T1}:hifz-lms`, '"a"');
    await rule(c, f, 'app', 'hifz-lms', '"c"');
    await rule(c, f, 'tenant', T1, '"b"', { priority: 999 });
    eq((await evalf(c, 'qa.noapp', T1, null, false)).tier, 'tenant', 'no app context → tenant tier');
    eq((await evalf(c, 'qa.noapp', T2, null, false)).tier, 'default', 'a different tenant matches nothing');
  });
});

test('§11 tier 1: the kill switch overrides every rule, serves off_value, and must be attributed', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.kill');
    await rule(c, f, 'tenant_app', `${T1}:hifz-lms`, '"a"');
    await expectErr(c, () => c.query("update feature_flag_environments set kill_engaged=true where flag_id=$1", [f]),
      /ck_ff_kill_attributed/, 'kill without reason/who/when');
    await c.query("update feature_flag_environments set kill_engaged=true, kill_reason='incident 42', killed_by=$2, killed_at=now() where flag_id=$1", [f, OP3]);
    const k = await evalf(c, 'qa.kill', T1, 'hifz-lms', false);
    eq(k.tier, 'kill_switch', 'kill tier wins over tenant_app'); eq(k.value, 'off', 'serves off_value'); eq(k.rule_id, null, 'no rule');
    await c.query("update feature_flag_environments set kill_engaged=false, kill_reason=null, killed_by=null, killed_at=null where flag_id=$1", [f]);
    eq((await evalf(c, 'qa.kill', T1, 'hifz-lms', false)).tier, 'tenant_app', 'release restores the rule');
  });
});

test('§11 in-tier: lower priority wins; at equal priority the newest created_at wins', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.order');
    await rule(c, f, 'tenant', T1, '"a"', { priority: 50 });
    await rule(c, f, 'tenant', T1, '"b"', { priority: 10 });
    eq((await evalf(c, 'qa.order', T1, null, false)).value, 'b', 'priority 10 beats 50');
    const g = await mkFlag(c, 'qa.tiebreak');
    await rule(c, g, 'tenant', T1, '"a"', { priority: 5, created_at: '2026-01-01T00:00:00Z' });
    await rule(c, g, 'tenant', T1, '"c"', { priority: 5, created_at: '2026-03-01T00:00:00Z' });
    await rule(c, g, 'tenant', T1, '"b"', { priority: 5, created_at: '2026-02-01T00:00:00Z' });
    eq((await evalf(c, 'qa.tiebreak', T1, null, false)).value, 'c', 'newest created_at breaks the tie');
  });
});

test('§11 active + in-window only: scheduled/paused/ended and out-of-window rules never fire', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.window');
    await rule(c, f, 'tenant', T1, '"a"', { start_at: new Date(Date.now() + 86400e3).toISOString() });
    await rule(c, f, 'tenant', T1, '"b"', { start_at: '2020-01-01T00:00:00Z', end_at: '2020-02-01T00:00:00Z' });
    await rule(c, f, 'tenant', T1, '"c"', { status: 'paused' });
    await rule(c, f, 'tenant', T1, '"d"', { status: 'scheduled' });
    const r = await evalf(c, 'qa.window', T1, null, false);
    eq(r.tier, 'default', 'nothing eligible → default');
    const reasons = (await c.query('select skip_reason from app.flag_candidates($1,$2,$3,null)', [f, 'dev', T1])).rows.map((x) => x.skip_reason).sort();
    eq(reasons.join(','), 'outside_window,outside_window,status_paused,status_scheduled', 'explain reports why each rule lost');
    await rule(c, f, 'tenant', T1, '"e"', { start_at: '2020-01-01T00:00:00Z' });  // open-ended, already started
    eq((await evalf(c, 'qa.window', T1, null, false)).tier, 'tenant', 'an in-window active rule fires');
  });
});

test('cohorts: deterministic md5 buckets; pct:0 never matches, pct:100 always does', async (c) => {
  await withCtx(c, ops(), async () => {
    const b1 = (await c.query("select app.flag_bucket('qa.cohort',$1) b", [T1])).rows[0].b;
    eq((await c.query("select app.flag_bucket('qa.cohort',$1) b", [T1])).rows[0].b, b1, 'stable bucket');
    if (b1 < 0 || b1 > 99) throw new Error(`bucket out of range: ${b1}`);
    const f = await mkFlag(c, 'qa.cohort');
    const z = await rule(c, f, 'cohort', 'pct:0', '"a"');
    eq((await evalf(c, 'qa.cohort', T1, null, false)).tier, 'default', 'pct:0 matches nobody');
    await endRule(c, z);
    const n = await rule(c, f, 'cohort', `pct:${b1 + 1}`, '"b"');
    eq((await evalf(c, 'qa.cohort', T1, null, false)).tier, 'cohort', 'bucket < pct → in');
    await endRule(c, n);
    await rule(c, f, 'cohort', `pct:${b1}`, '"c"');
    eq((await evalf(c, 'qa.cohort', T1, null, false)).tier, 'default', 'bucket == pct → out (strict <)');
    await rule(c, f, 'cohort', 'pct:100', '"d"', { priority: 1 });
    for (const t of [T1, T2, T3]) eq((await evalf(c, 'qa.cohort', t, null, false)).tier, 'cohort', `pct:100 includes ${t}`);
  });
});

test('§11 decision logging: each DISTINCT decision is logged once; a flip back is logged again', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.decisions');
    const count = async () => Number((await c.query('select count(*) n from feature_flag_decision_log where flag_id=$1', [f])).rows[0].n);
    await become(c, hub());
    await evalf(c, 'qa.decisions', T1); eq(await count(), 1, 'first decision logged (as svc_hub)');
    await evalf(c, 'qa.decisions', T1); eq(await count(), 1, 'identical repeat is not re-logged');
    await evalf(c, 'qa.decisions', T1, null, false); eq(await count(), 1, 'a dry run (p_log=false) never logs');
    await become(c, ops());
    const r = await rule(c, f, 'tenant', T1, '"a"');
    await become(c, hub());
    const d = await evalf(c, 'qa.decisions', T1); eq(await count(), 2, 'a changed decision is logged');
    const row = (await c.query('select tier, rule_id, value from feature_flag_decision_log where flag_id=$1 order by seq desc limit 1', [f])).rows[0];
    eq(row.tier, 'tenant', 'logged tier'); eq(row.rule_id, r, 'logged rule'); eq(row.value, 'a', 'logged value'); eq(d.rule_id, r, 'returned rule');
    await become(c, ops()); await endRule(c, r); await become(c, hub());
    await evalf(c, 'qa.decisions', T1); eq(await count(), 3, 'flipping back to the default is logged again');
    await evalf(c, 'qa.decisions', T2); eq(await count(), 4, 'a second subject has its own history');
  });
});

test('audit: every config change is recorded with actor + before/after, and the evidence is append-only', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.audit');
    const r = await rule(c, f, 'tenant', T1, '"a"');
    await c.query("update feature_flag_rollouts set status='paused' where id=$1", [r]);
    await c.query("update feature_flag_definitions set status='paused' where id=$1", [f]);
    const rows = (await c.query('select action, actor_id, before_value is not null b, after_value is not null a from feature_flag_audit_events where flag_id=$1 order by occurred_at, action', [f])).rows;
    eq(rows.map((x) => x.action).sort().join(','), 'environment.created,flag.created,flag.status.paused,rule.created,rule.status.paused', 'audit actions');
    for (const x of rows) eq(x.actor_id, OP3, `actor on ${x.action}`);
    eq(rows.find((x) => x.action === 'rule.status.paused').b, true, 'update carries before_value');
    await evalf(c, 'qa.audit', T1);
    for (const t of ['feature_flag_audit_events', 'feature_flag_decision_log']) {
      // Layer 1: no runtime role holds UPDATE/DELETE on the evidence tables.
      await expectErr(c, () => c.query(`update ${t} set environment='prod' where flag_id=$1`, [f]), /permission denied/, `svc_ops update ${t}`);
      await expectErr(c, () => c.query(`delete from ${t} where flag_id=$1`, [f]), /permission denied/, `svc_ops delete ${t}`);
    }
    // Layer 2: the trigger refuses even the superuser owner (a buggy migration, a console session).
    await c.query('reset role');
    for (const t of ['feature_flag_audit_events', 'feature_flag_decision_log']) {
      await expectErr(c, () => c.query(`update ${t} set environment='prod' where flag_id=$1`, [f]), /append-only/, `owner update ${t}`);
      await expectErr(c, () => c.query(`delete from ${t} where flag_id=$1`, [f]), /append-only/, `owner delete ${t}`);
    }
  });
});

test('immutability: rules are append-mostly, ended is terminal, type/key fixed, archive is terminal', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.immut');
    const r = await rule(c, f, 'tenant', T1, '"a"');
    await expectErr(c, () => c.query(`update feature_flag_rollouts set value='"b"' where id=$1`, [r]), /FLAG_RULE_IMMUTABLE/, 'edit rule value');
    await expectErr(c, () => c.query(`update feature_flag_rollouts set target_ref=$2 where id=$1`, [r, T2]), /FLAG_RULE_IMMUTABLE/, 'retarget rule');
    await endRule(c, r);
    await expectErr(c, () => c.query("update feature_flag_rollouts set status='active' where id=$1", [r]), /FLAG_RULE_TERMINAL/, 'revive ended rule');
    await expectErr(c, () => c.query("update feature_flag_definitions set flag_type='boolean', variants=null where id=$1", [f]), /FLAG_IMMUTABLE_FIELD/, 'change type');
    await c.query("update feature_flag_definitions set status='archived', archived_at=now() where id=$1", [f]);
    await expectErr(c, () => c.query("update feature_flag_definitions set status='active', archived_at=null where id=$1", [f]), /FLAG_ARCHIVED/, 'unarchive');
    for (const t of ['feature_flag_definitions', 'feature_flag_environments', 'feature_flag_rollouts']) {
      await expectErr(c, () => c.query(`delete from ${t} where ${t === 'feature_flag_definitions' ? 'id' : 'flag_id'}=$1`, [f]), /permission denied/, `no delete path on ${t}`);
    }
  });
});

test('inactive flags: paused/archived serve off_value regardless of rules (and unknown keys raise)', async (c) => {
  await withCtx(c, ops(), async () => {
    const f = await mkFlag(c, 'qa.paused');
    await rule(c, f, 'tenant', T1, '"a"');
    await c.query("update feature_flag_definitions set status='paused' where id=$1", [f]);
    const r = await evalf(c, 'qa.paused', T1, null, false);
    eq(r.tier, 'flag_inactive', 'paused tier'); eq(r.value, 'off', 'off_value');
    await expectErr(c, () => evalf(c, 'qa.nope', T1, null, false), /FLAG_NOT_FOUND/, 'unknown key');
    await expectErr(c, () => c.query("select * from app.evaluate_flag('qa.paused','qa',$1)", [T1]), /FLAG_BAD_ENVIRONMENT/, 'unknown environment');
  });
});

// ---------------------------------------------------------------------------------------------------
const c = new pg.Client({ connectionString: URL });
await c.connect();
let pass = 0, fail = 0;
for (const t of tests) {
  try { await t.f(c); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; }
  catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; }
}
await c.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
