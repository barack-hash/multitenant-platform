// Isolation gate — table-group 3 (billing + entitlements, FOUNDATION_03).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';

const userCtx = (t, a, m, perms = '') => ({
  'app.tenant_id': t, 'app.actor_type': 'user', 'app.actor_id': a, 'app.membership_id': m,
  'app.permissions': perms, 'app.tenant_writes_allowed': 'true',
});
const svcCtx = (role) => ({ 'app.actor_type': 'service', 'app.svc_role': role });

async function withCtx(c, { role, gucs = {} }, fn) {
  await c.query('begin');
  try {
    if (role) await c.query(`set local role ${role}`);
    for (const [k, v] of Object.entries(gucs)) await c.query('select set_config($1,$2,true)', [k, v]);
    return await fn();
  } finally { await c.query('rollback').catch(() => {}); }
}
const tests = [];
const test = (n, f) => tests.push({ n, f });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };
async function expectError(fn, frag) {
  try { await fn(); } catch (e) { if (frag && !e.message.includes(frag)) throw new Error(`wrong error: ${e.message}`); return; }
  throw new Error(`expected error${frag ? ` "${frag}"` : ''}, none thrown`);
}

test('1  plan catalog globally readable (Class C)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    eq((await c.query('select count(*)::int n from plans')).rows[0].n, 1, 'plans');
    eq((await c.query('select count(*)::int n from plan_app_entitlements')).rows[0].n, 1, 'plan_app_entitlements');
  }));

test('2  billing internals are NOT readable by svc_app (Class B)', async (c) => {
  // Each check in its own transaction — a permission-denied aborts the current tx.
  for (const t of ['billing_customers', 'subscriptions', 'subscription_items'])
    await withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, () =>
      expectError(() => c.query(`select * from ${t}`), 'permission denied'));
});

test('3  entitlement_snapshots tenant-scoped read (T1 sees only T1)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    eq((await c.query('select count(*)::int n from entitlement_snapshots')).rows[0].n, 1, 'T1 snapshot count');
    eq((await c.query('select count(*)::int n from entitlement_snapshots where tenant_id=$1', [T2])).rows[0].n, 0, 'T2 visible');
  }));

test('4  entitlement_snapshots missing-context fail-closed', async (c) =>
  withCtx(c, { role: 'svc_app' }, async () =>
    eq((await c.query('select count(*)::int n from entitlement_snapshots')).rows[0].n, 0, 'rows with empty context')));

test('5  svc_app cannot write entitlement_snapshots', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, () =>
    expectError(() => c.query("insert into entitlement_snapshots(tenant_id,snapshot_version,billing_status) values($1,99,'active')", [T1]), 'permission denied')));

test('6  recompute bumps tenants.entitlement_snapshot_version + writes a snapshot', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_billing') }, async () => {
    const before = (await c.query('select entitlement_snapshot_version ev from tenants where id=$1', [T1])).rows[0].ev;
    const nv = (await c.query('select app.recompute_entitlements($1) v', [T1])).rows[0].v;
    eq(Number(nv), Number(before) + 1, 'returned version');
    eq((await c.query('select entitlement_snapshot_version ev from tenants where id=$1', [T1])).rows[0].ev, nv, 'tenants version updated');
    const snap = await c.query('select entitlements from entitlement_snapshots where tenant_id=$1 and snapshot_version=$2', [T1, nv]);
    eq(snap.rowCount, 1, 'snapshot row written');
    // service-run recompute must resolve entitled apps (regression: apps unreadable by svc_billing)
    if (!JSON.stringify(snap.rows[0].entitlements.app_keys).includes('hifz-lms'))
      throw new Error('service recompute produced empty app_keys — apps not readable by svc_billing');
  }));

test('7  v_my_entitlements returns the current snapshot with entitled apps', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    const r = await c.query('select snapshot_version, billing_status, entitlements from app.v_my_entitlements');
    eq(r.rowCount, 1, 'one current snapshot');
    eq(r.rows[0].entitlements.plan_key, 'standard', 'plan_key');
    if (!JSON.stringify(r.rows[0].entitlements.app_keys).includes('hifz-lms')) throw new Error('hifz-lms not entitled');
  }));

test('8  entitlement_changes is append-only (no update)', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_ops') }, () =>
    expectError(() => c.query("update entitlement_changes set change_type='x'"), 'permission denied')));

test('9  no BYPASSRLS + force RLS on all group-3 tables', async (c) => {
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class where relname in
    ('plans','plan_app_entitlements','billing_customers','subscriptions','subscription_items','entitlement_snapshots','entitlement_changes')`);
  eq(f.rows[0].ok, true, 'force RLS on all group-3 tables');
});

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) {
  try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; }
  catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; }
}
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
