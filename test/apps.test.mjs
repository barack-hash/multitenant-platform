// Isolation gate — table-group 2 (app registry + tenant-app activation, FOUNDATION_02).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const U2 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const M2 = 'dddddddd-dddd-dddd-dddd-ddddddddddd2';
const APP_DIR = 'c1000000-0000-0000-0000-000000000002';
const TA_T1_HIFZ = 'c2000000-0000-0000-0000-000000000001';

const userCtx = (tenant, actor, membership, perms = '', writes = 'true') => ({
  'app.tenant_id': tenant, 'app.actor_type': 'user', 'app.actor_id': actor,
  'app.membership_id': membership, 'app.permissions': perms, 'app.tenant_writes_allowed': writes,
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

test('1  apps catalog is globally readable (Class C, tenant-independent)', async (c) => {
  const a = await withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, () => c.query('select count(*)::int n from apps'));
  eq(a.rows[0].n, 2, 'catalog count for T1 actor');
  const b = await withCtx(c, { role: 'svc_app', gucs: userCtx(T2, U2, M2) }, () => c.query('select count(*)::int n from apps'));
  eq(b.rows[0].n, 2, 'catalog count for T2 actor');
});

test('2  tenant_apps cross-tenant denial (T1 actor sees only T1 activations)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    const n = await c.query('select count(*)::int n from tenant_apps'); eq(n.rows[0].n, 2, 'T1 tenant_apps count');
    const t = await c.query('select count(*)::int n from tenant_apps where tenant_id=$1', [T2]); eq(t.rows[0].n, 0, 'T2 rows visible');
  }));

test('3  tenant_apps missing-context fail-closed', async (c) =>
  withCtx(c, { role: 'svc_app' }, async () => {
    const n = await c.query('select count(*)::int n from tenant_apps'); eq(n.rows[0].n, 0, 'rows with empty context');
  }));

test('4  svc_app cannot activate (write) tenant_apps directly', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, () =>
    expectError(() => c.query('insert into tenant_apps(tenant_id,app_id,status) values($1,$2,$3)', [T1, APP_DIR, 'active']), 'permission denied')));

test('5  service (svc_app_registry) can activate a tenant_app', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_app_registry') }, async () => {
    const r = await c.query('insert into tenant_apps(tenant_id,app_id,status) values($1,$2,$3) returning id', [T2, APP_DIR, 'active']);
    eq(r.rowCount, 1, 'service activation rowcount');
  }));

test('6  no BYPASSRLS + force RLS on apps, tenant_apps', async (c) => {
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class where relname in ('apps','tenant_apps')`);
  eq(f.rows[0].ok, true, 'force RLS');
});

test('7  v_my_apps launch-eligibility (active=>launchable, locked=>not)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    const r = await c.query('select app_key, launchable from app.v_my_apps order by app_key');
    eq(r.rowCount, 2, 'v_my_apps row count');
    const byKey = Object.fromEntries(r.rows.map((x) => [x.app_key, x.launchable]));
    eq(byKey['hifz-lms'], true, 'hifz launchable'); eq(byKey['directory'], false, 'locked app launchable');
  }));

test('8  tenant reassignment forbidden on tenant_apps (trigger)', async (c) => {
  await c.query('begin');
  try {
    await expectError(() => c.query('update tenant_apps set tenant_id=$1 where id=$2', [T2, TA_T1_HIFZ]), 'tenant_id reassignment is forbidden');
  } finally { await c.query('rollback').catch(() => {}); }
});

test('9  soft-delete invisibility (deactivated tenant_app not returned)', async (c) => {
  await c.query('begin');
  try {
    await c.query('update tenant_apps set deleted_at=now() where id=$1', [TA_T1_HIFZ]);
    await c.query('set local role svc_app');
    for (const [k, v] of Object.entries(userCtx(T1, U1, M1))) await c.query('select set_config($1,$2,true)', [k, v]);
    const r = await c.query('select count(*)::int n from app.v_my_apps');
    eq(r.rows[0].n, 1, 'apps visible after one soft-deleted'); // directory remains
  } finally { await c.query('rollback').catch(() => {}); }
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
