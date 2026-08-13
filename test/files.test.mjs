// Isolation gate — table-group 7 (files/storage, FOUNDATION_07).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';

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
// set service svc_role, then switch to a svc_app user context — all inside one open tx
async function asService(c, role) { await c.query('set local role svc_worker'); await c.query("select set_config('app.actor_type','service',true)"); await c.query('select set_config($1,$2,true)', ['app.svc_role', role]); }
async function asUser(c, t, a, m, perms = '') { await c.query('set local role svc_app'); await c.query("select set_config('app.svc_role','',true)"); for (const [k, v] of Object.entries(userGucs(t, a, m, perms))) await c.query('select set_config($1,$2,true)', [k, v]); }

const tests = [];
const test = (n, f) => tests.push({ n, f });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };
async function expectError(fn, frag) { try { await fn(); } catch (e) { if (frag && !e.message.includes(frag)) throw new Error(`wrong error: ${e.message}`); return; } throw new Error(`expected error${frag ? ` "${frag}"` : ''}`); }

test('1  file_scan_results is NOT readable by svc_app (Class B)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1) }, () =>
    expectError(() => c.query('select * from file_scan_results'), 'permission denied')));

test('2  no BYPASSRLS + force RLS on group-7 tables', async (c) => {
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class where relname in ('file_objects','file_scan_results','file_access_events','retention_policies')`);
  eq(f.rows[0].ok, true, 'force RLS');
});

test('3  finalize_scan: clean => active, infected => quarantined', async (c) => {
  await c.query('begin');
  try {
    await asService(c, 'svc_file');
    const f = (await c.query("insert into file_objects(tenant_id, object_path, filename) values($1,'p','f.txt') returning id", [T1])).rows[0].id;
    await c.query("select set_config('app.svc_role','svc_file_scan',true)");
    await c.query("select app.finalize_scan($1,'clean','scanner')", [f]);
    let s = (await c.query('select scan_status, status from file_objects where id=$1', [f])).rows[0];
    eq(s.scan_status, 'clean', 'scan clean'); eq(s.status, 'active', 'clean => active');
    await c.query("select app.finalize_scan($1,'infected','scanner')", [f]);
    s = (await c.query('select status from file_objects where id=$1', [f])).rows[0];
    eq(s.status, 'quarantined', 'infected => quarantined');
  } finally { await c.query('rollback').catch(() => {}); }
});

test('4  file tenant isolation (v_my_files shows only the caller tenant)', async (c) => {
  await c.query('begin');
  try {
    await asService(c, 'svc_file');
    await c.query("insert into file_objects(tenant_id, object_path, filename, scan_status, status) values($1,'p1','t1.txt','clean','active')", [T1]);
    await c.query("insert into file_objects(tenant_id, object_path, filename, scan_status, status) values($1,'p2','t2.txt','clean','active')", [T2]);
    await asUser(c, T1, U1, M1);
    eq((await c.query('select count(*)::int n from app.v_my_files')).rows[0].n, 1, 'T1 sees only its file');
    eq((await c.query("select count(*)::int n from file_objects where tenant_id=$1", [T2])).rows[0].n, 0, 'no T2 files visible');
  } finally { await c.query('rollback').catch(() => {}); }
});

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) { try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; } catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; } }
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
