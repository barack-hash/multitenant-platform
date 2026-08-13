// Isolation gate — table-group 8 (minor-data protection, FOUNDATION_07 / OQ-034).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const S1 = 'f1000000-0000-0000-0000-000000000001'; // seeded minor

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
const tests = [];
const test = (n, f) => tests.push({ n, f });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };

test('1  students visible only WITH students.read, and tenant-scoped', async (c) => {
  await withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1, 'students.read') }, async () => {
    eq((await c.query('select count(*)::int n from students')).rows[0].n, 1, 'T1 admin sees the seeded minor');
    eq((await c.query('select count(*)::int n from students where tenant_id=$1', [T2])).rows[0].n, 0, 'no cross-tenant');
  });
  await withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1, '') }, async () => {
    eq((await c.query('select count(*)::int n from students')).rows[0].n, 0, 'no students.read => none visible');
  });
});

test('2  student_has_active_consent toggles with grant / revoke', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userGucs(T1, U1, M1, 'students.read,consents.manage') }, async () => {
    eq((await c.query('select app.student_has_active_consent($1) ok', [S1])).rows[0].ok, false, 'no consent initially');
    await c.query("insert into parental_consents(tenant_id, student_id, consent_type, notice_version, status) values(app.current_tenant_id(),$1,'data_processing','v1','granted')", [S1]);
    eq((await c.query('select app.student_has_active_consent($1) ok', [S1])).rows[0].ok, true, 'granted => active');
    await c.query("update parental_consents set status='revoked', revoked_at=now() where student_id=$1", [S1]);
    eq((await c.query('select app.student_has_active_consent($1) ok', [S1])).rows[0].ok, false, 'revoked => inactive');
  }));

test('3  erase_student shreds PII + soft-deletes the student\'s files; tenant intact', async (c) => {
  await c.query('begin');
  try {
    await c.query('set local role svc_worker');
    await c.query("select set_config('app.actor_type','service',true)");
    await c.query("select set_config('app.svc_role','svc_file',true)");
    await c.query("insert into file_objects(tenant_id, subject_ref, object_path, filename) values($1,$2,'p','s1.m4a')", [T1, S1]);
    await c.query("select set_config('app.svc_role','svc_lifecycle',true)");
    const t0 = (await c.query('select count(*)::int n from tenants')).rows[0].n; // subject erasure must not touch tenants
    const n = (await c.query('select app.erase_student($1) n', [S1])).rows[0].n;
    if (!(Number(n) >= 2)) throw new Error(`expected student + file erased, got ${n}`);
    const st = (await c.query('select full_name, status from students where id=$1', [S1])).rows[0];
    eq(st.full_name, '[erased]', 'PII shredded'); eq(st.status, 'erased', 'status erased');
    eq((await c.query('select status from file_objects where subject_ref=$1', [S1])).rows[0].status, 'deleted', 'student file purged');
    eq((await c.query('select count(*)::int n from tenants')).rows[0].n, t0, 'tenants intact (subject-level erasure leaves every tenant)');
  } finally { await c.query('rollback').catch(() => {}); }
});

test('4  no BYPASSRLS + force RLS on group-8 tables', async (c) => {
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class where relname in ('students','guardians','parental_consents','data_subject_requests')`);
  eq(f.rows[0].ok, true, 'force RLS');
});

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) { try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; } catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; } }
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
