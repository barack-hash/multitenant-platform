// Isolation gate — proves the FOUNDATION_01 RLS model enforces tenant isolation.
// Connects as a superuser and simulates each request context with SET LOCAL ROLE + set_config GUCs.
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';

const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const U2 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const U3 = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const M3 = 'dddddddd-dddd-dddd-dddd-ddddddddddd3';
const ROLE_ADMIN = 'f0000000-0000-0000-0000-000000000001';

const userCtx = (tenant, actor, membership, perms = '', writes = 'true') => ({
  'app.tenant_id': tenant, 'app.actor_type': 'user', 'app.actor_id': actor,
  'app.membership_id': membership, 'app.permissions': perms, 'app.tenant_writes_allowed': writes,
});

async function withCtx(client, { role, gucs = {} }, fn) {
  await client.query('begin');
  try {
    if (role) await client.query(`set local role ${role}`);
    for (const [k, v] of Object.entries(gucs)) await client.query('select set_config($1,$2,true)', [k, v]);
    return await fn();
  } finally {
    await client.query('rollback').catch(() => {});
  }
}

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const eq = (a, b, msg) => { if (String(a) !== String(b)) throw new Error(`${msg}: expected ${b}, got ${a}`); };
async function expectError(fn, fragment) {
  try { await fn(); } catch (e) { if (fragment && !e.message.includes(fragment)) throw new Error(`wrong error: ${e.message}`); return; }
  throw new Error(`expected an error${fragment ? ` containing "${fragment}"` : ''}, but none was thrown`);
}

test('1  cross-tenant read denial (svc_app sees only its tenant)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1, 'memberships.read') }, async () => {
    const n = await c.query('select count(*)::int n from tenant_user_roles');
    eq(n.rows[0].n, 2, 'T1 role-assignment count');
    const t = await c.query('select count(*)::int n from tenant_user_roles where tenant_id=$1', [T2]);
    eq(t.rows[0].n, 0, 'T2 rows visible to a T1 actor');
  }));

test('2  missing-context fail-closed (no GUCs => zero rows, insert denied)', async (c) =>
  withCtx(c, { role: 'svc_app' }, async () => {
    const n = await c.query('select count(*)::int n from tenant_user_roles');
    eq(n.rows[0].n, 0, 'rows visible with empty context');
    await expectError(() => c.query(
      "insert into tenant_user_roles(tenant_id,membership_id,role_id) values($1,$2,$3)", [T1, M1, ROLE_ADMIN]), 'row-level security');
  }));

test('3a svc_app cannot read ungranted identity columns', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () =>
    expectError(() => c.query('select auth_subject from user_identities'), 'permission denied')));

test('3b svc_app identity read is limited to own row', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    const r = await c.query('select id from user_identities');
    eq(r.rowCount, 1, 'identity rows visible'); eq(r.rows[0].id, U1, 'visible identity');
  }));

test('4  GUC spoofing blocked (svc_app faking a service role cannot read all users)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: { 'app.actor_type': 'service', 'app.svc_role': 'svc_ops', 'app.actor_id': U1 } }, async () => {
    const r = await c.query('select count(*)::int n from user_identities');
    eq(r.rows[0].n, 1, 'spoofed-service svc_app user_identities visibility'); // own row only, not all 3
  }));

test('5  no BYPASSRLS + force RLS on every group-1 table', async (c) => {
  const b = await c.query("select count(*)::int n from pg_roles where rolbypassrls and rolname in ('svc_app','svc_worker','svc_migrate')");
  eq(b.rows[0].n, 0, 'runtime roles with BYPASSRLS');
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class
    where relname in ('tenants','user_identities','tenant_memberships','roles','permissions','role_permissions','tenant_user_roles')`);
  eq(f.rows[0].ok, true, 'force RLS on all group-1 tables');
});

test('6  mutation gating (tenant_writes_allowed=false blocks writes)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U3, M3, 'roles.assign', 'false') }, async () =>
    expectError(() => c.query('insert into tenant_user_roles(tenant_id,membership_id,role_id) values($1,$2,$3)', [T1, M1, ROLE_ADMIN]), 'row-level security')));

test('7a permission gating (no roles.assign => insert denied)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1, '') }, async () =>
    expectError(() => c.query('insert into tenant_user_roles(tenant_id,membership_id,role_id) values($1,$2,$3)', [T1, M1, ROLE_ADMIN]), 'row-level security')));

test('7b authorized write succeeds (admin with roles.assign)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U3, M3, 'roles.assign', 'true') }, async () => {
    const r = await c.query('insert into tenant_user_roles(tenant_id,membership_id,role_id) values($1,$2,$3) returning id', [T1, M1, ROLE_ADMIN]);
    eq(r.rowCount, 1, 'authorized insert rowcount');
  }));

test('8  pooler safety (SET LOCAL does not leak to next transaction)', async (c) => {
  await withCtx(c, { gucs: { 'app.tenant_id': T1 } }, async () => {});
  const r = await c.query("select coalesce(nullif(current_setting('app.tenant_id',true),''),'<unset>') v");
  eq(r.rows[0].v, '<unset>', 'leaked tenant context across transactions');
});

test('9  schema USAGE present (app.* helpers resolve for svc_app)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: { 'app.tenant_id': T1 } }, async () => {
    const r = await c.query('select app.current_tenant_id() t');
    eq(r.rows[0].t, T1, 'current_tenant_id via helper');
  }));

test('10 v_me projection (own row only, cross-user denied)', async (c) => {
  await withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    const r = await c.query('select user_id from app.v_me');
    eq(r.rowCount, 1, 'v_me rowcount for U1'); eq(r.rows[0].user_id, U1, 'v_me identity for U1');
  });
  await withCtx(c, { role: 'svc_app', gucs: userCtx(T2, U2, 'dddddddd-dddd-dddd-dddd-ddddddddddd2') }, async () => {
    const r = await c.query('select user_id from app.v_me');
    eq(r.rows[0].user_id, U2, 'v_me identity for U2');
  });
});

test('11 soft-delete invisibility (revoked membership not returned)', async (c) => {
  await c.query('begin');
  try {
    await c.query('update tenant_memberships set deleted_at=now() where id=$1', [M1]);
    await c.query('set local role svc_app');
    for (const [k, v] of Object.entries(userCtx(T1, U1, M1))) await c.query('select set_config($1,$2,true)', [k, v]);
    const r = await c.query('select count(*)::int n from app.v_my_memberships');
    eq(r.rows[0].n, 0, 'soft-deleted membership still visible');
  } finally { await c.query('rollback').catch(() => {}); }
});

test('12 tenant reassignment forbidden (trigger blocks UPDATE tenant_id)', async (c) => {
  await c.query('begin');
  try {
    await expectError(() => c.query('update tenant_memberships set tenant_id=$1 where id=$2', [T2, M1]), 'tenant_id reassignment is forbidden');
  } finally { await c.query('rollback').catch(() => {}); }
});

test('13 Postgres >= 15 (security_invoker views)', async (c) => {
  const r = await c.query("select (current_setting('server_version_num')::int >= 150000) ok");
  eq(r.rows[0].ok, true, 'postgres server_version_num >= 150000');
});

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) {
  try { await t.fn(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.name}`); pass++; }
  catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.name}\n        ${e.message}`); fail++; }
}
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
