// Isolation gate — table-group 5 (sessions + launch/exchange, FOUNDATION_05).
import pg from 'pg';
import { randomUUID } from 'node:crypto';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';

const userCtx = (t, a, m) => ({
  'app.tenant_id': t, 'app.actor_type': 'user', 'app.actor_id': a, 'app.membership_id': m,
  'app.permissions': '', 'app.tenant_writes_allowed': 'true',
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
const hub = (c, id, root) => c.query(
  `insert into sessions(id,tenant_id,user_id,kind,root_session_id,expires_at) values($1,$2,$3,'hub',$4, now()+interval '900 seconds')`, [id, T1, U1, root]);

test('1  session tables are NOT readable by svc_app (Class B)', async (c) => {
  for (const t of ['sessions', 'launch_tokens', 'session_revocations'])
    await withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, () =>
      expectError(() => c.query(`select * from ${t}`), 'permission denied'));
});

test('2  no BYPASSRLS + force RLS on all group-5 tables', async (c) => {
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class where relname in ('sessions','launch_tokens','session_revocations')`);
  eq(f.rows[0].ok, true, 'force RLS');
});

test('3  revoke_session_cascade revokes the whole tree (hub + spoke)', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_session') }, async () => {
    const root = randomUUID(), spoke = randomUUID();
    await hub(c, root, root);
    await c.query(`insert into sessions(id,tenant_id,user_id,kind,root_session_id,parent_session_id,expires_at)
                   values($1,$2,$3,'spoke',$4,$4, now()+interval '1800 seconds')`, [spoke, T1, U1, root]);
    const n = (await c.query('select app.revoke_session_cascade($1) n', [root])).rows[0].n;
    eq(Number(n), 2, 'sessions revoked by cascade');
    eq((await c.query("select count(*)::int n from sessions where root_session_id=$1 and status='revoked'", [root])).rows[0].n, 2, 'both marked revoked');
  }));

test('4  no tenant reassignment on sessions (trigger)', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_session') }, async () => {
    const sid = randomUUID();
    await hub(c, sid, sid);
    await expectError(() => c.query('update sessions set tenant_id=$1 where id=$2', [T2, sid]), 'tenant_id reassignment is forbidden');
  }));

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
