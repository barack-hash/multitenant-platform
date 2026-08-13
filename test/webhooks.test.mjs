// Isolation gate — table-group 6 (billing webhooks, FOUNDATION_06).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const APP_HIFZ = 'c1000000-0000-0000-0000-000000000001';

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

test('1  webhook_receipts + billing_events NOT readable by svc_app (Class B)', async (c) => {
  for (const t of ['webhook_receipts', 'billing_events'])
    await withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, () =>
      expectError(() => c.query(`select * from ${t}`), 'permission denied'));
});

test('2  no BYPASSRLS + force RLS on group-6 tables', async (c) => {
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class where relname in ('webhook_receipts','billing_events')`);
  eq(f.rows[0].ok, true, 'force RLS');
});

test('3  no tenant reassignment on billing_events (trigger)', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_billing') }, async () => {
    const r = await c.query(
      `insert into billing_events(tenant_id, provider, provider_event_id, event_type, occurred_at, watermark, payload)
       values($1,'stripe','evt_iso','test', now(), 1, '{}'::jsonb) returning id`, [T1]);
    await expectError(() => c.query('update billing_events set tenant_id=$1 where id=$2', [T2, r.rows[0].id]), 'tenant_id reassignment is forbidden');
  }));

test('4  apply_billing_lock locks/unlocks entitled apps by billing status', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_billing') }, async () => {
    await c.query("select app.apply_billing_lock($1,'past_due')", [T1]);
    eq((await c.query('select status from tenant_apps where tenant_id=$1 and app_id=$2', [T1, APP_HIFZ])).rows[0].status, 'locked', 'past_due locks hifz');
    await c.query("select app.apply_billing_lock($1,'active')", [T1]);
    eq((await c.query('select status from tenant_apps where tenant_id=$1 and app_id=$2', [T1, APP_HIFZ])).rows[0].status, 'active', 'active re-enables hifz');
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
