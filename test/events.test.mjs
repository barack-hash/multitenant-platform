// Isolation gate — table-group 4 (events + workers, FOUNDATION_04).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const T2 = '22222222-2222-2222-2222-222222222222';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const EVT = 'abcdef00-0000-0000-0000-000000000001';
const EVT2 = 'abcdef00-0000-0000-0000-000000000002';

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

test('1  domain_events tenant-scoped read (T1 sees only T1)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, async () => {
    if (!((await c.query('select count(*)::int n from domain_events')).rows[0].n >= 2)) throw new Error('T1 should see its seeded events');
    eq((await c.query('select count(*)::int n from domain_events where tenant_id=$1', [T2])).rows[0].n, 0, 'T2 events visible');
  }));

test('2  event infra is NOT readable by svc_app (Class B)', async (c) => {
  for (const t of ['outbox_events', 'inbox_events', 'consumer_checkpoints', 'dead_letter_events'])
    await withCtx(c, { role: 'svc_app', gucs: userCtx(T1, U1, M1) }, () =>
      expectError(() => c.query(`select * from ${t}`), 'permission denied'));
});

test('3  transactional outbox atomicity (emit + rollback => no event)', async (c) => {
  await withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_billing') }, async () => {
    await c.query("select app.emit_event('test.atomic', $1, '{}'::jsonb, 'test', 'atomic-key')", [T1]);
    eq((await c.query("select count(*)::int n from outbox_events where idempotency_key='atomic-key'")).rows[0].n, 1, 'present within tx');
  }); // rolls back
  const after = await c.query("select count(*)::int n from outbox_events where idempotency_key='atomic-key'");
  eq(after.rows[0].n, 0, 'outbox row survived rollback');
});

test('4  relay moves outbox -> domain_events (idempotent publish)', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_ops') }, async () => {
    const ev = (await c.query("select app.emit_event('test.relay', $1, '{}'::jsonb) id", [T1])).rows[0].id;
    const n = (await c.query('select app.relay_outbox(100) n')).rows[0].n;
    if (!(Number(n) >= 1)) throw new Error('relay should move >=1');
    eq((await c.query('select count(*)::int n from domain_events where id=$1', [ev])).rows[0].n, 1, 'event landed in domain_events');
  }));

test('5  consumer idempotency (try_consume twice => claim then skip)', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_events') }, async () => {
    eq((await c.query('select app.try_consume($1,$2,$3) ok', ['c1', EVT, T1])).rows[0].ok, true, 'first claim');
    eq((await c.query('select app.try_consume($1,$2,$3) ok', ['c1', EVT, T1])).rows[0].ok, false, 'duplicate skipped');
  }));

test('6  producer idempotency (duplicate idempotency_key rejected)', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_billing') }, async () => {
    await c.query("select app.emit_event('test.dup', $1, '{}'::jsonb, 'test', 'dup-key')", [T1]);
    await expectError(() => c.query("select app.emit_event('test.dup', $1, '{}'::jsonb, 'test', 'dup-key')", [T1]), 'duplicate key');
  }));

test('7  DLQ dedup + checkpoint upsert', async (c) =>
  withCtx(c, { role: 'svc_worker', gucs: svcCtx('svc_events') }, async () => {
    await c.query("select app.dead_letter('c1',$1,$2,'ERR','boom')", [EVT2, T1]);
    await c.query("select app.dead_letter('c1',$1,$2,'ERR','boom again')", [EVT2, T1]);
    eq((await c.query("select count(*)::int n from dead_letter_events where consumer_name='c1' and event_id=$1", [EVT2])).rows[0].n, 1, 'DLQ deduped');
    await c.query("select app.checkpoint_set('c1','part1',$1)", [EVT]);
    await c.query("select app.checkpoint_set('c1','part1',$1)", [EVT2]);
    eq((await c.query("select count(*)::int n from consumer_checkpoints where consumer_name='c1' and partition_key='part1'")).rows[0].n, 1, 'checkpoint upserted');
  }));

test('8  no BYPASSRLS + force RLS on all group-4 tables', async (c) => {
  const f = await c.query(`select bool_and(relforcerowsecurity) ok from pg_class where relname in
    ('domain_events','outbox_events','inbox_events','consumer_checkpoints','dead_letter_events')`);
  eq(f.rows[0].ok, true, 'force RLS on all group-4 tables');
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
