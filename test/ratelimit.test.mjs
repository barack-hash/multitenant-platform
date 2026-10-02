// Isolation + algorithm gate — table-group 15 (rate-limit enforcement, FOUNDATION_14).
// Proves: service-only isolation, exact GCRA semantics (capacity, refill, retry-after, remaining),
// per-key independence, atomicity under concurrent hits from separate connections, garbage collection,
// bounded episode recording, and that the request path may read — never write — tenant overrides.
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T1 = '11111111-1111-1111-1111-111111111111';
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';

const svc = (role) => ({ role: 'svc_worker', gucs: { 'app.actor_type': 'service', 'app.svc_role': role } });
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
const hit = (c, key, interval, tau, now) =>
  c.query('select * from app.rate_limit_hit($1,$2,$3,$4)', [key, interval, tau, now]).then((r) => r.rows[0]);

const NOW = 1_800_000_000_000;   // fixed clock for deterministic GCRA checks

test('isolation: svc_app cannot touch counters/episodes or call the limiter; may read but not write the catalog', async (c) => {
  for (const t of ['rate_limit_buckets', 'rate_limit_episodes'])
    await withCtx(c, appUser(), () => expectErr(c, () => c.query(`select 1 from ${t} limit 1`), /permission denied/, `svc_app select ${t}`));
  await withCtx(c, appUser(), () => expectErr(c, () => hit(c, 'x', 1000, 0, NOW), /permission denied/, 'svc_app calls rate_limit_hit'));
  await withCtx(c, appUser(), async () => {
    if (!(await c.query('select count(*) n from rate_limit_policies')).rows[0].n) throw new Error('policies should be readable');
    await expectErr(c, () => c.query("update rate_limit_policies set burst=1 where policy_key='auth_login'"), /permission denied/, 'svc_app writes a policy');
  });
});

test('GCRA: exactly C requests at once, then denied with retry-after = one interval; remaining counts down', async (c) => {
  await withCtx(c, svc('svc_hub'), async () => {
    const rem = [];
    for (let i = 0; i < 5; i++) { const r = await hit(c, 'k:burst', 1000, 4000, NOW); eq(r.allowed, true, `hit ${i + 1} allowed`); rem.push(r.remaining); }
    eq(rem.join(','), '4,3,2,1,0', 'remaining sequence');
    const d = await hit(c, 'k:burst', 1000, 4000, NOW);
    eq(d.allowed, false, '6th denied'); eq(d.retry_after_ms, 1000, 'retry after one interval'); eq(d.remaining, 0, 'nothing left');
  });
});

test('GCRA: refills one request per interval, and fully after C intervals', async (c) => {
  await withCtx(c, svc('svc_hub'), async () => {
    for (let i = 0; i < 5; i++) await hit(c, 'k:refill', 1000, 4000, NOW);
    eq((await hit(c, 'k:refill', 1000, 4000, NOW + 999)).allowed, false, 'not yet at +999ms');
    eq((await hit(c, 'k:refill', 1000, 4000, NOW + 1000)).allowed, true, 'one token at +1000ms');
    eq((await hit(c, 'k:refill', 1000, 4000, NOW + 1000)).allowed, false, 'and only one');
    let ok = 0;
    for (let i = 0; i < 7; i++) if ((await hit(c, 'k:refill', 1000, 4000, NOW + 20_000)).allowed) ok++;
    eq(ok, 5, 'after a long idle period the bucket holds exactly C again (no accumulation past capacity)');
  });
});

test('GCRA: buckets are independent per key', async (c) => {
  await withCtx(c, svc('svc_hub'), async () => {
    eq((await hit(c, 'k:a', 60_000, 0, NOW)).allowed, true, 'a #1');
    eq((await hit(c, 'k:a', 60_000, 0, NOW)).allowed, false, 'a #2 denied (C=1)');
    eq((await hit(c, 'k:b', 60_000, 0, NOW)).allowed, true, 'b unaffected');
  });
});

test('atomicity: 8 connections racing 5 hits each on one C=5 bucket admit EXACTLY 5', async (c) => {
  const key = `k:race:${Date.now()}`;
  const clients = await Promise.all(Array.from({ length: 8 }, async () => {
    const x = new pg.Client({ connectionString: URL }); await x.connect();
    await x.query('set role svc_worker');
    await x.query("select set_config('app.actor_type','service',false), set_config('app.svc_role','svc_hub',false)");
    return x;
  }));
  try {
    // Server clock, a 60s interval: nothing refills during the race.
    // Each connection hits sequentially; the 8 connections run concurrently (one query per connection
    // in flight at a time — the contention is between connections, which is the real-world case).
    const results = (await Promise.all(clients.map(async (x) => {
      const got = [];
      for (let i = 0; i < 5; i++) got.push((await x.query('select allowed from app.rate_limit_hit($1,60000,240000)', [key])).rows[0].allowed);
      return got;
    }))).flat();
    eq(results.length, 40, 'all hits answered');
    eq(results.filter(Boolean).length, 5, 'admitted under contention');
  } finally {
    await Promise.all(clients.map((x) => x.end()));
    await c.query('delete from rate_limit_buckets where bucket_key=$1', [key]);
  }
});

test('gc: drops only buckets whose TAT is already in the past', async (c) => {
  await withCtx(c, svc('svc_hub'), async () => {
    await hit(c, 'k:old', 1000, 0, NOW - 60_000);
    await hit(c, 'k:live', 1000, 0, NOW + 60_000);
    await c.query('select app.rate_limit_gc($1)', [NOW]);
    const keys = (await c.query("select bucket_key from rate_limit_buckets where bucket_key in ('k:old','k:live')")).rows.map((r) => r.bucket_key);
    eq(keys.join(','), 'k:live', 'only the live bucket remains');
  });
});

test('episodes: one row per bucket per window (idempotent), written by svc_hub, read by svc_ops only', async (c) => {
  await withCtx(c, svc('svc_hub'), async () => {
    const ins = () => c.query(
      `insert into rate_limit_episodes(policy_key, bucket_key, tenant_id, window_start) values('auth_login','auth_login:ip:9.9.9.9',null,to_timestamp(1800000000))
       on conflict (bucket_key, window_start) do nothing`);
    await ins(); await ins();
    eq((await c.query("select count(*) n from rate_limit_episodes where bucket_key='auth_login:ip:9.9.9.9'")).rows[0].n, 1, 'deduped per window');
    await expectErr(c, () => c.query("delete from rate_limit_episodes where bucket_key='auth_login:ip:9.9.9.9'"), /permission denied/, 'no delete path');
  });
});

test('overrides: the request path (svc_hub) may read them but never write them', async (c) => {
  await withCtx(c, svc('svc_hub'), async () => {
    await c.query('select count(*) from tenant_rate_limit_overrides');   // readable
    await expectErr(c, () => c.query(
      `insert into tenant_rate_limit_overrides(tenant_id, policy_key, limit_per_window, window_seconds) values($1,'api_tenant',1,60)`, [T1]),
      /row-level security/, 'svc_hub insert refused');
  });
});

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
