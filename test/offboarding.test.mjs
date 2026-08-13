// Isolation + state-machine gate — table-group 9 (TENANT-level offboarding lifecycle, FOUNDATION_08).
// Proves: service-only isolation, the canonical §13 phase DAG, legal-hold-blocks-purge, the retention
// gate, receipts-required-for-completion, and tombstone immutability (§6).
import pg from 'pg';

const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const T3 = '33333333-3333-3333-3333-333333333333';           // seeded lifecycle-demo tenant
const U1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const M1 = 'dddddddd-dddd-dddd-dddd-ddddddddddd1';
const POLICY = 'f3000000-0000-0000-0000-000000000003';       // offboarding-default (retention_days=0)

const svc = (role = 'svc_lifecycle') =>
  ({ role: 'svc_worker', gucs: { 'app.actor_type': 'service', 'app.svc_role': role } });
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
// Run fn expecting it to raise; use a SAVEPOINT so the OUTER tx survives the aborted statement and can
// continue (the memory's lesson: a raw error aborts the whole tx).
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

const OFFB_TABLES = ['tenant_offboarding_jobs', 'legal_holds', 'export_verification_receipts',
  'purge_jobs', 'purge_job_items', 'cache_purge_receipts', 'search_purge_receipts',
  'tenant_deletion_tombstones'];

const startJob = (c) => c.query(
  'insert into tenant_offboarding_jobs(tenant_id, retention_policy_id, reason, requested_by) values($1,$2,$3,$4) returning id',
  [T3, POLICY, 'test', U1]).then((r) => r.rows[0].id);
const adv = (c, job, to) => c.query('select app.advance_offboarding($1,$2,$3) p', [job, to, U1]).then((r) => r.rows[0].p);
const addExportReceipt = (c, job) => c.query(
  `insert into export_verification_receipts(tenant_id, offboarding_job_id, manifest_hash, signature_valid, checksum_valid, verified_by)
   values($1,$2,'deadbeef',true,true,'test')`, [T3, job]);

test('1  lifecycle internals are service-only; svc_app is denied; FORCE RLS on all 8 tables', async (c) => {
  // svc_app has NO grant on lifecycle internals (DEC-009) → privilege denied before RLS even runs.
  await withCtx(c, { role: 'svc_app', gucs: userGucs(T3, U1, M1) }, async () => {
    await expectErr(c, () => c.query('select * from tenant_offboarding_jobs'), /permission denied/, 'svc_app read denied');
    await expectErr(c, () => c.query('select * from tenant_deletion_tombstones'), /permission denied/, 'svc_app tombstone read denied');
  });
  const f = await c.query(
    `select bool_and(relforcerowsecurity) ok from pg_class where relname = any($1)`, [OFFB_TABLES]);
  eq(f.rows[0].ok, true, 'force RLS on every group-9 table');
  const cnt = await c.query(`select count(*)::int n from pg_class where relname = any($1) and relkind='r'`, [OFFB_TABLES]);
  eq(cnt.rows[0].n, 8, 'all 8 tables exist');
});

test('2  canonical progression requested→tombstoned enforces every gate; tenant status + tombstone follow', async (c) =>
  withCtx(c, svc('svc_lifecycle'), async () => {
    const job = await startJob(c);
    eq(await adv(c, job, 'approved'), 'approved', 'requested→approved');
    eq(await adv(c, job, 'freeze_started'), 'freeze_started', '→freeze_started');
    eq((await c.query('select status from tenants where id=$1', [T3])).rows[0].status, 'frozen', 'freeze sets tenant frozen');
    eq(await adv(c, job, 'freeze_completed'), 'freeze_completed', '→freeze_completed');
    eq(await adv(c, job, 'export_started'), 'export_started', '→export_started');
    eq((await c.query('select status from tenants where id=$1', [T3])).rows[0].status, 'suspended', 'export suspends tenant');
    // export_completed is blocked until a verified export receipt exists (§10).
    await expectErr(c, () => adv(c, job, 'export_completed'), /EXPORT_RECEIPT_REQUIRED/, 'no export receipt blocks');
    await addExportReceipt(c, job);
    eq(await adv(c, job, 'export_completed'), 'export_completed', '→export_completed after receipt');
    eq(await adv(c, job, 'retention_wait'), 'retention_wait', '→retention_wait');
    eq(await adv(c, job, 'purge_started'), 'purge_started', '→purge_started (retention_days=0)');
    eq((await c.query('select status from tenants where id=$1', [T3])).rows[0].status, 'offboarding', 'purge_started → offboarding');
    // purge_completed blocked until cache+search receipts also exist (§10/§15).
    await expectErr(c, () => adv(c, job, 'purge_completed'), /PURGE_RECEIPTS_REQUIRED/, 'missing purge receipts blocks completion');
    const pj = (await c.query('select app.execute_tenant_purge($1,$2) pj', [job, U1])).rows[0].pj;
    if (!pj) throw new Error('execute_tenant_purge returned no purge job');
    eq((await c.query('select count(*)::int n from cache_purge_receipts cpr join purge_jobs pjt on pjt.request_id=cpr.request_id where pjt.id=$1', [pj])).rows[0].n, 1, 'cache receipt written');
    eq((await c.query('select count(*)::int n from search_purge_receipts spr join purge_jobs pjt on pjt.request_id=spr.request_id where pjt.id=$1', [pj])).rows[0].n, 1, 'search receipt written');
    eq(await adv(c, job, 'purge_completed'), 'purge_completed', '→purge_completed with all receipts');
    eq(await adv(c, job, 'tombstoned'), 'tombstoned', '→tombstoned');
    eq((await c.query('select status, deleted_at is not null d from tenants where id=$1', [T3])).rows[0].status, 'deleted', 'tombstone deletes tenant');
    const tomb = (await c.query('select tenant_slug, offboarding_job_id from tenant_deletion_tombstones where tenant_id=$1', [T3])).rows[0];
    eq(tomb.tenant_slug, 'tenant-three', 'tombstone preserved the slug');
    eq(tomb.offboarding_job_id, job, 'tombstone links the job');
  }));

test('3  invalid transitions and terminal re-entry are rejected', async (c) =>
  withCtx(c, svc('svc_lifecycle'), async () => {
    const job = await startJob(c);
    await expectErr(c, () => adv(c, job, 'export_started'), /OFFBOARDING_INVALID_TRANSITION/, 'cannot skip to export');
    await expectErr(c, () => adv(c, job, 'purge_started'), /OFFBOARDING_INVALID_TRANSITION/, 'cannot skip to purge');
    eq(await adv(c, job, 'failed'), 'failed', 'requested→failed (abort) allowed');
    await expectErr(c, () => adv(c, job, 'approved'), /OFFBOARDING_TERMINAL/, 'failed is terminal');
  }));

test('4  an ACTIVE legal hold blocks purge_started; releasing it unblocks (§13)', async (c) =>
  withCtx(c, svc('svc_lifecycle'), async () => {
    const job = await startJob(c);
    for (const p of ['approved', 'freeze_started', 'freeze_completed', 'export_started']) await adv(c, job, p);
    await addExportReceipt(c, job);
    await adv(c, job, 'export_completed');
    await adv(c, job, 'retention_wait');
    const hold = (await c.query("insert into legal_holds(tenant_id, reason, placed_by) values($1,'litigation',$2) returning id", [T3, U1])).rows[0].id;
    eq((await c.query('select app.tenant_has_active_legal_hold($1) h', [T3])).rows[0].h, true, 'hold active');
    await expectErr(c, () => adv(c, job, 'purge_started'), /LEGAL_HOLD_ACTIVE/, 'active hold blocks purge');
    await c.query("update legal_holds set status='released', released_at=now() where id=$1", [hold]);
    eq(await adv(c, job, 'purge_started'), 'purge_started', 'released hold unblocks purge');
  }));

test('5  the retention window gates purge_started until scheduled_purge_after elapses (§15)', async (c) =>
  withCtx(c, svc('svc_lifecycle'), async () => {
    const job = await startJob(c);
    for (const p of ['approved', 'freeze_started', 'freeze_completed', 'export_started']) await adv(c, job, p);
    await addExportReceipt(c, job);
    await adv(c, job, 'export_completed');
    await adv(c, job, 'retention_wait');
    // Simulate a not-yet-elapsed retention window (a real policy would set this from retention_days).
    await c.query("update tenant_offboarding_jobs set scheduled_purge_after = now() + interval '1 day' where id=$1", [job]);
    await expectErr(c, () => adv(c, job, 'purge_started'), /RETENTION_NOT_ELAPSED/, 'future retention deadline blocks purge');
    await c.query("update tenant_offboarding_jobs set scheduled_purge_after = now() - interval '1 second' where id=$1", [job]);
    eq(await adv(c, job, 'purge_started'), 'purge_started', 'elapsed deadline allows purge');
  }));

test('6  tombstones are immutable — no update/delete path (§6)', async (c) =>
  withCtx(c, svc('svc_lifecycle'), async () => {
    await c.query(
      "insert into tenant_deletion_tombstones(tenant_id, tenant_slug, reason) values($1,'tenant-three','t')", [T3]);
    await expectErr(c, () => c.query('delete from tenant_deletion_tombstones where tenant_id=$1', [T3]), /permission denied/, 'no delete on tombstones');
    await expectErr(c, () => c.query("update tenant_deletion_tombstones set reason='x' where tenant_id=$1", [T3]), /permission denied/, 'no update on tombstones');
  }));

test('8  a job with NO retention policy cannot schedule a purge (§15 — no zero-retention bypass)', async (c) =>
  withCtx(c, svc('svc_lifecycle'), async () => {
    const job = (await c.query(
      'insert into tenant_offboarding_jobs(tenant_id, reason, requested_by) values($1,$2,$3) returning id',
      [T3, 'no-policy', U1])).rows[0].id;
    for (const p of ['approved', 'freeze_started', 'freeze_completed', 'export_started']) await adv(c, job, p);
    await addExportReceipt(c, job);
    await adv(c, job, 'export_completed');
    await expectErr(c, () => adv(c, job, 'retention_wait'), /RETENTION_POLICY_REQUIRED/, 'null policy must block retention scheduling');
  }));

test('7  svc_app cannot invoke the purge/advance functions (service-role bound)', async (c) =>
  withCtx(c, { role: 'svc_app', gucs: { ...userGucs(T3, U1, M1), 'app.svc_role': 'svc_lifecycle' } }, async () => {
    const job = '00000000-0000-0000-0000-0000000000ff';
    // Even with a spoofed svc_role GUC, svc_app fails: writes hit the service policy it can't satisfy
    // (current_user must be svc_worker), so the INSERT inside the function is denied.
    await expectErr(c, () => c.query('select app.advance_offboarding($1,$2,$3)', [job, 'approved', U1]),
      /permission denied|OFFBOARDING_JOB_NOT_FOUND|row-level security/, 'svc_app cannot drive lifecycle');
  }));

const client = new pg.Client({ connectionString: URL });
await client.connect();
let pass = 0, fail = 0;
for (const t of tests) { try { await t.f(client); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; } catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; } }
await client.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
