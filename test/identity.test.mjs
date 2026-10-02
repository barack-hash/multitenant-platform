// Identity-binding gate — table-group 16 (real Supabase authentication, FOUNDATION_15).
// Proves the binding rules are DATABASE invariants, not handler discipline: subject shapes, the
// invite -> supabase claim as the only legal transition (exactly once), no rebind of a bound identity
// (even by a service role), one open invitation per email, and svc_app has no write path.
import pg from 'pg';
const URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:55432/postgres';
const svc = (role) => ({ role: 'svc_worker', gucs: { 'app.actor_type': 'service', 'app.svc_role': role } });
async function withCtx(c, { role, gucs = {} }, fn) {
  await c.query('begin');
  try {
    if (role) await c.query(`set local role ${role}`);
    for (const [k, v] of Object.entries(gucs)) await c.query('select set_config($1,$2,true)', [k, v]);
    return await fn();
  } finally { await c.query('rollback').catch(() => {}); }
}
async function expectErr(c, fn, rx, m) {
  await c.query('savepoint sp'); let threw = null;
  try { await fn(); } catch (e) { threw = e; }
  await c.query('rollback to savepoint sp');
  if (!threw) throw new Error(`${m}: expected an error, got none`);
  if (rx && !rx.test(threw.message)) throw new Error(`${m}: wrong error: ${threw.message}`);
}
const tests = []; const test = (n, f) => tests.push({ n, f });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };
const SUB_A = '7a000000-0000-4000-8000-00000000000a', SUB_B = '7a000000-0000-4000-8000-00000000000b';
const invite = (c, email) => c.query(
  `insert into user_identities(auth_provider, auth_subject, primary_email) values('invite','invite:'||gen_random_uuid(),$1) returning id`, [email]).then((r) => r.rows[0].id);

test('shapes: a supabase subject must be a UUID; an invite must be invite:<uuid> and carry an email', async (c) => {
  await withCtx(c, svc('svc_identity'), async () => {
    await expectErr(c, () => c.query("insert into user_identities(auth_provider, auth_subject, primary_email) values('supabase','sub-x','x@e.example')"), /ck_identity_subject_shape/, 'non-uuid supabase subject');
    await expectErr(c, () => c.query("insert into user_identities(auth_provider, auth_subject, primary_email) values('github','x','x@e.example')"), /ck_identity_provider/, 'unknown provider');
    await expectErr(c, () => c.query("insert into user_identities(auth_provider, auth_subject) values('invite','invite:'||gen_random_uuid())"), /ck_identity_invite_email/, 'invite without email');
  });
});

test('claim: invite -> supabase is allowed exactly once', async (c) => {
  await withCtx(c, svc('svc_identity'), async () => {
    const id = await invite(c, 'claim@e.example');
    eq((await c.query("update user_identities set auth_provider='supabase', auth_subject=$2 where id=$1", [id, SUB_A])).rowCount, 1, 'claim');
    await expectErr(c, () => c.query("update user_identities set auth_subject=$2 where id=$1", [id, SUB_B]), /IDENTITY_REBIND_FORBIDDEN/, 'second claim / rebind');
  });
});

test('no rebind: a bound identity cannot be re-pointed — not even by a service role', async (c) => {
  await withCtx(c, svc('svc_identity'), async () => {
    await expectErr(c, () => c.query("update user_identities set auth_subject=$1 where primary_email='u1@example.com'", [SUB_B]), /IDENTITY_REBIND_FORBIDDEN/, 'rebind a seeded user');
    await expectErr(c, () => c.query("update user_identities set auth_provider='invite', auth_subject='invite:'||gen_random_uuid() where primary_email='u1@example.com'"), /IDENTITY_REBIND_FORBIDDEN/, 'downgrade to invite');
    eq((await c.query("update user_identities set display_name='Renamed' where primary_email='u1@example.com'")).rowCount, 1, 'non-binding fields still editable');
  });
  await withCtx(c, svc('svc_identity'), async () => {
    const id = await invite(c, 'weird@e.example');
    await expectErr(c, () => c.query("update user_identities set auth_subject='invite:'||gen_random_uuid() where id=$1", [id]), /IDENTITY_CLAIM_INVALID/, 'invite re-pointed at another invite');
  });
});

test('one live identity per email across providers (so a claim is never ambiguous)', async (c) => {
  await withCtx(c, svc('svc_identity'), async () => {
    await invite(c, 'dup@e.example');
    await expectErr(c, () => invite(c, 'dup@e.example'), /ux_user_identities_email/, 'second open invite');
    await expectErr(c, () => invite(c, 'DUP@e.example'), /ux_user_identities_email/, 'case-insensitive (citext)');
    await expectErr(c, () => invite(c, 'u1@example.com'), /ux_user_identities_email/, 'an invite beside a bound identity');
  });
});

test('isolation: svc_app has no write path to identities', async (c) => {
  await withCtx(c, { role: 'svc_app', gucs: { 'app.actor_type': 'user', 'app.actor_id': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } }, async () => {
    await expectErr(c, () => c.query("update user_identities set auth_subject='x' where primary_email='u1@example.com'"), /permission denied/, 'svc_app update');
    await expectErr(c, () => c.query("insert into user_identities(auth_provider, auth_subject, primary_email) values('invite','invite:'||gen_random_uuid(),'z@e.example')"), /permission denied/, 'svc_app insert');
  });
});

test('memberships: at most one LIVE membership per (tenant, user)', async (c) => {
  await withCtx(c, svc('svc_identity'), () => expectErr(c, () => c.query(
    `insert into tenant_memberships(tenant_id, user_id, status) values('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','invited')`),
    /ux_tenant_memberships_tenant_user/, 'second live membership'));
});

test('race: two concurrent invitations converge — B blocks on A, then returns A\u2019s membership', async () => {
  const T2 = '22222222-2222-2222-2222-222222222222', email = `race-${Date.now()}@e.example`;
  const conn = async () => {
    const x = new pg.Client({ connectionString: URL }); await x.connect();
    await x.query('set role svc_worker');
    await x.query("select set_config('app.actor_type','service',false), set_config('app.svc_role','svc_identity',false)");
    return x;
  };
  const A = await conn(), B = await conn();
  try {
    await A.query('begin');
    const a = (await A.query('select * from app.invite_to_tenant($1,$2,null)', [T2, email])).rows[0];   // uncommitted
    eq(a.created, true, 'A creates');
    await B.query('begin');
    let bDone = false;
    const bP = B.query('select * from app.invite_to_tenant($1,$2,null)', [T2, email]).then((r) => { bDone = true; return r.rows[0]; });
    await new Promise((r) => setTimeout(r, 400));
    eq(bDone, false, 'B is blocked on A\u2019s uncommitted identity row (it really is racing)');
    await A.query('commit');
    const b = await bP;
    await B.query('commit');
    eq(b.created, false, 'B did not create a second membership');
    eq(b.membership_id, a.membership_id, 'B converges on A\u2019s membership');
    eq(b.status, 'invited', 'status');
  } finally {
    await A.query('rollback').catch(() => {}); await B.query('rollback').catch(() => {});
    await A.end(); await B.end();
  }
});

const c = new pg.Client({ connectionString: URL }); await c.connect();
let pass = 0, fail = 0;
for (const t of tests) {
  try { await t.f(c); console.log(`  \x1b[32mPASS\x1b[0m  ${t.n}`); pass++; }
  catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  ${t.n}\n        ${e.message}`); fail++; }
}
await c.end();
console.log(`\n  ${pass} passed, ${fail} failed, ${tests.length} total`);
process.exit(fail ? 1 : 0);
