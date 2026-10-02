// Upstash store conformance — runs ONLY when real credentials are present (UPSTASH_REDIS_REST_URL +
// UPSTASH_REDIS_REST_TOKEN); otherwise it reports SKIP and exits 0. It runs the same GCRA contract the
// Postgres store is held to (test/ratelimit.test.mjs) against the Lua implementation over Upstash's REST
// protocol: capacity, denial + retry-after, remaining, key independence, and reset.
import { upstashStore } from '../src/ratelimit.js';

const url = process.env.UPSTASH_REDIS_REST_URL, token = process.env.UPSTASH_REDIS_REST_TOKEN;
if (!url || !token) {
  console.log('  \x1b[33mSKIP\x1b[0m  upstash conformance — set UPSTASH_REDIS_REST_URL/TOKEN to run against a real store');
  process.exit(0);
}
const store = upstashStore({ url, token, prefix: `rl:conformance:${Date.now()}` });
const eq = (a, b, m) => { if (String(a) !== String(b)) throw new Error(`${m}: expected ${b}, got ${a}`); };
const checks = [
  ['capacity C then denial with retry-after ≈ one interval', async () => {
    const rem = [];
    for (let i = 0; i < 5; i++) { const r = await store.hit('burst', 60_000, 240_000); eq(r.allowed, true, `hit ${i + 1}`); rem.push(r.remaining); }
    eq(rem.join(','), '4,3,2,1,0', 'remaining');
    const d = await store.hit('burst', 60_000, 240_000);
    eq(d.allowed, false, '6th denied');
    if (!(d.retryAfterMs > 59_000 && d.retryAfterMs <= 60_000)) throw new Error(`retry-after ${d.retryAfterMs}`);
  }],
  ['keys are independent', async () => {
    eq((await store.hit('a', 60_000, 0)).allowed, true, 'a1'); eq((await store.hit('a', 60_000, 0)).allowed, false, 'a2');
    eq((await store.hit('b', 60_000, 0)).allowed, true, 'b1');
  }],
  ['reset clears a bucket', async () => {
    await store.reset('a'); eq((await store.hit('a', 60_000, 0)).allowed, true, 'after reset');
  }],
  ['concurrent hits admit exactly C', async () => {
    const r = await Promise.all(Array.from({ length: 20 }, () => store.hit('race', 60_000, 240_000)));
    eq(r.filter((x) => x.allowed).length, 5, 'admitted');
  }],
];
let fail = 0;
for (const [n, f] of checks) {
  try { await f(); console.log(`  \x1b[32mPASS\x1b[0m  upstash: ${n}`); }
  catch (e) { console.log(`  \x1b[31mFAIL\x1b[0m  upstash: ${n}\n        ${e.message}`); fail++; }
}
for (const k of ['burst', 'a', 'b', 'race']) await store.reset(k).catch(() => {});
process.exit(fail ? 1 : 0);
