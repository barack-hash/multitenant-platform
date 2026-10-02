// Rate-limit enforcement (group 15, FOUNDATION_14): GCRA over a pluggable store.
//
// GCRA keeps ONE number per bucket — the theoretical arrival time (TAT). With T = window/limit and
// capacity C = limit + burst, a request is allowed iff max(TAT, now) - now <= T*(C-1), and then
// TAT := max(TAT, now) + T. That gives C requests at once, then `limit` per window sustained. Because
// the state is a single number, the algorithm is one atomic SQL function (Postgres store, the default)
// and one Lua script (Upstash/Redis store, DEPLOYMENT_ARCHITECTURE §3.3 for production) — the two
// stores implement the SAME contract: hit(key, intervalMs, tauMs) -> { allowed, remaining, retryAfterMs, resetMs }.
import { withServiceContext } from './db.js';

export function gcra(policy) {
  const limit = Number(policy.limit_per_window), windowMs = Number(policy.window_seconds) * 1000;
  const capacity = limit + Number(policy.burst || 0);
  const interval = Math.max(1, Math.round(windowMs / limit));
  return { interval, tau: interval * (capacity - 1), capacity };
}

const num = (r) => ({ allowed: r.allowed === true || r.allowed === 1 || r.allowed === '1',
  remaining: Number(r.remaining), retryAfterMs: Number(r.retry_after_ms), resetMs: Number(r.reset_ms) });

// ---- Postgres store (default; also the local/dev store) ----
export function postgresStore() {
  return {
    kind: 'postgres',
    hit: (key, interval, tau) => withServiceContext('svc_hub', (c) =>
      c.query('select * from app.rate_limit_hit($1,$2,$3)', [key, interval, tau])).then((r) => num(r.rows[0])),
    reset: (key) => withServiceContext('svc_ops', (c) =>
      c.query('delete from rate_limit_buckets where bucket_key=$1', [key])).then((r) => r.rowCount),
    gc: () => withServiceContext('svc_hub', (c) => c.query('select app.rate_limit_gc() n')).then((r) => r.rows[0].n),
  };
}

// ---- Upstash store (production per DEC-013) — the same GCRA as app.rate_limit_hit, in Lua. Uses the
// Redis server's clock (TIME) so several Hub instances agree, and a TTL so idle buckets expire themselves.
export const GCRA_LUA = `
local T = tonumber(ARGV[1])
local tau = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local tat = tonumber(redis.call('GET', KEYS[1])) or now
if tat < now then tat = now end
if tat - now > tau then return {0, 0, tat - tau - now, tat - now} end
local newtat = tat + T
redis.call('SET', KEYS[1], newtat, 'PX', newtat - now + 1000)
return {1, math.floor((now + tau - tat) / T), 0, newtat - now}
`;

export function upstashStore({ url, token, prefix = 'rl', fetchImpl = fetch }) {
  if (!url || !token) throw new Error('upstash store needs UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN');
  const call = async (command) => {
    const r = await fetchImpl(url, { method: 'POST', body: JSON.stringify(command),
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) throw new Error(`UPSTASH_ERROR: ${j.error || r.status}`);
    return j.result;
  };
  // The prefix carries the environment: DEPLOYMENT_ARCHITECTURE §2 wants a separate store per environment,
  // and the prefix keeps that true even if two environments are ever pointed at one database by mistake.
  const k = (key) => `${prefix}:${key}`;
  return {
    kind: 'upstash',
    hit: async (key, interval, tau) => {
      const [a, remaining, retry, reset] = await call(['EVAL', GCRA_LUA, '1', k(key), String(interval), String(tau)]);
      return num({ allowed: a, remaining, retry_after_ms: retry, reset_ms: reset });
    },
    reset: (key) => call(['DEL', k(key)]),
    gc: async () => 0,   // Redis expires idle buckets itself (PX)
  };
}

export function storeFromConfig(cfg) {
  return cfg.rateLimitStore === 'upstash'
    ? upstashStore({ url: cfg.upstashUrl, token: cfg.upstashToken, prefix: `rl:${cfg.platformEnv}` })
    : postgresStore();
}

// ---- the limiter: policy resolution (+ tenant overrides), multi-bucket checks, fail-open, episodes ----
export function createLimiter({ store, cacheMs = 10_000, clock = Date.now }) {
  let policies = null, policiesAt = 0;
  const overrides = new Map();          // `${tenant}|${policy}` -> { value, at }
  const episodes = new Set();           // `${bucket}|${windowStart}` already recorded by this process
  const stats = { allowed: 0, denied: 0, store_errors: 0, failed_open: 0, last_error: null, last_error_at: null };

  const loadPolicies = async () => {
    if (!policies || clock() - policiesAt > cacheMs) {
      const r = await withServiceContext('svc_hub', (c) => c.query(
        'select policy_key, scope, limit_per_window, window_seconds, burst from rate_limit_policies'));
      policies = new Map(r.rows.map((p) => [p.policy_key, p]));
      policiesAt = clock();
    }
    return policies;
  };
  // The newest override for (tenant, policy) wins; the table keeps the history.
  const overrideFor = async (tenant, policyKey) => {
    const ck = `${tenant}|${policyKey}`, hit = overrides.get(ck);
    if (hit && clock() - hit.at <= cacheMs) return hit.value;
    const r = await withServiceContext('svc_hub', (c) => c.query(
      `select limit_per_window, window_seconds from tenant_rate_limit_overrides
        where tenant_id=$1 and policy_key=$2 order by created_at desc, id desc limit 1`, [tenant, policyKey]));
    overrides.set(ck, { value: r.rows[0] || null, at: clock() });
    return r.rows[0] || null;
  };

  // Effective policy for a bucket: the catalog row, with limit/window replaced by a tenant override.
  const effective = async (policyKey, tenant) => {
    const base = (await loadPolicies()).get(policyKey);
    if (!base) return null;
    const ov = tenant ? await overrideFor(tenant, policyKey) : null;
    if (!ov) return { ...base, source: 'policy' };
    // Overrides carry no burst column. Inheriting the catalog burst would make a tight override
    // meaningless (3/min + a 300 burst), so burst scales with the overridden limit.
    const burst = Math.floor(Number(base.burst || 0) * ov.limit_per_window / Number(base.limit_per_window));
    return { ...base, limit_per_window: ov.limit_per_window, window_seconds: ov.window_seconds, burst, source: 'override' };
  };

  const recordEpisode = async (policy, bucket, tenant) => {
    const w = Number(policy.window_seconds);
    const windowStart = Math.floor(Date.now() / 1000 / w) * w;
    const mk = `${bucket}|${windowStart}`;
    if (episodes.has(mk)) return;
    if (episodes.size > 10_000) episodes.clear();
    episodes.add(mk);
    await withServiceContext('svc_hub', (c) => c.query(
      `insert into rate_limit_episodes(policy_key, bucket_key, tenant_id, window_start)
       values($1,$2,$3,to_timestamp($4)) on conflict (bucket_key, window_start) do nothing`,
      [policy.policy_key, bucket, tenant || null, windowStart])).catch(() => {});
  };

  // Check buckets in order (most specific first). Stops charging at the first denial. Returns the
  // decision plus the most constraining allowed bucket for the RateLimit-* headers.
  async function check(buckets) {
    let tightest = null;
    for (const b of buckets) {
      let policy;
      try { policy = await effective(b.policy, b.tenant); } catch (e) { return failOpen(e); }
      if (!policy) continue;                                   // unconfigured policy = unlimited
      const { interval, tau, capacity } = gcra(policy);
      let r;
      try { r = await store.hit(b.key, interval, tau); } catch (e) { return failOpen(e); }
      const d = { ...r, policy: policy.policy_key, source: policy.source, limit: capacity, bucket: b.key };
      if (!r.allowed) {
        stats.denied++;
        await recordEpisode(policy, b.key, b.tenant);
        return d;
      }
      if (!tightest || r.remaining < tightest.remaining) tightest = d;
    }
    stats.allowed++;
    return tightest || { allowed: true };
  }
  // A limiter outage must not become a platform outage: allow, but count it where operators can see it.
  function failOpen(e) {
    stats.store_errors++; stats.failed_open++;
    stats.last_error = String(e.message || e).slice(0, 200); stats.last_error_at = new Date().toISOString();
    return { allowed: true, failed_open: true };
  }

  return {
    check, effective,
    invalidate: () => { policies = null; overrides.clear(); },
    reset: (key) => store.reset(key),
    gc: () => store.gc(),
    status: () => ({ store: store.kind, cache_ms: cacheMs, ...stats }),
  };
}
