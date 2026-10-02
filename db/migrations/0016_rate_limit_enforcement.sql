-- 0016_rate_limit_enforcement.sql — table-group 15: rate-limit ENFORCEMENT (FOUNDATION_14).
-- Group 10 created the registries (rate_limit_policies, tenant_rate_limit_overrides); nothing enforced
-- them. This adds the Postgres limiter store (the default; DEPLOYMENT_ARCHITECTURE §3.3 names Redis/
-- Upstash for production, implemented in src/ratelimit.js behind the same interface) and a bounded
-- record of throttling episodes. Depends on 0000-0015.
--
-- Algorithm: GCRA (generic cell rate algorithm) — a token bucket stored as ONE number per key, the
-- "theoretical arrival time" (TAT). Emission interval T = window/limit; capacity C = limit + burst;
-- tolerance tau = T*(C-1). A request at `now` is allowed iff max(TAT, now) - now <= tau, and then
-- TAT := max(TAT, now) + T. So: C requests at once, then one per T, i.e. `limit` per window sustained.
-- One number per key is what makes the same algorithm a single atomic statement in Postgres and a
-- single Lua script in Redis.

-- Ephemeral counters. UNLOGGED: no WAL, fast, and truncated after a crash — losing rate-limit state on
-- a crash only ever errs toward ALLOWING traffic, which is the right direction for this table.
create unlogged table if not exists rate_limit_buckets (
  bucket_key text primary key,
  tat_ms     bigint not null,
  updated_at timestamptz not null default now()
);

-- Bounded evidence: at most ONE row per bucket per policy window, written on the first denial in that
-- window (the Hub also memoizes, so a flood of denials does not become a flood of writes).
create table if not exists rate_limit_episodes (
  id              uuid primary key default gen_random_uuid(),
  policy_key      text not null,
  bucket_key      text not null,
  tenant_id       uuid references tenants(id),
  window_start    timestamptz not null,
  first_denied_at timestamptz not null default now(),
  unique (bucket_key, window_start)
);
create index if not exists ix_rate_limit_episodes_recent on rate_limit_episodes (first_denied_at desc);

-- Overrides were insert-only history with no "current" marker; the newest per (tenant, policy) wins.
create index if not exists ix_rate_overrides_current on tenant_rate_limit_overrides (tenant_id, policy_key, created_at desc);

-- ============================= RLS =============================
-- Request path = hub-api (svc_hub); operator inspection/reset = svc_ops. svc_app has nothing.
alter table rate_limit_buckets enable row level security;
alter table rate_limit_buckets force  row level security;
create policy p_rate_limit_buckets_service on rate_limit_buckets
  for all using (app.assert_service_role(array['svc_hub','svc_ops']))
  with check (app.assert_service_role(array['svc_hub','svc_ops']));
revoke all on rate_limit_buckets from svc_app;
grant select, insert, update, delete on rate_limit_buckets to svc_worker;   -- delete = gc + operator reset

alter table rate_limit_episodes enable row level security;
alter table rate_limit_episodes force  row level security;
create policy p_rate_limit_episodes_insert on rate_limit_episodes
  for insert with check (app.assert_service_role(array['svc_hub']));
-- svc_hub must also pass SELECT for INSERT ... ON CONFLICT DO NOTHING (conflict arbitration — the
-- group-4 lesson); svc_ops reads for the console.
create policy p_rate_limit_episodes_select on rate_limit_episodes
  for select using (app.assert_service_role(array['svc_hub','svc_ops']));
revoke all on rate_limit_episodes from svc_app;
grant select, insert on rate_limit_episodes to svc_worker;

-- The request path resolves a tenant's effective limit, so svc_hub may READ overrides (never write them).
create policy p_rate_overrides_hub_read on tenant_rate_limit_overrides
  for select using (app.assert_service_role(array['svc_hub']));

-- ============================= the limiter =============================

-- One GCRA hit. Server time by default (clock_timestamp — so several Hub instances agree); p_now_ms
-- exists for deterministic tests and is only reachable by the worker pool.
create or replace function app.rate_limit_hit(p_key text, p_interval_ms bigint, p_tau_ms bigint, p_now_ms bigint default null)
returns table(allowed boolean, remaining integer, retry_after_ms bigint, reset_ms bigint)
language plpgsql as $$
declare
  v_now bigint := coalesce(p_now_ms, floor(extract(epoch from clock_timestamp()) * 1000)::bigint);
  v_tat bigint;
begin
  if p_interval_ms <= 0 or p_tau_ms < 0 then raise exception 'RATE_LIMIT_BAD_PARAMS' using errcode = 'P0001'; end if;
  insert into rate_limit_buckets(bucket_key, tat_ms) values (p_key, v_now) on conflict (bucket_key) do nothing;
  -- Row lock serializes concurrent hits on the same key (two Hub instances, one bucket).
  select b.tat_ms into v_tat from rate_limit_buckets b where b.bucket_key = p_key for update;
  v_tat := greatest(v_tat, v_now);
  if v_tat - v_now > p_tau_ms then
    return query select false, 0, v_tat - p_tau_ms - v_now, v_tat - v_now;
    return;
  end if;
  update rate_limit_buckets set tat_ms = v_tat + p_interval_ms, updated_at = now() where bucket_key = p_key;
  return query select true, floor((v_now + p_tau_ms - v_tat)::numeric / p_interval_ms)::int, 0::bigint, v_tat + p_interval_ms - v_now;
end$$;

-- A bucket whose TAT is in the past is indistinguishable from an absent one — drop those.
create or replace function app.rate_limit_gc(p_now_ms bigint default null)
returns integer language sql as $$
  with d as (
    delete from rate_limit_buckets
     where tat_ms < coalesce(p_now_ms, floor(extract(epoch from clock_timestamp()) * 1000)::bigint)
    returning 1)
  select count(*)::int from d;
$$;

revoke execute on function app.rate_limit_hit(text, bigint, bigint, bigint) from public;
revoke execute on function app.rate_limit_gc(bigint) from public;
grant execute on function app.rate_limit_hit(text, bigint, bigint, bigint) to svc_worker;
grant execute on function app.rate_limit_gc(bigint) to svc_worker;
