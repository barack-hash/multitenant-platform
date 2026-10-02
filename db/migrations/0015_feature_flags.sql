-- 0015_feature_flags.sql — table-group 14: feature-flag governance (MASTER_PLAN §11, FOUNDATION_13).
-- Builds the four flag tables whose DDL is authoritative in DATABASE_SCHEMA_FINAL §3, plus the §11
-- deterministic resolver and a decision log. Depends on 0000-0014.
--
-- §11 precedence: 1 global kill switch · 2 tenant_app · 3 tenant · 4 app · 5 cohort · 6 environment
-- default. Conflict resolution: active + in-window rules only; lower numeric priority wins inside a
-- tier; tie-breaker newest created_at (then id, so the result is total and therefore deterministic);
-- the final rule decision is logged.
--
-- Deviations from the §3 DDL (each closes a gap the §3 text leaves open — see FOUNDATION_13):
--   D1 `feature_flag_audit_events.flag_id` has NO `on delete cascade`. §6 says feature_flag_audit_events
--      is never hard-deleted; a cascade from a definition delete would silently do exactly that. There
--      is also no DELETE grant on any flag table: flags are retired by status ('archived'/'ended').
--   D2 §3 rollouts have no 'global' target, yet §11 tier 1 is a global kill switch. The kill switch is
--      modelled per (flag, environment) on feature_flag_environments (kill_engaged + who/why/when), and
--      serves the definition's new `off_value` — so engaging it can only ever turn a flag OFF, never
--      force a value on for every tenant.
--   D3 `off_value` + `variants` on definitions give every value a type to be validated against
--      (boolean/kill_switch -> JSON boolean; multivariate -> one of the declared variant strings).
--   D4 a `feature_flag_decision_log` table records the §11 "final rule decision" (Class D).
--
-- Ownership (MASTER_PLAN §3 service map): config is owned by platform-ops-service -> svc_ops. Tenant
-- request-path evaluation runs as hub-api -> svc_hub, which may READ config and APPEND decisions and
-- nothing else. svc_app has no grant on any of these tables (DEC-009) — tenants receive only resolved
-- values from the Hub, never rules or targets (DEC-010 / OQ-017: no tenant flag projection approved).

-- ============================= helpers =============================

-- A value is valid for a flag iff it matches the flag's declared type.
create or replace function app.flag_value_valid(p_type text, p_variants text[], p_value jsonb)
returns boolean language sql immutable as $$
  select case
    when p_value is null then false
    when p_type = 'multivariate' then jsonb_typeof(p_value) = 'string' and (p_value #>> '{}') = any(p_variants)
    else jsonb_typeof(p_value) = 'boolean'
  end;
$$;

-- Deterministic 0..99 bucket for percentage cohorts. md5 (not hashtext) so the bucket is stable across
-- Postgres versions; the flag key is mixed in so one tenant is not in the low bucket of every flag.
create or replace function app.flag_bucket(p_flag_key text, p_tenant uuid)
returns integer language sql immutable as $$
  select ((('x' || substr(md5(p_flag_key || ':' || p_tenant::text), 1, 8))::bit(32)::bigint) % 100)::int;
$$;

-- ============================= DDL =============================

create table if not exists feature_flag_definitions (
  id          uuid primary key default gen_random_uuid(),
  flag_key    text not null unique check (flag_key ~ '^[a-z][a-z0-9_.-]{1,62}$'),
  description text not null,
  flag_type   text not null check (flag_type in ('boolean','multivariate','kill_switch')),
  owner_team  text not null,
  risk_level  text not null check (risk_level in ('low','medium','high')),
  status      text not null default 'active' check (status in ('active','paused','archived')),
  variants    text[],                                   -- D3: multivariate only
  off_value   jsonb not null,                           -- D2/D3: served when killed / paused / archived
  created_at  timestamptz not null default now(),
  archived_at timestamptz,
  constraint ck_ff_variants check ((flag_type = 'multivariate') = (variants is not null and cardinality(variants) > 0)),
  constraint ck_ff_off_value check (app.flag_value_valid(flag_type, variants, off_value)),
  constraint ck_ff_archived check ((status = 'archived') = (archived_at is not null))
);

create table if not exists feature_flag_environments (
  id            uuid primary key default gen_random_uuid(),
  flag_id       uuid not null references feature_flag_definitions(id),
  environment   text not null check (environment in ('dev','staging','prod')),
  default_value jsonb not null,
  kill_engaged  boolean not null default false,          -- D2: §11 tier 1
  kill_reason   text,
  killed_by     uuid,
  killed_at     timestamptz,
  updated_by    uuid not null,
  updated_at    timestamptz not null default now(),
  unique (flag_id, environment),
  constraint ck_ff_kill_attributed check (not kill_engaged or (kill_reason is not null and killed_by is not null and killed_at is not null))
);

create table if not exists feature_flag_rollouts (
  id          uuid primary key default gen_random_uuid(),
  flag_id     uuid not null references feature_flag_definitions(id),
  environment text not null check (environment in ('dev','staging','prod')),
  target_type text not null check (target_type in ('tenant','app','tenant_app','cohort')),
  target_ref  text not null,      -- tenant: <tenant uuid> · app: <app_key> · tenant_app: <uuid>:<app_key> · cohort: pct:<0-100>
  value       jsonb not null,
  priority    integer not null default 100 check (priority >= 0),
  start_at    timestamptz,
  end_at      timestamptz,
  status      text not null check (status in ('scheduled','active','paused','ended')),
  created_by  uuid not null,
  created_at  timestamptz not null default now(),
  constraint ck_ff_window check (start_at is null or end_at is null or end_at > start_at)
);
create index if not exists ix_feature_flag_rollouts_lookup
  on feature_flag_rollouts (flag_id, environment, status, priority asc);
create index if not exists ix_feature_flag_rollouts_target
  on feature_flag_rollouts (target_type, target_ref);

-- Configuration history (§6: never hard-deleted). Written ONLY by the DB trigger below, so no change to
-- a flag can escape it. D1: no cascade.
create table if not exists feature_flag_audit_events (
  id           uuid primary key default gen_random_uuid(),
  flag_id      uuid not null references feature_flag_definitions(id),
  action       text not null,
  environment  text,
  before_value jsonb,
  after_value  jsonb,
  actor_id     uuid not null,
  -- clock_timestamp, not now(): several rows are written in one transaction (flag + its 3 environments)
  -- and the history must show them in the order they actually happened.
  occurred_at  timestamptz not null default clock_timestamp()
);
create index if not exists ix_ff_audit_flag on feature_flag_audit_events (flag_id, occurred_at desc);

-- D4: the §11 "final rule decision". One row per DISTINCT decision per subject (a repeat evaluation that
-- reaches the same rule + value is not re-logged; any change — including flipping back — is).
create table if not exists feature_flag_decision_log (
  seq          bigint generated always as identity primary key,
  flag_id      uuid not null references feature_flag_definitions(id),
  environment  text not null,
  tenant_id    uuid not null references tenants(id),
  app_key      text,
  value        jsonb not null,
  tier         text not null,
  rule_id      uuid,
  reason       text not null,
  fingerprint  text not null,
  decided_at   timestamptz not null default now()
);
create index if not exists ix_ff_decisions_subject
  on feature_flag_decision_log (flag_id, environment, tenant_id, app_key, seq desc);

-- ============================= integrity triggers =============================

-- Attribution: every config mutation must name its operator (set_config('app.flag_actor', ...) in the
-- same transaction). An unattributed change is refused rather than recorded with a placeholder actor.
create or replace function app.flag_actor()
returns uuid language plpgsql stable as $$
declare v text := nullif(current_setting('app.flag_actor', true), '');
begin
  if v is null then raise exception 'FLAG_ACTOR_REQUIRED: set app.flag_actor before changing a flag' using errcode = 'P0001'; end if;
  return v::uuid;
end$$;

-- Definitions: identity/type are immutable (changing the type would invalidate every stored value);
-- archived is terminal.
create or replace function app.ff_definitions_guard()
returns trigger language plpgsql as $$
begin
  if new.flag_key is distinct from old.flag_key or new.flag_type is distinct from old.flag_type
     or new.variants is distinct from old.variants or new.id is distinct from old.id then
    raise exception 'FLAG_IMMUTABLE_FIELD: flag_key/flag_type/variants cannot change' using errcode = 'P0001';
  end if;
  if old.status = 'archived' and new.status <> 'archived' then
    raise exception 'FLAG_ARCHIVED: an archived flag cannot be reactivated' using errcode = 'P0001';
  end if;
  return new;
end$$;
create trigger trg_ff_definitions_guard before update on feature_flag_definitions
  for each row execute function app.ff_definitions_guard();

-- Environment rows: value typed against the flag; (flag, environment) identity immutable.
create or replace function app.ff_environments_guard()
returns trigger language plpgsql as $$
declare d record;
begin
  if tg_op = 'UPDATE' and (new.flag_id is distinct from old.flag_id or new.environment is distinct from old.environment) then
    raise exception 'FLAG_IMMUTABLE_FIELD: an environment row cannot be re-pointed' using errcode = 'P0001';
  end if;
  select flag_type, variants into d from feature_flag_definitions where id = new.flag_id;
  if not app.flag_value_valid(d.flag_type, d.variants, new.default_value) then
    raise exception 'FLAG_VALUE_INVALID: default_value % is not a valid % value', new.default_value, d.flag_type using errcode = 'P0001';
  end if;
  return new;
end$$;
create trigger trg_ff_environments_guard before insert or update on feature_flag_environments
  for each row execute function app.ff_environments_guard();

-- Rollouts: typed value, a target that actually exists, and append-mostly — once written, only status
-- (and end_at) may change, and 'ended' is terminal. To change a rule you end it and create a new one,
-- so the history of what was served stays reconstructible from the audit log.
create or replace function app.ff_rollouts_guard()
returns trigger language plpgsql as $$
declare d record; v_tenant text; v_app text;
begin
  if tg_op = 'UPDATE' then
    if new.flag_id is distinct from old.flag_id or new.environment is distinct from old.environment
       or new.target_type is distinct from old.target_type or new.target_ref is distinct from old.target_ref
       or new.value is distinct from old.value or new.priority is distinct from old.priority
       or new.start_at is distinct from old.start_at or new.created_at is distinct from old.created_at
       or new.created_by is distinct from old.created_by then
      raise exception 'FLAG_RULE_IMMUTABLE: only status/end_at may change — end this rule and create a new one' using errcode = 'P0001';
    end if;
    if old.status = 'ended' and new.status <> 'ended' then
      raise exception 'FLAG_RULE_TERMINAL: an ended rule cannot be revived' using errcode = 'P0001';
    end if;
    return new;
  end if;

  select flag_type, variants, status into d from feature_flag_definitions where id = new.flag_id;
  if d.status = 'archived' then
    raise exception 'FLAG_ARCHIVED: cannot add a rule to an archived flag' using errcode = 'P0001';
  end if;
  if not app.flag_value_valid(d.flag_type, d.variants, new.value) then
    raise exception 'FLAG_VALUE_INVALID: value % is not a valid % value', new.value, d.flag_type using errcode = 'P0001';
  end if;

  if new.target_type = 'cohort' then
    if new.target_ref !~ '^pct:(100|[1-9]?[0-9])$' then
      raise exception 'FLAG_TARGET_INVALID: cohort target must be pct:<0-100>' using errcode = 'P0001';
    end if;
  else
    if new.target_type = 'tenant' then v_tenant := new.target_ref;
    elsif new.target_type = 'app' then v_app := new.target_ref;
    else v_tenant := split_part(new.target_ref, ':', 1); v_app := substr(new.target_ref, length(v_tenant) + 2);
    end if;
    if v_tenant is not null and (v_tenant !~ '^[0-9a-f-]{36}$'
        or not exists (select 1 from tenants where id = v_tenant::uuid and deleted_at is null)) then
      raise exception 'FLAG_TARGET_INVALID: no live tenant %', v_tenant using errcode = 'P0001';
    end if;
    if v_app is not null and not exists (select 1 from apps where app_key = v_app) then
      raise exception 'FLAG_TARGET_INVALID: no app %', v_app using errcode = 'P0001';
    end if;
  end if;
  return new;
end$$;
create trigger trg_ff_rollouts_guard before insert or update on feature_flag_rollouts
  for each row execute function app.ff_rollouts_guard();

-- The audit writer. AFTER trigger on all three config tables, so the history cannot be bypassed by any
-- code path — including a future endpoint that forgets to log.
create or replace function app.ff_audit()
returns trigger language plpgsql as $$
declare v_action text; v_flag uuid; v_env text;
begin
  if tg_table_name = 'feature_flag_definitions' then
    v_flag := new.id;
    v_action := case when tg_op = 'INSERT' then 'flag.created'
                     when new.status is distinct from old.status then 'flag.status.' || new.status
                     else 'flag.updated' end;
  elsif tg_table_name = 'feature_flag_environments' then
    v_flag := new.flag_id; v_env := new.environment;
    v_action := case when tg_op = 'INSERT' then 'environment.created'
                     when new.kill_engaged and not old.kill_engaged then 'kill_switch.engaged'
                     when old.kill_engaged and not new.kill_engaged then 'kill_switch.released'
                     else 'environment.default_changed' end;
  else
    v_flag := new.flag_id; v_env := new.environment;
    v_action := case when tg_op = 'INSERT' then 'rule.created' else 'rule.status.' || new.status end;
  end if;
  insert into feature_flag_audit_events(flag_id, action, environment, before_value, after_value, actor_id)
  values (v_flag, v_action, v_env,
          case when tg_op = 'UPDATE' then to_jsonb(old) end, to_jsonb(new), app.flag_actor());
  return null;
end$$;
create trigger trg_ff_definitions_audit after insert or update on feature_flag_definitions
  for each row execute function app.ff_audit();
create trigger trg_ff_environments_audit after insert or update on feature_flag_environments
  for each row execute function app.ff_audit();
create trigger trg_ff_rollouts_audit after insert or update on feature_flag_rollouts
  for each row execute function app.ff_audit();

-- Append-only evidence (§6 for the audit table; Class D for the decision log): refuse update/delete/
-- truncate even from the table owner or a buggy path.
create or replace function app.ff_forbid_mutation()
returns trigger language plpgsql as $$
begin
  raise exception '% is append-only (§6): % denied', tg_table_name, tg_op;
end$$;
create trigger trg_ff_audit_immutable before update or delete on feature_flag_audit_events
  for each row execute function app.ff_forbid_mutation();
create trigger trg_ff_audit_no_truncate before truncate on feature_flag_audit_events
  for each statement execute function app.ff_forbid_mutation();
create trigger trg_ff_decisions_immutable before update or delete on feature_flag_decision_log
  for each row execute function app.ff_forbid_mutation();
create trigger trg_ff_decisions_no_truncate before truncate on feature_flag_decision_log
  for each statement execute function app.ff_forbid_mutation();

-- ============================= RLS =============================
-- Config: svc_ops owns (all); svc_hub may only SELECT (evaluation). Evidence: insert+select only.

do $$
declare t text;
begin
  foreach t in array array['feature_flag_definitions','feature_flag_environments','feature_flag_rollouts'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_ops on %1$s
      for all using (app.assert_service_role(array['svc_ops']))
      with check (app.assert_service_role(array['svc_ops']));$p$, t);
    execute format($p$create policy p_%1$s_hub_read on %1$s
      for select using (app.assert_service_role(array['svc_hub']));$p$, t);
    execute format('revoke all on %I from svc_app;', t);
    execute format('grant select, insert, update on %I to svc_worker;', t);   -- no DELETE: retire by status
  end loop;
end$$;

alter table feature_flag_audit_events enable row level security;
alter table feature_flag_audit_events force  row level security;
create policy p_ff_audit_insert on feature_flag_audit_events
  for insert with check (app.assert_service_role(array['svc_ops']));
create policy p_ff_audit_select on feature_flag_audit_events
  for select using (app.assert_service_role(array['svc_ops','svc_audit']));
revoke all on feature_flag_audit_events from svc_app;
grant select, insert on feature_flag_audit_events to svc_worker;

alter table feature_flag_decision_log enable row level security;
alter table feature_flag_decision_log force  row level security;
create policy p_ff_decisions_insert on feature_flag_decision_log
  for insert with check (app.assert_service_role(array['svc_hub','svc_ops']));
-- svc_hub reads back only to compare against the subject's latest fingerprint (dedupe).
create policy p_ff_decisions_select on feature_flag_decision_log
  for select using (app.assert_service_role(array['svc_hub','svc_ops','svc_audit']));
revoke all on feature_flag_decision_log from svc_app;
grant select, insert on feature_flag_decision_log to svc_worker;

-- ============================= the §11 resolver =============================

-- Every rule for (flag, environment) annotated with WHY it is or isn't eligible for this subject. The
-- resolver and the operator "explain" view share this one predicate, so they cannot drift apart.
create or replace function app.flag_candidates(p_flag uuid, p_env text, p_tenant uuid, p_app_key text)
returns table(rule_id uuid, target_type text, target_ref text, value jsonb, priority integer,
              created_at timestamptz, status text, start_at timestamptz, end_at timestamptz,
              tier_rank integer, eligible boolean, skip_reason text)
language sql stable as $$
  with r as (
    select ro.*, d.flag_key,
           case ro.target_type when 'tenant_app' then 2 when 'tenant' then 3 when 'app' then 4 else 5 end as rank_,
           case ro.target_type
             when 'tenant_app' then p_app_key is not null and ro.target_ref = p_tenant::text || ':' || p_app_key
             when 'tenant'     then ro.target_ref = p_tenant::text
             when 'app'        then p_app_key is not null and ro.target_ref = p_app_key
             else app.flag_bucket(d.flag_key, p_tenant) < split_part(ro.target_ref, ':', 2)::int
           end as matches,
           (ro.start_at is null or ro.start_at <= now()) and (ro.end_at is null or now() < ro.end_at) as in_window
      from feature_flag_rollouts ro join feature_flag_definitions d on d.id = ro.flag_id
     where ro.flag_id = p_flag and ro.environment = p_env
  )
  select r.id, r.target_type, r.target_ref, r.value, r.priority, r.created_at, r.status, r.start_at, r.end_at,
         r.rank_, (r.status = 'active' and r.in_window and r.matches),
         case when r.status <> 'active' then 'status_' || r.status
              when not r.in_window then 'outside_window'
              when not r.matches then 'target_mismatch' end
    from r
   order by r.rank_, r.priority asc, r.created_at desc, r.id desc;
$$;

-- Resolve one flag for one subject. Returns the value plus the decision (tier, rule, reason) and, when
-- p_log, appends it to the decision log iff it differs from the subject's last logged decision.
create or replace function app.evaluate_flag(p_flag_key text, p_env text, p_tenant uuid,
                                             p_app_key text default null, p_log boolean default true)
returns table(flag_key text, value jsonb, tier text, rule_id uuid, reason text, fingerprint text)
language plpgsql as $$
declare d record; e record; c record; v_value jsonb; v_tier text; v_rule uuid; v_reason text;
        v_fp text; v_last text; v_has_env boolean; v_has_rule boolean;
begin
  if p_env not in ('dev','staging','prod') then
    raise exception 'FLAG_BAD_ENVIRONMENT: %', p_env using errcode = 'P0001';
  end if;
  select * into d from feature_flag_definitions fd where fd.flag_key = p_flag_key;
  if not found then raise exception 'FLAG_NOT_FOUND: %', p_flag_key using errcode = 'P0002'; end if;
  select * into e from feature_flag_environments fe where fe.flag_id = d.id and fe.environment = p_env;
  v_has_env := found;

  if d.status <> 'active' then
    v_value := d.off_value; v_tier := 'flag_inactive'; v_reason := 'flag is ' || d.status;
  elsif v_has_env and e.kill_engaged then                                    -- tier 1
    v_value := d.off_value; v_tier := 'kill_switch'; v_reason := 'kill switch engaged: ' || e.kill_reason;
  else
    -- The ORDER BY is the whole of §11 conflict resolution: tier precedence, then lower priority, then
    -- newest created_at, then id (a total order, so the pick is deterministic).
    select * into c from app.flag_candidates(d.id, p_env, p_tenant, p_app_key) fc
     where fc.eligible
     order by fc.tier_rank, fc.priority asc, fc.created_at desc, fc.rule_id desc
     limit 1;
    v_has_rule := found;
    if v_has_rule then                                                  -- tiers 2-5
      v_value := c.value; v_tier := c.target_type; v_rule := c.rule_id;
      v_reason := format('%s rule %s (priority %s)', c.target_type, c.target_ref, c.priority);
    elsif v_has_env then                                                           -- tier 6
      v_value := e.default_value; v_tier := 'default'; v_reason := 'environment default';
    else
      v_value := d.off_value; v_tier := 'no_environment'; v_reason := 'flag not configured for ' || p_env;
    end if;
  end if;

  v_fp := md5(concat_ws('|', d.id, p_env, v_tier, coalesce(v_rule::text, '-'), v_value::text));

  if p_log then
    -- Serialize per subject so concurrent evaluations agree on "is this a new decision".
    perform pg_advisory_xact_lock(hashtext('flag_decision'),
      hashtext(d.id::text || '|' || p_env || '|' || p_tenant::text || '|' || coalesce(p_app_key, '')));
    select l.fingerprint into v_last from feature_flag_decision_log l
     where l.flag_id = d.id and l.environment = p_env and l.tenant_id = p_tenant
       and l.app_key is not distinct from p_app_key
     order by l.seq desc limit 1;
    if v_last is distinct from v_fp then
      insert into feature_flag_decision_log(flag_id, environment, tenant_id, app_key, value, tier, rule_id, reason, fingerprint)
      values (d.id, p_env, p_tenant, p_app_key, v_value, v_tier, v_rule, v_reason, v_fp);
    end if;
  end if;

  return query select d.flag_key, v_value, v_tier, v_rule, v_reason, v_fp;
end$$;

-- Destructive/privileged surface: no PUBLIC execute; only the worker pool may call these.
revoke execute on function app.evaluate_flag(text, text, uuid, text, boolean) from public;
revoke execute on function app.flag_candidates(uuid, text, uuid, text) from public;
grant execute on function app.evaluate_flag(text, text, uuid, text, boolean) to svc_worker;
grant execute on function app.flag_candidates(uuid, text, uuid, text) to svc_worker;
