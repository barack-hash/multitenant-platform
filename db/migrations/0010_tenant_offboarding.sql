-- 0010_tenant_offboarding.sql — table-group 9: TENANT-level offboarding lifecycle (FOUNDATION_08).
-- The phase state machine (MASTER_PLAN §13), legal-hold gating, mandatory verification receipts
-- (§10), retention gating (§15), and a permanent tombstone (§6). All Class B service-only, owned by
-- svc_lifecycle (+ svc_ops) per DEC-008/009. Depends on 0000-0009.
-- DISTINCT from group-8 subject-level erasure (app.erase_student): this offboards a WHOLE tenant.

-- ============================= DDL =============================

-- 1. The offboarding job = the phase state machine (§13 canonical phases).
create table if not exists tenant_offboarding_jobs (
  id                    uuid primary key default gen_random_uuid(),
  tenant_id             uuid not null references tenants(id),
  phase                 text not null default 'requested'
                          check (phase in ('requested','approved','freeze_started','freeze_completed',
                            'export_started','export_completed','retention_wait','purge_started',
                            'purge_completed','tombstoned','failed')),
  retention_policy_id   uuid references retention_policies(id),   -- §15: lifecycle must reference retention_policies.id
  reason                text,
  requested_by          uuid,
  approved_by           uuid,
  requested_at          timestamptz not null default now(),
  approved_at           timestamptz,
  scheduled_purge_after timestamptz,          -- retention_wait deadline (from retention_days)
  completed_at          timestamptz,
  failed_at             timestamptz,
  failure_reason        text,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now()
);
-- At most one LIVE offboarding job per tenant (terminal phases are exempt).
create unique index if not exists ux_offb_active_per_tenant
  on tenant_offboarding_jobs (tenant_id) where phase not in ('tombstoned','failed');
create index if not exists ix_offb_tenant on tenant_offboarding_jobs (tenant_id, phase);

-- 2. Legal holds — an ACTIVE hold blocks purge progression (§13; §15 precedence #1).
create table if not exists legal_holds (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references tenants(id),
  reason       text not null,
  reference    text,                          -- case/matter reference
  status       text not null default 'active' check (status in ('active','released')),
  placed_by    uuid,
  placed_at    timestamptz not null default now(),
  released_by  uuid,
  released_at  timestamptz
);
create index if not exists ix_legal_holds_tenant on legal_holds (tenant_id, status);

-- 3. Export verification receipt (§3 DDL) — the export completion gate (one per job).
create table if not exists export_verification_receipts (
  id                 uuid primary key default gen_random_uuid(),
  tenant_id          uuid not null references tenants(id),
  offboarding_job_id uuid not null references tenant_offboarding_jobs(id),
  manifest_hash      text not null,
  signature_valid    boolean not null,
  checksum_valid     boolean not null,
  verified_by        text not null,
  verified_at        timestamptz not null default now(),
  details            jsonb not null default '{}'::jsonb
);
create unique index if not exists ux_export_verification_receipts_job
  on export_verification_receipts (offboarding_job_id);

-- 4. Purge job — one data-plane run per offboarding job; request_id ties it to the receipts.
create table if not exists purge_jobs (
  id                 uuid primary key default gen_random_uuid(),
  offboarding_job_id uuid not null references tenant_offboarding_jobs(id),
  tenant_id          uuid not null references tenants(id),
  request_id         uuid not null default gen_random_uuid(),
  status             text not null default 'pending' check (status in ('pending','running','completed','failed')),
  started_at         timestamptz,
  completed_at       timestamptz,
  created_at         timestamptz not null default now()
);
create unique index if not exists ux_purge_jobs_request on purge_jobs (request_id);
create index if not exists ix_purge_jobs_offb on purge_jobs (offboarding_job_id);

-- 5. Purge job items — per data-plane target, with the receipt it produced.
create table if not exists purge_job_items (
  id            uuid primary key default gen_random_uuid(),
  purge_job_id  uuid not null references purge_jobs(id),
  tenant_id     uuid not null references tenants(id),
  data_plane    text not null check (data_plane in ('database','files','cache','search','export')),
  target_ref    text,
  status        text not null default 'pending' check (status in ('pending','purged','skipped','failed')),
  rows_affected bigint not null default 0,
  receipt_id    uuid,
  completed_at  timestamptz
);
create index if not exists ix_purge_job_items_job on purge_job_items (purge_job_id);

-- 6. Cache purge receipt (§3 DDL).
create table if not exists cache_purge_receipts (
  id           uuid primary key default gen_random_uuid(),
  request_id   uuid not null,
  tenant_id    uuid not null references tenants(id),
  app_id       uuid references apps(id),
  scope        text not null,
  keys_matched bigint not null default 0,
  keys_deleted bigint not null default 0,
  node_count   integer not null default 0,
  completed_at timestamptz not null default now(),
  details      jsonb not null default '{}'::jsonb
);
create unique index if not exists ux_cache_purge_receipts_request on cache_purge_receipts (request_id);

-- 7. Search purge receipt (§3 DDL).
create table if not exists search_purge_receipts (
  id                    uuid primary key default gen_random_uuid(),
  request_id            uuid not null,
  tenant_id             uuid not null references tenants(id),
  app_id                uuid references apps(id),
  index_alias           text,
  aliases_deleted       bigint not null default 0,
  docs_deleted          bigint not null default 0,
  index_cluster_version text not null,
  completed_at          timestamptz not null default now(),
  details               jsonb not null default '{}'::jsonb
);
create unique index if not exists ux_search_purge_receipts_request on search_purge_receipts (request_id);

-- 8. Tenant deletion tombstone — terminal proof; NEVER hard-deleted (§6). One per tenant.
create table if not exists tenant_deletion_tombstones (
  id                 uuid primary key default gen_random_uuid(),
  tenant_id          uuid not null references tenants(id),
  offboarding_job_id uuid references tenant_offboarding_jobs(id),
  tenant_slug        text not null,           -- preserved for audit even after the tenant is anonymized
  reason             text,
  export_receipt_id  uuid references export_verification_receipts(id),
  purge_request_id   uuid,
  purged_at          timestamptz not null default now(),
  created_at         timestamptz not null default now()
);
create unique index if not exists ux_tombstone_tenant on tenant_deletion_tombstones (tenant_id);

-- ============================= RLS =============================
-- Class B service-only. svc_lifecycle owns; svc_ops co-operates. NO svc_app grant (DEC-009: revoke all
-- on lifecycle/purge internals from svc_app). FORCE RLS everywhere; no role has BYPASSRLS.

-- Mutable lifecycle tables: FOR ALL service policy + reassignment guard.
do $$
declare t text;
begin
  foreach t in array array['tenant_offboarding_jobs','legal_holds','purge_jobs','purge_job_items'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_lifecycle','svc_ops']))
      with check (app.assert_service_role(array['svc_lifecycle','svc_ops']));$p$, t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
    execute format($p$create trigger trg_no_reassign_%1$s before update on %1$s
      for each row execute function app.forbid_tenant_reassignment();$p$, t);
  end loop;
end$$;

-- Receipt tables: insert-once evidence. FOR ALL service policy, but grant only select+insert (no update
-- path) — receipts are immutable once written.
do $$
declare t text;
begin
  foreach t in array array['export_verification_receipts','cache_purge_receipts','search_purge_receipts'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_lifecycle','svc_ops']))
      with check (app.assert_service_role(array['svc_lifecycle','svc_ops']));$p$, t);
    execute format('grant select, insert on %I to svc_worker;', t);
  end loop;
end$$;

-- Tombstones: NEVER hard-deleted (§6). Separate INSERT + SELECT policies (no update/delete policy at
-- all), and only select+insert granted — there is no privilege OR policy path to modify or remove a row.
alter table tenant_deletion_tombstones enable row level security;
alter table tenant_deletion_tombstones force  row level security;
create policy p_tenant_deletion_tombstones_insert on tenant_deletion_tombstones
  for insert with check (app.assert_service_role(array['svc_lifecycle','svc_ops']));
create policy p_tenant_deletion_tombstones_select on tenant_deletion_tombstones
  for select using (app.assert_service_role(array['svc_lifecycle','svc_ops','svc_audit']));
grant select, insert on tenant_deletion_tombstones to svc_worker;

-- ============================= Functions =============================

-- An active legal hold on the tenant (blocks purge progression, §13).
create or replace function app.tenant_has_active_legal_hold(p_tenant uuid)
returns boolean language sql stable as $$
  select exists (select 1 from legal_holds where tenant_id = p_tenant and status = 'active');
$$;

-- Completion readiness: export + cache + search receipts ALL present for the job (§10/§15).
create or replace function app.offboarding_completion_ready(p_job uuid)
returns boolean language sql stable as $$
  select
    exists (select 1 from export_verification_receipts r
             where r.offboarding_job_id = p_job and r.signature_valid and r.checksum_valid)
    and exists (select 1 from purge_jobs pj join cache_purge_receipts c on c.request_id = pj.request_id
                 where pj.offboarding_job_id = p_job)
    and exists (select 1 from purge_jobs pj join search_purge_receipts s on s.request_id = pj.request_id
                 where pj.offboarding_job_id = p_job);
$$;

-- The guarded state machine. Enforces the §13 DAG + legal-hold/export/retention/completion gates,
-- side-effects tenants.status (active->frozen->suspended->offboarding->deleted), writes the tombstone
-- on the terminal transition, and emits an offboarding.phase_changed event. Runs as svc_lifecycle.
create or replace function app.advance_offboarding(p_job uuid, p_target text, p_actor uuid default null)
returns text language plpgsql as $$
declare
  v_tenant uuid;
  v_phase  text;
  v_policy uuid;
  v_sched  timestamptz;
  v_ok     boolean;
begin
  select tenant_id, phase, retention_policy_id, scheduled_purge_after
    into v_tenant, v_phase, v_policy, v_sched
    from tenant_offboarding_jobs where id = p_job for update;
  if v_tenant is null then
    raise exception 'OFFBOARDING_JOB_NOT_FOUND' using errcode = 'P0002';
  end if;

  -- DEC-014 single-flight: serialize concurrent lifecycle mutations for this tenant.
  perform pg_advisory_xact_lock(hashtext('offboarding'), hashtext(v_tenant::text));

  if v_phase in ('tombstoned','failed') then
    raise exception 'OFFBOARDING_TERMINAL: % is terminal', v_phase using errcode = 'P0001';
  end if;

  -- 'failed' (abort) is reachable from any non-terminal phase.
  if p_target = 'failed' then
    update tenant_offboarding_jobs
       set phase = 'failed', failed_at = now(),
           failure_reason = coalesce(failure_reason, 'operator_abort'), updated_at = now()
     where id = p_job;
    perform app.emit_event('offboarding.phase_changed', v_tenant,
      jsonb_build_object('job', p_job, 'from', v_phase, 'to', 'failed'), 'lifecycle-service');
    return 'failed';
  end if;

  -- Valid forward edges only.
  v_ok := (
    (v_phase = 'requested'        and p_target = 'approved') or
    (v_phase = 'approved'         and p_target = 'freeze_started') or
    (v_phase = 'freeze_started'   and p_target = 'freeze_completed') or
    (v_phase = 'freeze_completed' and p_target = 'export_started') or
    (v_phase = 'export_started'   and p_target = 'export_completed') or
    (v_phase = 'export_completed' and p_target = 'retention_wait') or
    (v_phase = 'retention_wait'   and p_target = 'purge_started') or
    (v_phase = 'purge_started'    and p_target = 'purge_completed') or
    (v_phase = 'purge_completed'  and p_target = 'tombstoned')
  );
  if not v_ok then
    raise exception 'OFFBOARDING_INVALID_TRANSITION: % -> %', v_phase, p_target using errcode = 'P0001';
  end if;

  -- Legal hold BLOCKS purge progression (§13).
  if p_target in ('purge_started','purge_completed','tombstoned')
     and app.tenant_has_active_legal_hold(v_tenant) then
    raise exception 'LEGAL_HOLD_ACTIVE: purge blocked for tenant %', v_tenant using errcode = 'P0001';
  end if;

  -- Export completion requires a verified export receipt (§10).
  if p_target = 'export_completed'
     and not exists (select 1 from export_verification_receipts
                      where offboarding_job_id = p_job and signature_valid and checksum_valid) then
    raise exception 'EXPORT_RECEIPT_REQUIRED' using errcode = 'P0001';
  end if;

  -- A retention policy is MANDATORY before a purge can be scheduled (§15: offboarding/purge must
  -- reference retention_policies.id). Without this, a null policy would coalesce to a 0-day window
  -- and defeat the retention gate entirely.
  if p_target = 'retention_wait' and v_policy is null then
    raise exception 'RETENTION_POLICY_REQUIRED: offboarding must reference retention_policies.id' using errcode = 'P0001';
  end if;

  -- Retention window must elapse before purge starts (§15).
  if p_target = 'purge_started' and v_sched is not null and now() < v_sched then
    raise exception 'RETENTION_NOT_ELAPSED: purge allowed after %', v_sched using errcode = 'P0001';
  end if;

  -- Completion requires export + cache + search receipts (§10/§15).
  if p_target = 'purge_completed' and not app.offboarding_completion_ready(p_job) then
    raise exception 'PURGE_RECEIPTS_REQUIRED: export+cache+search receipts incomplete' using errcode = 'P0001';
  end if;

  -- Apply the phase + bookkeeping. On retention_wait, stamp the purge-eligible deadline from policy.
  update tenant_offboarding_jobs
     set phase = p_target,
         approved_by = case when p_target = 'approved' then p_actor else approved_by end,
         approved_at = case when p_target = 'approved' then now() else approved_at end,
         scheduled_purge_after = case when p_target = 'retention_wait'
              then now() + make_interval(days => coalesce(
                   (select retention_days from retention_policies where id = v_policy), 0))
              else scheduled_purge_after end,
         completed_at = case when p_target = 'tombstoned' then now() else completed_at end,
         updated_at = now()
   where id = p_job;

  -- Tenant status DAG (§13): active -> frozen -> suspended -> offboarding -> deleted.
  if p_target = 'freeze_started' then
    update tenants set status = 'frozen',    updated_at = now() where id = v_tenant and status <> 'deleted';
  elsif p_target = 'export_started' then
    update tenants set status = 'suspended', updated_at = now() where id = v_tenant and status <> 'deleted';
  elsif p_target = 'purge_started' then
    update tenants set status = 'offboarding', updated_at = now() where id = v_tenant and status <> 'deleted';
  elsif p_target = 'tombstoned' then
    update tenants set status = 'deleted', deleted_at = now(),
           delete_reason = 'tenant_offboarding_purge', updated_at = now() where id = v_tenant;
    -- Permanent proof (never hard-deleted). Preserve the slug before any later anonymization.
    insert into tenant_deletion_tombstones(tenant_id, offboarding_job_id, tenant_slug, reason,
                                           export_receipt_id, purge_request_id)
    select v_tenant, p_job, t.slug, 'tenant_offboarding_purge',
           (select id from export_verification_receipts where offboarding_job_id = p_job),
           (select request_id from purge_jobs where offboarding_job_id = p_job order by created_at desc limit 1)
      from tenants t where t.id = v_tenant
    on conflict (tenant_id) do nothing;
  end if;

  perform app.emit_event('offboarding.phase_changed', v_tenant,
    jsonb_build_object('job', p_job, 'from', v_phase, 'to', p_target), 'lifecycle-service');
  return p_target;
end$$;

-- Data-plane purge (runs only while in purge_started). Soft-deletes the tenant's files, anonymizes its
-- students, records the purge_job + items, and writes the cache + search purge receipts. NEVER touches
-- audit_events/billing_events/domain_events/webhook_receipts/tombstones (§6). Runs as svc_lifecycle.
create or replace function app.execute_tenant_purge(p_job uuid, p_actor uuid default null)
returns uuid language plpgsql as $$
declare
  v_tenant uuid; v_phase text; v_pj uuid; v_req uuid;
  n_files bigint := 0; n_students bigint := 0;
begin
  select tenant_id, phase into v_tenant, v_phase from tenant_offboarding_jobs where id = p_job for update;
  if v_tenant is null then raise exception 'OFFBOARDING_JOB_NOT_FOUND' using errcode = 'P0002'; end if;
  if v_phase <> 'purge_started' then
    raise exception 'PURGE_WRONG_PHASE: purge runs only in purge_started (now %)', v_phase using errcode = 'P0001';
  end if;
  if app.tenant_has_active_legal_hold(v_tenant) then
    raise exception 'LEGAL_HOLD_ACTIVE' using errcode = 'P0001';
  end if;
  -- Idempotency: one data-plane purge run per offboarding job (don't duplicate receipts on a re-call).
  if exists (select 1 from purge_jobs where offboarding_job_id = p_job and status <> 'failed') then
    raise exception 'PURGE_ALREADY_RUN: a purge job already exists for %', p_job using errcode = 'P0001';
  end if;

  insert into purge_jobs(offboarding_job_id, tenant_id, status, started_at)
    values (p_job, v_tenant, 'running', now()) returning id, request_id into v_pj, v_req;

  -- DATABASE + FILES data planes (tenant-confidential; soft-delete/anonymize per retention purge_mode).
  update file_objects
     set status = 'deleted', deleted_at = now(), delete_reason = 'tenant_offboarding_purge', updated_at = now()
   where tenant_id = v_tenant and deleted_at is null;
  get diagnostics n_files = row_count;
  update students
     set full_name = '[purged]', date_of_birth = null, external_ref = null, status = 'erased',
         deleted_at = now(), delete_reason = 'tenant_offboarding_purge', updated_at = now()
   where tenant_id = v_tenant and status <> 'erased';
  get diagnostics n_students = row_count;
  insert into purge_job_items(purge_job_id, tenant_id, data_plane, target_ref, status, rows_affected, completed_at)
  values (v_pj, v_tenant, 'files',    'file_objects', 'purged', n_files,    now()),
         (v_pj, v_tenant, 'database', 'students',     'purged', n_students, now());

  -- CACHE + SEARCH data planes: verification receipts (evidence required for completion, §10).
  insert into cache_purge_receipts(request_id, tenant_id, scope, keys_matched, keys_deleted, node_count)
    values (v_req, v_tenant, 'env:local:tenant:' || v_tenant::text || ':*', 0, 0, 1);
  insert into search_purge_receipts(request_id, tenant_id, index_alias, aliases_deleted, docs_deleted, index_cluster_version)
    values (v_req, v_tenant, 'local_tenant_' || replace(v_tenant::text, '-', '') || '_*', 0, 0, 'es-mvp');
  insert into purge_job_items(purge_job_id, tenant_id, data_plane, target_ref, status, receipt_id, completed_at)
    select v_pj, v_tenant, 'cache', 'cache_purge_receipts', 'purged', id, now()
      from cache_purge_receipts where request_id = v_req;
  insert into purge_job_items(purge_job_id, tenant_id, data_plane, target_ref, status, receipt_id, completed_at)
    select v_pj, v_tenant, 'search', 'search_purge_receipts', 'purged', id, now()
      from search_purge_receipts where request_id = v_req;

  update purge_jobs set status = 'completed', completed_at = now() where id = v_pj;
  perform app.emit_event('offboarding.purge_executed', v_tenant,
    jsonb_build_object('job', p_job, 'purge_job', v_pj, 'files', n_files, 'students', n_students), 'lifecycle-service');
  return v_pj;
end$$;

-- DEC-009 hardening: the lifecycle/purge functions are the platform's most destructive surface. Deny
-- PUBLIC (hence svc_app) EXECUTE outright — only the worker pool, acting as svc_lifecycle/svc_ops, may
-- call them. (Isolation already holds via invoker+FORCE-RLS, but for THIS surface we also close the
-- EXECUTE-grant door per DEC-009's "svc_app gets no privilege on lifecycle/purge internals".)
revoke all on function
  app.advance_offboarding(uuid, text, uuid),
  app.execute_tenant_purge(uuid, uuid),
  app.tenant_has_active_legal_hold(uuid),
  app.offboarding_completion_ready(uuid)
from public;
grant execute on function
  app.advance_offboarding(uuid, text, uuid),
  app.execute_tenant_purge(uuid, uuid),
  app.tenant_has_active_legal_hold(uuid),
  app.offboarding_completion_ready(uuid)
to svc_worker;
