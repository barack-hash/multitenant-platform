-- 0008_files_storage.sql — table-group 7: files/storage (FOUNDATION_07, MASTER_PLAN §10).
-- Brokered, quarantine-first, tenant-scoped, audited. Depends on 0000-0007.

-- Authoritative retention registry (Class C global reference; §3 DDL).
create table if not exists retention_policies (
  id                      uuid primary key default gen_random_uuid(),
  policy_key              text not null unique,
  retention_class         text not null check (retention_class in ('C0','C1','C2','C3','C4')),
  retention_days          integer not null check (retention_days >= 0),
  purge_mode              text not null check (purge_mode in ('hard_delete','soft_delete','tombstone','immutable_retain')),
  legal_hold_blocks_purge boolean not null default true,
  description             text not null,
  created_at              timestamptz not null default now(),
  updated_at              timestamptz not null default now()
);
alter table retention_policies enable row level security;
alter table retention_policies force  row level security;
create policy p_retention_policies_read on retention_policies
  for select using (app.current_actor_id() is not null or app.current_actor_type() = 'service');
create policy p_retention_policies_write on retention_policies
  for all using (app.assert_service_role(array['svc_ops']))
  with check (app.assert_service_role(array['svc_ops']));
grant select on retention_policies to svc_app;
grant select, insert, update on retention_policies to svc_worker;

-- File metadata (Class A tenant read; brokered/service writes). subject_ref optionally ties a file to a student.
create table if not exists file_objects (
  id                  uuid primary key default gen_random_uuid(),
  tenant_id           uuid not null references tenants(id),
  app_id              uuid references apps(id),
  owner_membership_id uuid references tenant_memberships(id),
  subject_ref         uuid,                    -- optional: a student (minor). Consent-gated at the app layer.
  bucket              text not null default 'private',
  object_path         text not null,
  filename            text not null,
  content_type        text,
  size_bytes          bigint,
  checksum            text,
  scan_status         text not null default 'pending' check (scan_status in ('pending','clean','infected','error')),
  status              text not null default 'quarantined' check (status in ('quarantined','active','deleted')),
  retention_policy_id uuid references retention_policies(id),
  uploaded_by         uuid,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now(),
  version             bigint not null default 1,
  deleted_at          timestamptz, deleted_by uuid, delete_reason text
);
create index if not exists ix_file_objects_tenant_status on file_objects (tenant_id, status);
create index if not exists ix_file_objects_subject on file_objects (subject_ref) where subject_ref is not null;

alter table file_objects enable row level security;
alter table file_objects force  row level security;
create policy p_file_objects_tenant_select on file_objects
  for select using (
    app.assert_tenant_context() and tenant_id = app.current_tenant_id()
    and app.assert_membership_active() and deleted_at is null);
create policy p_file_objects_service on file_objects
  for all
  using (app.assert_service_role(array['svc_file','svc_file_scan','svc_lifecycle','svc_ops']))
  with check (app.assert_service_role(array['svc_file','svc_file_scan','svc_lifecycle','svc_ops']));
grant select on file_objects to svc_app;
grant select, insert, update on file_objects to svc_worker;
create trigger trg_no_reassign_file_objects before update on file_objects
  for each row execute function app.forbid_tenant_reassignment();

-- Scan verdicts (Class B service-only).
create table if not exists file_scan_results (
  id             uuid primary key default gen_random_uuid(),
  file_object_id uuid not null references file_objects(id),
  scan_status    text not null check (scan_status in ('clean','infected','error')),
  scanner        text not null,
  detail         text,
  scanned_at     timestamptz not null default now()
);
alter table file_scan_results enable row level security;
alter table file_scan_results force  row level security;
create policy p_file_scan_results_service on file_scan_results
  for all using (app.assert_service_role(array['svc_file_scan','svc_ops']))
  with check (app.assert_service_role(array['svc_file_scan','svc_ops']));
grant select, insert, update on file_scan_results to svc_worker;

-- Access log (Class D append-only).
create table if not exists file_access_events (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references tenants(id),
  file_object_id uuid not null references file_objects(id),
  actor_id       uuid,
  action         text not null,     -- upload | download | download_denied
  result         text,
  occurred_at    timestamptz not null default now()
);
alter table file_access_events enable row level security;
alter table file_access_events force  row level security;
create policy p_file_access_events_insert on file_access_events
  for insert with check (app.assert_service_role(array['svc_file','svc_ops']));
create policy p_file_access_events_select on file_access_events
  for select using (
    (app.assert_tenant_context() and tenant_id = app.current_tenant_id() and app.assert_membership_active())
    or app.assert_service_role(array['svc_ops','svc_audit']));
grant select on file_access_events to svc_app;
grant select, insert on file_access_events to svc_worker;

-- Record a scan verdict and flip the file to active/quarantined (the file-scan service).
create or replace function app.finalize_scan(p_file uuid, p_status text, p_scanner text, p_detail text default null)
returns void language plpgsql as $$
begin
  insert into file_scan_results(file_object_id, scan_status, scanner, detail) values (p_file, p_status, p_scanner, p_detail);
  update file_objects
     set scan_status = p_status,
         status = case when p_status = 'clean' then 'active' else 'quarantined' end,
         updated_at = now()
   where id = p_file;
end$$;

-- Projection: the tenant's files.
create or replace view app.v_my_files
  with (security_invoker = true) as
  select id, filename, content_type, size_bytes, scan_status, status, subject_ref, created_at
  from file_objects
  where tenant_id = app.current_tenant_id() and deleted_at is null
  order by created_at desc
  limit 50;
grant select on app.v_my_files to svc_app;
