-- 0009_minor_data_consent.sql — table-group 8: minor-data protection (FOUNDATION_07, OQ-034).
-- Vertical-owned, tenant-scoped (DEC-008). Students are DATA SUBJECTS, not users. Depends on 0000-0008.

create table if not exists students (
  id                  uuid primary key default gen_random_uuid(),
  tenant_id           uuid not null references tenants(id),
  app_id              uuid references apps(id),
  full_name           text not null,
  date_of_birth       date,
  is_minor            boolean not null default true,
  external_ref        text,
  retention_policy_id uuid references retention_policies(id),
  status              text not null default 'active' check (status in ('active','erased','archived')),
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now(),
  version             bigint not null default 1,
  deleted_at          timestamptz, deleted_by uuid, delete_reason text
);
create index if not exists ix_students_tenant on students (tenant_id, status);

create table if not exists guardians (
  id                   uuid primary key default gen_random_uuid(),
  tenant_id            uuid not null references tenants(id),
  student_id           uuid not null references students(id),
  guardian_membership_id uuid references tenant_memberships(id),
  full_name            text not null,
  contact_email        text,
  relationship         text,
  created_at           timestamptz not null default now()
);
create index if not exists ix_guardians_student on guardians (student_id);

create table if not exists parental_consents (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references tenants(id),
  student_id     uuid not null references students(id),
  guardian_id    uuid references guardians(id),
  consent_type   text not null default 'data_processing',
  notice_version text not null,
  method         text,                          -- verifiable-consent method (counsel-defined)
  status         text not null default 'granted' check (status in ('granted','revoked')),
  granted_at     timestamptz not null default now(),
  revoked_at     timestamptz
);
create index if not exists ix_parental_consents_student on parental_consents (student_id, consent_type);

create table if not exists data_subject_requests (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references tenants(id),
  student_id   uuid not null references students(id),
  request_type text not null check (request_type in ('access','delete','rectify')),
  status       text not null default 'received' check (status in ('received','completed','rejected')),
  requested_by uuid,
  requested_at timestamptz not null default now(),
  completed_at timestamptz
);

-- ===== RLS: Class A tenant-scoped, permission-gated; service path for lifecycle/erasure =====
alter table students enable row level security;
alter table students force  row level security;
create policy p_students_select on students
  for select using (app.assert_tenant_context() and tenant_id = app.current_tenant_id()
    and app.assert_membership_active() and app.assert_permission('students.read') and deleted_at is null);
create policy p_students_insert on students
  for insert with check (app.assert_tenant_context() and tenant_id = app.current_tenant_id()
    and app.assert_permission('students.manage') and app.assert_tenant_mutation_allowed());
create policy p_students_update on students
  for update using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id() and app.assert_permission('students.manage'));
create policy p_students_service on students
  for all using (app.assert_service_role(array['svc_lifecycle','svc_ops']))
  with check (app.assert_service_role(array['svc_lifecycle','svc_ops']));
grant select, insert, update on students to svc_app;
grant select, insert, update on students to svc_worker;
create trigger trg_no_reassign_students before update on students
  for each row execute function app.forbid_tenant_reassignment();

do $$
declare t text;
begin
  foreach t in array array['guardians','parental_consents','data_subject_requests'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_tenant_select on %1$s
      for select using (app.assert_tenant_context() and tenant_id = app.current_tenant_id()
        and app.assert_membership_active() and app.assert_permission('students.read'));$p$, t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_lifecycle','svc_ops']))
      with check (app.assert_service_role(array['svc_lifecycle','svc_ops']));$p$, t);
    execute format('grant select, insert, update on %I to svc_app;', t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;
-- tenant-admin write paths for guardians/consents/requests (permission-gated Class A writes)
create policy p_guardians_write on guardians
  for insert with check (tenant_id = app.current_tenant_id() and app.assert_permission('students.manage'));
create policy p_parental_consents_write on parental_consents
  for insert with check (tenant_id = app.current_tenant_id() and app.assert_permission('consents.manage'));
create policy p_parental_consents_update on parental_consents
  for update using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id() and app.assert_permission('consents.manage'));
create policy p_data_subject_requests_write on data_subject_requests
  for insert with check (tenant_id = app.current_tenant_id() and app.assert_permission('students.manage'));

-- ===== Consent gate (authoritative; called by the app in a service context) =====
create or replace function app.student_has_active_consent(p_student uuid, p_type text default 'data_processing')
returns boolean language sql stable as $$
  select exists (
    select 1 from parental_consents
     where student_id = p_student and consent_type = p_type and status = 'granted' and revoked_at is null);
$$;

-- ===== Subject-level erasure: shred one student's PII + purge their files; tenant stays intact =====
create or replace function app.erase_student(p_student uuid, p_reason text default 'subject_erasure', p_actor uuid default null)
returns integer language plpgsql as $$
declare v_tenant uuid; n integer := 0; nf integer := 0;
begin
  select tenant_id into v_tenant from students where id = p_student;
  if v_tenant is null then return 0; end if;
  update students
     set full_name = '[erased]', date_of_birth = null, external_ref = null,
         status = 'erased', deleted_at = now(), delete_reason = p_reason, updated_at = now()
   where id = p_student and status <> 'erased';
  get diagnostics n = row_count;
  update file_objects
     set status = 'deleted', deleted_at = now(), delete_reason = p_reason, updated_at = now()
   where subject_ref = p_student and deleted_at is null;
  get diagnostics nf = row_count;
  insert into data_subject_requests(tenant_id, student_id, request_type, status, requested_by, completed_at)
  values (v_tenant, p_student, 'delete', 'completed', p_actor, now());
  return n + nf;
end$$;
