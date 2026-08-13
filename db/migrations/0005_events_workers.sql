-- 0005_events_workers.sql — table-group 4: events + workers (FOUNDATION_04).
-- Transactional outbox, canonical event log, consumer inbox (exactly-once), checkpoints, DLQ.
-- Depends on 0000-0004.

-- ============================= DDL =============================

-- Canonical published event log (Class D append-only; never hard-deleted per §6).
create table if not exists domain_events (
  id             uuid primary key,                    -- the event_id
  event_type     text not null,
  schema_version integer not null default 1,
  tenant_id      uuid references tenants(id),         -- null only for explicit global events
  source_service text,
  source_app_id  uuid,
  correlation_id uuid,
  causation_id   uuid,
  idempotency_key text,
  ordering_key   text,
  payload        jsonb not null default '{}'::jsonb,
  metadata       jsonb not null default '{}'::jsonb,
  occurred_at    timestamptz not null default now(),
  created_at     timestamptz not null default now()
);
create index if not exists ix_domain_events_tenant on domain_events (tenant_id, occurred_at desc);
create unique index if not exists ux_domain_events_idem on domain_events (idempotency_key) where idempotency_key is not null;

-- Transactional outbox (Class B service-only). Written in the business tx; relayed later.
create table if not exists outbox_events (
  id             uuid primary key default gen_random_uuid(),
  event_id       uuid not null default gen_random_uuid(),
  event_type     text not null,
  schema_version integer not null default 1,
  tenant_id      uuid references tenants(id),
  source_service text,
  correlation_id uuid,
  causation_id   uuid,
  idempotency_key text,
  ordering_key   text,
  payload        jsonb not null default '{}'::jsonb,
  metadata       jsonb not null default '{}'::jsonb,
  status         text not null default 'pending' check (status in ('pending','relayed','failed')),
  attempt_count  integer not null default 0,
  created_at     timestamptz not null default now(),
  relayed_at     timestamptz
);
create index if not exists ix_outbox_pending on outbox_events (status, created_at) where status = 'pending';
create unique index if not exists ux_outbox_idem on outbox_events (idempotency_key) where idempotency_key is not null;

-- Consumer inbox (Class B). Exactly-once via unique (consumer_name, event_id).
create table if not exists inbox_events (
  id            uuid primary key default gen_random_uuid(),
  consumer_name text not null,
  event_id      uuid not null,
  tenant_id     uuid references tenants(id),
  status        text not null default 'received' check (status in ('received','processed','failed')),
  received_at   timestamptz not null default now(),
  processed_at  timestamptz,
  unique (consumer_name, event_id)
);

-- Per-consumer partition watermark (Class B).
create table if not exists consumer_checkpoints (
  id                uuid primary key default gen_random_uuid(),
  consumer_name     text not null,
  partition_key     text not null,
  last_event_id     uuid,
  last_ordering_key text,
  updated_at        timestamptz not null default now(),
  unique (consumer_name, partition_key)
);

-- Dead-letter queue (Class B; §3 shape). Dedup via unique (consumer_name, event_id).
create table if not exists dead_letter_events (
  id              uuid primary key default gen_random_uuid(),
  event_id        uuid not null,
  tenant_id       uuid references tenants(id),
  consumer_name   text not null,
  failure_code    text not null,
  failure_detail  text,
  attempt_count   integer not null default 0,
  dead_lettered_at timestamptz not null default now(),
  payload         jsonb not null default '{}'::jsonb,
  unique (consumer_name, event_id)
);

-- ============================= RLS =============================

-- domain_events: Class D (append-only; tenant reads own, operators read all)
alter table domain_events enable row level security;
alter table domain_events force  row level security;
create policy p_domain_events_insert on domain_events
  for insert with check (app.assert_service_role(array['svc_events','svc_ops']));
-- svc_events must be able to SELECT so the relay's INSERT ... ON CONFLICT DO NOTHING can
-- arbitrate conflicts (Postgres requires the SELECT policy to pass for ON CONFLICT).
create policy p_domain_events_select on domain_events
  for select using (
    (app.assert_tenant_context() and tenant_id = app.current_tenant_id() and app.assert_membership_active())
    or app.assert_service_role(array['svc_events','svc_ops','svc_audit']));
grant select on domain_events to svc_app;
grant select, insert on domain_events to svc_worker;

-- outbox_events: Class B, producer-writable
alter table outbox_events enable row level security;
alter table outbox_events force  row level security;
create policy p_outbox_events_service on outbox_events
  for all
  using (app.assert_service_role(array['svc_events','svc_billing','svc_entitlement','svc_app_registry','svc_lifecycle','svc_support','svc_ops']))
  with check (app.assert_service_role(array['svc_events','svc_billing','svc_entitlement','svc_app_registry','svc_lifecycle','svc_support','svc_ops']));
grant select, insert, update on outbox_events to svc_worker;
create trigger trg_no_reassign_outbox before update on outbox_events
  for each row execute function app.forbid_tenant_reassignment();

-- inbox_events / consumer_checkpoints / dead_letter_events: Class B service-only (event infra)
do $$
declare t text;
begin
  foreach t in array array['inbox_events','consumer_checkpoints','dead_letter_events'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_events','svc_ops']))
      with check (app.assert_service_role(array['svc_events','svc_ops']));$p$, t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;
create trigger trg_no_reassign_inbox before update on inbox_events
  for each row execute function app.forbid_tenant_reassignment();

-- ============================= Functions =============================

-- Emit into the outbox INSIDE the caller's transaction (transactional outbox).
create or replace function app.emit_event(
  p_event_type text, p_tenant uuid, p_payload jsonb default '{}'::jsonb,
  p_source_service text default 'hub', p_idempotency_key text default null,
  p_ordering_key text default null, p_correlation_id uuid default null, p_causation_id uuid default null)
returns uuid language plpgsql as $$
declare v_event_id uuid := gen_random_uuid();
begin
  insert into outbox_events(event_id, event_type, tenant_id, source_service, payload,
                            idempotency_key, ordering_key, correlation_id, causation_id)
  values (v_event_id, p_event_type, p_tenant, p_source_service, coalesce(p_payload, '{}'::jsonb),
          p_idempotency_key, p_ordering_key, p_correlation_id, p_causation_id);
  return v_event_id;
end$$;

-- Relay pending outbox rows into the canonical log (idempotent publish). Runs as svc_events.
create or replace function app.relay_outbox(p_limit integer default 100)
returns integer language plpgsql as $$
declare r record; n integer := 0;
begin
  for r in select * from outbox_events where status = 'pending' order by created_at limit p_limit for update skip locked
  loop
    insert into domain_events(id, event_type, schema_version, tenant_id, source_service,
                              correlation_id, causation_id, idempotency_key, ordering_key, payload, metadata, occurred_at)
    values (r.event_id, r.event_type, r.schema_version, r.tenant_id, r.source_service,
            r.correlation_id, r.causation_id, r.idempotency_key, r.ordering_key, r.payload, r.metadata, r.created_at)
    on conflict (id) do nothing;
    update outbox_events set status = 'relayed', relayed_at = now(), attempt_count = attempt_count + 1 where id = r.id;
    n := n + 1;
  end loop;
  return n;
end$$;

-- Claim an event for a consumer; returns false if already processed (exactly-once).
create or replace function app.try_consume(p_consumer text, p_event_id uuid, p_tenant uuid default null)
returns boolean language plpgsql as $$
declare v_id uuid;
begin
  insert into inbox_events(consumer_name, event_id, tenant_id)
  values (p_consumer, p_event_id, p_tenant)
  on conflict (consumer_name, event_id) do nothing
  returning id into v_id;
  return v_id is not null;
end$$;

-- Route a terminal failure to the DLQ (deduped by consumer+event).
create or replace function app.dead_letter(p_consumer text, p_event_id uuid, p_tenant uuid, p_code text,
                                           p_detail text default null, p_payload jsonb default '{}'::jsonb)
returns void language plpgsql as $$
begin
  insert into dead_letter_events(event_id, tenant_id, consumer_name, failure_code, failure_detail, payload)
  values (p_event_id, p_tenant, p_consumer, p_code, p_detail, coalesce(p_payload, '{}'::jsonb))
  on conflict (consumer_name, event_id)
  do update set failure_code = excluded.failure_code, failure_detail = excluded.failure_detail,
                attempt_count = dead_letter_events.attempt_count + 1;
end$$;

-- Advance a consumer's partition watermark.
create or replace function app.checkpoint_set(p_consumer text, p_partition text, p_event_id uuid, p_ordering_key text default null)
returns void language plpgsql as $$
begin
  insert into consumer_checkpoints(consumer_name, partition_key, last_event_id, last_ordering_key)
  values (p_consumer, p_partition, p_event_id, p_ordering_key)
  on conflict (consumer_name, partition_key)
  do update set last_event_id = excluded.last_event_id, last_ordering_key = excluded.last_ordering_key, updated_at = now();
end$$;

-- ============================= Projection =============================
create or replace view app.v_my_events
  with (security_invoker = true) as
  select id as event_id, event_type, occurred_at, payload
  from domain_events
  where tenant_id = app.current_tenant_id()
  order by occurred_at desc
  limit 20;
grant select on app.v_my_events to svc_app;
