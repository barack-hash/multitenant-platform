-- 0007_billing_webhooks.sql — table-group 6: Stripe webhook ingestion (FOUNDATION_06).
-- webhook_receipts + billing_events (§3 DDL) + apply_billing_lock. Class B service-only. Depends on 0000-0006.

-- Global dedupe ledger (no tenant at ingress).
create table if not exists webhook_receipts (
  id                      uuid primary key default gen_random_uuid(),
  provider                text not null,
  endpoint_key            text not null,
  external_event_id       text,
  idempotency_fingerprint text not null,
  signature_valid         boolean not null,
  payload_hash            text not null,
  status                  text not null check (status in ('received','processing','processed','failed','discarded')),
  first_seen_at           timestamptz not null default now(),
  last_seen_at            timestamptz not null default now(),
  attempt_count           integer not null default 0,
  processed_at            timestamptz,
  error_code              text,
  error_detail            text
);
create unique index if not exists ux_webhook_receipts_event
  on webhook_receipts (provider, endpoint_key, external_event_id) where external_event_id is not null;
create unique index if not exists ux_webhook_receipts_fingerprint
  on webhook_receipts (provider, endpoint_key, idempotency_fingerprint);
create index if not exists ix_webhook_receipts_status_seen on webhook_receipts (status, first_seen_at desc);

-- Tenant-scoped provider event log (idempotent + ordered).
create table if not exists billing_events (
  id                uuid primary key default gen_random_uuid(),
  tenant_id         uuid not null references tenants(id),
  provider          text not null,
  provider_event_id text not null,
  event_type        text not null,
  occurred_at       timestamptz not null,
  watermark         bigint not null,
  payload           jsonb not null,
  created_at        timestamptz not null default now()
);
create unique index if not exists ux_billing_events_provider_event on billing_events (provider, provider_event_id);
create unique index if not exists ux_billing_events_tenant_watermark on billing_events (tenant_id, watermark);

-- ===== RLS: both Class B service-only [svc_billing, svc_ops] =====
do $$
declare t text;
begin
  foreach t in array array['webhook_receipts','billing_events'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_billing','svc_ops']))
      with check (app.assert_service_role(array['svc_billing','svc_ops']));$p$, t);
    execute format('grant select, insert, update on %I to svc_worker;', t);
  end loop;
end$$;
create trigger trg_no_reassign_billing_events before update on billing_events
  for each row execute function app.forbid_tenant_reassignment();

-- ===== Billing lock: set the tenant's entitled apps active/locked from billing status (MASTER_PLAN §7) =====
create or replace function app.apply_billing_lock(p_tenant uuid, p_billing_status text)
returns void language plpgsql as $$
begin
  update tenant_apps ta
     set status = case when p_billing_status in ('active','trialing') then 'active' else 'locked' end,
         lock_reason = case when p_billing_status in ('active','trialing') then null else 'billing:' || p_billing_status end,
         updated_at = now()
   where ta.tenant_id = p_tenant and ta.deleted_at is null
     and ta.app_id in (
       select pae.app_id from plan_app_entitlements pae
       join subscriptions s on s.plan_id = pae.plan_id and s.tenant_id = p_tenant);
end$$;
