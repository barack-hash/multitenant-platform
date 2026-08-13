-- 0004_events.sql — group-4 seed: a little event history per tenant. Superuser (bypasses RLS).
insert into domain_events (id, event_type, tenant_id, source_service, payload, occurred_at) values
  ('e5000000-0000-0000-0000-000000000001','tenant.provisioned','11111111-1111-1111-1111-111111111111','hub','{}'::jsonb, now() - interval '2 hours'),
  ('e5000000-0000-0000-0000-000000000002','app.activated','11111111-1111-1111-1111-111111111111','app-registry-service','{"app_key":"hifz-lms"}'::jsonb, now() - interval '1 hour'),
  ('e5000000-0000-0000-0000-000000000003','tenant.provisioned','22222222-2222-2222-2222-222222222222','hub','{}'::jsonb, now() - interval '2 hours')
on conflict (id) do nothing;
