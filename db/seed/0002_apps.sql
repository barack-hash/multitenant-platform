-- 0002_apps.sql — group-2 seed: app catalog + per-tenant activations. Superuser (bypasses RLS).

-- Catalog
insert into apps (id, app_key, name, category, description) values
  ('c1000000-0000-0000-0000-000000000001','hifz-lms','Hifz LMS','education','Quran memorization tracking (first vertical)'),
  ('c1000000-0000-0000-0000-000000000002','directory','Community Directory','community','Member directory and profiles')
on conflict (id) do nothing;

-- Activations: T1 has hifz active + directory LOCKED; T2 has hifz active.
insert into tenant_apps (id, tenant_id, app_id, status, lock_reason, activated_at) values
  ('c2000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','c1000000-0000-0000-0000-000000000001','active', null, now()),
  ('c2000000-0000-0000-0000-000000000002','11111111-1111-1111-1111-111111111111','c1000000-0000-0000-0000-000000000002','locked','billing past_due', now()),
  ('c2000000-0000-0000-0000-000000000003','22222222-2222-2222-2222-222222222222','c1000000-0000-0000-0000-000000000001','active', null, now())
on conflict (id) do nothing;
