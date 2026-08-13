-- 0000_roles.sql — bootstrap login roles (DECISION_LOG DEC-009)
-- MVP collapses the 14 designed service roles into 3 physical login roles.
-- The 14 LOGICAL svc_* identities live in the app.svc_role GUC, not as DB roles.
-- No role receives BYPASSRLS (authoritative invariant).
-- Dev passwords here are placeholders; production credentials come from the secret manager (DEC-013).

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'svc_app') then
    create role svc_app    login password 'dev_only' noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'svc_worker') then
    create role svc_worker login password 'dev_only' noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'svc_migrate') then
    create role svc_migrate login password 'dev_only' noinherit;
  end if;
end$$;

-- Explicitly assert the no-BYPASSRLS invariant.
alter role svc_app    nobypassrls;
alter role svc_worker nobypassrls;
alter role svc_migrate nobypassrls;
