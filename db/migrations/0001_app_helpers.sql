-- 0001_app_helpers.sql — the app.* RLS helper functions (FOUNDATION_01 §3)
-- Helpers read ONLY trusted server-set context GUCs (never client JWT claims). DEC-011/DEC-012.

create schema if not exists app;

-- REQUIRED: without USAGE, every policy call to app.* errors "permission denied for schema app"
-- and the entire RLS layer is locked out.
grant usage on schema app to svc_app, svc_worker, svc_migrate;
-- Explicit public-schema USAGE (do not rely on the PG15+ default, which locks public down).
grant usage on schema public to svc_app, svc_worker, svc_migrate;

create or replace function app.current_tenant_id()
returns uuid language sql stable as $$
  select nullif(current_setting('app.tenant_id', true), '')::uuid;
$$;

create or replace function app.current_actor_type()
returns text language sql stable as $$
  select nullif(current_setting('app.actor_type', true), '');
$$;

create or replace function app.current_actor_id()
returns uuid language sql stable as $$
  select nullif(current_setting('app.actor_id', true), '')::uuid;
$$;

create or replace function app.current_svc_role()
returns text language sql stable as $$
  select nullif(current_setting('app.svc_role', true), '');
$$;

create or replace function app.assert_tenant_context()
returns boolean language sql stable as $$
  select app.current_tenant_id() is not null;
$$;

-- Trusts Hub-set context; hardening option = SECURITY DEFINER re-validation (FOUNDATION_01 §8).
create or replace function app.assert_membership_active()
returns boolean language sql stable as $$
  select app.current_actor_type() = 'user'
     and nullif(current_setting('app.membership_id', true), '') is not null;
$$;

create or replace function app.assert_permission(required text)
returns boolean language sql stable as $$
  select position(
    ',' || required || ',' in
    ',' || coalesce(nullif(current_setting('app.permissions', true), ''), '') || ','
  ) > 0;
$$;

create or replace function app.assert_tenant_mutation_allowed()
returns boolean language sql stable as $$
  select coalesce(nullif(current_setting('app.tenant_writes_allowed', true), '')::boolean, false);
$$;

-- DEC-009: must be a SERVICE actor whose LOGICAL role is in allowed[]; svc_app can never satisfy this.
-- The current_user = 'svc_worker' check binds the logical svc_role GUC to the PHYSICAL service
-- login role, so a compromised/buggy svc_app path cannot pass a service policy by spoofing the GUC.
create or replace function app.assert_service_role(allowed text[])
returns boolean language sql stable as $$
  select current_user = 'svc_worker'
     and app.current_actor_type() = 'service'
     and app.current_svc_role() is not null
     and app.current_svc_role() <> 'svc_app'
     and app.current_svc_role() = any(allowed);
$$;

-- Enforces "tenant reassignment forbidden" (schema §1) at the row level, including the service path.
create or replace function app.forbid_tenant_reassignment()
returns trigger language plpgsql as $$
begin
  if new.tenant_id is distinct from old.tenant_id then
    raise exception 'tenant_id reassignment is forbidden';
  end if;
  return new;
end$$;
