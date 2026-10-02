-- 0017_identity_binding.sql — table-group 16: real Supabase authentication (DEC-012, FOUNDATION_15).
-- Supabase establishes WHO (the `sub` of a verified Supabase access token); the Hub decides WHAT, via
-- user_identities(auth_provider='supabase', auth_subject=<sub>) -> memberships -> roles. This migration
-- makes that binding a database invariant rather than handler discipline. Depends on 0000-0016.
--
-- Identity states:
--   auth_provider='invite'   — provisioned by a tenant-admin invitation, not yet bound to anyone.
--                              auth_subject = 'invite:<uuid>' (a placeholder; never a real login).
--   auth_provider='supabase' — bound to exactly one Supabase user; auth_subject = that user's uuid.
-- The only legal transition is invite -> supabase (a CLAIM), exactly once. A bound identity can never be
-- re-pointed at a different Supabase account — that would be an account takeover with one UPDATE.

-- (The demo identities' placeholder subjects 'sub-uN' were never real Supabase subjects; the seeds now
-- use stable UUIDs 5b000000-0000-4000-8000-00000000000N so test/demo tokens can carry them.)

alter table user_identities add constraint ck_identity_provider
  check (auth_provider in ('supabase', 'invite'));
alter table user_identities add constraint ck_identity_subject_shape
  check ((auth_provider = 'supabase' and auth_subject ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
      or (auth_provider = 'invite'   and auth_subject ~ '^invite:[0-9a-f-]{36}$'));
-- An invitation must say who it is for (the claim is matched on the verified email).
alter table user_identities add constraint ck_identity_invite_email
  check (auth_provider <> 'invite' or primary_email is not null);
-- A claim is never ambiguous: group 1's ux_user_identities_email already allows only ONE live identity
-- per email across all providers (so no second invite for an email, and no invite beside a bound one).

create or replace function app.forbid_identity_rebind()
returns trigger language plpgsql as $$
begin
  if (new.auth_provider, new.auth_subject) is distinct from (old.auth_provider, old.auth_subject) then
    if old.auth_provider <> 'invite' then
      raise exception 'IDENTITY_REBIND_FORBIDDEN: a bound identity cannot be re-pointed at another account' using errcode = 'P0001';
    end if;
    if new.auth_provider <> 'supabase' then
      raise exception 'IDENTITY_CLAIM_INVALID: an invitation can only be claimed by a supabase subject' using errcode = 'P0001';
    end if;
  end if;
  return new;
end$$;
create trigger trg_identity_no_rebind before update on user_identities
  for each row execute function app.forbid_identity_rebind();

-- The invitation write, as ONE function so concurrent callers converge instead of erroring. Group 1
-- already guarantees one live identity per email (ux_user_identities_email) and one live membership per
-- (tenant, user) (ux_tenant_memberships_tenant_user); without ON CONFLICT the loser of a race got a raw
-- unique violation (HTTP 500). Each step is INSERT ... ON CONFLICT DO NOTHING against those indexes,
-- then a re-read (READ COMMITTED: a fresh snapshot per statement, so the loser sees the winner's row).
create or replace function app.invite_to_tenant(p_tenant uuid, p_email citext, p_invited_by uuid)
returns table(membership_id uuid, status text, created boolean)
language plpgsql as $$
declare v_user uuid; v_m uuid; v_status text;
begin
  insert into user_identities(auth_provider, auth_subject, primary_email, status)
  values ('invite', 'invite:' || gen_random_uuid(), p_email, 'active')
  on conflict (primary_email) where primary_email is not null and deleted_at is null do nothing;
  select ui.id into v_user from user_identities ui where ui.primary_email = p_email and ui.deleted_at is null;

  insert into tenant_memberships(tenant_id, user_id, status, invited_by, invited_at)
  values (p_tenant, v_user, 'invited', p_invited_by, now())
  on conflict (tenant_id, user_id) where deleted_at is null do nothing
  returning id into v_m;
  if v_m is not null then
    return query select v_m, 'invited'::text, true;
    return;
  end if;
  select m.id, m.status into v_m, v_status from tenant_memberships m
   where m.tenant_id = p_tenant and m.user_id = v_user and m.deleted_at is null;
  return query select v_m, v_status, false;
end$$;
revoke execute on function app.invite_to_tenant(uuid, citext, uuid) from public;
grant execute on function app.invite_to_tenant(uuid, citext, uuid) to svc_worker;
