-- 0014_operator_webauthn.sql — table-group 13: WebAuthn / passkeys for operators (FOUNDATION_12).
-- Phishing-resistant public-key auth. The WebAuthn crypto (CBOR/COSE parse, ES256 verify, challenge/
-- origin/RP-ID binding) is app-layer (src/webauthn.js); the DB stores registered credentials + a
-- single-use challenge store. Class B service-only (svc_ops/svc_authz); NO svc_app grant (DEC-009).
-- Depends on 0000-0013 (platform_operators, operator_sessions amr/acr, the audit chain).

-- ============================= DDL =============================

-- A registered passkey: the operator's PUBLIC key (never a secret), a monotonic sign counter (clone
-- detection), and the credential id the authenticator returns.
create table if not exists operator_webauthn_credentials (
  id             uuid primary key default gen_random_uuid(),
  operator_id    uuid not null references platform_operators(id),
  credential_id  text not null unique,          -- base64url
  public_key_jwk jsonb not null,                -- EC P-256 public key (public — safe to store)
  sign_count     bigint not null default 0,
  transports     text,
  aaguid         text,
  nickname       text,
  status         text not null default 'active' check (status in ('active','revoked')),
  created_at     timestamptz not null default now(),
  last_used_at   timestamptz,
  revoked_at     timestamptz
);
create index if not exists ix_webauthn_cred_operator on operator_webauthn_credentials (operator_id, status);

-- Server-issued challenges (single-use, short-TTL) that bind a ceremony to an operator.
create table if not exists operator_webauthn_challenges (
  id           uuid primary key default gen_random_uuid(),
  operator_id  uuid references platform_operators(id),
  challenge    text not null,                   -- base64url random bytes
  ceremony     text not null check (ceremony in ('registration','authentication')),
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null,
  consumed_at  timestamptz
);
create index if not exists ix_webauthn_chal_operator on operator_webauthn_challenges (operator_id, ceremony);

-- ============================= RLS =============================
do $$
declare t text;
begin
  foreach t in array array['operator_webauthn_credentials','operator_webauthn_challenges'] loop
    execute format('alter table %I enable row level security;', t);
    execute format('alter table %I force  row level security;', t);
    execute format($p$create policy p_%1$s_service on %1$s
      for all using (app.assert_service_role(array['svc_ops','svc_authz']))
      with check (app.assert_service_role(array['svc_ops','svc_authz']));$p$, t);
    execute format('grant select, insert, update, delete on %I to svc_worker;', t);
  end loop;
end$$;

-- ============================= Functions =============================

-- Issue a challenge (the app generates the random bytes; ≤5-min TTL clamp).
create or replace function app.webauthn_new_challenge(p_operator uuid, p_ceremony text, p_challenge text, p_ttl integer default 300)
returns uuid language plpgsql as $$
declare v_id uuid; v_ttl integer;
begin
  v_ttl := least(greatest(coalesce(p_ttl, 300), 30), 300);
  insert into operator_webauthn_challenges(operator_id, ceremony, challenge, expires_at)
  values (p_operator, p_ceremony, p_challenge, now() + make_interval(secs => v_ttl))
  returning id into v_id;
  return v_id;
end$$;

-- Consume a challenge (SINGLE-USE, even on a later failed verify → anti-replay): returns the bound
-- operator_id + the stored challenge value iff the ceremony matches and it is unexpired+unconsumed, and
-- marks it consumed. Returns no row otherwise.
create or replace function app.webauthn_consume_challenge(p_id uuid, p_ceremony text)
returns table(operator_id uuid, challenge text) language plpgsql as $$
declare v_op uuid; v_ch text; v_ok boolean;
begin
  select c.operator_id, c.challenge, (c.ceremony = p_ceremony and c.consumed_at is null and c.expires_at > now())
    into v_op, v_ch, v_ok
    from operator_webauthn_challenges c where c.id = p_id for update;
  if not found or not v_ok then return; end if;
  update operator_webauthn_challenges set consumed_at = now() where id = p_id;
  operator_id := v_op; challenge := v_ch; return next;
end$$;

create or replace function app.webauthn_add_credential(
  p_operator uuid, p_credential_id text, p_public_key jsonb, p_sign_count bigint,
  p_transports text default null, p_aaguid text default null, p_nickname text default null)
returns uuid language plpgsql as $$
declare v_id uuid;
begin
  insert into operator_webauthn_credentials(operator_id, credential_id, public_key_jwk, sign_count, transports, aaguid, nickname)
  values (p_operator, p_credential_id, p_public_key, p_sign_count, p_transports, p_aaguid, p_nickname)
  returning id into v_id;
  return v_id;
end$$;

-- Fetch an ACTIVE credential for assertion (public key + prior sign count + owner).
create or replace function app.webauthn_get_credential(p_credential_id text)
returns table(operator_id uuid, public_key_jwk jsonb, sign_count bigint) language sql stable as $$
  select operator_id, public_key_jwk, sign_count
    from operator_webauthn_credentials where credential_id = p_credential_id and status = 'active';
$$;

-- Advance the sign counter (clone detection): only moves forward, unless the authenticator reports 0/0.
-- Returns true if updated; false means a NON-monotonic count (possible cloned authenticator) → reject.
create or replace function app.webauthn_bump_sign_count(p_credential_id text, p_new_count bigint)
returns boolean language plpgsql as $$
declare n integer;
begin
  update operator_webauthn_credentials
     set sign_count = p_new_count, last_used_at = now()
   where credential_id = p_credential_id and status = 'active'
     and (p_new_count > sign_count or (p_new_count = 0 and sign_count = 0));
  get diagnostics n = row_count;
  return n > 0;
end$$;

create or replace function app.webauthn_active_credential_ids(p_operator uuid)
returns table(credential_id text) language sql stable as $$
  select credential_id from operator_webauthn_credentials where operator_id = p_operator and status = 'active';
$$;

create or replace function app.webauthn_revoke(p_credential_id text, p_operator uuid)
returns integer language plpgsql as $$
declare n integer;
begin
  update operator_webauthn_credentials set status = 'revoked', revoked_at = now()
   where credential_id = p_credential_id and operator_id = p_operator and status = 'active';
  get diagnostics n = row_count;
  return n;
end$$;

-- DEC-009 hardening: deny PUBLIC (svc_app) EXECUTE; only the worker pool may call these.
revoke all on function
  app.webauthn_new_challenge(uuid, text, text, integer), app.webauthn_consume_challenge(uuid, text),
  app.webauthn_add_credential(uuid, text, jsonb, bigint, text, text, text), app.webauthn_get_credential(text),
  app.webauthn_bump_sign_count(text, bigint), app.webauthn_active_credential_ids(uuid), app.webauthn_revoke(text, uuid)
from public;
grant execute on function
  app.webauthn_new_challenge(uuid, text, text, integer), app.webauthn_consume_challenge(uuid, text),
  app.webauthn_add_credential(uuid, text, jsonb, bigint, text, text, text), app.webauthn_get_credential(text),
  app.webauthn_bump_sign_count(text, bigint), app.webauthn_active_credential_ids(uuid), app.webauthn_revoke(text, uuid)
to svc_worker;
