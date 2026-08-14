// Hub token minting/verification (DEC-012: the Hub is the sole issuer of tenant-trust tokens;
// Supabase Auth only establishes `sub`). Claim set follows SYSTEM_ARCHITECTURE §3.
import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { cfg } from './config.js';

export function mintHubToken({ sub, tid, mid, permissions, roles = [], ent_v, tw, sid, root_sid }) {
  const s = sid || randomUUID();
  return jwt.sign(
    {
      ver: 1, jti: randomUUID(),
      tid, mid, sid: s, root_sid: root_sid || s,   // session lineage (root == self at login)
      ent_v, roles, permissions,
      tw: tw === true,                             // tenant_writes_allowed, computed at login
    },
    cfg.jwtSecret,
    { algorithm: 'HS256', subject: sub, issuer: cfg.iss, audience: cfg.aud, expiresIn: cfg.accessTtlSec, notBefore: 0 }
  );
}

// Launch token: 60s, one-time, aud='launch' (MASTER_PLAN §5).
export function mintLaunchToken({ jti, tid, sid, root_sid, app_id, ent_v }) {
  return jwt.sign({ jti, tid, sid, root_sid, app_id, ent_v }, cfg.jwtSecret,
    { algorithm: 'HS256', issuer: cfg.iss, audience: 'launch', expiresIn: 60 });
}
export const verifyLaunchToken = (t) =>
  jwt.verify(t, cfg.jwtSecret, { algorithms: ['HS256'], issuer: cfg.iss, audience: 'launch' });

// Support/impersonation token (group 10): a target-tenant USER token minted for an operator, but
// read-only (tw=false → assert_tenant_mutation_allowed blocks every write) and carrying impersonation
// provenance (imp=operator, ssid=support session). `sid` is the group-5 session (so revocation works).
export function mintSupportToken({ sub, tid, mid, permissions = [], sid, ssid, imp, smode = 'read_only' }) {
  return jwt.sign(
    { ver: 1, jti: randomUUID(), tid, mid, sid, root_sid: sid, ent_v: 0, roles: [], permissions,
      tw: false, imp, ssid, smode },
    cfg.jwtSecret,
    { algorithm: 'HS256', subject: sub, issuer: cfg.iss, audience: cfg.aud, expiresIn: 1800 }
  );
}

// Spoke session token: 1800s, aud='spoke'.
export function mintSpokeToken({ sub, tid, mid, app_id, sid, root_sid, ent_v }) {
  return jwt.sign({ tid, mid, app_id, sid, root_sid, ent_v }, cfg.jwtSecret,
    { algorithm: 'HS256', subject: sub, issuer: cfg.iss, audience: 'spoke', expiresIn: 1800 });
}
export const verifySpokeToken = (t) =>
  jwt.verify(t, cfg.jwtSecret, { algorithms: ['HS256'], issuer: cfg.iss, audience: 'spoke' });

export function verifyHubToken(token) {
  return jwt.verify(token, cfg.jwtSecret, { algorithms: ['HS256'], issuer: cfg.iss, audience: cfg.aud });
}

// Operator token (group 11): authenticates a PLATFORM OPERATOR (not a tenant user) for /admin/*.
// aud='operator'; bound to a live operator_session (osid) so revocation kills it before expiry.
// amr/acr (group 12) carry the auth methods + assurance level ('mfa' unlocks step-up endpoints).
export function mintOperatorToken({ operator_id, operator_role, osid, amr = ['pwd'], acr = 'pwd', ttlSec = cfg.operatorTokenTtlSec }) {
  return jwt.sign(
    { ver: 1, jti: randomUUID(), actor_type: 'operator', orole: operator_role, osid, amr, acr },
    cfg.jwtSecret,
    { algorithm: 'HS256', subject: operator_id, issuer: cfg.iss, audience: 'operator', expiresIn: ttlSec }
  );
}
export const verifyOperatorToken = (t) =>
  jwt.verify(t, cfg.jwtSecret, { algorithms: ['HS256'], issuer: cfg.iss, audience: 'operator' });

// Pending-MFA token (group 12): issued by /operator/login when the operator has active MFA. It is NOT a
// session token (distinct aud) — it can ONLY be exchanged at /operator/mfa/verify for a real session.
export function mintOperatorMfaToken({ operator_id }) {
  return jwt.sign({ ver: 1, jti: randomUUID(), mfa_pending: true }, cfg.jwtSecret,
    { algorithm: 'HS256', subject: operator_id, issuer: cfg.iss, audience: 'operator-mfa', expiresIn: cfg.operatorMfaTtlSec });
}
export const verifyOperatorMfaToken = (t) =>
  jwt.verify(t, cfg.jwtSecret, { algorithms: ['HS256'], issuer: cfg.iss, audience: 'operator-mfa' });

// Map verified token claims to the DB context GUCs the RLS helpers read.
export function gucsFromClaims(c) {
  const g = {
    'app.tenant_id': c.tid,
    'app.actor_type': 'user',
    'app.actor_id': c.sub,
    'app.membership_id': c.mid,
    'app.permissions': (c.permissions || []).join(','),
    'app.entitlement_snapshot_version': String(c.ent_v ?? ''),
    'app.tenant_writes_allowed': String(!!c.tw),
  };
  // Impersonation provenance (group 10): present only for support tokens. actor_type stays 'user' so the
  // request reads through the SAME target-tenant RLS ("see what the user sees"); tw=false blocks writes.
  if (c.imp) {
    g['app.impersonator_id'] = String(c.imp);
    g['app.support_session_id'] = String(c.ssid || '');
    g['app.support_mode'] = String(c.smode || 'read_only');
  }
  return g;
}
