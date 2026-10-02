// Supabase Auth verification (group 16, DEC-012, FOUNDATION_15). Supabase authenticates; the Hub only
// needs to know, with certainty, WHICH Supabase user is presenting a token. Everything else (tenant,
// membership, roles, permissions) is the Hub's own decision.
//
// Hard rules, each a known way JWT verification goes wrong:
//  - the VERIFYING KEY is chosen by the algorithm, never the other way round: HS256 only ever uses the
//    configured project secret, ES256/RS256 only ever use a JWKS key of that exact type. That closes
//    algorithm confusion (an HS256 token "signed" with the public key) and `alg: none`.
//  - iss must be <SUPABASE_URL>/auth/v1 and aud must be `authenticated`; exp/nbf with 60s skew (MASTER_PLAN §5).
//  - role must be `authenticated`: Supabase's own anon and service_role API keys are ALSO JWTs signed
//    with the project secret, and must never authenticate as a user.
//  - anonymous Supabase users are refused (they have no verified identity to bind).
import jwt from 'jsonwebtoken';
import { createPublicKey } from 'node:crypto';

export class AuthError extends Error {
  constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.code = code; }
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const jwkAlg = (k) => k.alg || (k.kty === 'EC' && k.crv === 'P-256' ? 'ES256' : k.kty === 'RSA' ? 'RS256' : null);

export function createSupabaseAuth({ url, jwtSecret, serviceRoleKey, fetchImpl = fetch, skewSec = 60, jwksTtlMs = 600_000 }) {
  const issuer = `${url}/auth/v1`;
  let keys = new Map(), fetchedAt = 0, lastForced = 0;

  const loadJwks = async () => {
    const r = await fetchImpl(`${issuer}/.well-known/jwks.json`);
    if (!r.ok) throw new AuthError('SUPABASE_JWKS_UNAVAILABLE', `HTTP ${r.status}`);
    const body = await r.json();
    const next = new Map();
    for (const k of body.keys || []) {
      const alg = jwkAlg(k);
      if (!k.kid || !['ES256', 'RS256'].includes(alg)) continue;
      next.set(k.kid, { alg, key: createPublicKey({ key: k, format: 'jwk' }) });
    }
    keys = next; fetchedAt = Date.now();
  };
  // Cached; an unknown kid forces ONE refetch (key rotation) at most every 30s, so a stream of tokens
  // with random kids cannot turn the Hub into a JWKS-fetching amplifier.
  const keyFor = async (kid) => {
    if (!fetchedAt || Date.now() - fetchedAt > jwksTtlMs) await loadJwks();
    if (!keys.has(kid) && Date.now() - lastForced > 30_000) { lastForced = Date.now(); await loadJwks(); }
    return keys.get(kid);
  };

  async function verify(token) {
    if (typeof token !== 'string' || !token) throw new AuthError('SUPABASE_TOKEN_MISSING');
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded.payload !== 'object') throw new AuthError('SUPABASE_TOKEN_MALFORMED');
    const { alg, kid } = decoded.header;
    let key;
    if (alg === 'HS256') {
      if (!jwtSecret) throw new AuthError('SUPABASE_ALG_NOT_ALLOWED', 'HS256 is disabled (no SUPABASE_JWT_SECRET)');
      key = jwtSecret;
    } else if (alg === 'ES256' || alg === 'RS256') {
      const k = kid && await keyFor(kid);
      if (!k || k.alg !== alg) throw new AuthError('SUPABASE_UNKNOWN_KEY');
      key = k.key;
    } else throw new AuthError('SUPABASE_ALG_NOT_ALLOWED', String(alg));

    let claims;
    try { claims = jwt.verify(token, key, { algorithms: [alg], issuer, audience: 'authenticated', clockTolerance: skewSec }); }
    catch (e) { throw new AuthError('SUPABASE_TOKEN_INVALID', e.message); }
    if (claims.role !== 'authenticated') throw new AuthError('SUPABASE_ROLE_INVALID', String(claims.role));
    if (claims.is_anonymous === true) throw new AuthError('SUPABASE_ANONYMOUS_REFUSED');
    if (!UUID.test(String(claims.sub))) throw new AuthError('SUPABASE_SUB_INVALID');
    return claims;
  }

  // Authoritative email-verification check for a FIRST login (claiming an invitation). Token claims are
  // not trusted for this: the Admin API is asked directly, with the server-only service-role key.
  async function verifiedEmail(sub) {
    if (!serviceRoleKey) throw new AuthError('SUPABASE_ADMIN_UNCONFIGURED', 'SUPABASE_SERVICE_ROLE_KEY is required to claim an invitation');
    const r = await fetchImpl(`${issuer}/admin/users/${sub}`, {
      headers: { apikey: serviceRoleKey, authorization: `Bearer ${serviceRoleKey}` } });
    if (r.status === 404) throw new AuthError('SUPABASE_USER_NOT_FOUND');
    if (!r.ok) throw new AuthError('SUPABASE_ADMIN_UNAVAILABLE', `HTTP ${r.status}`);
    const u = await r.json();
    if (u.id !== sub) throw new AuthError('SUPABASE_ADMIN_MISMATCH');
    return { email: u.email || null, confirmed: Boolean(u.email_confirmed_at) };
  }

  return { verify, verifiedEmail, issuer };
}
