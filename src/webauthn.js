// Real WebAuthn / FIDO2 (group 13) in pure Node — no external deps. Implements the security-critical
// ceremonies: registration (parse the attestation object → COSE EC2/P-256 public key) and authentication
// (verify a genuine ES256 signature over authenticatorData||SHA256(clientDataJSON), with challenge +
// origin + RP-ID binding, user-presence flag, and monotonic sign-count clone detection).
//
// Attestation format is treated as 'none'/self (standard for platform passkeys — the RP trusts the
// public key, not an attestation CA chain). `makeCredential()` is a test/demo authenticator that produces
// byte-for-byte the same structures a browser+authenticator would, so the verifier is exercised for real.
import { createHash, createPublicKey, verify as cryptoVerify, generateKeyPairSync, sign as cryptoSign, randomBytes } from 'node:crypto';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => Buffer.from(String(s), 'base64url');
const sha256 = (b) => createHash('sha256').update(b).digest();

// ---------------- minimal CBOR (RFC 8949 subset: uint, negint, bytes, text, array, map) ----------------
function head(major, n) {
  const mt = major << 5;
  if (n < 24) return Buffer.from([mt | n]);
  if (n < 0x100) return Buffer.from([mt | 24, n]);
  if (n < 0x10000) return Buffer.from([mt | 25, n >> 8, n & 0xff]);
  return Buffer.from([mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
export function cborEncode(v) {
  if (typeof v === 'number' && Number.isInteger(v)) return v >= 0 ? head(0, v) : head(1, -v - 1);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); return Buffer.concat([head(3, b.length), b]); }
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cborEncode)]);
  if (v instanceof Map) { const items = []; for (const [k, val] of v) items.push(cborEncode(k), cborEncode(val)); return Buffer.concat([head(5, v.size), ...items]); }
  if (v && typeof v === 'object') { const ks = Object.keys(v); const items = []; for (const k of ks) items.push(cborEncode(k), cborEncode(v[k])); return Buffer.concat([head(5, ks.length), ...items]); }
  throw new Error('cbor: unsupported value');
}
function decodeAt(buf, off) {
  const b = buf[off]; const major = b >> 5; const info = b & 0x1f; off++;
  let len = info;
  if (info === 24) { len = buf[off]; off += 1; }
  else if (info === 25) { len = buf.readUInt16BE(off); off += 2; }
  else if (info === 26) { len = buf.readUInt32BE(off); off += 4; }
  else if (info === 27) { len = Number(buf.readBigUInt64BE(off)); off += 8; }
  else if (info >= 28) throw new Error('cbor: bad additional info');
  switch (major) {
    case 0: return [len, off];
    case 1: return [-1 - len, off];
    case 2: return [buf.subarray(off, off + len), off + len];
    case 3: return [buf.subarray(off, off + len).toString('utf8'), off + len];
    case 4: { const arr = []; for (let i = 0; i < len; i++) { const [x, o] = decodeAt(buf, off); arr.push(x); off = o; } return [arr, off]; }
    case 5: { const m = new Map(); for (let i = 0; i < len; i++) { const [k, o1] = decodeAt(buf, off); const [val, o2] = decodeAt(buf, o1); m.set(k, val); off = o2; } return [m, off]; }
    default: throw new Error('cbor: unsupported major ' + major);
  }
}
export const cborDecode = (buf) => decodeAt(buf, 0)[0];
const cborDecodeWithOffset = (buf, off) => decodeAt(buf, off);

// ---------------- authenticatorData + COSE ----------------
function parseAuthData(ad) {
  const rpIdHash = ad.subarray(0, 32);
  const flagsByte = ad[32];
  const flags = { up: !!(flagsByte & 0x01), uv: !!(flagsByte & 0x04), at: !!(flagsByte & 0x40), ed: !!(flagsByte & 0x80) };
  const signCount = ad.readUInt32BE(33);
  const out = { rpIdHash, flags, signCount };
  let off = 37;
  if (flags.at) {
    out.aaguid = ad.subarray(off, off + 16); off += 16;
    const idLen = ad.readUInt16BE(off); off += 2;
    out.credentialId = ad.subarray(off, off + idLen); off += idLen;
    const [cose] = cborDecodeWithOffset(ad, off);
    out.cose = cose;
  }
  return out;
}
function coseToJwk(cose) {
  if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) throw new Error('unsupported COSE key (need EC2 / P-256 / ES256)');
  return { kty: 'EC', crv: 'P-256', x: b64u(cose.get(-2)), y: b64u(cose.get(-3)) };
}

// ---------------- RP verification ----------------
function checkClientData(clientDataJSON, type, expectedChallenge, expectedOrigin) {
  const cd = JSON.parse(fromB64u(clientDataJSON).toString('utf8'));
  if (cd.type !== type) throw new Error('WEBAUTHN_TYPE_MISMATCH');
  if (cd.challenge !== expectedChallenge) throw new Error('WEBAUTHN_CHALLENGE_MISMATCH');
  if (cd.origin !== expectedOrigin) throw new Error('WEBAUTHN_ORIGIN_MISMATCH');
  return cd;
}

export function verifyRegistration({ attestationObject, clientDataJSON, expectedChallenge, expectedOrigin, expectedRpId }) {
  checkClientData(clientDataJSON, 'webauthn.create', expectedChallenge, expectedOrigin);
  const att = cborDecode(fromB64u(attestationObject));
  const authData = att.get('authData');
  const p = parseAuthData(authData);
  if (!p.rpIdHash.equals(sha256(Buffer.from(expectedRpId)))) throw new Error('WEBAUTHN_RPID_MISMATCH');
  if (!p.flags.up) throw new Error('WEBAUTHN_NO_USER_PRESENCE');
  if (!p.flags.at || !p.cose) throw new Error('WEBAUTHN_NO_CREDENTIAL');
  return { credentialId: b64u(p.credentialId), publicKeyJwk: coseToJwk(p.cose), signCount: p.signCount, uv: p.flags.uv, aaguid: b64u(p.aaguid) };
}

// Returns { newSignCount, uv } on success; throws a typed error otherwise. Sign-count clone detection is
// the caller's job (compare newSignCount to the stored one) — this verifies the cryptographic assertion.
export function verifyAssertion({ authenticatorData, clientDataJSON, signature, publicKeyJwk, expectedChallenge, expectedOrigin, expectedRpId }) {
  checkClientData(clientDataJSON, 'webauthn.get', expectedChallenge, expectedOrigin);
  const authData = fromB64u(authenticatorData);
  const p = parseAuthData(authData);
  if (!p.rpIdHash.equals(sha256(Buffer.from(expectedRpId)))) throw new Error('WEBAUTHN_RPID_MISMATCH');
  if (!p.flags.up) throw new Error('WEBAUTHN_NO_USER_PRESENCE');
  const signed = Buffer.concat([authData, sha256(fromB64u(clientDataJSON))]);
  const pub = createPublicKey({ key: publicKeyJwk, format: 'jwk' });
  if (!cryptoVerify('sha256', signed, pub, fromB64u(signature))) throw new Error('WEBAUTHN_BAD_SIGNATURE');
  return { newSignCount: p.signCount, uv: p.flags.uv };
}

// ---------------- test/demo authenticator (produces real, verifiable ceremonies) ----------------
export function makeCredential(rpId) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = randomBytes(16);
  const rpIdHash = sha256(Buffer.from(rpId));
  let signCount = 0;
  const authData = (withAT) => {
    const flags = Buffer.from([0x01 | 0x04 | (withAT ? 0x40 : 0x00)]);   // UP | UV (| AT)
    const sc = Buffer.alloc(4); sc.writeUInt32BE(signCount);
    const parts = [rpIdHash, flags, sc];
    if (withAT) {
      const idLen = Buffer.alloc(2); idLen.writeUInt16BE(credId.length);
      const cose = cborEncode(new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64u(jwk.x)], [-3, fromB64u(jwk.y)]]));
      parts.push(Buffer.alloc(16), idLen, credId, cose);   // aaguid = zeros
    }
    return Buffer.concat(parts);
  };
  return {
    credentialId: b64u(credId),
    attestation(challenge, origin) {
      const clientDataJSON = b64u(Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin })));
      const attestationObject = b64u(cborEncode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData(true)]])));
      return { attestationObject, clientDataJSON };
    },
    assertion(challenge, origin, { bump = true } = {}) {
      if (bump) signCount += 1;
      const clientDataJSON = b64u(Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin })));
      const ad = authData(false);
      const signature = b64u(cryptoSign('sha256', Buffer.concat([ad, sha256(fromB64u(clientDataJSON))]), privateKey));
      return { credentialId: b64u(credId), authenticatorData: b64u(ad), clientDataJSON, signature };
    },
    setSignCount(n) { signCount = n; },
    get signCount() { return signCount; },
  };
}
