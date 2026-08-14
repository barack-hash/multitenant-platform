// TOTP (RFC 6238) + base32 (RFC 4648) in pure Node — no external deps. The Hub stores the base32 secret
// (group 12) and verifies codes here, the same app-layer pattern as the webhook-HMAC and consent gates.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s) {
  const clean = String(s || '').replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

export const generateTotpSecret = (bytes = 20) => base32Encode(randomBytes(bytes));

// HOTP over an 8-byte big-endian counter (RFC 4226).
function hotp(secretBuf, counter) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const h = createHmac('sha1', secretBuf).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return (bin % 1_000_000).toString().padStart(6, '0');
}

const STEP = 30;
export function totp(secretB32, forTimeMs = Date.now()) {
  return hotp(base32Decode(secretB32), Math.floor(forTimeMs / 1000 / STEP));
}

// Verify with a ±`window`-step skew tolerance, constant-time per candidate.
export function verifyTotp(secretB32, code, window = 1, forTimeMs = Date.now()) {
  const c = String(code || '');
  if (!/^\d{6}$/.test(c)) return false;
  const secret = base32Decode(secretB32);
  const step = Math.floor(forTimeMs / 1000 / STEP);
  const given = Buffer.from(c);
  for (let w = -window; w <= window; w++) {
    const cand = Buffer.from(hotp(secret, step + w));
    if (cand.length === given.length && timingSafeEqual(cand, given)) return true;
  }
  return false;
}

export function otpauthUri(issuer, account, secretB32) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const q = new URLSearchParams({ secret: secretB32, issuer, algorithm: 'SHA1', digits: '6', period: String(STEP) });
  return `otpauth://totp/${label}?${q.toString()}`;
}
