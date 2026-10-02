// Server-only BFF client for the Hub. The operator token lives in an httpOnly cookie and is attached
// here — it is NEVER sent to the browser. HUB_URL is a server env var (not exposed to the client).
import { cookies, headers as requestHeaders } from 'next/headers';
import { createHmac } from 'node:crypto';

export const HUB_URL = process.env.HUB_URL || 'http://localhost:3939';
export const TOKEN_COOKIE = 'op_token';
export const MFA_COOKIE = 'op_mfa';
export const SUPPORT_COOKIE = 'sup_token';
const PROD = process.env.NODE_ENV === 'production';

export const sessionCookie = (value: string, maxAge: number) => ({
  name: TOKEN_COOKIE, value,
  options: { httpOnly: true, sameSite: 'lax' as const, secure: PROD, path: '/', maxAge },
});
export const mfaCookie = (value: string) => ({
  name: MFA_COOKIE, value,
  options: { httpOnly: true, sameSite: 'lax' as const, secure: PROD, path: '/', maxAge: 300 },
});
// An impersonation (support) token is a bearer credential like the operator token, so it gets the same
// treatment: httpOnly, server-side only, never handed to client JS. It is a SEPARATE cookie because it
// authenticates as the impersonated tenant user, not as the operator.
export const supportCookie = (value: string, maxAge: number) => ({
  name: SUPPORT_COOKIE, value,
  options: { httpOnly: true, sameSite: 'lax' as const, secure: PROD, path: '/', maxAge },
});

export type HubResult = { status: number; body: any };

// Every operator reaches the Hub through this server, i.e. from ONE address — which would put all of
// them in one per-IP login bucket. So the BFF asserts the browser's address, signed with a secret it
// shares with the Hub (server-only env; never sent to the browser). The Hub ignores unsigned/forged values.
const BFF_SECRET = process.env.BFF_SHARED_SECRET || 'dev-bff-secret-change-me';
async function clientIpHeaders(): Promise<Record<string, string>> {
  const h = await requestHeaders();
  const ip = (h.get('x-forwarded-for') || '').split(',')[0].trim() || h.get('x-real-ip') || '';
  if (!ip) return {};
  const ts = String(Date.now());
  return { 'x-client-ip': ip, 'x-client-ip-ts': ts,
           'x-client-ip-sig': createHmac('sha256', BFF_SECRET).update(`${ip}|${ts}`).digest('hex') };
}

export async function hubFetch(
  path: string,
  init: RequestInit = {},
  opts: { auth?: boolean; cookie?: string } = {},
): Promise<HubResult> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set('content-type', 'application/json');
  for (const [k, v] of Object.entries(await clientIpHeaders())) headers.set(k, v);
  if (opts.auth !== false) {
    // opts.cookie selects WHICH bearer to attach — the operator session by default, or the support
    // (impersonation) token for the /support/* surface.
    const token = (await cookies()).get(opts.cookie || TOKEN_COOKIE)?.value;
    if (token) headers.set('authorization', `Bearer ${token}`);
  }
  const res = await fetch(`${HUB_URL}${path}`, { ...init, headers, cache: 'no-store' });
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
  return { status: res.status, body };
}
