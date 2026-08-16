// Server-only BFF client for the Hub. The operator token lives in an httpOnly cookie and is attached
// here — it is NEVER sent to the browser. HUB_URL is a server env var (not exposed to the client).
import { cookies } from 'next/headers';

export const HUB_URL = process.env.HUB_URL || 'http://localhost:3939';
export const TOKEN_COOKIE = 'op_token';
export const MFA_COOKIE = 'op_mfa';
const PROD = process.env.NODE_ENV === 'production';

export const sessionCookie = (value: string, maxAge: number) => ({
  name: TOKEN_COOKIE, value,
  options: { httpOnly: true, sameSite: 'lax' as const, secure: PROD, path: '/', maxAge },
});
export const mfaCookie = (value: string) => ({
  name: MFA_COOKIE, value,
  options: { httpOnly: true, sameSite: 'lax' as const, secure: PROD, path: '/', maxAge: 300 },
});

export type HubResult = { status: number; body: any };

export async function hubFetch(path: string, init: RequestInit = {}, opts: { auth?: boolean } = {}): Promise<HubResult> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set('content-type', 'application/json');
  if (opts.auth !== false) {
    const token = (await cookies()).get(TOKEN_COOKIE)?.value;
    if (token) headers.set('authorization', `Bearer ${token}`);
  }
  const res = await fetch(`${HUB_URL}${path}`, { ...init, headers, cache: 'no-store' });
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
  return { status: res.status, body };
}
