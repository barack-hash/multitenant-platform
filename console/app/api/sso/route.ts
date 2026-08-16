import { NextResponse } from 'next/server';
import { hubFetch, sessionCookie } from '@/lib/hub';

// SSO login: forward a signed IdP assertion to the Hub; on success, set the session cookie.
export async function POST(req: Request) {
  const { idp, assertion } = await req.json();
  const { status, body } = await hubFetch('/operator/sso/login', { method: 'POST', body: JSON.stringify({ idp, assertion }) }, { auth: false });
  if (status !== 200) return NextResponse.json({ error: body?.error || 'SSO failed' }, { status });
  const res = NextResponse.json({ ok: true, role: body.operator_role, acr: body.acr });
  const c = sessionCookie(body.operator_token, body.expires_in || 1800);
  res.cookies.set(c.name, c.value, c.options);
  return res;
}
