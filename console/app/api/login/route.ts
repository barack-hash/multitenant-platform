import { NextResponse } from 'next/server';
import { hubFetch, sessionCookie, mfaCookie } from '@/lib/hub';

// Password login (factor 1). If the operator has MFA, we stash the short-lived pending-MFA token in its
// own httpOnly cookie and tell the client to collect a second factor — the session cookie is only set
// once fully authenticated.
export async function POST(req: Request) {
  const { email, api_key } = await req.json();
  const { status, body } = await hubFetch('/operator/login', { method: 'POST', body: JSON.stringify({ email, api_key }) }, { auth: false });
  if (status !== 200) return NextResponse.json({ error: body?.error || 'login failed' }, { status });
  if (body.mfa_required) {
    const res = NextResponse.json({ mfa_required: true });
    const c = mfaCookie(body.mfa_token);
    res.cookies.set(c.name, c.value, c.options);
    return res;
  }
  const res = NextResponse.json({ ok: true, role: body.operator_role, acr: body.acr });
  const c = sessionCookie(body.operator_token, body.expires_in || 1800);
  res.cookies.set(c.name, c.value, c.options);
  return res;
}
