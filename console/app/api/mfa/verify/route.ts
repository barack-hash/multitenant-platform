import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { hubFetch, sessionCookie, MFA_COOKIE } from '@/lib/hub';

// Second factor (TOTP or recovery code) → exchange the pending-MFA token for a real operator session.
export async function POST(req: Request) {
  const { code, recovery_code } = await req.json();
  const mfa_token = (await cookies()).get(MFA_COOKIE)?.value;
  if (!mfa_token) return NextResponse.json({ error: 'no pending MFA challenge' }, { status: 400 });
  const { status, body } = await hubFetch('/operator/mfa/verify', { method: 'POST', body: JSON.stringify({ mfa_token, code, recovery_code }) }, { auth: false });
  if (status !== 200) return NextResponse.json({ error: body?.error || 'verification failed' }, { status });
  const res = NextResponse.json({ ok: true, role: body.operator_role, acr: body.acr });
  const c = sessionCookie(body.operator_token, body.expires_in || 1800);
  res.cookies.set(c.name, c.value, c.options);
  res.cookies.delete(MFA_COOKIE);
  return res;
}
