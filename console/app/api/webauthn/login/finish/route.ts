import { NextResponse } from 'next/server';
import { hubFetch, sessionCookie } from '@/lib/hub';

// Passwordless passkey login: on a verified assertion, set the session cookie.
export async function POST(req: Request) {
  const { status, body } = await hubFetch('/operator/webauthn/login/finish', { method: 'POST', body: await req.text() }, { auth: false });
  if (status !== 200) return NextResponse.json(body, { status });
  const res = NextResponse.json({ ok: true, role: body.operator_role, acr: body.acr, amr: body.amr });
  const c = sessionCookie(body.operator_token, body.expires_in || 1800);
  res.cookies.set(c.name, c.value, c.options);
  return res;
}
