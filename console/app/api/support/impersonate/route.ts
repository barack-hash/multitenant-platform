import { NextResponse } from 'next/server';
import { hubFetch, supportCookie } from '@/lib/hub';

// Start impersonation. The Hub returns a SUPPORT TOKEN — a real bearer credential for the impersonated
// tenant user — so it is stashed in its own httpOnly cookie here and never reaches client JS. Only the
// non-secret banner context (§12 C5) is returned to the browser.
export async function POST(req: Request) {
  const { request_id } = await req.json();
  const { status, body } = await hubFetch('/admin/support/impersonate', {
    method: 'POST', body: JSON.stringify({ request_id }),
  });
  if (status !== 200) return NextResponse.json(body ?? { error: 'impersonation failed' }, { status });
  const res = NextResponse.json({
    support_session_id: body.support_session_id,
    banner_required: body.banner_required,
    mode: body.mode,
    expires_in: body.expires_in,
  });
  const c = supportCookie(body.support_token, body.expires_in || 1800);
  res.cookies.set(c.name, c.value, c.options);
  return res;
}
