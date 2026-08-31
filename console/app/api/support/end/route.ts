import { NextResponse } from 'next/server';
import { hubFetch, SUPPORT_COOKIE } from '@/lib/hub';

// Ending a session is an OPERATOR action (operator token). If the session being ended is the one THIS
// console holds a token for, the support cookie is dropped too — otherwise the console would keep
// presenting a credential the Hub has already revoked. Ending someone ELSE's session from the list
// must not silently discard your own live impersonation, so the ids are compared first.
export async function POST(req: Request) {
  const { support_session_id } = await req.json();
  const mine = await hubFetch('/support/session', { method: 'GET' }, { cookie: SUPPORT_COOKIE });
  const isOwn = mine.status === 200 && mine.body?.support_session_id === support_session_id;

  const { status, body } = await hubFetch(`/admin/support/session/${encodeURIComponent(support_session_id)}/end`, { method: 'POST' });
  const res = NextResponse.json({ ...(body ?? {}), ended_own_session: isOwn }, { status });
  // Fail closed: once the end call has been made for our own session, discard the credential even if
  // the Hub reported an error — a token we can no longer account for should not stay in the browser.
  if (isOwn) res.cookies.delete(SUPPORT_COOKIE);
  return res;
}
