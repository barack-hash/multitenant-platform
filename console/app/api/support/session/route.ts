import { NextResponse } from 'next/server';
import { hubFetch, SUPPORT_COOKIE } from '@/lib/hub';

// The banner context the UI MUST render while impersonating (§12 C5). Authenticated with the SUPPORT
// token, not the operator token — this call answers "who am I acting as", not "who am I".
export async function GET() {
  const { status, body } = await hubFetch('/support/session', { method: 'GET' }, { cookie: SUPPORT_COOKIE });
  if (status !== 200) return NextResponse.json({ impersonating: false });
  return NextResponse.json(body);
}
