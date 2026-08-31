import { NextResponse } from 'next/server';
import { hubFetch, SUPPORT_COOKIE } from '@/lib/hub';

// Probe an action class under impersonation. The five prohibited classes hard-deny (403) and the
// denial is written to the tenant's audit chain before the rejection is returned (§12 C6/P1-P5).
export async function POST(req: Request) {
  const { action_class } = await req.json();
  const { status, body } = await hubFetch('/support/attempt', {
    method: 'POST', body: JSON.stringify({ action_class }),
  }, { cookie: SUPPORT_COOKIE });
  return NextResponse.json(body ?? {}, { status });
}
