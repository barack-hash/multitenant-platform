import { NextResponse } from 'next/server';
import { hubFetch } from '@/lib/hub';

export async function POST(req: Request) {
  const { status, body } = await hubFetch('/operator/webauthn/register/finish', { method: 'POST', body: await req.text() });
  return NextResponse.json(body, { status });
}
