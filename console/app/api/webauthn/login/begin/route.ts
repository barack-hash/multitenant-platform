import { NextResponse } from 'next/server';
import { hubFetch } from '@/lib/hub';

export async function POST(req: Request) {
  const { status, body } = await hubFetch('/operator/webauthn/login/begin', { method: 'POST', body: await req.text() }, { auth: false });
  return NextResponse.json(body, { status });
}
