import { NextResponse } from 'next/server';
import { hubFetch } from '@/lib/hub';

export async function POST() {
  const { status, body } = await hubFetch('/operator/webauthn/register/begin', { method: 'POST', body: '{}' });
  return NextResponse.json(body, { status });
}
