import { NextResponse } from 'next/server';
import { hubFetch, TOKEN_COOKIE } from '@/lib/hub';

export async function POST() {
  await hubFetch('/operator/logout', { method: 'POST' }).catch(() => {});
  const res = NextResponse.json({ ok: true });
  res.cookies.delete(TOKEN_COOKIE);
  return res;
}
