import { NextResponse } from 'next/server';
import { hubFetch } from '@/lib/hub';

// Guarded, authenticated proxy for admin/operator reads+actions. Only /admin/* and /operator/* are
// forwarded, always with the session token attached server-side (never exposed to the browser).
async function proxy(req: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const rel = (path || []).join('/');
  if (!/^(admin|operator)(\/|$)/.test(rel)) return NextResponse.json({ error: 'forbidden path' }, { status: 403 });
  const url = new URL(req.url);
  const init: RequestInit = { method: req.method };
  if (req.method !== 'GET' && req.method !== 'HEAD') init.body = await req.text();
  const { status, body } = await hubFetch('/' + rel + (url.search || ''), init);
  return NextResponse.json(body, { status });
}
export { proxy as GET, proxy as POST };
