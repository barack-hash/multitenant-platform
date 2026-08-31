'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';

// FOUNDATION_09 §12 — support access + impersonation. Everything here goes through the BFF: reads and
// operator actions via /api/hub/admin/*, and the impersonation surface via /api/support/* (which keeps
// the support token in its own httpOnly cookie — the browser never holds either bearer).

type Me = { operator_id: string; email: string; display_name: string; role: string; acr: string };
type Tenant = { id: string; slug: string; name: string; status: string };
type Req = {
  id: string; tenant_slug: string; status: string; mode: string; reason: string; ticket_ref: string | null;
  ttl_seconds: number; requested_at: string; requested_by: string; requested_by_email: string;
  approved_by: string | null; approved_by_email: string | null; deny_reason: string | null;
  target_user_id: string | null; target_email: string | null; active_support_session_id: string | null;
};
type Sess = {
  id: string; tenant_slug: string; operator_email: string; target_email: string | null; mode: string;
  status: string; started_at: string; expires_at: string; past_ttl: boolean; revoke_reason: string | null;
};
type Banner = {
  impersonating?: boolean; operator?: string; support_session_id?: string;
  acting_as?: string; tenant?: string; mode?: string;
};

// The five classes §12 hard-denies during impersonation, plus a benign control so the prober shows
// both sides of the gate rather than just a wall of red.
const PROHIBITED = ['billing', 'identity_secret', 'lifecycle_destructive', 'role_privilege', 'infra_secret'];
const BENIGN = ['view_reports', 'read_profile'];

async function api(url: string, init?: RequestInit) {
  const r = await fetch(url, {
    ...init,
    headers: init?.body ? { 'content-type': 'application/json' } : undefined,
    cache: 'no-store',
  });
  const body = await r.json().catch(() => null);
  return { status: r.status, body };
}

const ago = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—');
const statusBadge = (s: string) =>
  s === 'approved' ? 'ok' : s === 'denied' ? 'bad' : s === 'pending' ? 'wait' : 'off';

export default function Support() {
  const [me, setMe] = useState<Me | null>(null);
  const [authErr, setAuthErr] = useState(false);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [requests, setRequests] = useState<Req[]>([]);
  const [sessions, setSessions] = useState<Sess[]>([]);
  const [banner, setBanner] = useState<Banner | null>(null);
  const [attempts, setAttempts] = useState<{ cls: string; allowed: boolean; detail: string }[]>([]);
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const [form, setForm] = useState({ tenant: '', target_email: '', reason: '', ticket_ref: '', ttl_seconds: '1800' });

  const load = useCallback(async () => {
    const [m, t, r, s, b] = await Promise.all([
      api('/api/hub/operator/me'),
      api('/api/hub/admin/tenants'),
      api('/api/hub/admin/support/requests?limit=25'),
      api('/api/hub/admin/support/sessions?limit=15'),
      api('/api/support/session'),
    ]);
    if (m.status !== 200) { setAuthErr(true); return; }
    setMe(m.body);
    const ts: Tenant[] = (t.body?.tenants || []).filter((x: any) => !x.deleted_at);
    setTenants(ts);
    setForm((f) => (f.tenant ? f : { ...f, tenant: ts[0]?.slug || '' }));
    setRequests(r.body?.requests || []);
    setSessions(s.body?.sessions || []);
    setBanner(b.body?.impersonating ? b.body : null);
  }, []);

  useEffect(() => { load(); }, [load]);

  async function act(key: string, fn: () => Promise<void>) {
    setBusy(key); setMsg(null);
    try { await fn(); } catch (e: any) { setMsg({ kind: 'err', text: String(e?.message || e) }); }
    finally { setBusy(''); }
  }

  const fail = (b: any, fallback: string) => b?.error ? `${b.error}${b.detail ? ` — ${b.detail}` : ''}` : fallback;

  const createRequest = () => act('create', async () => {
    const { status, body } = await api('/api/hub/admin/support/request', {
      method: 'POST',
      body: JSON.stringify({
        tenant: form.tenant,
        target_email: form.target_email || undefined,
        reason: form.reason,
        ticket_ref: form.ticket_ref || undefined,
        ttl_seconds: Number(form.ttl_seconds) || 1800,
      }),
    });
    if (status !== 200) return setMsg({ kind: 'err', text: fail(body, 'request failed') });
    setMsg({
      kind: body.target_resolved ? 'ok' : 'err',
      text: body.target_resolved
        ? `Request ${body.support_access_request_id} opened — pending approval by a DIFFERENT operator.`
        : `Request opened, but "${form.target_email}" matched no user — it can be approved, yet impersonation will refuse it (no target).`,
    });
    setForm((f) => ({ ...f, reason: '', ticket_ref: '' }));
    await load();
  });

  const approve = (r: Req) => act(`ap-${r.id}`, async () => {
    const { status, body } = await api(`/api/hub/admin/support/request/${r.id}/approve`, { method: 'POST' });
    setMsg(status === 200
      ? { kind: 'ok', text: `Approved by ${me?.email} — dual control satisfied (requester ${r.requested_by_email}).` }
      : { kind: 'err', text: fail(body, 'approve failed') });
    await load();
  });

  const deny = (r: Req) => act(`dn-${r.id}`, async () => {
    const { status, body } = await api(`/api/hub/admin/support/request/${r.id}/deny`, {
      method: 'POST', body: JSON.stringify({ reason: 'denied from console' }),
    });
    setMsg(status === 200 ? { kind: 'ok', text: 'Request denied.' } : { kind: 'err', text: fail(body, 'deny failed') });
    await load();
  });

  const impersonate = (r: Req) => act(`im-${r.id}`, async () => {
    const { status, body } = await api('/api/support/impersonate', {
      method: 'POST', body: JSON.stringify({ request_id: r.id }),
    });
    if (status !== 200) { setMsg({ kind: 'err', text: fail(body, 'impersonation failed') }); return load(); }
    setAttempts([]);
    setMsg({ kind: 'ok', text: `Impersonating — read-only, ${body.expires_in}s, session ${body.support_session_id}.` });
    await load();
  });

  const attempt = (cls: string) => act(`at-${cls}`, async () => {
    const { status, body } = await api('/api/support/attempt', {
      method: 'POST', body: JSON.stringify({ action_class: cls }),
    });
    setAttempts((a) => [
      { cls, allowed: status === 200, detail: status === 200 ? 'allowed' : fail(body, `HTTP ${status}`) },
      ...a.filter((x) => x.cls !== cls),
    ]);
  });

  const endSession = (id: string) => act(`en-${id}`, async () => {
    const { status, body } = await api('/api/support/end', {
      method: 'POST', body: JSON.stringify({ support_session_id: id }),
    });
    setMsg(status === 200
      ? { kind: 'ok', text: `Session ended — ${body.revoked} underlying session(s) revoked.` }
      : { kind: 'err', text: fail(body, 'end failed') });
    if (body?.ended_own_session) setAttempts([]);   // ending another operator's leaves ours intact
    await load();
  });

  if (authErr) return (
    <>
      <h1>Support access &amp; impersonation</h1>
      <div className="card"><p className="err">Not signed in as an operator.</p><Link href="/login">→ Sign in</Link></div>
    </>
  );

  return (
    <>
      <h1>Support access &amp; impersonation</h1>
      <p className="muted">
        FOUNDATION_09 §12 — dual-control approval, ≤30&nbsp;min non-renewable read-only sessions, one active
        session per operator+tenant, a mandatory banner, and five hard-denied action classes.
      </p>

      {banner && (
        <div className="banner">
          <span className="dot" />
          <div>
            <strong>IMPERSONATION ACTIVE</strong> — operator <code>{banner.operator}</code> is acting as{' '}
            <code>{banner.acting_as}</code> in tenant <code>{banner.tenant}</code> ({banner.mode}).
            <div className="hint">
              Session <code>{banner.support_session_id}</code>. The token is read-only (<code>tw=false</code>):
              reads pass the target&apos;s own RLS, every write is denied.
            </div>
          </div>
        </div>
      )}

      {msg && <div className="card" style={{ padding: '12px 18px' }}><span className={msg.kind}>{msg.text}</span></div>}

      <div className="card">
        <h2>Open a support access request</h2>
        <p className="hint" style={{ marginTop: 0 }}>
          The requester is taken from your operator token — it is never a form field, so dual control cannot be
          gamed by naming someone else.
        </p>
        <div className="row">
          <div>
            <label>Tenant</label>
            <select value={form.tenant} onChange={(e) => setForm({ ...form, tenant: e.target.value })}>
              {tenants.map((t) => <option key={t.id} value={t.slug}>{t.slug} — {t.name} ({t.status})</option>)}
            </select>
          </div>
          <div>
            <label>Target user email</label>
            <input value={form.target_email} onChange={(e) => setForm({ ...form, target_email: e.target.value })} placeholder="u3@example.com" />
          </div>
        </div>
        <div className="row">
          <div>
            <label>Reason</label>
            <input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} placeholder="why access is needed" />
          </div>
          <div>
            <label>Ticket ref</label>
            <input value={form.ticket_ref} onChange={(e) => setForm({ ...form, ticket_ref: e.target.value })} placeholder="SUP-1234" />
          </div>
          <div>
            <label>TTL (s, max 1800)</label>
            <input value={form.ttl_seconds} onChange={(e) => setForm({ ...form, ttl_seconds: e.target.value })} />
          </div>
        </div>
        <div className="actions">
          <button onClick={createRequest} disabled={!!busy || !form.tenant || !form.reason}>
            {busy === 'create' ? '…' : 'Open request'}
          </button>
          <span className="muted">
            as {me?.email} <span className="badge role">{me?.role}</span>
          </span>
        </div>
      </div>

      <div className="card">
        <h2>Access requests</h2>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th className="entity">tenant / reason</th><th>target</th><th>status</th>
                <th className="dual">dual control (requester → approver)</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => {
                const mine = me?.operator_id === r.requested_by;
                return (
                  <tr key={r.id}>
                    <td className="entity">
                      {r.tenant_slug}
                      <div className="hint" style={{ marginTop: 2 }}>{r.reason}{r.ticket_ref ? ` · ${r.ticket_ref}` : ''}</div>
                    </td>
                    <td>{r.target_email || <span className="muted">— no target</span>}</td>
                    <td><span className={`badge ${statusBadge(r.status)}`}>{r.status}</span></td>
                    <td className="dual">
                      <div className="hint" style={{ margin: '0 0 6px' }}>
                        {r.requested_by_email}{mine ? ' (you)' : ''} → {r.approved_by_email || 'unapproved'}
                      </div>
                      {r.status === 'pending' && mine && (
                        <span className="tag" title="§12 C1: requester ≠ approver">
                          you opened this — another operator must approve
                        </span>
                      )}
                      {r.status === 'pending' && !mine && (
                        <span className="rowline" style={{ display: 'flex', gap: 8 }}>
                          <button className="tiny" onClick={() => approve(r)} disabled={!!busy}>
                            {busy === `ap-${r.id}` ? '…' : 'Approve'}
                          </button>
                          <button className="tiny secondary" onClick={() => deny(r)} disabled={!!busy}>Deny</button>
                        </span>
                      )}
                      {r.status === 'approved' && (
                        <button className="tiny" onClick={() => impersonate(r)} disabled={!!busy || !r.target_user_id}
                          title={r.target_user_id ? 'start a read-only impersonation session' : 'no target user resolved'}>
                          {busy === `im-${r.id}` ? '…' : 'Impersonate'}
                        </button>
                      )}
                      {r.status === 'consumed' && r.active_support_session_id && (
                        <span className="badge ok">session live</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!requests.length && <tr><td colSpan={4} className="muted">no requests yet</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="hint">
          Approve is withheld on your own requests because the Hub would refuse it anyway
          (<code>SELF_APPROVAL_DENIED</code>) — the approver is derived from the approving operator&apos;s live
          session inside the database function, so this is a real two-person control, not a UI convention.
        </p>
      </div>

      <div className="card">
        <h2>Prohibited-action gate</h2>
        {banner ? (
          <>
            <p className="hint" style={{ marginTop: 0 }}>
              Probe an action class against the live session. The five §12 classes hard-deny with 403 and the
              denial is written to the tenant&apos;s audit chain <em>before</em> the rejection is returned.
            </p>
            <div className="actions">
              {PROHIBITED.map((c) => (
                <button key={c} className="tiny danger" onClick={() => attempt(c)} disabled={!!busy}>{c}</button>
              ))}
              {BENIGN.map((c) => (
                <button key={c} className="tiny secondary" onClick={() => attempt(c)} disabled={!!busy}>{c}</button>
              ))}
            </div>
            {attempts.length > 0 && (
              <table>
                <thead><tr><th>action class</th><th>result</th></tr></thead>
                <tbody>
                  {attempts.map((a) => (
                    <tr key={a.cls}>
                      <td>{a.cls}</td>
                      <td className={a.allowed ? 'success' : 'denied'}>{a.allowed ? 'allowed' : a.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        ) : (
          <p className="muted">No impersonation session. Approve a request (as a different operator) and start one.</p>
        )}
      </div>

      <div className="card">
        <h2>Support sessions</h2>
        <div className="scroll">
          <table>
            <thead>
              <tr><th>tenant</th><th>operator</th><th>acting as</th><th>mode</th><th>status</th><th>expires</th><th /></tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id}>
                  <td>{s.tenant_slug}</td>
                  <td className="muted">{s.operator_email}</td>
                  <td className="muted">{s.target_email || '—'}</td>
                  <td>{s.mode}</td>
                  <td>
                    <span className={`badge ${s.status === 'active' ? (s.past_ttl ? 'wait' : 'ok') : 'off'}`}>
                      {s.status}{s.past_ttl ? ' · past TTL' : ''}
                    </span>
                  </td>
                  <td className="muted">{ago(s.expires_at)}</td>
                  <td>
                    {s.status === 'active' && (
                      <button className="tiny danger" onClick={() => endSession(s.id)} disabled={!!busy}>
                        {busy === `en-${s.id}` ? '…' : 'End'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {!sessions.length && <tr><td colSpan={7} className="muted">no sessions yet</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="hint">
          Sessions are non-renewable and capped at 30 minutes; one active session per operator+tenant. Ending a
          session cascades the group-5 revocation to the impersonated session tree.
        </p>
      </div>
    </>
  );
}
