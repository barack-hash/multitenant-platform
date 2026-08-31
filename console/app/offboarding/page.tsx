'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';

// FOUNDATION_08 — the tenant-level offboarding state machine. DESTRUCTIVE: the terminal transition
// deletes a tenant and leaves only a tombstone. Everything routes through the BFF proxy; the whole
// surface is ops|admin AND step-up (acr='mfa'), so a password-only session is refused by the Hub.

const PHASES = [
  'requested', 'approved', 'freeze_started', 'freeze_completed', 'export_started',
  'export_completed', 'retention_wait', 'purge_started', 'purge_completed', 'tombstoned',
] as const;

// The forward edges the DB will accept (app.advance_offboarding); 'failed' is reachable from any
// non-terminal phase. Mirrored here so the panel offers the valid move instead of guessing.
const NEXT: Record<string, string | null> = {
  requested: 'approved', approved: 'freeze_started', freeze_started: 'freeze_completed',
  freeze_completed: 'export_started', export_started: 'export_completed',
  export_completed: 'retention_wait', retention_wait: 'purge_started',
  purge_started: 'purge_completed', purge_completed: 'tombstoned',
  tombstoned: null, failed: null,
};
// Transitions the console makes you type the tenant slug to arm. 'failed' is included: aborting is
// terminal for the job and strands the tenant mid-lifecycle (frozen/suspended with no live job).
const DESTRUCTIVE = new Set(['purge_started', 'purge_completed', 'tombstoned', 'failed']);

type Me = { operator_id: string; email: string; role: string; acr: string };
type Tenant = { id: string; slug: string; name: string; status: string; deleted_at: string | null; live_offboarding_job_id: string | null; legal_hold_active: boolean };
type Policy = { id: string; policy_key: string; retention_class: string; retention_days: number; purge_mode: string; description: string };
type Job = {
  id: string; tenant_slug: string; tenant_status: string; phase: string; reason: string | null;
  requested_at: string; scheduled_purge_after: string | null; failure_reason: string | null;
  requested_by_email: string | null; approved_by_email: string | null;
  retention_policy_key: string | null; retention_days: number | null;
  legal_hold_active: boolean; completion_ready: boolean;
};
type Hold = { id: string; reason: string; reference: string | null; status: string; placed_at: string; released_at: string | null };
type Detail = {
  job: any;
  receipts: { export: any | null; cache: any | null; search: any | null };
  completion_ready: boolean; legal_hold_active: boolean;
  tenant_slug: string | null; tenant_status: string | null;
  retention_policy: { policy_key: string; retention_class: string; retention_days: number } | null;
  legal_holds: Hold[];
};

async function api(url: string, init?: RequestInit) {
  const r = await fetch(url, {
    ...init,
    headers: init?.body ? { 'content-type': 'application/json' } : undefined,
    cache: 'no-store',
  });
  const body = await r.json().catch(() => null);
  return { status: r.status, body };
}

const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : '—');
const yes = (b: boolean, ok = 'ok', bad = 'bad') => <span className={`badge ${b ? ok : bad}`}>{b ? 'yes' : 'no'}</span>;

export default function Offboarding() {
  const [me, setMe] = useState<Me | null>(null);
  const [authErr, setAuthErr] = useState(false);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [detail, setDetail] = useState<Detail | null>(null);
  const [confirmSlug, setConfirmSlug] = useState('');
  const [holdReason, setHoldReason] = useState('litigation hold');
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [form, setForm] = useState({ tenant: '', reason: 'customer_churn', retention_policy_key: 'offboarding-default' });

  const gated = !!me && (!['ops', 'admin'].includes(me.role) || me.acr !== 'mfa');

  const loadDetail = useCallback(async (id: string) => {
    if (!id) { setDetail(null); return; }
    const { status, body } = await api(`/api/hub/admin/offboarding/${id}`);
    setDetail(status === 200 ? body : null);
  }, []);

  const load = useCallback(async () => {
    const m = await api('/api/hub/operator/me');
    if (m.status !== 200) { setAuthErr(true); return; }
    setMe(m.body);
    if (!['ops', 'admin'].includes(m.body.role) || m.body.acr !== 'mfa') return;
    const [t, p, j] = await Promise.all([
      api('/api/hub/admin/tenants'),
      api('/api/hub/admin/retention-policies'),
      api('/api/hub/admin/offboarding?limit=25'),
    ]);
    const ts: Tenant[] = t.body?.tenants || [];
    setTenants(ts);
    setPolicies(p.body?.policies || []);
    setJobs(j.body?.jobs || []);
    setForm((f) => (f.tenant ? f : { ...f, tenant: ts.find((x) => !x.deleted_at && !x.live_offboarding_job_id)?.slug || ts[0]?.slug || '' }));
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadDetail(selected); }, [selected, loadDetail]);

  const fail = (b: any, f: string) => (b?.error ? `${b.error}${b.detail ? ` — ${b.detail}` : ''}` : f);

  async function act(key: string, fn: () => Promise<void>) {
    setBusy(key); setMsg(null);
    try { await fn(); } catch (e: any) { setMsg({ kind: 'err', text: String(e?.message || e) }); }
    finally { setBusy(''); }
  }
  const refresh = async (id?: string) => { await load(); await loadDetail(id ?? selected); };

  const start = () => act('start', async () => {
    const { status, body } = await api('/api/hub/admin/offboarding/start', {
      method: 'POST', body: JSON.stringify(form),
    });
    if (status !== 200) return setMsg({ kind: 'err', text: fail(body, 'start failed') });
    setMsg({ kind: 'ok', text: `Job ${body.offboarding_job_id} opened for ${form.tenant} — phase ${body.phase}.` });
    setSelected(body.offboarding_job_id);
    await refresh(body.offboarding_job_id);
  });

  const advance = (to: string) => act(`adv-${to}`, async () => {
    const { status, body } = await api(`/api/hub/admin/offboarding/${selected}/advance`, {
      method: 'POST', body: JSON.stringify({ to }),
    });
    setMsg(status === 200
      ? { kind: 'ok', text: `Phase → ${body.phase}` }
      : { kind: 'err', text: `${fail(body, 'advance failed')} — the gate for "${to}" is not satisfied` });
    setConfirmSlug('');
    await refresh();
  });

  const exportVerify = () => act('exp', async () => {
    const { status, body } = await api(`/api/hub/admin/offboarding/${selected}/export-verify`, { method: 'POST', body: '{}' });
    setMsg(status === 200
      ? { kind: 'ok', text: 'Export verification receipt written (immutable, one per job).' }
      : { kind: 'err', text: fail(body, 'export-verify failed') });
    await refresh();
  });

  const purge = () => act('purge', async () => {
    const { status, body } = await api(`/api/hub/admin/offboarding/${selected}/purge`, { method: 'POST' });
    setMsg(status === 200
      ? { kind: 'ok', text: `Data-plane purge ran (job ${body.purge_job_id}) — cache + search receipts written.` }
      : { kind: 'err', text: fail(body, 'purge failed') });
    setConfirmSlug('');
    await refresh();
  });

  const placeHold = () => act('hold', async () => {
    const { status, body } = await api('/api/hub/admin/legal-hold', {
      method: 'POST', body: JSON.stringify({ tenant: detail?.tenant_slug, reason: holdReason }),
    });
    setMsg(status === 200
      ? { kind: 'ok', text: `Legal hold ${body.legal_hold_id} placed — purge progression is now blocked.` }
      : { kind: 'err', text: fail(body, 'legal hold failed') });
    await refresh();
  });

  const releaseHold = (id: string) => act(`rel-${id}`, async () => {
    const { status, body } = await api(`/api/hub/admin/legal-hold/${id}/release`, { method: 'POST' });
    setMsg(status === 200
      ? { kind: 'ok', text: `Hold released (${body.released} row) — purge progression unblocked.` }
      : { kind: 'err', text: fail(body, 'release failed') });
    await refresh();
  });

  if (authErr) return (
    <>
      <h1>Tenant offboarding</h1>
      <div className="card"><p className="err">Not signed in as an operator.</p><Link href="/login">→ Sign in</Link></div>
    </>
  );

  if (gated) return (
    <>
      <h1>Tenant offboarding</h1>
      <div className="banner danger">
        <span className="dot" />
        <div>
          <strong>{!['ops', 'admin'].includes(me!.role) ? 'OPERATOR_ROLE_REQUIRED' : 'MFA_REQUIRED'}</strong>
          {!['ops', 'admin'].includes(me!.role)
            ? <> — the lifecycle surface is restricted to <code>ops</code> and <code>admin</code>; you are <code>{me!.role}</code>.</>
            : <> — this is a destructive surface, so every call needs step-up (<code>acr=mfa</code>). Your session is
                password-only, and the Hub will refuse each action.</>}
          <div className="hint">Sign in again with TOTP or a passkey to raise the session assurance.</div>
        </div>
      </div>
      <div className="card"><Link href="/login">→ Re-authenticate</Link></div>
    </>
  );

  const phase: string = detail?.job?.phase ?? '';
  const next = NEXT[phase] ?? null;
  const terminal = phase === 'tombstoned' || phase === 'failed';
  const idx = PHASES.indexOf(phase as any);
  const needConfirm = (to: string) => DESTRUCTIVE.has(to) && confirmSlug !== detail?.tenant_slug;
  const retentionElapsed = !detail?.job?.scheduled_purge_after || new Date(detail.job.scheduled_purge_after) <= new Date();

  return (
    <>
      <h1>Tenant offboarding</h1>
      <p className="muted">
        FOUNDATION_08 — freeze → export → retention → purge → tombstone, with legal-hold gating and mandatory
        verification receipts. The terminal transition deletes a tenant permanently.
      </p>

      <div className="banner danger">
        <span className="dot" />
        <div>
          <strong>DESTRUCTIVE SURFACE</strong> — <code>tombstoned</code> sets the tenant <code>deleted</code> and
          leaves only an unremovable tombstone. Demo against the throwaway tenant <code>tenant-three</code>.
          <div className="hint">
            Signed in as {me?.email} · <span className="badge role">{me?.role}</span>{' '}
            <span className="badge mfa">acr=mfa</span> — step-up satisfied.
          </div>
        </div>
      </div>

      {msg && <div className="card" style={{ padding: '12px 18px' }}><span className={msg.kind}>{msg.text}</span></div>}

      <div className="card">
        <h2>Start an offboarding job</h2>
        <div className="row">
          <div>
            <label>Tenant</label>
            <select value={form.tenant} onChange={(e) => setForm({ ...form, tenant: e.target.value })}>
              {tenants.map((t) => (
                <option key={t.id} value={t.slug} disabled={!!t.deleted_at || !!t.live_offboarding_job_id}>
                  {t.slug} ({t.status}){t.live_offboarding_job_id ? ' — job already live' : ''}{t.deleted_at ? ' — deleted' : ''}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label>Reason</label>
            <input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
          </div>
          <div>
            <label>Retention policy (§15)</label>
            <select value={form.retention_policy_key} onChange={(e) => setForm({ ...form, retention_policy_key: e.target.value })}>
              {policies.map((p) => (
                <option key={p.id} value={p.policy_key}>{p.policy_key} — {p.retention_class}, {p.retention_days}d</option>
              ))}
            </select>
          </div>
        </div>
        <div className="actions">
          <button onClick={start} disabled={!!busy || !form.tenant}>{busy === 'start' ? '…' : 'Start offboarding'}</button>
          <span className="hint" style={{ margin: 0 }}>
            One live job per tenant; a job without a retention policy can never enter <code>retention_wait</code>.
          </span>
        </div>
      </div>

      <div className="card">
        <h2>Offboarding jobs</h2>
        <div className="scroll">
          <table>
            <thead><tr><th>tenant</th><th>phase</th><th>tenant status</th><th>hold</th><th>receipts</th><th>opened</th><th /></tr></thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id} style={j.id === selected ? { background: 'rgba(91,157,255,.07)' } : undefined}>
                  <td>{j.tenant_slug}</td>
                  <td><span className={`badge ${j.phase === 'tombstoned' ? 'off' : j.phase === 'failed' ? 'bad' : 'wait'}`}>{j.phase}</span></td>
                  <td className="muted">{j.tenant_status}</td>
                  <td>{j.legal_hold_active ? <span className="badge bad">held</span> : <span className="muted">—</span>}</td>
                  <td>{j.completion_ready ? <span className="badge ok">complete</span> : <span className="muted">partial</span>}</td>
                  <td className="muted">{when(j.requested_at)}</td>
                  <td><button className="tiny secondary" onClick={() => setSelected(j.id)}>Inspect</button></td>
                </tr>
              ))}
              {!jobs.length && <tr><td colSpan={7} className="muted">no offboarding jobs</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {detail && (
        <div className="card">
          <h2>Job {detail.tenant_slug} · {phase}</h2>

          <div className="phases">
            {PHASES.map((p, i) => (
              <span key={p} className={`p ${p === phase ? 'now' : p === next ? 'next' : idx >= 0 && i < idx ? 'done' : ''}`}>{p}</span>
            ))}
            {phase === 'failed' && <span className="p dead">failed</span>}
          </div>

          <div className="gate">
            <div className="g">Tenant status</div><div><span className="badge off">{detail.tenant_status}</span></div>
            <div className="g">Retention policy</div>
            <div>
              {detail.retention_policy
                ? <>{detail.retention_policy.policy_key} <span className="tag">{detail.retention_policy.retention_class} · {detail.retention_policy.retention_days}d</span></>
                : <span className="badge bad">none — retention_wait will be refused</span>}
            </div>
            <div className="g">Purge eligible after</div>
            <div>
              {detail.job.scheduled_purge_after
                ? <>{when(detail.job.scheduled_purge_after)} {retentionElapsed ? <span className="badge ok">elapsed</span> : <span className="badge wait">waiting</span>}</>
                : <span className="muted">not scheduled yet (set on entering retention_wait)</span>}
            </div>
            <div className="g">Legal hold</div>
            <div>{detail.legal_hold_active ? <span className="badge bad">ACTIVE — purge blocked</span> : <span className="badge ok">clear</span>}</div>
            <div className="g">Export receipt</div>
            <div>
              {detail.receipts.export
                ? <><span className="badge ok">verified</span> <span className="muted">{when(detail.receipts.export.verified_at)}</span></>
                : <span className="badge bad">missing — export_completed blocked</span>}
            </div>
            <div className="g">Cache purge receipt</div>
            <div>{detail.receipts.cache ? <span className="badge ok">written</span> : <span className="badge bad">missing</span>}</div>
            <div className="g">Search purge receipt</div>
            <div>{detail.receipts.search ? <span className="badge ok">written</span> : <span className="badge bad">missing</span>}</div>
            <div className="g">Completion ready</div><div>{yes(detail.completion_ready)}</div>
          </div>

          {!terminal && (
            <>
              <label>Type the tenant slug to arm the destructive steps (purge · tombstone · abort)</label>
              <input value={confirmSlug} onChange={(e) => setConfirmSlug(e.target.value)} placeholder={detail.tenant_slug || ''} />
            </>
          )}

          <div className="actions">
            {next && (
              <button onClick={() => advance(next)} disabled={!!busy || needConfirm(next)}>
                {busy === `adv-${next}` ? '…' : `Advance → ${next}`}
              </button>
            )}
            {terminal && <span className="muted">{phase} is terminal — no further transitions.</span>}
            {phase === 'export_started' && !detail.receipts.export && (
              <button className="secondary" onClick={exportVerify} disabled={!!busy}>
                {busy === 'exp' ? '…' : 'Record export verification'}
              </button>
            )}
            {phase === 'purge_started' && (
              <button className="danger" onClick={purge} disabled={!!busy || confirmSlug !== detail.tenant_slug}>
                {busy === 'purge' ? '…' : 'Run data-plane purge'}
              </button>
            )}
            {!terminal && (
              <button className="ghost" onClick={() => advance('failed')} disabled={!!busy || needConfirm('failed')}>
                Abort → failed
              </button>
            )}
          </div>
          {!terminal && needConfirm('failed') && (
            <p className="hint">Destructive steps stay disabled until the slug matches <code>{detail.tenant_slug}</code>; every attempt disarms them again.</p>
          )}

          <h2 style={{ marginTop: 26 }}>Legal holds</h2>
          <div className="scroll">
            <table>
              <thead><tr><th>reason</th><th>status</th><th>placed</th><th>released</th><th /></tr></thead>
              <tbody>
                {detail.legal_holds.map((h) => (
                  <tr key={h.id}>
                    <td>{h.reason}{h.reference ? <span className="tag" style={{ marginLeft: 8 }}>{h.reference}</span> : null}</td>
                    <td><span className={`badge ${h.status === 'active' ? 'bad' : 'off'}`}>{h.status}</span></td>
                    <td className="muted">{when(h.placed_at)}</td>
                    <td className="muted">{when(h.released_at)}</td>
                    <td>
                      {h.status === 'active' && (
                        <button className="tiny secondary" onClick={() => releaseHold(h.id)} disabled={!!busy}>
                          {busy === `rel-${h.id}` ? '…' : 'Release'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {!detail.legal_holds.length && <tr><td colSpan={5} className="muted">no holds on this tenant</td></tr>}
              </tbody>
            </table>
          </div>
          <div className="row" style={{ marginTop: 4 }}>
            <div>
              <label>Place a hold (blocks purge progression)</label>
              <input value={holdReason} onChange={(e) => setHoldReason(e.target.value)} />
            </div>
            <div style={{ flex: '0 0 auto', display: 'flex', alignItems: 'flex-end' }}>
              <button className="secondary" style={{ marginTop: 0 }} onClick={placeHold} disabled={!!busy || !holdReason}>
                {busy === 'hold' ? '…' : 'Place legal hold'}
              </button>
            </div>
          </div>
          <p className="hint">
            Precedence is legal hold first (§15): while a hold is active, <code>purge_started</code>,{' '}
            <code>purge_completed</code> and <code>tombstoned</code> all raise <code>LEGAL_HOLD_ACTIVE</code>.
          </p>
        </div>
      )}
    </>
  );
}
