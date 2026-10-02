'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';

// FOUNDATION_14 — rate-limit enforcement. Reads open to support|ops|admin; policy edits, tenant
// overrides and bucket resets are ops|admin + step-up (the Hub enforces; this page mirrors it).

type Me = { role: string; acr: string };
type Policy = { policy_key: string; scope: string; limit_per_window: number; window_seconds: number; burst: number; description: string; updated_at: string };
type Override = { id: string; tenant_slug: string; policy_key: string; limit_per_window: number; window_seconds: number; reason: string | null; created_at: string; created_by_email: string | null };
type Episode = { policy_key: string; bucket_key: string; tenant_slug: string | null; window_start: string; first_denied_at: string };
type Status = { store: string; allowed: number; denied: number; store_errors: number; failed_open: number; last_error: string | null; last_error_at: string | null; cache_ms: number };
type Data = { enabled: boolean; status: Status; policies: Policy[]; overrides: Override[]; episodes: Episode[] };

async function api(url: string, init?: RequestInit) {
  const r = await fetch(url, { ...init, headers: init?.body ? { 'content-type': 'application/json' } : undefined, cache: 'no-store' });
  return { status: r.status, body: await r.json().catch(() => null) };
}
const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—');
const rate = (limit: number, win: number) => `${limit} / ${win >= 60 && win % 60 === 0 ? `${win / 60} min` : `${win}s`}`;
// What a bucket key protects, in operator terms (keys are `<policy>:<kind>:<subject>`).
const subject = (k: string) => k.replace(/^[a-z_]+:/, '').replace(/^ip:/, 'IP ').replace(/^tenant:/, 'tenant ').replace(/^operator:/, 'operator ').replace(/^user:/, 'user ');

export default function RateLimits() {
  const [me, setMe] = useState<Me | null>(null);
  const [authErr, setAuthErr] = useState(false);
  const [data, setData] = useState<Data | null>(null);
  const [tenants, setTenants] = useState<string[]>([]);
  const [edit, setEdit] = useState<Record<string, { limit: string; window: string; burst: string }>>({});
  const [ov, setOv] = useState({ tenant: '', policy_key: 'api_tenant', limit: '', window: '60', reason: '' });
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const canWrite = !!me && ['ops', 'admin'].includes(me.role) && me.acr === 'mfa';

  const load = useCallback(async () => {
    const m = await api('/api/hub/operator/me');
    if (m.status !== 200) { setAuthErr(true); return; }
    setMe(m.body);
    const [d, t] = await Promise.all([api('/api/hub/admin/rate-limits'), api('/api/hub/admin/tenants')]);
    if (d.status === 200) {
      setData(d.body);
      setEdit(Object.fromEntries(d.body.policies.map((p: Policy) => [p.policy_key, { limit: String(p.limit_per_window), window: String(p.window_seconds), burst: String(p.burst) }])));
    }
    const live = (t.body?.tenants || []).filter((x: any) => !x.deleted_at).map((x: any) => x.slug);
    setTenants(live); setOv((o) => (o.tenant ? o : { ...o, tenant: live[0] || '' }));
  }, []);
  useEffect(() => { load(); }, [load]);

  const fail = (b: any, f: string) => (b?.error ? `${b.error}${b.detail ? ` — ${b.detail}` : ''}` : f);
  async function act(key: string, url: string, body: any, ok: (b: any) => string) {
    setBusy(key); setMsg(null);
    const { status, body: b } = await api(url, { method: 'POST', body: JSON.stringify(body) });
    setMsg(status === 200 ? { kind: 'ok', text: ok(b) } : { kind: 'err', text: fail(b, `HTTP ${status}`) });
    setBusy(''); await load();
  }

  if (authErr) return (<><h1>Rate limits</h1><div className="card"><p className="err">Not signed in as an operator.</p><Link href="/login">→ Sign in</Link></div></>);
  if (!data) return (<><h1>Rate limits</h1><p className="muted">Loading…</p></>);
  const s = data.status;

  return (
    <>
      <h1>Rate limits</h1>
      <p className="muted">
        GCRA token buckets. Login and webhook ingress are limited per client IP; authenticated traffic per principal
        <em> and</em> per tenant, so one tenant cannot starve the others. A store outage fails open and is counted here.
      </p>

      {!canWrite && me && (
        <div className="banner"><span className="dot" /><div>
          <strong>READ-ONLY</strong> — changing limits, overrides or buckets needs <code>ops</code>/<code>admin</code> <em>and</em> step-up;
          you are <code>{me.role}</code> · <code>acr={me.acr}</code>.
        </div></div>
      )}
      {s.failed_open > 0 && (
        <div className="banner danger"><span className="dot" /><div>
          <strong>LIMITER FAILING OPEN</strong> — {s.failed_open} request(s) were allowed without a limit check because the {s.store} store errored.
          <div className="hint">Last error {when(s.last_error_at)}: <code>{s.last_error}</code></div>
        </div></div>
      )}
      {msg && <div className="card" style={{ padding: '12px 18px' }}><span className={msg.kind}>{msg.text}</span></div>}

      <div className="card">
        <h2>Limiter</h2>
        <div className="gate">
          <div className="g">Enforcement</div><div>{data.enabled ? <span className="badge ok">on</span> : <span className="badge bad">OFF (RATE_LIMIT_ENABLED=false)</span>}</div>
          <div className="g">Store</div><div><code>{s.store}</code> <span className="muted">{s.store === 'postgres' ? '— local/default; production uses upstash' : ''}</span></div>
          <div className="g">This Hub instance</div><div className="muted">{s.allowed} allowed · {s.denied} denied · {s.failed_open} failed open</div>
          <div className="g">Policy cache</div><div className="muted">{s.cache_ms / 1000}s — edits apply at once on the Hub that took them, on others within this window</div>
        </div>
      </div>

      <div className="card">
        <h2>Policies</h2>
        <div className="scroll">
          <table>
            <thead><tr><th className="entity">policy</th><th>keyed by</th><th>sustained</th><th>burst</th><th>capacity</th>{canWrite && <th className="dual">edit (limit · window s · burst)</th>}</tr></thead>
            <tbody>
              {data.policies.map((p) => {
                const e = edit[p.policy_key];
                return (
                  <tr key={p.policy_key}>
                    <td className="entity">{p.policy_key}<div className="hint" style={{ marginTop: 2 }}>{p.description}</div></td>
                    <td className="muted">{p.policy_key.startsWith('auth') || p.policy_key.startsWith('webhook') ? 'client IP' : p.policy_key === 'api_tenant' ? 'tenant' : 'principal'}</td>
                    <td>{rate(p.limit_per_window, p.window_seconds)}</td>
                    <td>{p.burst}</td>
                    <td>{p.limit_per_window + p.burst} at once</td>
                    {canWrite && e && (
                      <td className="dual">
                        <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          {(['limit', 'window', 'burst'] as const).map((f) => (
                            <input key={f} style={{ width: 70, padding: '4px 6px' }} value={e[f]}
                              onChange={(ev) => setEdit({ ...edit, [p.policy_key]: { ...e, [f]: ev.target.value } })} />
                          ))}
                          <button className="tiny" disabled={!!busy} onClick={() => act(`p${p.policy_key}`, `/api/hub/admin/rate-limits/policies/${p.policy_key}`,
                            { limit_per_window: Number(e.limit), window_seconds: Number(e.window), burst: Number(e.burst) }, () => `${p.policy_key} updated.`)}>Save</button>
                        </span>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <h2>Tenant overrides</h2>
        <div className="scroll">
          <table>
            <thead><tr><th>tenant</th><th>policy</th><th>limit</th><th className="entity">reason</th><th>set by</th></tr></thead>
            <tbody>
              {data.overrides.map((o) => (
                <tr key={o.id}>
                  <td>{o.tenant_slug}</td><td>{o.policy_key}</td><td>{rate(o.limit_per_window, o.window_seconds)}</td>
                  <td className="entity muted">{o.reason}</td><td className="muted">{o.created_by_email}<div className="hint" style={{ marginTop: 2 }}>{when(o.created_at)}</div></td>
                </tr>
              ))}
              {!data.overrides.length && <tr><td colSpan={5} className="muted">no overrides — every tenant gets the catalog limits</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="hint">Overrides are history: a newer one supersedes the previous. Burst scales with the overridden limit.</p>
        {canWrite && (
          <>
            <div className="row">
              <div><label>Tenant</label><select value={ov.tenant} onChange={(e) => setOv({ ...ov, tenant: e.target.value })}>{tenants.map((t) => <option key={t}>{t}</option>)}</select></div>
              <div><label>Policy</label><select value={ov.policy_key} onChange={(e) => setOv({ ...ov, policy_key: e.target.value })}>
                {data.policies.filter((p) => p.policy_key.startsWith('api')).map((p) => <option key={p.policy_key}>{p.policy_key}</option>)}</select></div>
              <div><label>Limit</label><input value={ov.limit} onChange={(e) => setOv({ ...ov, limit: e.target.value })} placeholder="e.g. 600" /></div>
              <div><label>Window (s)</label><input value={ov.window} onChange={(e) => setOv({ ...ov, window: e.target.value })} /></div>
            </div>
            <div className="row"><div><label>Reason</label><input value={ov.reason} onChange={(e) => setOv({ ...ov, reason: e.target.value })} placeholder="ticket / why" /></div></div>
            <div className="actions">
              <button disabled={!!busy || !ov.tenant || !ov.limit || !ov.reason} onClick={() => act('ov', '/api/hub/admin/rate-limits/overrides',
                { tenant: ov.tenant, policy_key: ov.policy_key, limit_per_window: Number(ov.limit), window_seconds: Number(ov.window), reason: ov.reason },
                (b) => `Override set: ${b.tenant} ${b.policy_key} → ${rate(b.limit_per_window, b.window_seconds)}.`)}>Set override</button>
            </div>
          </>
        )}
      </div>

      <div className="card">
        <h2>Throttling episodes</h2>
        <div className="scroll">
          <table>
            <thead><tr><th>policy</th><th className="entity">who</th><th>tenant</th><th>first denied</th><th /></tr></thead>
            <tbody>
              {data.episodes.map((e) => (
                <tr key={e.bucket_key + e.window_start}>
                  <td>{e.policy_key}</td><td className="entity">{e.tenant_slug && e.bucket_key.includes(':tenant:') ? `tenant ${e.tenant_slug}` : subject(e.bucket_key)}</td><td className="muted">{e.tenant_slug || '—'}</td>
                  <td className="muted">{when(e.first_denied_at)}</td>
                  <td>{canWrite && <button className="tiny secondary" disabled={!!busy} onClick={() => act(`r${e.bucket_key}`, '/api/hub/admin/rate-limits/reset',
                    { bucket_key: e.bucket_key }, (b) => (b.cleared ? `Cleared ${subject(b.bucket_key)}.` : `${subject(b.bucket_key)} had already refilled.`))}>Reset</button>}</td>
                </tr>
              ))}
              {!data.episodes.length && <tr><td colSpan={5} className="muted">nobody has been throttled</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="hint">One row per bucket per window, written on the first denial — a flood of 429s does not become a flood of rows. Reset is audited: it bypasses a control.</p>
      </div>
    </>
  );
}
