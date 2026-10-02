'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';

// MASTER_PLAN §11 / FOUNDATION_13 — feature-flag governance. Reads + explain are open to
// support|ops|admin; every write is ops|admin AND step-up (the Hub enforces both; this page just
// renders the same matrix so nobody discovers it as a 403).

const ENVS = ['dev', 'staging', 'prod'] as const;
const TIERS = ['tenant_app', 'tenant', 'app', 'cohort'] as const;
const TIER_LABEL: Record<string, string> = {
  kill_switch: '1 · kill switch', tenant_app: '2 · tenant+app', tenant: '3 · tenant', app: '4 · app',
  cohort: '5 · cohort', default: '6 · env default', flag_inactive: 'flag inactive', no_environment: 'not configured',
};

type Me = { operator_id: string; email: string; role: string; acr: string };
type EnvSummary = { default_value: any; kill_engaged: boolean; kill_reason: string | null };
type FlagRow = {
  id: string; flag_key: string; description: string; flag_type: string; owner_team: string; risk_level: string;
  status: string; variants: string[] | null; off_value: any; environments: Record<string, EnvSummary>; active_rules: number;
};
type Env = { environment: string; default_value: any; kill_engaged: boolean; kill_reason: string | null; killed_by_email: string | null; killed_at: string | null };
type Rule = {
  id: string; environment: string; target_type: string; target_ref: string; tenant_slug: string | null; value: any;
  priority: number; start_at: string | null; end_at: string | null; status: string; live: boolean; created_by_email: string | null; created_at: string;
};
type Detail = {
  flag: FlagRow; environments: Env[]; rollouts: Rule[];
  audit: { action: string; environment: string | null; occurred_at: string; actor_email: string | null }[];
  decisions: { seq: number; environment: string; tenant_slug: string | null; app_key: string | null; value: any; tier: string; reason: string; decided_at: string }[];
};
type Explain = {
  decision: { value: any; tier: string; reason: string; rule_id: string | null };
  candidates: { rule_id: string; target_type: string; target_ref: string; value: any; priority: number; eligible: boolean; skip_reason: string | null; selected: boolean }[];
};

async function api(url: string, init?: RequestInit) {
  const r = await fetch(url, { ...init, headers: init?.body ? { 'content-type': 'application/json' } : undefined, cache: 'no-store' });
  return { status: r.status, body: await r.json().catch(() => null) };
}
const show = (v: any) => (v === undefined || v === null ? '—' : typeof v === 'string' ? v : JSON.stringify(v));
const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—');
const riskBadge = (r: string) => (r === 'high' ? 'bad' : r === 'medium' ? 'wait' : 'off');
const choices = (f: FlagRow) => (f.flag_type === 'multivariate' ? (f.variants || []) : [true, false]);
const parseChoice = (f: FlagRow, s: string) => (f.flag_type === 'multivariate' ? s : s === 'true');
const target = (r: { target_type: string; target_ref: string; tenant_slug?: string | null }) =>
  r.target_type === 'tenant' ? r.tenant_slug || r.target_ref
    : r.target_type === 'tenant_app' ? `${r.tenant_slug || r.target_ref.split(':')[0]} · ${r.target_ref.split(':').slice(1).join(':')}`
    : r.target_type === 'cohort' ? `${r.target_ref.replace('pct:', '')}% of tenants` : r.target_ref;

export default function Flags() {
  const [me, setMe] = useState<Me | null>(null);
  const [authErr, setAuthErr] = useState(false);
  const [served, setServed] = useState('dev');
  const [flags, setFlags] = useState<FlagRow[]>([]);
  const [tenants, setTenants] = useState<{ slug: string; deleted_at: string | null }[]>([]);
  const [selected, setSelected] = useState('');
  const [detail, setDetail] = useState<Detail | null>(null);
  const [env, setEnv] = useState<string>('dev');
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [killReason, setKillReason] = useState('');
  const [rule, setRule] = useState({ target_type: 'tenant', tenant: '', app: '', percent: '10', value: '', priority: '100', status: 'active' });
  const [ex, setEx] = useState({ tenant: '', app: '' });
  const [explain, setExplain] = useState<Explain | null>(null);
  const [nf, setNf] = useState({ flag_key: '', description: '', flag_type: 'boolean', owner_team: '', risk_level: 'low', variants: 'control,variant', off_value: 'false' });

  const canWrite = !!me && ['ops', 'admin'].includes(me.role) && me.acr === 'mfa';
  const flag = detail?.flag;

  const loadDetail = useCallback(async (key: string) => {
    if (!key) return setDetail(null);
    const { status, body } = await api(`/api/hub/admin/flags/${encodeURIComponent(key)}`);
    setDetail(status === 200 ? body : null);
  }, []);
  const load = useCallback(async () => {
    const m = await api('/api/hub/operator/me');
    if (m.status !== 200) { setAuthErr(true); return; }
    setMe(m.body);
    const [f, t] = await Promise.all([api('/api/hub/admin/flags'), api('/api/hub/admin/tenants')]);
    setFlags(f.body?.flags || []); setServed(f.body?.environment || 'dev');
    const live = (t.body?.tenants || []).filter((x: any) => !x.deleted_at);
    setTenants(live);
    setRule((r) => (r.tenant ? r : { ...r, tenant: live[0]?.slug || '' }));
    setEx((e) => (e.tenant ? e : { ...e, tenant: live[0]?.slug || '' }));
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadDetail(selected); setExplain(null); }, [selected, loadDetail]);
  useEffect(() => { if (flag) setRule((r) => ({ ...r, value: String(choices(flag)[0]) })); }, [flag?.flag_key]); // eslint-disable-line

  const fail = (b: any, f: string) => (b?.error ? `${b.error}${b.detail ? ` — ${b.detail}` : ''}` : f);
  async function act(key: string, fn: () => Promise<{ status: number; body: any }>, ok: (b: any) => string) {
    setBusy(key); setMsg(null);
    try {
      const { status, body } = await fn();
      setMsg(status === 200 ? { kind: 'ok', text: ok(body) } : { kind: 'err', text: fail(body, `HTTP ${status}`) });
      await load(); await loadDetail(selected);
    } catch (e: any) { setMsg({ kind: 'err', text: String(e?.message || e) }); }
    finally { setBusy(''); }
  }
  const post = (path: string, body: any) => api(`/api/hub/admin/flags/${encodeURIComponent(selected)}${path}`, { method: 'POST', body: JSON.stringify(body) });

  const runExplain = async () => {
    setBusy('explain');
    const q = new URLSearchParams({ environment: env, tenant: ex.tenant, ...(ex.app ? { app: ex.app } : {}) });
    const { status, body } = await api(`/api/hub/admin/flags/${encodeURIComponent(selected)}/explain?${q}`);
    setBusy('');
    if (status === 200) setExplain(body); else { setExplain(null); setMsg({ kind: 'err', text: fail(body, 'explain failed') }); }
  };

  const createFlag = () => {
    setBusy('create'); setMsg(null);
    const variants = nf.flag_type === 'multivariate' ? nf.variants.split(',').map((s) => s.trim()).filter(Boolean) : null;
    const off = nf.flag_type === 'multivariate' ? nf.off_value : nf.off_value === 'true';
    api('/api/hub/admin/flags', { method: 'POST', body: JSON.stringify({ ...nf, variants, off_value: off }) }).then(async ({ status, body }) => {
      setBusy('');
      if (status !== 200) return setMsg({ kind: 'err', text: fail(body, 'create failed') });
      setMsg({ kind: 'ok', text: `Created ${body.flag_key} — every environment starts at off_value ${show(off)}.` });
      await load(); setSelected(body.flag_key);
    });
  };

  if (authErr) return (<><h1>Feature flags</h1><div className="card"><p className="err">Not signed in as an operator.</p><Link href="/login">→ Sign in</Link></div></>);

  const envRow = detail?.environments.find((e) => e.environment === env);
  const envRules = (detail?.rollouts || []).filter((r) => r.environment === env);

  return (
    <>
      <h1>Feature flags</h1>
      <p className="muted">
        MASTER_PLAN §11 — precedence: kill switch → tenant+app → tenant → app → cohort → environment default. Active,
        in-window rules only; lower priority wins within a tier; newest wins a tie. Every distinct decision is logged.
      </p>

      {!canWrite && me && (
        <div className="banner">
          <span className="dot" />
          <div>
            <strong>READ-ONLY</strong> — you can inspect and explain flags. Changing one needs <code>ops</code>/<code>admin</code>{' '}
            <em>and</em> step-up (<code>acr=mfa</code>); you are <code>{me.role}</code> · <code>acr={me.acr}</code>.
          </div>
        </div>
      )}

      {msg && <div className="card" style={{ padding: '12px 18px' }}><span className={msg.kind}>{msg.text}</span></div>}

      <div className="card">
        <h2>Flags <span className="tag" style={{ marginLeft: 8 }}>this Hub serves: {served}</span></h2>
        <div className="scroll">
          <table>
            <thead><tr><th className="entity">flag</th><th>risk</th><th>status</th>{ENVS.map((e) => <th key={e}>{e}</th>)}<th>rules</th><th /></tr></thead>
            <tbody>
              {flags.map((f) => (
                <tr key={f.id} style={f.flag_key === selected ? { background: 'rgba(91,157,255,.07)' } : undefined}>
                  <td className="entity">{f.flag_key}<div className="hint" style={{ marginTop: 2 }}>{f.description}</div></td>
                  <td><span className={`badge ${riskBadge(f.risk_level)}`}>{f.risk_level}</span></td>
                  <td><span className={`badge ${f.status === 'active' ? 'ok' : f.status === 'paused' ? 'wait' : 'off'}`}>{f.status}</span></td>
                  {ENVS.map((e) => (
                    <td key={e}>{f.environments[e]?.kill_engaged ? <span className="badge bad">KILLED</span> : <code>{show(f.environments[e]?.default_value)}</code>}</td>
                  ))}
                  <td className="muted">{f.active_rules}</td>
                  <td><button className="tiny secondary" onClick={() => setSelected(f.flag_key)}>Inspect</button></td>
                </tr>
              ))}
              {!flags.length && <tr><td colSpan={8} className="muted">no flags</td></tr>}
            </tbody>
          </table>
        </div>
        {canWrite && (
          <details>
            <summary>Create a flag</summary>
            <div className="row">
              <div><label>Key</label><input value={nf.flag_key} onChange={(e) => setNf({ ...nf, flag_key: e.target.value })} placeholder="hifz.new_thing" /></div>
              <div><label>Owner team</label><input value={nf.owner_team} onChange={(e) => setNf({ ...nf, owner_team: e.target.value })} /></div>
            </div>
            <div className="row">
              <div><label>Description</label><input value={nf.description} onChange={(e) => setNf({ ...nf, description: e.target.value })} /></div>
            </div>
            <div className="row">
              <div><label>Type</label>
                <select value={nf.flag_type} onChange={(e) => setNf({ ...nf, flag_type: e.target.value, off_value: e.target.value === 'multivariate' ? 'control' : 'false' })}>
                  <option value="boolean">boolean</option><option value="multivariate">multivariate</option><option value="kill_switch">kill_switch</option>
                </select></div>
              <div><label>Risk</label>
                <select value={nf.risk_level} onChange={(e) => setNf({ ...nf, risk_level: e.target.value })}>
                  <option>low</option><option>medium</option><option>high</option>
                </select></div>
              {nf.flag_type === 'multivariate'
                ? <div><label>Variants (comma-separated)</label><input value={nf.variants} onChange={(e) => setNf({ ...nf, variants: e.target.value })} /></div>
                : null}
              <div><label>Off value (served when killed/paused)</label>
                {nf.flag_type === 'multivariate'
                  ? <input value={nf.off_value} onChange={(e) => setNf({ ...nf, off_value: e.target.value })} />
                  : <select value={nf.off_value} onChange={(e) => setNf({ ...nf, off_value: e.target.value })}><option>false</option><option>true</option></select>}
              </div>
            </div>
            <div className="actions">
              <button onClick={createFlag} disabled={!!busy || !nf.flag_key || !nf.description || !nf.owner_team}>{busy === 'create' ? '…' : 'Create flag'}</button>
            </div>
          </details>
        )}
      </div>

      {detail && flag && (
        <>
          <div className="card">
            <h2>{flag.flag_key}</h2>
            <div className="gate">
              <div className="g">Description</div><div>{flag.description}</div>
              <div className="g">Type · owner</div><div>{flag.flag_type}{flag.variants ? ` (${flag.variants.join(' | ')})` : ''} · {flag.owner_team}</div>
              <div className="g">Off value</div><div><code>{show(flag.off_value)}</code> <span className="muted">— served when killed, paused or archived</span></div>
              <div className="g">Status</div><div><span className={`badge ${flag.status === 'active' ? 'ok' : flag.status === 'paused' ? 'wait' : 'off'}`}>{flag.status}</span></div>
            </div>
            {canWrite && flag.status !== 'archived' && (
              <div className="actions">
                {flag.status === 'active'
                  ? <button className="secondary" disabled={!!busy} onClick={() => act('st', () => post('/status', { status: 'paused' }), () => 'Flag paused — every tenant now gets off_value.')}>Pause flag</button>
                  : <button className="secondary" disabled={!!busy} onClick={() => act('st', () => post('/status', { status: 'active' }), () => 'Flag active again.')}>Activate flag</button>}
                <button className="ghost" disabled={!!busy} onClick={() => act('st', () => post('/status', { status: 'archived' }), () => 'Flag archived (terminal) — no longer served to tenants.')}>Archive (terminal)</button>
              </div>
            )}
          </div>

          <div className="card">
            <div className="actions" style={{ marginTop: 0, marginBottom: 14 }}>
              {ENVS.map((e) => (
                <button key={e} className={e === env ? '' : 'secondary'} onClick={() => { setEnv(e); setExplain(null); }}>
                  {e}{detail.environments.find((x) => x.environment === e)?.kill_engaged ? ' · KILLED' : ''}
                </button>
              ))}
            </div>

            {envRow?.kill_engaged ? (
              <div className="banner danger">
                <span className="dot" />
                <div>
                  <strong>KILL SWITCH ENGAGED in {env}</strong> — every tenant gets <code>{show(flag.off_value)}</code>, regardless of rules.
                  <div className="hint">“{envRow.kill_reason}” · {envRow.killed_by_email} · {when(envRow.killed_at)}</div>
                </div>
                {canWrite && <button className="secondary" style={{ marginTop: 0 }} disabled={!!busy}
                  onClick={() => act('kill', () => post(`/environments/${env}/kill`, { engaged: false }), () => `Kill switch released in ${env}.`)}>Release</button>}
              </div>
            ) : canWrite ? (
              <div className="row">
                <div><label>Kill switch reason (tier 1 — forces off_value for everyone in {env})</label>
                  <input value={killReason} onChange={(e) => setKillReason(e.target.value)} placeholder="incident / ticket" /></div>
                <div style={{ flex: '0 0 auto', display: 'flex', alignItems: 'flex-end' }}>
                  <button className="danger" style={{ marginTop: 0 }} disabled={!!busy || !killReason}
                    onClick={() => act('kill', () => post(`/environments/${env}/kill`, { engaged: true, reason: killReason }), () => { setKillReason(''); return `Kill switch ENGAGED in ${env}.`; })}>Engage kill switch</button>
                </div>
              </div>
            ) : null}

            <div className="gate" style={{ marginTop: 14 }}>
              <div className="g">Environment default (tier 6)</div>
              <div>
                {canWrite ? (
                  <select style={{ width: 'auto' }} value={String(envRow?.default_value)} disabled={!!busy}
                    onChange={(e) => act('def', () => post(`/environments/${env}`, { default_value: parseChoice(flag, e.target.value) }), () => `Default for ${env} updated.`)}>
                    {choices(flag).map((c) => <option key={String(c)} value={String(c)}>{String(c)}</option>)}
                  </select>
                ) : <code>{show(envRow?.default_value)}</code>}
              </div>
            </div>

            <h2 style={{ marginTop: 24 }}>Rules in {env}</h2>
            <div className="scroll">
              <table>
                <thead><tr><th>tier</th><th className="entity">target</th><th>value</th><th>priority</th><th>window</th><th>status</th><th /></tr></thead>
                <tbody>
                  {envRules.map((r) => (
                    <tr key={r.id}>
                      <td className="muted">{TIER_LABEL[r.target_type]}</td>
                      <td className="entity">{target(r)}<div className="hint" style={{ marginTop: 2 }}>{r.created_by_email} · {when(r.created_at)}</div></td>
                      <td><code>{show(r.value)}</code></td>
                      <td>{r.priority}</td>
                      <td className="muted">{r.start_at || r.end_at ? `${when(r.start_at)} → ${when(r.end_at)}` : 'always'}</td>
                      <td><span className={`badge ${r.live ? 'ok' : r.status === 'ended' ? 'off' : 'wait'}`}>{r.live ? 'live' : r.status}</span></td>
                      <td>
                        {canWrite && r.status !== 'ended' && (
                          <span style={{ display: 'flex', gap: 6 }}>
                            {r.status === 'active'
                              ? <button className="tiny secondary" disabled={!!busy} onClick={() => act(`r${r.id}`, () => post(`/rollouts/${r.id}/status`, { status: 'paused' }), () => 'Rule paused.')}>Pause</button>
                              : <button className="tiny secondary" disabled={!!busy} onClick={() => act(`r${r.id}`, () => post(`/rollouts/${r.id}/status`, { status: 'active' }), () => 'Rule active.')}>Activate</button>}
                            <button className="tiny ghost" disabled={!!busy} onClick={() => act(`r${r.id}`, () => post(`/rollouts/${r.id}/status`, { status: 'ended' }), () => 'Rule ended (terminal).')}>End</button>
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {!envRules.length && <tr><td colSpan={7} className="muted">no rules in {env} — everyone gets the default</td></tr>}
                </tbody>
              </table>
            </div>
            <p className="hint">Rules are append-only: to change one, end it and add a new one. Ended rules can never be revived.</p>

            {canWrite && flag.status !== 'archived' && (
              <>
                <h2 style={{ marginTop: 22 }}>Add a rule in {env}</h2>
                <div className="row">
                  <div><label>Tier</label>
                    <select value={rule.target_type} onChange={(e) => setRule({ ...rule, target_type: e.target.value })}>
                      {TIERS.map((t) => <option key={t} value={t}>{TIER_LABEL[t]}</option>)}
                    </select></div>
                  {(rule.target_type === 'tenant' || rule.target_type === 'tenant_app') && (
                    <div><label>Tenant</label>
                      <select value={rule.tenant} onChange={(e) => setRule({ ...rule, tenant: e.target.value })}>
                        {tenants.map((t) => <option key={t.slug}>{t.slug}</option>)}
                      </select></div>
                  )}
                  {(rule.target_type === 'app' || rule.target_type === 'tenant_app') && (
                    <div><label>App key</label><input value={rule.app} onChange={(e) => setRule({ ...rule, app: e.target.value })} placeholder="hifz-lms" /></div>
                  )}
                  {rule.target_type === 'cohort' && (
                    <div><label>Percent of tenants (0–100)</label><input value={rule.percent} onChange={(e) => setRule({ ...rule, percent: e.target.value })} /></div>
                  )}
                </div>
                <div className="row">
                  <div><label>Value</label>
                    <select value={rule.value} onChange={(e) => setRule({ ...rule, value: e.target.value })}>
                      {choices(flag).map((c) => <option key={String(c)} value={String(c)}>{String(c)}</option>)}
                    </select></div>
                  <div><label>Priority (lower wins)</label><input value={rule.priority} onChange={(e) => setRule({ ...rule, priority: e.target.value })} /></div>
                  <div><label>Status</label>
                    <select value={rule.status} onChange={(e) => setRule({ ...rule, status: e.target.value })}>
                      <option>active</option><option>paused</option><option>scheduled</option>
                    </select></div>
                </div>
                <div className="actions">
                  <button disabled={!!busy} onClick={() => act('rule', () => post('/rollouts', {
                    environment: env, target_type: rule.target_type, tenant: rule.tenant, app: rule.app,
                    percent: Number(rule.percent), value: parseChoice(flag, rule.value), priority: Number(rule.priority), status: rule.status,
                  }), (b) => `Rule added → ${b.target_type} ${b.target_ref}.`)}>{busy === 'rule' ? '…' : 'Add rule'}</button>
                </div>
              </>
            )}
          </div>

          <div className="card">
            <h2>Explain a decision in {env}</h2>
            <p className="hint" style={{ marginTop: 0 }}>
              A dry run of the resolver for one tenant (and optionally one app): which tier won, and why every other rule lost.
              It uses the same predicate the Hub serves from, and is not logged as a decision.
            </p>
            <div className="row">
              <div><label>Tenant</label>
                <select value={ex.tenant} onChange={(e) => setEx({ ...ex, tenant: e.target.value })}>
                  {tenants.map((t) => <option key={t.slug}>{t.slug}</option>)}
                </select></div>
              <div><label>App key (optional)</label><input value={ex.app} onChange={(e) => setEx({ ...ex, app: e.target.value })} placeholder="hifz-lms" /></div>
              <div style={{ flex: '0 0 auto', display: 'flex', alignItems: 'flex-end' }}>
                <button style={{ marginTop: 0 }} onClick={runExplain} disabled={!!busy || !ex.tenant}>{busy === 'explain' ? '…' : 'Explain'}</button>
              </div>
            </div>
            {explain && (
              <>
                <p className="ok">
                  → <code>{show(explain.decision.value)}</code> from <strong>{TIER_LABEL[explain.decision.tier] || explain.decision.tier}</strong>
                  <span className="muted"> — {(() => {
                    const win = explain.candidates.find((c) => c.selected);
                    if (!win) return explain.decision.reason;
                    const slug = detail.rollouts.find((r) => r.id === win.rule_id)?.tenant_slug;
                    return `${target({ ...win, tenant_slug: slug })}, priority ${win.priority}`;
                  })()}</span>
                </p>
                <div className="scroll">
                  <table>
                    <thead><tr><th>tier</th><th className="entity">target</th><th>value</th><th>priority</th><th>outcome</th></tr></thead>
                    <tbody>
                      {explain.candidates.map((c) => (
                        <tr key={c.rule_id} style={c.selected ? { background: 'rgba(126,231,135,.08)' } : undefined}>
                          <td className="muted">{TIER_LABEL[c.target_type]}</td>
                          <td className="entity">{target({ ...c, tenant_slug: detail.rollouts.find((r) => r.id === c.rule_id)?.tenant_slug })}</td>
                          <td><code>{show(c.value)}</code></td>
                          <td>{c.priority}</td>
                          <td className={c.selected ? 'success' : 'muted'}>
                            {c.selected ? 'SELECTED' : c.eligible ? 'eligible — lost on tier/priority/recency' : c.skip_reason}
                          </td>
                        </tr>
                      ))}
                      {!explain.candidates.length && <tr><td colSpan={5} className="muted">no rules in {env}</td></tr>}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>

          <div className="card">
            <h2>History</h2>
            <div className="scroll">
              <table>
                <thead><tr><th>change</th><th>env</th><th>by</th><th>when</th></tr></thead>
                <tbody>
                  {detail.audit.map((a, i) => (
                    <tr key={i}><td>{a.action}</td><td className="muted">{a.environment || '—'}</td><td className="muted">{a.actor_email}</td><td className="muted">{when(a.occurred_at)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            <h2 style={{ marginTop: 24 }}>Decisions served</h2>
            <div className="scroll">
              <table>
                <thead><tr><th>tenant</th><th>app</th><th>env</th><th>tier</th><th>value</th><th>when</th></tr></thead>
                <tbody>
                  {detail.decisions.map((d) => (
                    <tr key={d.seq}>
                      <td>{d.tenant_slug}</td><td className="muted">{d.app_key || '—'}</td><td className="muted">{d.environment}</td>
                      <td className="muted">{TIER_LABEL[d.tier] || d.tier}</td><td><code>{show(d.value)}</code></td><td className="muted">{when(d.decided_at)}</td>
                    </tr>
                  ))}
                  {!detail.decisions.length && <tr><td colSpan={6} className="muted">nothing served yet</td></tr>}
                </tbody>
              </table>
            </div>
            <p className="hint">Each row is a distinct decision for one tenant — a repeat of the same decision is not re-logged; a change (including a flip back) is.</p>
          </div>
        </>
      )}
    </>
  );
}
