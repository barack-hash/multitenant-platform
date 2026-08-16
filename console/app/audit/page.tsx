'use client';
import { useState } from 'react';

type Ev = { chain_seq: number; action: string; outcome: string; reason_code: string | null; hash: string };
type Verify = { ok: boolean; checked: number; first_bad_seq: number | null; failure_kind: string | null };

export default function Audit() {
  const [chain, setChain] = useState('platform');
  const [verify, setVerify] = useState<Verify | null>(null);
  const [events, setEvents] = useState<Ev[]>([]);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function run() {
    setErr(''); setBusy(true);
    try {
      const v = await (await fetch(`/api/hub/admin/audit/verify?chain=${encodeURIComponent(chain)}`)).json();
      if (v.error) { setErr(v.error); setVerify(null); setEvents([]); return; }
      setVerify(v);
      const t = await (await fetch(`/api/hub/admin/audit/tail?chain=${encodeURIComponent(chain)}`)).json();
      setEvents(t.events || []);
    } finally { setBusy(false); }
  }

  return (
    <>
      <h1>Audit chain viewer</h1>
      <p className="muted">Tier-A, tamper-evident hash chain. Verify recomputes every row; the tail shows recent events.</p>
      <div className="card">
        <div className="row">
          <div><label>Chain</label><input value={chain} onChange={(e) => setChain(e.target.value)} placeholder="platform, or a tenant slug" /></div>
          <div style={{ flex: '0 0 auto', display: 'flex', alignItems: 'flex-end' }}>
            <button onClick={run} disabled={busy} style={{ marginTop: 0 }}>{busy ? '…' : 'Verify + tail'}</button>
          </div>
        </div>
        {err && <div className="err">{err}</div>}
        {verify && (
          <p className={verify.ok ? 'ok' : 'err'}>
            {verify.ok ? `✓ chain intact — ${verify.checked} rows verified` : `✗ tampered at seq ${verify.first_bad_seq} (${verify.failure_kind})`}
          </p>
        )}
      </div>
      {events.length > 0 && (
        <div className="card">
          <h2>Recent events</h2>
          <table>
            <thead><tr><th>seq</th><th>action</th><th>outcome</th><th>reason</th><th>hash</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.chain_seq}>
                  <td>{e.chain_seq}</td>
                  <td>{e.action}</td>
                  <td className={e.outcome === 'denied' ? 'denied' : e.outcome === 'success' ? 'success' : ''}>{e.outcome}</td>
                  <td className="muted">{e.reason_code || ''}</td>
                  <td className="muted">{e.hash}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
