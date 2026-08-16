'use client';
import { useEffect, useState } from 'react';
import { registerPasskey, supportsWebAuthn } from '@/lib/webauthn-client';

type Cred = { credential_id: string; nickname: string | null; sign_count: number; created_at: string; last_used_at: string | null };

export default function Passkeys() {
  const [creds, setCreds] = useState<Cred[]>([]);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    const r = await (await fetch('/api/hub/operator/webauthn/credentials')).json();
    setCreds(r.credentials || []);
  }
  useEffect(() => { load(); }, []);

  async function register() {
    setErr(''); setMsg(''); setBusy(true);
    try {
      const r = await registerPasskey();
      if (r.error) setErr(r.error); else { setMsg('Passkey registered on this device.'); load(); }
    } catch (e) { setErr((e as Error).message || 'registration failed'); }
    setBusy(false);
  }
  async function revoke(id: string) {
    await fetch(`/api/hub/operator/webauthn/credentials/${encodeURIComponent(id)}/revoke`, { method: 'POST' });
    load();
  }

  return (
    <>
      <h1>Passkeys</h1>
      <p className="muted">Phishing-resistant WebAuthn credentials for passwordless, step-up sign-in.</p>
      <div className="card">
        <button onClick={register} disabled={busy || !supportsWebAuthn()}>🔑 Register a passkey on this device</button>
        {!supportsWebAuthn() && <p className="hint">This browser reports no WebAuthn support.</p>}
        {msg && <div className="ok">{msg}</div>}
        {err && <div className="err">{err}</div>}
      </div>
      <div className="card">
        <h2>Registered passkeys</h2>
        {creds.length === 0 ? <p className="muted">None yet.</p> : (
          <table>
            <thead><tr><th>credential</th><th>nickname</th><th>sign count</th><th /></tr></thead>
            <tbody>
              {creds.map((c) => (
                <tr key={c.credential_id}>
                  <td className="muted">{c.credential_id.slice(0, 20)}…</td>
                  <td>{c.nickname || '—'}</td>
                  <td>{c.sign_count}</td>
                  <td><button className="ghost" style={{ marginTop: 0 }} onClick={() => revoke(c.credential_id)}>revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
