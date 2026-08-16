'use client';
import { useState, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { loginPasskey, supportsWebAuthn } from '@/lib/webauthn-client';

export default function Login() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [mfa, setMfa] = useState(false);
  const [code, setCode] = useState('');
  const [idp, setIdp] = useState('demo-oidc');
  const [assertion, setAssertion] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const done = () => { router.push('/'); router.refresh(); };
  const call = async (url: string, payload: unknown) =>
    (await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })).json();

  async function pwLogin(e: FormEvent) {
    e.preventDefault(); setErr(''); setBusy(true);
    const r = await call('/api/login', { email, api_key: apiKey });
    setBusy(false);
    if (r.error) return setErr(r.error);
    if (r.mfa_required) return setMfa(true);
    done();
  }
  async function mfaVerify(e: FormEvent) {
    e.preventDefault(); setErr(''); setBusy(true);
    const r = await call('/api/mfa/verify', { code });
    setBusy(false);
    if (r.error) return setErr(r.error);
    done();
  }
  async function passkey() {
    if (!email) return setErr('enter your operator email first');
    setErr(''); setBusy(true);
    try { const r = await loginPasskey(email); if (r.error) setErr(r.error); else done(); }
    catch (e) { setErr((e as Error).message || 'passkey login failed'); }
    setBusy(false);
  }
  async function sso(e: FormEvent) {
    e.preventDefault(); setErr(''); setBusy(true);
    const r = await call('/api/sso', { idp, assertion });
    setBusy(false);
    if (r.error) return setErr(r.error);
    done();
  }

  return (
    <div style={{ maxWidth: 440, margin: '6vh auto' }}>
      <h1>Hub<span style={{ color: 'var(--accent)' }}>Ops</span> Console</h1>
      <p className="muted">Platform operator sign-in.</p>

      <div className="card">
        {!mfa ? (
          <form onSubmit={pwLogin}>
            <h2>Password</h2>
            <label>Operator email</label>
            <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="ops1@platform.example" autoComplete="username" />
            <label>API key</label>
            <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} type="password" placeholder="opk_…" autoComplete="current-password" />
            <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
          </form>
        ) : (
          <form onSubmit={mfaVerify}>
            <h2>Second factor</h2>
            <p className="muted">Enter the 6-digit code from your authenticator (or a recovery code).</p>
            <label>Code</label>
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" placeholder="123456" autoFocus />
            <button disabled={busy}>{busy ? 'Verifying…' : 'Verify'}</button>
            <button type="button" className="ghost" onClick={() => { setMfa(false); setCode(''); }}>Back</button>
          </form>
        )}
        {err && <div className="err">{err}</div>}
      </div>

      {!mfa && (
        <div className="card">
          <h2>Passwordless</h2>
          <button type="button" className="secondary" style={{ marginTop: 0 }} disabled={busy || !supportsWebAuthn()} onClick={passkey}>
            🔑 Sign in with a passkey
          </button>
          <p className="hint">Uses this device&apos;s authenticator (Touch ID / security key). Requires a registered passkey.</p>

          <details>
            <summary>Enterprise SSO</summary>
            <form onSubmit={sso}>
              <label>IdP</label>
              <input value={idp} onChange={(e) => setIdp(e.target.value)} placeholder="demo-oidc" />
              <label>Signed assertion</label>
              <textarea value={assertion} onChange={(e) => setAssertion(e.target.value)} rows={3} placeholder="base64url(payload).hmac" />
              <button className="secondary" disabled={busy}>Sign in with SSO</button>
              <p className="hint">In production this is a redirect to your IdP; here it accepts a signed assertion directly.</p>
            </form>
          </details>
        </div>
      )}
    </div>
  );
}
