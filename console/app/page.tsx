import { hubFetch } from '@/lib/hub';
import { redirect } from 'next/navigation';
import Link from 'next/link';

export const dynamic = 'force-dynamic';

export default async function Dashboard() {
  const { status, body } = await hubFetch('/operator/me', { method: 'GET' });
  if (status !== 200) redirect('/login');
  const stepUp = body.acr === 'mfa';
  return (
    <>
      <h1>Operator dashboard</h1>
      <p className="muted">Signed in to the platform operations plane.</p>

      <div className="card">
        <h2>Identity &amp; assurance</h2>
        <div className="kv">
          <div className="k">Operator</div>
          <div>{body.display_name} <span className="muted">({body.email})</span></div>
          <div className="k">Role</div>
          <div><span className="badge role">{body.role}</span></div>
          <div className="k">Assurance (acr)</div>
          <div>
            {stepUp ? <span className="badge mfa">mfa · step-up</span> : <span className="badge pwd">pwd</span>}
            <span className="muted" style={{ marginLeft: 10 }}>amr: {(body.amr || []).join(', ') || 'pwd'}</span>
          </div>
          <div className="k">Operator ID</div>
          <div className="muted">{body.operator_id}</div>
        </div>
        {!stepUp && (
          <p className="hint">This is a password-only session. Destructive lifecycle and operator-management actions require step-up — sign in again with MFA or a passkey.</p>
        )}
      </div>

      <div className="card">
        <h2>Operator surfaces</h2>
        <div className="row">
          <Link href="/audit">→ Audit chain viewer</Link>
          <Link href="/passkeys">→ Manage passkeys</Link>
        </div>
        <p className="hint">
          Support/impersonation and tenant-offboarding panels use the same authenticated BFF proxy
          (<code>/api/hub/admin/*</code>) — extend under <code>app/</code>.
        </p>
      </div>
    </>
  );
}
