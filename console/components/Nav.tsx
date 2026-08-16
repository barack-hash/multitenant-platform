'use client';
import Link from 'next/link';
import { useRouter, usePathname } from 'next/navigation';

export default function Nav() {
  const router = useRouter();
  const path = usePathname();
  if (path === '/login') return null;
  async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    router.push('/login');
    router.refresh();
  }
  return (
    <header className="nav">
      <div className="brand">Hub<span>Ops</span> Console</div>
      <nav className="links">
        <Link href="/">Dashboard</Link>
        <Link href="/audit">Audit</Link>
        <Link href="/passkeys">Passkeys</Link>
      </nav>
      <div className="spacer" />
      <button className="ghost" style={{ marginTop: 0 }} onClick={logout}>Sign out</button>
    </header>
  );
}
