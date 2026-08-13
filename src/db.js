// Two least-privilege pools (DEC-009): svc_app for tenant-request handling (RLS-enforced),
// svc_worker for privileged service operations (login/identity/RBAC lookups).
import pg from 'pg';
import { cfg } from './config.js';

export const appPool    = new pg.Pool({ connectionString: cfg.appUrl,    max: 5 });
export const workerPool = new pg.Pool({ connectionString: cfg.workerUrl, max: 5 });

async function runInTx(pool, gucs, fn) {
  const client = await pool.connect();
  try {
    await client.query('begin');
    // DEC-011: context set with set_config LOCAL, inside the transaction — never session-level.
    for (const [k, v] of Object.entries(gucs)) await client.query('select set_config($1,$2,true)', [k, v]);
    const out = await fn(client);
    await client.query('commit');
    return out;
  } catch (e) {
    await client.query('rollback').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

// A tenant-scoped user request. Runs as svc_app; RLS enforces isolation from the GUC context.
export const withUserContext = (gucs, fn) => runInTx(appPool, gucs, fn);

// A privileged service operation. Runs as svc_worker acting as a logical svc_role.
export const withServiceContext = (svcRole, fn) =>
  runInTx(workerPool, { 'app.actor_type': 'service', 'app.svc_role': svcRole }, fn);

export const closePools = () => Promise.all([appPool.end(), workerPool.end()]);
