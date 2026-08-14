// Modular-monolith Hub runtime over the proven foundation-1 DB slice.
import Fastify from 'fastify';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomUUID, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { withUserContext, withServiceContext } from './db.js';
import { mintHubToken, verifyHubToken, gucsFromClaims,
         mintLaunchToken, verifyLaunchToken, mintSpokeToken, verifySpokeToken, mintSupportToken,
         mintOperatorToken, verifyOperatorToken, mintOperatorMfaToken, verifyOperatorMfaToken } from './tokens.js';
import { generateTotpSecret, verifyTotp, otpauthUri } from './mfa.js';
import { cfg } from './config.js';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const HERE = dirname(fileURLToPath(import.meta.url));

export function buildServer() {
  const app = Fastify({ logger: false });

  // Capture the raw JSON body (webhook HMAC must be over the exact bytes).
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    req.rawBody = body;
    try { done(null, body ? JSON.parse(body) : {}); } catch (e) { done(e); }
  });

  // Lightweight console served by the Hub (production web is Next.js/Vercel per DEC-013).
  const CONSOLE = readFileSync(join(HERE, '..', 'public', 'index.html'), 'utf8');
  app.get('/', async (_req, reply) => reply.type('text/html').send(CONSOLE));

  // Auth guard: verify the Hub token and attach claims.
  const auth = async (req, reply) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!m) return reply.code(401).send({ error: 'missing bearer token' });
    try { req.claims = verifyHubToken(m[1]); }
    catch { return reply.code(401).send({ error: 'invalid token' }); }
  };

  app.get('/healthz', async () => ({ ok: true }));

  // Authentication is assumed done upstream (Supabase). Here the Hub verifies the user has an
  // active membership, loads their effective permissions, and mints the tenant-trust token.
  app.post('/auth/login', async (req, reply) => {
    const { email, tenant } = req.body || {};
    if (!email || !tenant) return reply.code(400).send({ error: 'email and tenant are required' });

    const found = await withServiceContext('svc_ops', async (c) => {
      const u = await c.query('select id from user_identities where primary_email=$1 and status=$2 and deleted_at is null', [email, 'active']);
      const t = await c.query('select id, status, billing_status, entitlement_snapshot_version ev from tenants where slug=$1 and deleted_at is null', [tenant]);
      if (!u.rowCount || !t.rowCount) return null;
      const userId = u.rows[0].id, tenantId = t.rows[0].id;
      const m = await c.query('select id from tenant_memberships where tenant_id=$1 and user_id=$2 and status=$3 and deleted_at is null', [tenantId, userId, 'active']);
      if (!m.rowCount) return null;
      const membershipId = m.rows[0].id;
      const perms = await c.query(
        `select distinct p.permission_key
           from tenant_user_roles tur
           join role_permissions rp on rp.role_id = tur.role_id
           join permissions p on p.id = rp.permission_id
          where tur.tenant_id=$1 and tur.membership_id=$2 and tur.deleted_at is null`, [tenantId, membershipId]);
      const roles = await c.query(
        `select r.role_key from tenant_user_roles tur join roles r on r.id=tur.role_id
          where tur.tenant_id=$1 and tur.membership_id=$2 and tur.deleted_at is null`, [tenantId, membershipId]);
      const tw = t.rows[0].status === 'active' && t.rows[0].billing_status !== 'locked';
      return {
        userId, tenantId, membershipId, tw, ev: t.rows[0].ev,
        permissions: perms.rows.map((r) => r.permission_key),
        roles: roles.rows.map((r) => r.role_key),
      };
    });

    if (!found) return reply.code(401).send({ error: 'invalid login or no active membership in that tenant' });
    // Create the root (hub) session; id == root_session_id.
    const sid = randomUUID();
    await withServiceContext('svc_session', (c) => c.query(
      `insert into sessions(id, tenant_id, user_id, membership_id, kind, root_session_id, entitlement_snapshot_version, expires_at)
       values($1,$2,$3,$4,'hub',$1,$5, now() + interval '900 seconds')`,
      [sid, found.tenantId, found.userId, found.membershipId, found.ev]));
    const token = mintHubToken({
      sub: found.userId, tid: found.tenantId, mid: found.membershipId,
      permissions: found.permissions, roles: found.roles, ent_v: found.ev, tw: found.tw,
      sid, root_sid: sid,
    });
    return { token, token_type: 'Bearer', expires_in: cfg.accessTtlSec };
  });

  // Current user's own identity (via the RLS-scoped v_me projection).
  app.get('/me', { preHandler: auth }, async (req) =>
    withUserContext(gucsFromClaims(req.claims), async (c) => {
      const r = await c.query('select * from app.v_me');
      return { me: r.rows[0] ?? null, tenant_id: req.claims.tid, roles: req.claims.roles, permissions: req.claims.permissions };
    }));

  // The user's memberships in the current tenant (RLS-scoped).
  app.get('/memberships', { preHandler: auth }, async (req) =>
    withUserContext(gucsFromClaims(req.claims), async (c) => {
      const r = await c.query('select * from app.v_my_memberships');
      return { memberships: r.rows };
    }));

  // The tenant's activated apps + launch-eligibility (RLS-scoped, group 2).
  app.get('/my-apps', { preHandler: auth }, async (req) =>
    withUserContext(gucsFromClaims(req.claims), async (c) => {
      const r = await c.query('select * from app.v_my_apps order by app_key');
      return { apps: r.rows };
    }));

  // The tenant's current entitlement snapshot (group 3, RLS-scoped).
  app.get('/my-entitlements', { preHandler: auth }, async (req) =>
    withUserContext(gucsFromClaims(req.claims), async (c) => {
      const r = await c.query('select * from app.v_my_entitlements');
      return { entitlements: r.rows[0] ?? null };
    }));

  // Recompute entitlements (a billing-service operation; requires billing.manage). Bumps ent_v.
  app.post('/billing/recompute', { preHandler: auth }, async (req, reply) => {
    if (!(req.claims.permissions || []).includes('billing.manage'))
      return reply.code(403).send({ error: 'requires billing.manage' });
    // recompute + emit in ONE svc_billing transaction (transactional outbox).
    const ent_v = await withServiceContext('svc_billing', async (c) => {
      const r = await c.query('select app.recompute_entitlements($1) v', [req.claims.tid]);
      await c.query("select app.emit_event('entitlements.recomputed', $1, $2::jsonb, 'entitlement-service')",
        [req.claims.tid, JSON.stringify({ ent_v: Number(r.rows[0].v) })]);
      return Number(r.rows[0].v);
    });
    // relay the outbox (the event-service runtime) so it lands in the canonical log.
    await withServiceContext('svc_events', (c) => c.query('select app.relay_outbox(100)'));
    return { ent_v, note: 'existing tokens are now stale; re-login to refresh' };
  });

  // The tenant's recent event stream (group 4, RLS-scoped).
  app.get('/my-events', { preHandler: auth }, async (req) =>
    withUserContext(gucsFromClaims(req.claims), async (c) => {
      const r = await c.query('select * from app.v_my_events');
      return { events: r.rows };
    }));

  // ---- group 5: 4-token launch/exchange (MASTER_PLAN §5) ----

  const sessionActive = (sid) => withServiceContext('svc_session', async (c) => {
    const s = await c.query('select status, expires_at from sessions where id=$1', [sid]);
    return s.rowCount === 1 && s.rows[0].status === 'active' && new Date(s.rows[0].expires_at) > new Date();
  });

  // Step 2: issue a 60s one-time launch token for an app the tenant may launch.
  app.post('/launch', { preHandler: auth }, async (req, reply) => {
    const { app_key } = req.body || {};
    if (!app_key) return reply.code(400).send({ error: 'app_key is required' });
    if (!(await sessionActive(req.claims.sid))) return reply.code(401).send({ error: 'SESSION_INVALID' });

    const gate = await withUserContext(gucsFromClaims(req.claims), async (c) => {
      const app = await c.query('select launchable from app.v_my_apps where app_key=$1', [app_key]);
      const cur = Number((await c.query('select entitlement_snapshot_version ev from tenants where id = app.current_tenant_id()')).rows[0].ev);
      return { launchable: app.rowCount ? app.rows[0].launchable : null, stale: Number(req.claims.ent_v ?? 0) < cur };
    });
    if (gate.launchable === null) return reply.code(404).send({ error: 'APP_NOT_ACTIVATED' });
    if (!gate.launchable) return reply.code(423).send({ error: 'TENANT_LOCKED' });
    if (gate.stale) return reply.code(409).send({ error: 'STALE_ENTITLEMENT_VERSION' });

    const nonce = randomUUID(), jti = randomUUID();
    const app_id = await withServiceContext('svc_session', async (c) => {
      const a = await c.query('select id from apps where app_key=$1', [app_key]);
      if (!a.rowCount) return null;
      await c.query(
        `insert into launch_tokens(jti, tenant_id, session_id, root_session_id, app_id, nonce_hash, entitlement_snapshot_version, expires_at)
         values($1,$2,$3,$4,$5,$6,$7, now() + interval '60 seconds')`,
        [jti, req.claims.tid, req.claims.sid, req.claims.root_sid, a.rows[0].id, sha256(nonce), req.claims.ent_v]);
      return a.rows[0].id;
    });
    if (!app_id) return reply.code(404).send({ error: 'APP_NOT_FOUND' });
    const launch_token = mintLaunchToken({ jti, tid: req.claims.tid, sid: req.claims.sid, root_sid: req.claims.root_sid, app_id, ent_v: req.claims.ent_v });
    return { launch_token, nonce, app_key, expires_in: 60 };
  });

  // Step 3: exchange the one-time launch token (+nonce) for a 1800s spoke session.
  app.post('/token/exchange', async (req, reply) => {
    const { launch_token, nonce } = req.body || {};
    if (!launch_token || !nonce) return reply.code(400).send({ error: 'launch_token and nonce are required' });
    let lc;
    try { lc = verifyLaunchToken(launch_token); } catch { return reply.code(401).send({ error: 'LAUNCH_INVALID' }); }

    const out = await withServiceContext('svc_session', async (c) => {
      const lt = (await c.query('select * from launch_tokens where jti=$1', [lc.jti])).rows[0];
      if (!lt || lt.status !== 'issued') return { code: 401, error: 'LAUNCH_INVALID' };           // replay/consumed
      if (new Date(lt.expires_at) < new Date()) return { code: 401, error: 'LAUNCH_EXPIRED' };
      if (lt.nonce_hash !== sha256(nonce)) return { code: 401, error: 'LAUNCH_INVALID' };
      const cur = Number((await c.query('select entitlement_snapshot_version ev from tenants where id=$1', [lt.tenant_id])).rows[0].ev);
      if (Number(lt.entitlement_snapshot_version) < cur) return { code: 409, error: 'STALE_ENTITLEMENT_VERSION' };
      const hub = (await c.query('select user_id, membership_id, status from sessions where id=$1', [lt.session_id])).rows[0];
      if (!hub || hub.status !== 'active') return { code: 401, error: 'SESSION_INVALID' };
      await c.query("update launch_tokens set status='consumed', consumed_at=now() where id=$1", [lt.id]);   // one-time
      const spokeId = randomUUID();
      await c.query(
        `insert into sessions(id, tenant_id, user_id, membership_id, kind, app_id, root_session_id, parent_session_id, entitlement_snapshot_version, expires_at)
         values($1,$2,$3,$4,'spoke',$5,$6,$7,$8, now() + interval '1800 seconds')`,
        [spokeId, lt.tenant_id, hub.user_id, hub.membership_id, lt.app_id, lt.root_session_id, lt.session_id, cur]);
      return { spokeId, tenant_id: lt.tenant_id, user_id: hub.user_id, membership_id: hub.membership_id, app_id: lt.app_id, root_sid: lt.root_session_id, ent_v: cur };
    });
    if (out.error) return reply.code(out.code).send({ error: out.error });
    const spoke_session_token = mintSpokeToken({ sub: out.user_id, tid: out.tenant_id, mid: out.membership_id, app_id: out.app_id, sid: out.spokeId, root_sid: out.root_sid, ent_v: out.ent_v });
    return { spoke_session_token, token_type: 'Bearer', expires_in: 1800, app_id: out.app_id };
  });

  // A spoke-authenticated endpoint — proves the spoke session works AND is revocable.
  const spokeAuth = async (req, reply) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!m) return reply.code(401).send({ error: 'missing spoke token' });
    try { req.spoke = verifySpokeToken(m[1]); } catch { return reply.code(401).send({ error: 'invalid spoke token' }); }
    if (!(await sessionActive(req.spoke.sid))) return reply.code(401).send({ error: 'SESSION_REVOKED' });
  };
  app.get('/spoke/context', { preHandler: spokeAuth }, async (req) =>
    ({ app_id: req.spoke.app_id, tenant_id: req.spoke.tid, session: req.spoke.sid, active: true }));

  // Revoke the caller's whole session tree (sign out everywhere) — cascades to spokes.
  app.post('/sessions/revoke', { preHandler: auth }, async (req) => {
    const r = await withServiceContext('svc_session', (c) =>
      c.query('select app.revoke_session_cascade($1,$2,$3) n', [req.claims.root_sid, 'user_signout_all', req.claims.sub]));
    return { revoked: Number(r.rows[0].n) };
  });

  // ---- group 6: Stripe webhook ingestion (MASTER_PLAN §9) ----

  const signStripe = (raw, t) => `t=${t},v1=${createHmac('sha256', cfg.stripeWebhookSecret).update(`${t}.${raw}`).digest('hex')}`;
  const verifyStripe = (header, raw) => {
    const parts = Object.fromEntries(String(header || '').split(',').map((kv) => kv.split('=')));
    if (!parts.t || !parts.v1) return false;
    const expected = createHmac('sha256', cfg.stripeWebhookSecret).update(`${parts.t}.${raw}`).digest('hex');
    try { return timingSafeEqual(Buffer.from(parts.v1), Buffer.from(expected)); } catch { return false; }
  };

  // Resolve customer -> tenant, record the event, update the subscription, recompute + lock/unlock apps.
  async function processStripeEvent(event) {
    return withServiceContext('svc_billing', async (c) => {
      const obj = event.data?.object || {};
      const bc = (await c.query("select tenant_id from billing_customers where provider='stripe' and provider_customer_id=$1", [obj.customer])).rows[0];
      if (!bc) return { skipped: 'unknown_customer' };
      const tenant = bc.tenant_id;
      await c.query(
        `insert into billing_events(tenant_id, provider, provider_event_id, event_type, occurred_at, watermark, payload)
         values($1,'stripe',$2,$3, to_timestamp($4), $4, $5::jsonb) on conflict do nothing`,
        [tenant, event.id, event.type, event.created, JSON.stringify(event)]);
      if (String(event.type).startsWith('customer.subscription')) {
        const raw = event.type === 'customer.subscription.deleted' ? 'canceled' : (obj.status || 'active');
        const status = raw === 'unpaid' ? 'locked' : raw;
        await c.query('update subscriptions set status=$1, updated_at=now() where tenant_id=$2', [status, tenant]);
        const nv = Number((await c.query('select app.recompute_entitlements($1) v', [tenant])).rows[0].v);
        await c.query('select app.apply_billing_lock($1,$2)', [tenant, status]);
        await c.query("select app.emit_event('billing.subscription_updated', $1, $2::jsonb, 'billing-service')",
          [tenant, JSON.stringify({ status, ent_v: nv })]);
        return { tenant, subscription_status: status, ent_v: nv };   // not 'status' (would clobber the outer 'processed')
      }
      return { tenant, ignored: event.type };
    });
  }

  // The dedupe + process pipeline (shared by the real endpoint and the dev simulator).
  async function handleStripeWebhook(raw, sigHeader) {
    if (!verifyStripe(sigHeader, raw)) return { code: 401, body: { error: 'invalid signature' } };
    let event; try { event = JSON.parse(raw); } catch { return { code: 400, body: { error: 'bad json' } }; }
    if (!event?.id) return { code: 400, body: { error: 'missing event id' } };
    const payloadHash = sha256(raw), fingerprint = sha256(`stripe|${event.id}`);

    const claim = await withServiceContext('svc_billing', async (c) => {
      const ins = await c.query(
        `insert into webhook_receipts(provider, endpoint_key, external_event_id, idempotency_fingerprint, signature_valid, payload_hash, status, attempt_count)
         values('stripe','stripe',$1,$2,true,$3,'processing',1) on conflict do nothing returning id`,
        [event.id, fingerprint, payloadHash]);
      if (ins.rowCount) return { receiptId: ins.rows[0].id };
      const ex = (await c.query("select status, payload_hash from webhook_receipts where provider='stripe' and endpoint_key='stripe' and external_event_id=$1", [event.id])).rows[0];
      if (!ex) return { inProgress: true };
      if (ex.payload_hash !== payloadHash) return { conflict: true };
      if (ex.status === 'processed') return { duplicate: true };
      return { inProgress: true };
    });
    if (claim.conflict) return { code: 409, body: { error: 'WEBHOOK_CONFLICT' } };
    if (claim.duplicate) return { code: 200, body: { status: 'duplicate' } };
    if (claim.inProgress) return { code: 202, body: { status: 'in_progress' } };

    try {
      const result = await processStripeEvent(event);
      await withServiceContext('svc_events', (c) => c.query('select app.relay_outbox(100)'));
      await withServiceContext('svc_billing', (c) => c.query("update webhook_receipts set status='processed', processed_at=now() where id=$1", [claim.receiptId]));
      return { code: 200, body: { status: 'processed', ...result } };
    } catch (e) {
      await withServiceContext('svc_billing', (c) => c.query("update webhook_receipts set status='failed', error_detail=$2 where id=$1", [claim.receiptId, String(e.message).slice(0, 200)]));
      return { code: 500, body: { error: 'processing_failed' } };
    }
  }

  app.post('/webhooks/stripe', async (req, reply) => {
    const { code, body } = await handleStripeWebhook(req.rawBody ?? JSON.stringify(req.body ?? {}), req.headers['stripe-signature']);
    return reply.code(code).send(body);
  });

  // Dev-only simulator: builds a properly-signed event and runs the REAL handler (not a bypass).
  app.post('/dev/simulate-stripe', async (req) => {
    const status = (req.body?.status) || 'past_due';
    const event = { id: `evt_dev_${randomUUID().slice(0, 8)}`, type: 'customer.subscription.updated', created: Math.floor(Date.now() / 1000), data: { object: { customer: 'cus_t1', status } } };
    const raw = JSON.stringify(event);
    const t = Math.floor(Date.now() / 1000);
    const { code, body } = await handleStripeWebhook(raw, signStripe(raw, t));
    return { sent: { type: event.type, status }, result: { code, ...body } };
  });

  // ---- group 7: files (brokered, quarantine-first, audited) ----
  const signFileUrl = (fileId, action) => {
    const exp = Math.floor(Date.now() / 1000) + 300;
    const sig = createHmac('sha256', cfg.jwtSecret).update(`${action}.${fileId}.${exp}`).digest('hex').slice(0, 32);
    return `/files/${fileId}/blob?action=${action}&exp=${exp}&sig=${sig}`; // brokered signed URL (byte store is external)
  };
  const recordFileAccess = (tid, fileId, actor, action, result) =>
    withServiceContext('svc_file', (c) => c.query(
      'insert into file_access_events(tenant_id, file_object_id, actor_id, action, result) values($1,$2,$3,$4,$5)',
      [tid, fileId, actor, action, result]));

  // Init an upload: create a QUARANTINED file record + a brokered signed upload URL.
  app.post('/files', { preHandler: auth }, async (req, reply) => {
    const { filename, content_type, size_bytes, subject_ref } = req.body || {};
    if (!filename) return reply.code(400).send({ error: 'filename is required' });
    const fileId = randomUUID();
    const objectPath = `${req.claims.tid}/hifz-lms/${fileId}`;
    await withServiceContext('svc_file', async (c) => {
      await c.query(
        `insert into file_objects(id, tenant_id, app_id, owner_membership_id, subject_ref, object_path, filename, content_type, size_bytes, uploaded_by, retention_policy_id)
         values($1,$2,(select id from apps where app_key='hifz-lms'),$3,$4,$5,$6,$7,$8,$9,(select id from retention_policies where policy_key=$10))`,
        [fileId, req.claims.tid, req.claims.mid, subject_ref || null, objectPath, filename, content_type || null, size_bytes || null, req.claims.sub, subject_ref ? 'minors' : 'default']);
    });
    await recordFileAccess(req.claims.tid, fileId, req.claims.sub, 'upload', 'quarantined');
    return { file_id: fileId, object_path: objectPath, status: 'quarantined', upload_url: signFileUrl(fileId, 'upload') };
  });

  // Record a scan verdict (normally the file-scan service; exposed for the demo).
  app.post('/files/:id/scan', { preHandler: auth }, async (req) => {
    const status = (req.body?.status) || 'clean';
    await withServiceContext('svc_file_scan', (c) => c.query('select app.finalize_scan($1,$2,$3)', [req.params.id, status, 'demo-scanner']));
    return { file_id: req.params.id, scan_status: status };
  });

  // Download: brokered, only when CLEAN, and consent-gated for minor files.
  app.get('/files/:id/download', { preHandler: auth }, async (req, reply) => {
    const file = await withUserContext(gucsFromClaims(req.claims), async (c) =>
      (await c.query('select id, scan_status, status, subject_ref from file_objects where id=$1', [req.params.id])).rows[0]);
    if (!file) return reply.code(404).send({ error: 'not found' });
    if (file.scan_status !== 'clean' || file.status !== 'active') {
      await recordFileAccess(req.claims.tid, req.params.id, req.claims.sub, 'download_denied', 'not_clean');
      return reply.code(423).send({ error: 'FILE_NOT_CLEAN' });
    }
    if (file.subject_ref) {
      const ok = await withServiceContext('svc_ops', (c) => c.query('select app.student_has_active_consent($1) ok', [file.subject_ref]));
      if (!ok.rows[0].ok) {
        await recordFileAccess(req.claims.tid, req.params.id, req.claims.sub, 'download_denied', 'consent_required');
        return reply.code(403).send({ error: 'CONSENT_REQUIRED' });
      }
    }
    await recordFileAccess(req.claims.tid, req.params.id, req.claims.sub, 'download', 'ok');
    return { download_url: signFileUrl(req.params.id, 'download'), expires_in: 300 };
  });

  app.get('/my-files', { preHandler: auth }, async (req) =>
    withUserContext(gucsFromClaims(req.claims), async (c) => ({ files: (await c.query('select * from app.v_my_files')).rows })));

  // ---- group 8: minor-data protection (students, consent, subject erasure — OQ-034) ----

  const consentActive = (studentId) =>
    withServiceContext('svc_ops', (c) => c.query('select app.student_has_active_consent($1) ok', [studentId])).then((r) => r.rows[0].ok);

  app.post('/students', { preHandler: auth }, async (req, reply) => {
    const { full_name, date_of_birth } = req.body || {};
    if (!full_name) return reply.code(400).send({ error: 'full_name is required' });
    try {
      const id = await withUserContext(gucsFromClaims(req.claims), async (c) => (await c.query(
        `insert into students(tenant_id, app_id, full_name, date_of_birth, retention_policy_id)
         values(app.current_tenant_id(), (select id from apps where app_key='hifz-lms'), $1, $2, (select id from retention_policies where policy_key='minors')) returning id`,
        [full_name, date_of_birth || null])).rows[0].id);
      return { student_id: id };
    } catch (e) { if (/row-level security/.test(e.message)) return reply.code(403).send({ error: 'requires students.manage' }); throw e; }
  });

  app.post('/students/:id/consent', { preHandler: auth }, async (req, reply) => {
    const { consent_type = 'data_processing', notice_version = 'v1', granted = true } = req.body || {};
    try {
      await withUserContext(gucsFromClaims(req.claims), async (c) => {
        if (granted) await c.query(
          `insert into parental_consents(tenant_id, student_id, consent_type, notice_version, method, status)
           values(app.current_tenant_id(), $1, $2, $3, 'verifiable_parental', 'granted')`, [req.params.id, consent_type, notice_version]);
        else await c.query(
          "update parental_consents set status='revoked', revoked_at=now() where student_id=$1 and consent_type=$2 and status='granted' and revoked_at is null",
          [req.params.id, consent_type]);
      });
      return { student_id: req.params.id, consent_type, granted };
    } catch (e) { if (/row-level security/.test(e.message)) return reply.code(403).send({ error: 'requires consents.manage' }); throw e; }
  });

  // Reading a student REQUIRES active parental consent (OQ-034 gate).
  app.get('/students/:id', { preHandler: auth }, async (req, reply) => {
    if (!(await consentActive(req.params.id))) return reply.code(403).send({ error: 'CONSENT_REQUIRED' });
    const student = await withUserContext(gucsFromClaims(req.claims), async (c) =>
      (await c.query('select id, full_name, date_of_birth, is_minor, status from students where id=$1', [req.params.id])).rows[0]);
    if (!student) return reply.code(404).send({ error: 'not found' });
    return { student };
  });

  // Subject-level erasure (right to be forgotten) — shreds one student + their files; tenant intact.
  app.post('/students/:id/erase', { preHandler: auth }, async (req, reply) => {
    if (!(req.claims.permissions || []).includes('students.manage')) return reply.code(403).send({ error: 'requires students.manage' });
    const n = await withServiceContext('svc_lifecycle', (c) => c.query('select app.erase_student($1,$2,$3) n', [req.params.id, 'subject_erasure', req.claims.sub]));
    return { erased: Number(n.rows[0].n) };
  });

  // ---- group 11: per-operator platform-ops auth (FOUNDATION_10) ----
  // Every /admin/* call carries an OPERATOR token (aud='operator') bound to a live operator_session; the
  // acting operator is taken from the token, never the body — so §12 dual-control is a true two-person
  // control. The shared admin token survives ONLY as an env-gated (default OFF), audited break-glass.
  // (auditAppend is defined further below; it is only referenced at request time, so ordering is fine.)
  const BREAKGLASS_OP = '0b000000-0000-0000-0000-0000000000ff';
  const operatorLive = (osid) => withServiceContext('svc_ops', (c) =>
    c.query('select app.assert_operator_session_live($1) live', [osid])).then((r) => r.rows[0].live);

  const operatorAuth = async (req, reply) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (m) {
      let claims; try { claims = verifyOperatorToken(m[1]); } catch { return reply.code(401).send({ error: 'invalid operator token' }); }
      if (!(await operatorLive(claims.osid))) return reply.code(401).send({ error: 'OPERATOR_SESSION_INACTIVE' });
      req.operator = { id: claims.sub, role: claims.orole, osid: claims.osid, acr: claims.acr || 'pwd' };
      return;
    }
    if (req.headers['x-admin-token']) {                       // break-glass (env-gated, loudly audited)
      if (cfg.breakGlassEnabled && req.headers['x-admin-token'] === cfg.adminToken) {
        req.operator = { id: BREAKGLASS_OP, role: 'admin', breakglass: true };
        await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.breakglass.used',
          actor_ref: BREAKGLASS_OP, resource_type: 'endpoint', resource_ref: req.url, outcome: 'success', reason_code: 'BREAKGLASS' });
        return;
      }
      return reply.code(401).send({ error: 'BREAKGLASS_DISABLED' });
    }
    return reply.code(401).send({ error: 'operator authentication required' });
  };

  // Role-matrix guard: call at the top of a handler. Audits the denial (§12) and 403s.
  const requireRole = async (req, reply, allowed) => {
    if (req.operator?.breakglass || allowed.includes(req.operator.role)) return true;
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.role_denied', actor_ref: req.operator.id,
      resource_type: 'endpoint', resource_ref: req.url, outcome: 'denied', reason_code: 'ROLE_REQUIRED' });
    reply.code(403).send({ error: 'OPERATOR_ROLE_REQUIRED', allowed });
    return false;
  };

  // Step-up guard (group 12): the session must carry acr='mfa'. Break-glass counts as admin-equivalent.
  const requireMfa = async (req, reply) => {
    if (req.operator?.breakglass || req.operator.acr === 'mfa') return true;
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.stepup_required', actor_ref: req.operator.id,
      resource_type: 'endpoint', resource_ref: req.url, outcome: 'denied', reason_code: 'MFA_REQUIRED' });
    reply.code(403).send({ error: 'MFA_REQUIRED', detail: 're-authenticate with a second factor for this action' });
    return false;
  };

  // ---- group 9: TENANT-level offboarding lifecycle (MASTER_PLAN §13/§10/§15) — now operator-gated ----
  // Map the state-machine's RAISEs to HTTP. Gate failures are 409 (conflict with current state).
  const lifecycleError = (e) => {
    const m = String(e.message || '');
    if (/OFFBOARDING_JOB_NOT_FOUND/.test(m)) return { code: 404, error: 'OFFBOARDING_JOB_NOT_FOUND' };
    if (/LEGAL_HOLD_ACTIVE/.test(m)) return { code: 409, error: 'LEGAL_HOLD_ACTIVE' };
    if (/EXPORT_RECEIPT_REQUIRED/.test(m)) return { code: 409, error: 'EXPORT_RECEIPT_REQUIRED' };
    if (/RETENTION_NOT_ELAPSED/.test(m)) return { code: 409, error: 'RETENTION_NOT_ELAPSED' };
    if (/RETENTION_POLICY_REQUIRED/.test(m)) return { code: 409, error: 'RETENTION_POLICY_REQUIRED' };
    if (/PURGE_RECEIPTS_REQUIRED/.test(m)) return { code: 409, error: 'PURGE_RECEIPTS_REQUIRED' };
    if (/PURGE_ALREADY_RUN/.test(m)) return { code: 409, error: 'PURGE_ALREADY_RUN' };
    if (/PURGE_WRONG_PHASE/.test(m)) return { code: 409, error: 'PURGE_WRONG_PHASE' };
    if (/OFFBOARDING_(INVALID_TRANSITION|TERMINAL)/.test(m)) return { code: 409, error: 'OFFBOARDING_INVALID_TRANSITION' };
    if (/duplicate key/.test(m)) return { code: 409, error: 'OFFBOARDING_ALREADY_ACTIVE' };
    return null;
  };
  const relay = () => withServiceContext('svc_events', (c) => c.query('select app.relay_outbox(100)'));

  // Start an offboarding job for a tenant (phase 'requested').
  app.post('/admin/offboarding/start', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const { tenant, reason, retention_policy_key = 'offboarding-default' } = req.body || {};
    if (!tenant) return reply.code(400).send({ error: 'tenant (slug) is required' });
    try {
      const out = await withServiceContext('svc_lifecycle', async (c) => {
        const t = (await c.query('select id from tenants where slug=$1 and deleted_at is null', [tenant])).rows[0];
        if (!t) return null;
        const j = await c.query(
          `insert into tenant_offboarding_jobs(tenant_id, retention_policy_id, reason, requested_by)
           values($1,(select id from retention_policies where policy_key=$2),$3,$4) returning id, phase`,
          [t.id, retention_policy_key, reason || null, req.operator.id]);
        return { tenant_id: t.id, job: j.rows[0] };
      });
      if (!out) return reply.code(404).send({ error: 'tenant not found' });
      return { offboarding_job_id: out.job.id, tenant_id: out.tenant_id, phase: out.job.phase };
    } catch (e) {
      const le = lifecycleError(e); if (le) return reply.code(le.code).send({ error: le.error });
      throw e;
    }
  });

  // Advance the state machine (enforces the §13 DAG + legal-hold/export/retention/completion gates).
  app.post('/admin/offboarding/:id/advance', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const { to } = req.body || {};
    if (!to) return reply.code(400).send({ error: 'target phase "to" is required' });
    try {
      const phase = await withServiceContext('svc_lifecycle', (c) =>
        c.query('select app.advance_offboarding($1,$2,$3) p', [req.params.id, to, req.operator.id]))
        .then((r) => r.rows[0].p);
      await relay();
      return { offboarding_job_id: req.params.id, phase };
    } catch (e) {
      const le = lifecycleError(e); if (le) return reply.code(le.code).send({ error: le.error });
      throw e;
    }
  });

  // Persist an export verification receipt (the export completion gate, §10).
  app.post('/admin/offboarding/:id/export-verify', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const { manifest_hash = 'demo-manifest', signature_valid = true, checksum_valid = true } = req.body || {};
    const out = await withServiceContext('svc_lifecycle', async (c) => {
      const j = (await c.query('select tenant_id from tenant_offboarding_jobs where id=$1', [req.params.id])).rows[0];
      if (!j) return null;
      // Receipts are immutable evidence (grant is select+insert only). A repeat verify is a no-op.
      await c.query(
        `insert into export_verification_receipts(tenant_id, offboarding_job_id, manifest_hash, signature_valid, checksum_valid, verified_by)
         values($1,$2,$3,$4,$5,'platform-ops')
         on conflict (offboarding_job_id) do nothing`,
        [j.tenant_id, req.params.id, manifest_hash, signature_valid, checksum_valid]);
      return true;
    });
    if (!out) return reply.code(404).send({ error: 'OFFBOARDING_JOB_NOT_FOUND' });
    return { offboarding_job_id: req.params.id, export_verified: true };
  });

  // Run the data-plane purge (only valid in purge_started) — writes cache + search receipts.
  app.post('/admin/offboarding/:id/purge', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    try {
      const pj = await withServiceContext('svc_lifecycle', (c) =>
        c.query('select app.execute_tenant_purge($1,$2) pj', [req.params.id, req.operator.id]))
        .then((r) => r.rows[0].pj);
      await relay();
      return { offboarding_job_id: req.params.id, purge_job_id: pj };
    } catch (e) {
      const le = lifecycleError(e); if (le) return reply.code(le.code).send({ error: le.error });
      throw e;
    }
  });

  // Inspect a job + its receipts and purge summary.
  app.get('/admin/offboarding/:id', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const out = await withServiceContext('svc_lifecycle', async (c) => {
      const job = (await c.query('select * from tenant_offboarding_jobs where id=$1', [req.params.id])).rows[0];
      if (!job) return null;
      const receipts = {
        export: (await c.query('select signature_valid, checksum_valid, verified_at from export_verification_receipts where offboarding_job_id=$1', [req.params.id])).rows[0] || null,
        cache: (await c.query('select c.completed_at from cache_purge_receipts c join purge_jobs p on p.request_id=c.request_id where p.offboarding_job_id=$1', [req.params.id])).rows[0] || null,
        search: (await c.query('select s.completed_at from search_purge_receipts s join purge_jobs p on p.request_id=s.request_id where p.offboarding_job_id=$1', [req.params.id])).rows[0] || null,
      };
      const ready = (await c.query('select app.offboarding_completion_ready($1) r', [req.params.id])).rows[0].r;
      const hold = (await c.query('select app.tenant_has_active_legal_hold($1) h', [job.tenant_id])).rows[0].h;
      return { job, receipts, completion_ready: ready, legal_hold_active: hold };
    });
    if (!out) return reply.code(404).send({ error: 'OFFBOARDING_JOB_NOT_FOUND' });
    return out;
  });

  // Place a legal hold on a tenant (blocks purge progression, §13).
  app.post('/admin/legal-hold', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const { tenant, reason, reference } = req.body || {};
    if (!tenant || !reason) return reply.code(400).send({ error: 'tenant (slug) and reason are required' });
    const out = await withServiceContext('svc_lifecycle', async (c) => {
      const t = (await c.query('select id from tenants where slug=$1', [tenant])).rows[0];
      if (!t) return null;
      const h = await c.query(
        'insert into legal_holds(tenant_id, reason, reference, placed_by) values($1,$2,$3,$4) returning id',
        [t.id, reason, reference || null, req.operator.id]);
      return h.rows[0].id;
    });
    if (!out) return reply.code(404).send({ error: 'tenant not found' });
    return { legal_hold_id: out, tenant, status: 'active' };
  });

  // Release a legal hold (unblocks purge progression).
  app.post('/admin/legal-hold/:id/release', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const n = await withServiceContext('svc_lifecycle', (c) =>
      c.query("update legal_holds set status='released', released_at=now(), released_by=$2 where id=$1 and status='active'",
        [req.params.id, req.operator.id]));
    return { legal_hold_id: req.params.id, released: n.rowCount };
  });

  // ---- group 10: support/impersonation + platform-ops + Tier-A audit (MASTER_PLAN §12/§16) ----
  // Operator surface, gated by the same out-of-band admin token (a stand-in for full dual-control
  // platform-ops auth). DB writes run as svc_support / svc_audit / svc_ops.

  // Canonical audit writer — always its OWN committed transaction (Postgres has no autonomous tx, so a
  // DENIAL must be persisted here BEFORE the request is rejected, never inside a rolled-back tx).
  const auditAppend = (role, a) => withServiceContext(role, (c) => c.query(
    'select app.audit_append($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) id',
    [a.chain_id, a.tenant ?? null, a.action, a.actor_type ?? 'service', a.actor_ref ?? null,
     a.resource_type ?? null, a.resource_ref ?? null, a.subject_token ?? null, a.outcome ?? 'success',
     a.reason_code ?? null, a.correlation_id ?? null, a.support_session_id ?? null,
     JSON.stringify(a.meta ?? {})])).then((r) => r.rows[0].id);

  // Resolve a target tenant user's membership + effective permissions (for the impersonation token).
  const resolveTarget = (tenantId, userId) => withServiceContext('svc_ops', async (c) => {
    const m = await c.query('select id from tenant_memberships where tenant_id=$1 and user_id=$2 and status=$3 and deleted_at is null', [tenantId, userId, 'active']);
    if (!m.rowCount) return null;
    const perms = await c.query(
      `select distinct p.permission_key from tenant_user_roles tur
         join role_permissions rp on rp.role_id=tur.role_id join permissions p on p.id=rp.permission_id
        where tur.tenant_id=$1 and tur.membership_id=$2 and tur.deleted_at is null`, [tenantId, m.rows[0].id]);
    return { membershipId: m.rows[0].id, permissions: perms.rows.map((r) => r.permission_key) };
  });

  // ---- group 11: operator login/session + operator management ----

  // Operator login: (email, api_key) -> an operator token bound to a fresh operator_session. The raw key
  // is hashed server-side (no pass-the-hash). Both success and failure are audited to the platform chain.
  app.post('/operator/login', async (req, reply) => {
    const { email, api_key } = req.body || {};
    if (!email || !api_key) return reply.code(400).send({ error: 'email and api_key are required' });
    const key_prefix = String(api_key).slice(0, 12);
    const authed = await withServiceContext('svc_ops', (c) =>
      c.query('select * from app.operator_authenticate($1,$2,$3)', [email, key_prefix, api_key])).then((r) => r.rows[0]);
    if (!authed) {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.login.denied',
        actor_ref: String(email).slice(0, 80), outcome: 'denied', reason_code: 'BAD_CREDENTIAL' });
      return reply.code(401).send({ error: 'invalid operator credentials' });
    }
    // Group 12: an MFA-enrolled operator gets only a short-lived pending-MFA challenge from factor 1.
    const hasMfa = await withServiceContext('svc_ops', (c) =>
      c.query('select app.operator_has_active_mfa($1) m', [authed.operator_id])).then((r) => r.rows[0].m);
    if (hasMfa) {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.login.mfa_challenge', actor_ref: authed.operator_id, outcome: 'success' });
      return { mfa_required: true, mfa_token: mintOperatorMfaToken({ operator_id: authed.operator_id }), token_type: 'pending-mfa', expires_in: cfg.operatorMfaTtlSec };
    }
    const osid = await withServiceContext('svc_ops', (c) =>
      c.query("select app.start_operator_session($1,$2,'pwd','pwd') id", [authed.operator_id, cfg.operatorTokenTtlSec])).then((r) => r.rows[0].id);
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.login', actor_ref: authed.operator_id,
      resource_type: 'operator_session', resource_ref: osid, outcome: 'success' });
    const operator_token = mintOperatorToken({ operator_id: authed.operator_id, operator_role: authed.operator_role, osid, amr: ['pwd'], acr: 'pwd' });
    return { operator_token, token_type: 'Bearer', operator_role: authed.operator_role, acr: 'pwd', expires_in: cfg.operatorTokenTtlSec };
  });

  // Operator logout: revoke the caller's session — its token dies immediately (before TTL).
  app.post('/operator/logout', { preHandler: operatorAuth }, async (req) => {
    const n = await withServiceContext('svc_ops', (c) =>
      c.query('select app.revoke_operator_session($1,$2) n', [req.operator.osid, 'logout'])).then((r) => Number(r.rows[0].n));
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.logout', actor_ref: req.operator.id,
      resource_type: 'operator_session', resource_ref: req.operator.osid, outcome: 'success' });
    return { revoked: n };
  });

  // ---- group 12: operator MFA (TOTP) + SSO ----

  // Enroll TOTP for the calling operator: returns the secret + otpauth URI for an authenticator app.
  app.post('/operator/mfa/enroll', { preHandler: operatorAuth }, async (req) => {
    const secret = generateTotpSecret();
    await withServiceContext('svc_ops', (c) => c.query('select app.operator_mfa_begin_enroll($1,$2)', [req.operator.id, secret]));
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.mfa.enroll_started', actor_ref: req.operator.id, outcome: 'success' });
    return { secret, otpauth_uri: otpauthUri(cfg.mfaIssuer, req.operator.id, secret), note: 'add to your authenticator, then POST /operator/mfa/activate {code}' };
  });

  // Activate the pending enrollment by proving a live code; returns one-time recovery codes (shown once).
  app.post('/operator/mfa/activate', { preHandler: operatorAuth }, async (req, reply) => {
    const { code } = req.body || {};
    const mfa = await withServiceContext('svc_ops', (c) => c.query('select * from app.operator_mfa_get($1)', [req.operator.id])).then((r) => r.rows[0]);
    if (!mfa || mfa.status !== 'pending') return reply.code(409).send({ error: 'no pending enrollment' });
    if (!verifyTotp(mfa.secret, code)) {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.mfa.activate', actor_ref: req.operator.id, outcome: 'denied', reason_code: 'BAD_CODE' });
      return reply.code(401).send({ error: 'INVALID_CODE' });
    }
    await withServiceContext('svc_ops', (c) => c.query('select app.operator_mfa_activate($1)', [req.operator.id]));
    const codes = Array.from({ length: 8 }, () => `rc_${randomUUID().replace(/-/g, '').slice(0, 10)}`);
    await withServiceContext('svc_ops', (c) => c.query('select app.operator_add_recovery_codes($1,$2::text[])', [req.operator.id, codes.map(sha256)]));
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.mfa.activated', actor_ref: req.operator.id, outcome: 'success' });
    return { mfa: 'active', recovery_codes: codes, note: 'store these recovery codes now — shown once' };
  });

  // Complete login: exchange a pending-MFA token + a TOTP (or recovery) code for a full session token.
  app.post('/operator/mfa/verify', async (req, reply) => {
    const { mfa_token, code, recovery_code } = req.body || {};
    if (!mfa_token) return reply.code(400).send({ error: 'mfa_token is required' });
    let opId; try { opId = verifyOperatorMfaToken(mfa_token).sub; } catch { return reply.code(401).send({ error: 'invalid or expired mfa_token' }); }
    const mfa = await withServiceContext('svc_ops', (c) => c.query('select * from app.operator_mfa_get($1)', [opId])).then((r) => r.rows[0]);
    if (!mfa || mfa.status !== 'active') return reply.code(409).send({ error: 'no active MFA' });
    if (mfa.locked) {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.mfa.verify', actor_ref: opId, outcome: 'denied', reason_code: 'LOCKED' });
      return reply.code(429).send({ error: 'MFA_LOCKED', detail: 'too many failed attempts; try again later' });
    }
    let ok = false, method = 'otp';
    if (recovery_code) { ok = await withServiceContext('svc_ops', (c) => c.query('select app.operator_consume_recovery_code($1,$2) ok', [opId, sha256(recovery_code)])).then((r) => r.rows[0].ok); method = 'recovery'; }
    else ok = verifyTotp(mfa.secret, code);
    await withServiceContext('svc_ops', (c) => c.query('select app.operator_mfa_record($1,$2)', [opId, ok]));
    if (!ok) {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.mfa.verify', actor_ref: opId, outcome: 'denied', reason_code: 'BAD_CODE' });
      return reply.code(401).send({ error: 'INVALID_CODE' });
    }
    const op = await withServiceContext('svc_ops', (c) => c.query('select operator_role from platform_operators where id=$1', [opId])).then((r) => r.rows[0]);
    const osid = await withServiceContext('svc_ops', (c) => c.query("select app.start_operator_session($1,$2,$3,'mfa') id", [opId, cfg.operatorTokenTtlSec, `pwd,${method}`])).then((r) => r.rows[0].id);
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.login', actor_ref: opId, resource_type: 'operator_session', resource_ref: osid, outcome: 'success', meta: { acr: 'mfa', method } });
    const operator_token = mintOperatorToken({ operator_id: opId, operator_role: op.operator_role, osid, amr: ['pwd', method], acr: 'mfa' });
    return { operator_token, token_type: 'Bearer', operator_role: op.operator_role, acr: 'mfa', expires_in: cfg.operatorTokenTtlSec };
  });

  // Admin: reset an operator's MFA (disables it + clears recovery codes). §12 sensitive; admin + step-up.
  app.post('/admin/operators/:id/mfa/reset', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const n = await withServiceContext('svc_ops', (c) => c.query('select app.operator_reset_mfa($1,$2) n', [req.params.id, 'admin_reset'])).then((r) => Number(r.rows[0].n));
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.mfa.reset', actor_ref: req.operator.id, resource_type: 'operator', resource_ref: req.params.id, outcome: 'success', meta: { disabled: n } });
    return { operator_id: req.params.id, mfa_reset: true };
  });

  // SSO login: verify a signed IdP assertion → resolve/JIT the operator → session (amr=['sso']). The
  // assertion is `base64url(json).hmac-sha256(secret,payload)` — an MVP stand-in for OIDC JWKS / SAML x509
  // (the live redirect/code-exchange handshake is deferred; the trust contract is what's implemented).
  app.post('/operator/sso/login', async (req, reply) => {
    const { idp, assertion } = req.body || {};
    if (!idp || !assertion) return reply.code(400).send({ error: 'idp and assertion are required' });
    const provider = await withServiceContext('svc_ops', (c) => c.query("select * from operator_idp where idp_key=$1 and status='active'", [idp])).then((r) => r.rows[0]);
    if (!provider) return reply.code(404).send({ error: 'unknown idp' });
    let claims;
    try {
      const [payloadB64, sig] = String(assertion).split('.');
      const expected = createHmac('sha256', provider.signing_secret).update(payloadB64 || '').digest('hex');
      if (!sig || sig.length !== expected.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) throw new Error('sig');
      claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.sso.login', actor_ref: String(idp).slice(0, 40), outcome: 'denied', reason_code: 'BAD_ASSERTION' });
      return reply.code(401).send({ error: 'INVALID_ASSERTION' });
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.iss !== provider.issuer || claims.aud !== provider.audience || !claims.sub || (claims.exp && claims.exp < now)) {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.sso.login', actor_ref: String(idp).slice(0, 40), outcome: 'denied', reason_code: 'ASSERTION_REJECTED' });
      return reply.code(401).send({ error: 'ASSERTION_REJECTED' });
    }
    let resolved;
    try {
      resolved = await withServiceContext('svc_ops', (c) => c.query('select * from app.operator_sso_login($1,$2,$3)',
        [provider.id, claims.sub, claims.email || `${claims.sub}@${provider.allowed_domain || 'unknown'}`])).then((r) => r.rows[0]);
    } catch (e) {
      const reason = /DOMAIN_NOT_ALLOWED/.test(e.message) ? 'DOMAIN_NOT_ALLOWED' : /duplicate|unique/.test(e.message) ? 'EMAIL_EXISTS' : 'SSO_FAILED';
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.sso.login', actor_ref: String(idp).slice(0, 40), resource_ref: claims.sub, outcome: 'denied', reason_code: reason });
      return reply.code(403).send({ error: reason });
    }
    if (!resolved) {
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.sso.login', actor_ref: String(idp).slice(0, 40), resource_ref: claims.sub, outcome: 'denied', reason_code: 'NO_LINK' });
      return reply.code(401).send({ error: 'NO_FEDERATED_IDENTITY' });
    }
    const acr = Array.isArray(claims.amr) && claims.amr.includes('mfa') ? 'mfa' : 'sso';
    const osid = await withServiceContext('svc_ops', (c) => c.query("select app.start_operator_session($1,$2,'sso',$3) id", [resolved.operator_id, cfg.operatorTokenTtlSec, acr])).then((r) => r.rows[0].id);
    await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.sso.login', actor_ref: resolved.operator_id, resource_type: 'operator_session', resource_ref: osid, outcome: 'success', meta: { idp, jit: resolved.jit, acr } });
    const operator_token = mintOperatorToken({ operator_id: resolved.operator_id, operator_role: resolved.operator_role, osid, amr: ['sso'], acr });
    return { operator_token, token_type: 'Bearer', operator_role: resolved.operator_role, acr, jit_provisioned: resolved.jit, expires_in: cfg.operatorTokenTtlSec };
  });

  // Create a platform operator (admin only).
  app.post('/admin/operators', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const { email, display_name, operator_role = 'support' } = req.body || {};
    if (!email || !display_name) return reply.code(400).send({ error: 'email and display_name are required' });
    try {
      const id = await withServiceContext('svc_ops', (c) => c.query(
        'insert into platform_operators(email, display_name, operator_role) values($1,$2,$3) returning id',
        [email, display_name, operator_role])).then((r) => r.rows[0].id);
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.created', actor_ref: req.operator.id,
        resource_type: 'operator', resource_ref: id, meta: { operator_role } });
      return { operator_id: id, operator_role };
    } catch (e) { return reply.code(400).send({ error: /duplicate|unique/.test(e.message) ? 'operator already exists' : /check/.test(e.message) ? 'invalid operator_role' : 'create_failed' }); }
  });

  // Issue an API-key credential for an operator (admin only). Returns the raw key ONCE.
  app.post('/admin/operators/:id/credential', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const api_key = `opk_${randomUUID().replace(/-/g, '')}`;      // opaque high-entropy key
    const key_prefix = api_key.slice(0, 12), secret_hash = sha256(api_key);
    try {
      const credId = await withServiceContext('svc_ops', (c) => c.query(
        'insert into operator_credentials(operator_id, key_prefix, secret_hash, created_by) values($1,$2,$3,$4) returning id',
        [req.params.id, key_prefix, secret_hash, req.operator.id])).then((r) => r.rows[0].id);
      await auditAppend('svc_ops', { chain_id: 'platform', action: 'operator.credential.issued', actor_ref: req.operator.id,
        resource_type: 'operator_credential', resource_ref: credId });
      return { credential_id: credId, operator_id: req.params.id, api_key, note: 'store this key now — it is not retrievable' };
    } catch (e) { return reply.code(400).send({ error: /foreign key/.test(e.message) ? 'operator not found' : 'issue_failed' }); }
  });

  // Open a support access request for a tenant. The requester IS the authenticated operator (from the
  // token) — not a body field — so dual-control can't be gamed by naming someone else as requester.
  app.post('/admin/support/request', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['support', 'ops', 'admin'])) return;
    const { tenant, target_email, reason, ticket_ref, ttl_seconds = 1800, mode = 'read_only' } = req.body || {};
    const requested_by = req.operator.id;
    if (!tenant || !reason) return reply.code(400).send({ error: 'tenant and reason are required' });
    // MVP is read-only (spec §Notes): reject read_write so the returned mode never diverges from the
    // actually-enforced capability (the token is always tw=false). read_write is a future group.
    if (mode !== 'read_only') return reply.code(400).send({ error: 'MODE_UNSUPPORTED', detail: 'read_write impersonation is deferred; MVP is read-only' });
    // Tenant + user lookups run as svc_ops (svc_support does NOT own those tables — least privilege).
    const resolved = await withServiceContext('svc_ops', async (c) => {
      const t = (await c.query('select id from tenants where slug=$1 and deleted_at is null', [tenant])).rows[0];
      if (!t) return null;
      const target = target_email
        ? (await c.query('select id from user_identities where primary_email=$1', [target_email])).rows[0]?.id ?? null
        : null;
      return { tenantId: t.id, target };
    });
    if (!resolved) return reply.code(404).send({ error: 'tenant not found' });
    let id;
    try {
      id = await withServiceContext('svc_support', (c) => c.query(
        `insert into support_access_requests(tenant_id, requested_by, target_user_id, reason, ticket_ref, mode, ttl_seconds)
         values($1,$2,$3,$4,$5,$6,$7) returning id`,
        [resolved.tenantId, requested_by, resolved.target, reason, ticket_ref || null, mode, ttl_seconds])).then((r) => r.rows[0].id);
    } catch (e) { return reply.code(400).send({ error: /check constraint|invalid input|violates/.test(e.message) ? 'invalid_request' : String(e.message).slice(0, 120) }); }
    await auditAppend('svc_support', { chain_id: resolved.tenantId, tenant: resolved.tenantId, action: 'support.request.created',
      actor_ref: requested_by, resource_type: 'support_access_request', resource_ref: id, meta: { mode, ttl_seconds } });
    return { support_access_request_id: id, tenant_id: resolved.tenantId, status: 'pending' };
  });

  // Approve a request — TRUE dual-control: the approver is derived from the AUTHENTICATED operator's live
  // session inside app.approve_support_request, and must differ from the requester (else 409 + audited).
  app.post('/admin/support/request/:id/approve', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['support', 'ops', 'admin'])) return;
    // svc_ops spans support_access_requests + operator_sessions + platform_operators (the approve fn reads all).
    const tenantId = await withServiceContext('svc_ops', (c) =>
      c.query('select tenant_id from support_access_requests where id=$1', [req.params.id])).then((r) => r.rows[0]?.tenant_id);
    if (!tenantId) return reply.code(404).send({ error: 'SUPPORT_REQUEST_NOT_FOUND' });
    try {
      await withServiceContext('svc_ops', (c) => c.query('select app.approve_support_request($1,$2)', [req.params.id, req.operator.osid]));
      await auditAppend('svc_support', { chain_id: tenantId, tenant: tenantId, action: 'support.request.approved',
        actor_ref: req.operator.id, resource_type: 'support_access_request', resource_ref: req.params.id });
      return { support_access_request_id: req.params.id, status: 'approved' };
    } catch (e) {
      const m = String(e.message);
      const reason = /SELF_APPROVAL/.test(m) ? 'SELF_APPROVAL_DENIED' : /NOT_PENDING/.test(m) ? 'NOT_PENDING'
        : /APPROVER_SESSION_INVALID/.test(m) ? 'APPROVER_SESSION_INVALID' : 'APPROVE_FAILED';
      await auditAppend('svc_support', { chain_id: tenantId, tenant: tenantId, action: 'support.request.approve',
        actor_ref: req.operator.id, resource_type: 'support_access_request', resource_ref: req.params.id, outcome: 'denied', reason_code: reason });
      if (/SELF_APPROVAL|NOT_PENDING|APPROVER_SESSION_INVALID/.test(m)) return reply.code(409).send({ error: reason });
      throw e;
    }
  });

  // Deny a request (audited).
  app.post('/admin/support/request/:id/deny', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['support', 'ops', 'admin'])) return;
    const { reason } = req.body || {};
    const out = await withServiceContext('svc_support', async (c) => {
      const r = (await c.query('select tenant_id from support_access_requests where id=$1', [req.params.id])).rows[0];
      if (!r) return null;
      await c.query("update support_access_requests set status='denied', denied_at=now(), deny_reason=$2 where id=$1 and status='pending'", [req.params.id, reason || null]);
      return r.tenant_id;
    });
    if (!out) return reply.code(404).send({ error: 'SUPPORT_REQUEST_NOT_FOUND' });
    await auditAppend('svc_support', { chain_id: out, tenant: out, action: 'support.request.denied',
      actor_ref: req.operator.id, resource_type: 'support_access_request', resource_ref: req.params.id, outcome: 'denied', reason_code: 'operator_denied' });
    return { support_access_request_id: req.params.id, status: 'denied' };
  });

  // Start impersonation from an approved request → returns a READ-ONLY support token + banner signal.
  app.post('/admin/support/impersonate', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['support', 'ops', 'admin'])) return;
    const { request_id } = req.body || {};
    if (!request_id) return reply.code(400).send({ error: 'request_id is required' });
    const rq = await withServiceContext('svc_support', (c) =>
      c.query('select tenant_id, requested_by, target_user_id, status, mode from support_access_requests where id=$1', [request_id])).then((r) => r.rows[0]);
    if (!rq) return reply.code(404).send({ error: 'SUPPORT_REQUEST_NOT_FOUND' });
    if (rq.status !== 'approved') {
      await auditAppend('svc_support', { chain_id: rq.tenant_id, tenant: rq.tenant_id, action: 'support.impersonation.denied',
        actor_ref: rq.requested_by, resource_type: 'support_access_request', resource_ref: request_id, outcome: 'denied', reason_code: 'NOT_APPROVED' });
      return reply.code(409).send({ error: 'SUPPORT_REQUEST_NOT_APPROVED' });
    }
    if (!rq.target_user_id) {
      await auditAppend('svc_support', { chain_id: rq.tenant_id, tenant: rq.tenant_id, action: 'support.impersonation.denied',
        actor_ref: rq.requested_by, resource_type: 'support_access_request', resource_ref: request_id, outcome: 'denied', reason_code: 'NO_TARGET' });
      return reply.code(400).send({ error: 'request has no target_user to impersonate' });
    }
    const target = await resolveTarget(rq.tenant_id, rq.target_user_id);
    if (!target) {
      // A denied impersonation ATTEMPT (§12 "denied attempts must be audited").
      await auditAppend('svc_support', { chain_id: rq.tenant_id, tenant: rq.tenant_id, action: 'support.impersonation.denied',
        actor_ref: rq.requested_by, resource_type: 'user', resource_ref: rq.target_user_id, outcome: 'denied', reason_code: 'NO_ACTIVE_MEMBERSHIP' });
      return reply.code(404).send({ error: 'target user has no active membership in that tenant' });
    }
    // A group-5 session for the impersonated view (so revocation cascade works).
    const sid = randomUUID();
    await withServiceContext('svc_session', (c) => c.query(
      `insert into sessions(id, tenant_id, user_id, membership_id, kind, root_session_id, entitlement_snapshot_version, expires_at)
       values($1,$2,$3,$4,'hub',$1,0, now() + interval '1800 seconds')`,
      [sid, rq.tenant_id, rq.target_user_id, target.membershipId]));
    let ssid;
    try {
      ssid = await withServiceContext('svc_support', (c) =>
        c.query('select app.start_support_session($1,$2) id', [request_id, sid])).then((r) => r.rows[0].id);
    } catch (e) {
      const reason = /duplicate key|one_active/.test(e.message) ? 'ALREADY_ACTIVE' : /NOT_APPROVED|APPROVAL_EXPIRED/.test(e.message) ? 'NOT_APPROVED' : 'START_FAILED';
      await auditAppend('svc_support', { chain_id: rq.tenant_id, tenant: rq.tenant_id, action: 'support.impersonation.denied',
        actor_ref: rq.requested_by, resource_type: 'support_access_request', resource_ref: request_id, outcome: 'denied', reason_code: reason });
      await withServiceContext('svc_session', (c) => c.query("update sessions set status='revoked', revoked_at=now() where id=$1", [sid])).catch(() => {});
      if (reason === 'ALREADY_ACTIVE') return reply.code(409).send({ error: 'SUPPORT_SESSION_ALREADY_ACTIVE' });
      throw e;
    }
    await auditAppend('svc_support', { chain_id: rq.tenant_id, tenant: rq.tenant_id, action: 'support.impersonation.granted',
      actor_ref: rq.requested_by, resource_type: 'user', resource_ref: rq.target_user_id, support_session_id: ssid, meta: { mode: rq.mode } });
    const support_token = mintSupportToken({ sub: rq.target_user_id, tid: rq.tenant_id, mid: target.membershipId,
      permissions: target.permissions, sid, ssid, imp: rq.requested_by, smode: rq.mode });
    return { support_token, token_type: 'Bearer', support_session_id: ssid, banner_required: true, mode: rq.mode, expires_in: 1800 };
  });

  // Support-token guard: a valid impersonation token (carries imp/ssid).
  const supportAuth = async (req, reply) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!m) return reply.code(401).send({ error: 'missing support token' });
    try { req.claims = verifyHubToken(m[1]); } catch { return reply.code(401).send({ error: 'invalid token' }); }
    if (!req.claims.imp) return reply.code(403).send({ error: 'not an impersonation token' });
  };

  // The banner context the UI MUST render (C5 visible-banner signal).
  app.get('/support/session', { preHandler: supportAuth }, async (req) => ({
    impersonating: true, operator: req.claims.imp, support_session_id: req.claims.ssid,
    acting_as: req.claims.sub, tenant: req.claims.tid, mode: req.claims.smode, banner_required: true,
  }));

  // Attempt an action class under impersonation — prohibited classes hard-deny (403) and are AUDITED.
  app.post('/support/attempt', { preHandler: supportAuth }, async (req, reply) => {
    const { action_class } = req.body || {};
    if (!action_class) return reply.code(400).send({ error: 'action_class is required' });
    const ssid = req.claims.ssid, tenant = req.claims.tid;
    const live = await withServiceContext('svc_support', (c) =>
      c.query('select status, expires_at from support_sessions where id=$1', [ssid])).then((r) => r.rows[0]);
    if (!live || live.status !== 'active' || new Date(live.expires_at) <= new Date()) {
      await auditAppend('svc_support', { chain_id: tenant, tenant, action: 'support.action', actor_ref: req.claims.imp,
        resource_type: 'action_class', resource_ref: action_class, support_session_id: ssid, outcome: 'denied', reason_code: 'SESSION_EXPIRED' });
      return reply.code(401).send({ error: 'SUPPORT_SESSION_EXPIRED' });
    }
    const prohibited = await withServiceContext('svc_support', (c) =>
      c.query('select app.support_action_prohibited($1) p', [action_class])).then((r) => r.rows[0].p);
    if (prohibited) {
      await auditAppend('svc_support', { chain_id: tenant, tenant, action: 'support.action', actor_ref: req.claims.imp,
        resource_type: 'action_class', resource_ref: action_class, support_session_id: ssid, outcome: 'denied', reason_code: 'PROHIBITED' });
      return reply.code(403).send({ error: 'SUPPORT_ACTION_PROHIBITED', action_class });
    }
    await auditAppend('svc_support', { chain_id: tenant, tenant, action: 'support.action', actor_ref: req.claims.imp,
      resource_type: 'action_class', resource_ref: action_class, support_session_id: ssid, outcome: 'success' });
    return { action_class, allowed: true };
  });

  // End an impersonation session (revokes the underlying group-5 session tree). Runs as svc_ops so the
  // internal revoke_session_cascade can touch the svc_session-owned `sessions` table.
  app.post('/admin/support/session/:id/end', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['support', 'ops', 'admin'])) return;
    const out = await withServiceContext('svc_ops', async (c) => {
      const s = (await c.query('select tenant_id from support_sessions where id=$1', [req.params.id])).rows[0];
      if (!s) return null;
      const n = (await c.query("select app.end_support_session($1,'operator_end') n", [req.params.id])).rows[0].n;
      return { tenant: s.tenant_id, revoked: Number(n) };
    });
    if (!out) return reply.code(404).send({ error: 'SUPPORT_SESSION_NOT_FOUND' });
    await auditAppend('svc_support', { chain_id: out.tenant, tenant: out.tenant, action: 'support.session.ended',
      resource_type: 'support_session', resource_ref: req.params.id });
    return { support_session_id: req.params.id, revoked: out.revoked };
  });

  // Verify a chain's integrity (operator/audit read).
  app.get('/admin/audit/verify', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['support', 'ops', 'admin'])) return;
    const chain = req.query.chain;
    if (!chain) return reply.code(400).send({ error: 'chain query param required (tenant slug or "platform")' });
    const chainId = chain === 'platform' ? 'platform'
      : (await withServiceContext('svc_ops', (c) => c.query('select id from tenants where slug=$1', [chain]))).rows?.[0]?.id;
    if (!chainId) return reply.code(404).send({ error: 'chain not found' });
    const r = await withServiceContext('svc_audit', (c) => c.query('select * from app.audit_verify_chain($1)', [String(chainId)]));
    return { chain: String(chainId), ...r.rows[0] };
  });

  // Tail a chain (operator/audit read).
  app.get('/admin/audit/tail', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['support', 'ops', 'admin'])) return;
    const chain = req.query.chain;
    if (!chain) return reply.code(400).send({ error: 'chain query param required' });
    const chainId = chain === 'platform' ? 'platform'
      : (await withServiceContext('svc_ops', (c) => c.query('select id from tenants where slug=$1', [chain]))).rows?.[0]?.id;
    if (!chainId) return reply.code(404).send({ error: 'chain not found' });
    const r = await withServiceContext('svc_audit', (c) => c.query(
      'select chain_seq, action, outcome, reason_code, left(row_hash,12) hash from audit_events where chain_id=$1 order by chain_seq desc limit 20', [String(chainId)]));
    return { chain: String(chainId), events: r.rows };
  });

  // Anchor a chain's current head (§16 Tier-A periodic external anchoring). Records the head hash in an
  // insert-once anchor point (idempotent); the external WORM/notary sink is a Tier-B deferral.
  app.post('/admin/audit/anchor', { preHandler: operatorAuth }, async (req, reply) => {
    if (!await requireRole(req, reply, ['ops', 'admin'])) return;
    if (!await requireMfa(req, reply)) return;
    const chain = (req.body && req.body.chain) || req.query.chain;
    if (!chain) return reply.code(400).send({ error: 'chain required (tenant slug or "platform")' });
    const chainId = chain === 'platform' ? 'platform'
      : (await withServiceContext('svc_ops', (c) => c.query('select id from tenants where slug=$1', [chain]))).rows?.[0]?.id;
    if (!chainId) return reply.code(404).send({ error: 'chain not found' });
    try {
      const r = await withServiceContext('svc_audit', (c) =>
        c.query('select app.audit_anchor($1,$2) id', [String(chainId), (req.body && req.body.external_ref) || null]));
      return { chain: String(chainId), anchor_id: r.rows[0].id };
    } catch (e) {
      if (/AUDIT_CHAIN_EMPTY/.test(e.message)) return reply.code(404).send({ error: 'AUDIT_CHAIN_EMPTY' });
      throw e;
    }
  });

  // Assign a role — RLS enforces the roles.assign permission AND tenant write-eligibility.
  app.post('/roles/assign', { preHandler: auth }, async (req, reply) => {
    const { membership_id, role_id } = req.body || {};
    if (!membership_id || !role_id) return reply.code(400).send({ error: 'membership_id and role_id are required' });
    try {
      const out = await withUserContext(gucsFromClaims(req.claims), async (c) => {
        // Entitlement staleness gate (MASTER_PLAN §7): reject writes carrying an outdated ent_v.
        const cur = await c.query('select entitlement_snapshot_version ev from tenants where id = app.current_tenant_id()');
        const current = cur.rows[0] ? Number(cur.rows[0].ev) : 0;
        if (Number(req.claims.ent_v ?? 0) < current) return { stale: current };
        const r = await c.query(
          'insert into tenant_user_roles(tenant_id, membership_id, role_id) values($1,$2,$3) returning id',
          [req.claims.tid, membership_id, role_id]);
        return { assigned: r.rows[0].id };
      });
      if (out.stale) return reply.code(409).send({ error: 'STALE_ENTITLEMENT_VERSION', current: out.stale });
      return out;
    } catch (e) {
      if (/row-level security/.test(e.message)) return reply.code(403).send({ error: 'not permitted' });
      if (/duplicate key/.test(e.message)) return reply.code(409).send({ error: 'already assigned' });
      if (/foreign key/.test(e.message)) return reply.code(400).send({ error: 'membership does not belong to this tenant' });
      throw e;
    }
  });

  return app;
}

// Run directly: node src/server.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const app = buildServer();
  app.listen({ port: cfg.port, host: '0.0.0.0' }).then(() => console.log(`hub listening on :${cfg.port}`));
}
