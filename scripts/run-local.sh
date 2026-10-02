#!/usr/bin/env bash
# Reproduce the foundation isolation gate on a disposable LOCAL Postgres (no Docker required).
# Uses a Homebrew postgresql@16 cluster in a scratch dir. Safe: nothing system-wide, own port.
set -euo pipefail

PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}"
PGDATA="${PGDATA:-$(pwd)/.localpg/data}"
PORT="${PORT:-55432}"
export DATABASE_URL="postgres://postgres:postgres@localhost:${PORT}/postgres"
# Point the app-layer pools (used by the API gate) at this same cluster.
export APP_DATABASE_URL="postgres://svc_app@localhost:${PORT}/postgres"
export WORKER_DATABASE_URL="postgres://svc_worker@localhost:${PORT}/postgres"
export LC_ALL=C LANG=C

if [ ! -d "$PGDATA" ]; then
  echo "== initdb =="
  mkdir -p "$PGDATA"
  "$PGBIN/initdb" -D "$PGDATA" -U postgres --auth=trust --locale=C --encoding=UTF8 >/dev/null
fi

echo "== start (port $PORT) =="
"$PGBIN/pg_ctl" -D "$PGDATA" -o "-p $PORT -k /tmp -c listen_addresses=localhost" -w start >/dev/null 2>&1 \
  || echo "(already running)"
"$PGBIN/pg_isready" -h localhost -p "$PORT"

echo "== reset =="
"$PGBIN/psql" "$DATABASE_URL" -q -c "drop schema if exists app cascade;
  drop table if exists rate_limit_episodes, rate_limit_buckets,
    feature_flag_decision_log, feature_flag_audit_events, feature_flag_rollouts,
    feature_flag_environments, feature_flag_definitions,
    operator_webauthn_challenges, operator_webauthn_credentials,
    operator_federated_identities, operator_idp, operator_recovery_codes, operator_mfa,
    operator_sessions, operator_credentials,
    audit_anchor_points, audit_events, support_sessions, support_access_requests,
    platform_operators, tenant_rate_limit_overrides, rate_limit_policies, platform_deployments,
    schema_migration_runs, environment_promotions,
    tenant_deletion_tombstones, search_purge_receipts, cache_purge_receipts,
    purge_job_items, purge_jobs, export_verification_receipts, legal_holds, tenant_offboarding_jobs,
    data_subject_requests, parental_consents, guardians, students,
    file_access_events, file_scan_results, file_objects, retention_policies,
    webhook_receipts, billing_events,
    launch_tokens, session_revocations, sessions,
    domain_events, outbox_events, inbox_events, consumer_checkpoints, dead_letter_events,
    entitlement_changes, entitlement_snapshots, subscription_items, subscriptions, billing_customers, plan_app_entitlements, plans,
    tenant_apps, apps, tenant_user_roles, role_permissions, permissions, roles, tenant_memberships, user_identities, tenants cascade;
  drop extension if exists citext cascade;" >/dev/null 2>&1 || true
"$PGBIN/psql" "$DATABASE_URL" -q -c "drop owned by svc_app, svc_worker, svc_migrate;
  drop role if exists svc_app, svc_worker, svc_migrate;" >/dev/null 2>&1 || true

echo "== migrate =="
for f in db/migrations/*.sql; do "$PGBIN/psql" "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$f"; done
echo "== seed =="
for f in db/seed/*.sql; do "$PGBIN/psql" "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$f"; done

# Run every suite even if one fails (|| RC=1 keeps `set -e` from bailing early).
RC=0
echo "== DB isolation gate (group 1) =="
node test/isolation.mjs || RC=1
echo ""
echo "== DB isolation gate (group 2 · app registry) =="
node test/apps.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 3 · billing + entitlements) =="
node test/entitlements.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 4 · events + workers) =="
node test/events.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 5 · sessions + launch) =="
node test/sessions.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 6 · billing webhooks) =="
node test/webhooks.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 7 · files/storage) =="
node test/files.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 8 · minor-data protection) =="
node test/minors.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 9 · tenant offboarding lifecycle) =="
node test/offboarding.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 10 · support/impersonation + audit) =="
node test/support.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 11 · per-operator platform-ops auth) =="
node test/operator.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 12 · operator MFA + SSO) =="
node test/mfa.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 13 · WebAuthn / passkeys) =="
node test/webauthn.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 14 · feature-flag governance) =="
node test/flags.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 15 · rate-limit enforcement) =="
node test/ratelimit.test.mjs || RC=1
node test/ratelimit.upstash.test.mjs || RC=1
echo ""
echo "== DB isolation gate (group 16 · identity binding / Supabase auth) =="
node test/identity.test.mjs || RC=1
echo ""
echo "== API gate =="
node test/api.test.mjs || RC=1

echo "== stop =="
"$PGBIN/pg_ctl" -D "$PGDATA" -w stop >/dev/null 2>&1 || true
exit $RC
