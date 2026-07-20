# Deployment guide

Operator-facing walkthrough for standing up GuardX in production. If you're just trying it locally, use [docker-compose](../../deploy/compose/docker-compose.yml) instead:

```sh
docker compose -f deploy/compose/docker-compose.yml up --build -d
# → Control API on :8080, gateway on :8081, console on :5173
```

The rest of this document assumes Kubernetes.

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Provisioning order](#2-provisioning-order)
3. [Postgres schema bootstrap](#3-postgres-schema-bootstrap)
4. [Signing key](#4-signing-key)
5. [OIDC (recommended)](#5-oidc-recommended)
6. [Helm install](#6-helm-install)
7. [First-boot checklist](#7-first-boot-checklist)
8. [Post-install verification](#8-post-install-verification)
9. [Observability wiring](#9-observability-wiring)
10. [Upgrade path](#10-upgrade-path)
11. [Rollback](#11-rollback)
12. [Multi-tenant deployment shape](#12-multi-tenant-deployment-shape)

---

## 1. Prerequisites

| Component | Version | Notes |
| ----- | ----- | ----- |
| Kubernetes | 1.28+ | Any conformant cluster |
| Postgres | 16+ | Managed (RDS, Supabase, Cloud SQL) or in-cluster StatefulSet |
| Helm | 3.14+ | For the chart install |
| A secrets manager | — | For the Ed25519 signing key + API keys (External Secrets Operator, sealed-secrets, or Kubernetes Secrets with a hardening story) |
| An OIDC provider | — | Supabase Auth, Keycloak, Auth0, Okta, Google, or Dex — anything with a JWKS URL. See [runbooks/oidc-setup.md](../runbooks/oidc-setup.md). Optional if you're OK with the API-key shim. |
| Prometheus + Grafana | — | Optional but strongly recommended. The chart ships a [dashboard](../../deploy/helm/dashboards/gateway.json) and [alert rules](../../deploy/helm/alerts/guardx-alerts.yaml) — see §9. |
| kubectl access to a namespace | — | The chart uses `Release.Name` for prefixing; no cluster-wide RBAC needed unless you enable ServiceMonitor. |

Optional:

- **cert-manager** if you'll terminate TLS at Ingress
- **A container registry** if you're building images locally instead of using the published `ghcr.io/guardx/*` images

## 2. Provisioning order

Follow this order — the Control API needs Postgres and the signing key before it can boot, and the gateway needs the Control API before it can install a bundle.

```
Postgres  ──► signing key (secret)  ──► Control API  ──► first bundle
                                            │
   OIDC IdP ──►────────────────────►────────┘
                                            │
   Detector images ──►────────────► gateway/detectors  ──►  console
```

## 3. Postgres schema bootstrap

The Control API runs its Alembic migrations at boot. There's no separate init job — first pod up applies migrations, subsequent pods no-op via Alembic's version table.

```sh
# Sanity check the URI works from your cluster.
kubectl run -it --rm --restart=Never pg-check --image=postgres:16 -- \
  psql "$POSTGRES_URI" -c 'select current_database(), current_user, version()'
```

If you're on **Supabase** and hit `connection refused` on the direct URI, use the **Session pooler** URI instead (Project Settings → Database → Connection string → Session pooler). Direct connections are free-tier IPv6-only.

The URI you feed the chart accepts either `postgresql://` or `postgresql+psycopg://` — the Control API normalises to the driver-qualified form on load.

## 4. Signing key

The Ed25519 keypair signs policy bundles and chain anchors. It must survive Control API pod restarts.

**Recommended: mount from a Secret.**

```sh
# 1. Generate a key.
openssl genpkey -algorithm Ed25519 -out signing.pem

# 2. Extract the raw public key for the gateway env.
openssl pkey -in signing.pem -pubout -outform der 2>/dev/null \
  | tail -c 32 | base64 > signing.pub.b64
cat signing.pub.b64

# 3. Store the private key as a Secret.
kubectl create secret generic guardx-signing-key \
  --namespace guardx \
  --from-file=signing.pem=signing.pem
```

Then in `values.yaml`:

```yaml
control:
  signingKey:
    existingSecret: guardx-signing-key   # mounted at /var/run/guardx/signing.pem
gateway:
  env:
    signingKeyID: prod-2026-q3
    signingPublicKeyB64: <contents of signing.pub.b64>   # or use env-var Secret ref
```

**Not recommended in prod:** letting the Control API auto-generate a key on first boot. This works — and is what compose does — but the key lives on a pod's ephemeral filesystem and disappears when the pod restarts. If you go this path, mount a PVC at `/data` and set `GUARDX_SIGNING_KEY_PATH=/data/signing.pem`.

**Rotation:** publish a new key ID + public key in the gateway env, roll the gateway (so it accepts both old and new), then flip the Control API to sign with the new key, then remove the old key from the gateway env after the last old-signature bundle ages out (`GUARDX_BUNDLE_MAX_AGE_HOURS`, default 72).

## 5. OIDC (recommended)

See [runbooks/oidc-setup.md](../runbooks/oidc-setup.md) for provider-specific recipes. Minimum values for the Control API:

```yaml
control:
  env:
    databaseUrl: postgresql+psycopg://user:pass@postgres/guardx
    corsAllowedOrigins: "https://console.guardx.example.com"
    # OIDC is set via extra env vars below, not the chart top-level keys.
```

Add these to the deployment via values (extend the chart or use a Secret + `envFrom`):

```
GUARDX_OIDC_ENABLED=true
GUARDX_OIDC_ISSUER=https://<ref>.supabase.co/auth/v1
GUARDX_OIDC_AUDIENCE=authenticated
GUARDX_OIDC_JWKS_URL=https://<ref>.supabase.co/auth/v1/.well-known/jwks.json
GUARDX_OIDC_ROLE_CLAIM=app_metadata.guardx_role
GUARDX_OIDC_SUBJECT_CLAIM=email
```

The console picks up OIDC at build time via Vite env:

```
VITE_CONTROL_URL=https://api.guardx.example.com
VITE_SUPABASE_URL=https://<ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<supabase-anon-key>
```

If you leave OIDC off, the console shows the API-key login tab and the Control API only accepts `X-GuardX-Key`. Not recommended for production but valid.

## 6. Helm install

```sh
# 1. Add repo (or use --generate-name from the checkout).
helm repo add guardx https://guardx.github.io/helm  # or path: deploy/helm

# 2. Create the namespace + secrets you referenced above.
kubectl create ns guardx

kubectl -n guardx create secret generic guardx-db \
  --from-literal=databaseUrl='postgresql+psycopg://user:pass@postgres/guardx'

kubectl -n guardx create secret generic guardx-api-keys \
  --from-literal=apiKeyAdmin=$(openssl rand -hex 32) \
  --from-literal=apiKeyService=$(openssl rand -hex 32)

# 3. Author values-prod.yaml (see below for a full example).

# 4. Install.
helm -n guardx install guardx guardx/guardx \
  -f values-prod.yaml \
  --wait --timeout 5m
```

Minimum viable `values-prod.yaml`:

```yaml
image:
  registry: ghcr.io/guardx
  tag: "0.1.0"

common:
  env:
    tenant: acme
    environment: prod

control:
  env:
    databaseUrl: postgresql+psycopg://user:pass@postgres/guardx
    corsAllowedOrigins: "https://console.guardx.example.com"
    apiKeyAdmin: ""     # empty when OIDC + real users; keep populated if you need it for CI
    apiKeyService: ""   # keep populated for automation-plane services
  signingKey:
    existingSecret: guardx-signing-key

gateway:
  replicaCount: 3
  env:
    controlBaseURL: http://guardx-control:8080
    upstreamBaseURL: https://api.openai.com     # or your own upstream
    piiBackendURL: http://guardx-detector-pii:9100
    safetyBackendURL: http://guardx-detector-safety:9200
    nliBackendURL: http://guardx-detector-nli:9300
    signingKeyID: prod-2026-q3
    signingPublicKeyB64: <base64-of-signing.pub>
    bundlePollInterval: "2s"
  metrics:
    serviceMonitor:
      enabled: true              # if you run Prometheus Operator

detectors:
  safety:
    env:
      togetherApiKeySecret: guardx-provider-keys   # holds TOGETHER_AI_API_KEY
      deepInfraApiKeySecret: guardx-provider-keys  # holds DEEPINFRA_API_KEY

observability:
  alerts:
    enabled: true
    crd: true    # if you run Prometheus Operator
  grafana:
    dashboards:
      enabled: true
```

## 7. First-boot checklist

The Control API is up. GuardX has zero content yet. Do these in order.

```sh
# Convenience: shell into a busybox pod or run these from your dev box with kubectl port-forward.
kubectl -n guardx port-forward svc/guardx-control 8080:8080 &
export CONTROL=http://127.0.0.1:8080
export ADMIN='X-GuardX-Key: <apiKeyAdmin from your secret>'   # or a Bearer JWT from your IdP
```

1. **Create a tenant.**
   ```sh
   curl -sSf -X POST "$CONTROL/v1/tenants" -H "$ADMIN" \
     -H 'content-type: application/json' -d '{"slug":"acme"}'
   ```

2. **Seed the detector catalog.** This is what makes detectors selectable in the console (spec §7).
   ```sh
   CONTROL=$CONTROL ADMIN_KEY='<key>' ./harness/seed_catalog.sh
   ```

3. **Author your first policy** — either interactively via the console **Onboarding** page or via the API:
   ```sh
   # Compile from a framework profile, then submit + approve.
   curl -sSf -X POST "$CONTROL/v1/profiles/compile" -H "$ADMIN" \
     -H 'content-type: application/json' \
     -d '{"tenant":"acme","profile":"baseline@1.0.0",
          "app_policy":{"metadata":{"id":"my-first","version":"1.0.0"},
                        "spec":{"applies_to":{"apps":["my-app"],"environments":["prod"]}}}}' \
     | jq
   ```

4. **Build the first bundle** so the gateway can install policy.
   ```sh
   curl -sSf -X POST "$CONTROL/v1/bundles/prod:build?tenant=acme" -H "$ADMIN" | jq
   ```

5. **Point your application at the gateway.** In your app config:
   ```
   OPENAI_BASE_URL=https://gateway.guardx.example.com/v1/proxy/my-app
   ```
   The `/v1/proxy/my-app` prefix tells GuardX which app's policy to apply. The rest of the OpenAI path is preserved.

## 8. Post-install verification

Everything below should return a value or a healthy status.

```sh
# Health.
curl -sSf https://api.guardx.example.com/healthz          # {"status":"ok"}
curl -sSf https://gateway.guardx.example.com/healthz      # {"status":"ok"}
curl -sSf https://gateway.guardx.example.com/readyz       # {"status":"ready"}

# Metrics scrape.
curl -sSf https://gateway.guardx.example.com/metrics | grep guardx_bundle_seq

# End-to-end proxied call.
curl -sSf -X POST https://gateway.guardx.example.com/v1/proxy/my-app/v1/chat/completions \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $UPSTREAM_KEY" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}' | jq
```

If the gateway logs `no policy index loaded`, the bundle build hasn't reached it yet — wait one poll interval (default 2 s) and retry. If it never resolves, check the bundle-stale runbook.

## 9. Observability wiring

The chart ships two artifacts:

- **[deploy/helm/dashboards/gateway.json](../../deploy/helm/dashboards/gateway.json)** — Grafana dashboard.
- **[deploy/helm/alerts/guardx-alerts.yaml](../../deploy/helm/alerts/guardx-alerts.yaml)** — Prometheus alert rules.

**With Prometheus Operator** (recommended):

```yaml
observability:
  alerts: { enabled: true, crd: true }
  grafana:
    dashboards:
      enabled: true
      labels: { grafana_dashboard: "1" }
gateway:
  metrics:
    serviceMonitor: { enabled: true, interval: 30s }
```

**Without the Operator** (rely on `prometheus.io/scrape` annotations):

```yaml
observability:
  prometheusScrape: { enabled: true }
  alerts: { enabled: true, crd: false }   # ConfigMap output
```

Alerts link to [docs/runbooks](../runbooks/) — deploy the runbook files somewhere the alert URL can reach (a docs bucket, an internal wiki, or serve them from the console via a docs subpath).

## 10. Upgrade path

GuardX follows a rolling-upgrade path. **The invariants are:**

- Bundle format is versioned (`apiVersion: guardx/v1`) — breaking changes bump the version.
- Postgres migrations run at Control API boot and are additive.
- Gateway can serve a previous bundle while the Control API rolls to a newer version.

**Standard upgrade:**

```sh
# 1. Read the release notes for schema changes. Almost always none.
# 2. Bump image tags.
helm -n guardx upgrade guardx guardx/guardx \
  -f values-prod.yaml --set image.tag=0.2.0 --wait --timeout 5m

# 3. Verify: readyz + a real request through the gateway.
```

Control API rolls first (its Deployment has `maxUnavailable: 0, maxSurge: 1` — new pods come up green before old ones die). Gateway rolls second (`maxUnavailable: 1` — you keep at least 2 of 3 replicas serving). Detectors last — they're stateless HTTP services.

If Alembic reports a new migration, it runs on the first Control API pod that boots the new image. It's idempotent — subsequent pods no-op.

## 11. Rollback

Every state change goes through the append-only `policy_audit` table and the hash-chained `guard_decisions` table — old data isn't destroyed by a rollback. Software rollback is standard Helm:

```sh
helm -n guardx history guardx
helm -n guardx rollback guardx <prev-revision>
```

**Bundle rollback** (independent of software rollback): revoke the current policy version and rebuild the bundle to install the prior approved version.

```sh
curl -sSf -X POST "$CONTROL/v1/policies/$POLICY_ID/$BAD_VERSION:revoke?tenant=acme" \
  -H "$ADMIN" -d '{"note":"rollback: broke claims-bot"}'
curl -sSf -X POST "$CONTROL/v1/bundles/prod:build?tenant=acme" -H "$ADMIN"
```

The gateway hot-swaps to the new bundle within one poll interval. The revoked version is stamped in `policy_audit`; a re-promotion is a fresh version, not an un-revoke.

## 12. Multi-tenant deployment shape

The chart runs a single-tenant deployment by default (one `tenant` value at the top-level). For multi-tenant:

**A. Single-plane multi-tenant** (recommended when tenants trust the same operator).

- One Helm release, tenants live as rows in `tenants` table.
- Bundles are per-`(tenant, environment)` — the gateway installs one bundle per tenant it serves.
- Data isolation via application-layer tenant filtering (every route requires `?tenant=`). If your Postgres supports RLS, enable it as belt-and-braces.

**B. Namespace-per-tenant** (recommended for regulated tenants).

- One Helm release per tenant, each in its own namespace.
- Separate Postgres databases (or separate schemas). Separate signing keys. Separate secrets.
- More ops overhead; strongest isolation. Common for HIPAA/PCI shops where a tenant's evidence must be provably separated.

The current chart shape supports (A) natively and (B) via one release-per-tenant. A future values shape may add (B) as a first-class mode; for now, use `-f values-tenant-a.yaml` per tenant.

---

## See also

- [../runbooks/bundle-stale.md](../runbooks/bundle-stale.md) — policy drift on the installed bundle
- [../runbooks/chain-anchor-fail.md](../runbooks/chain-anchor-fail.md) — evidence integrity break
- [../runbooks/provider-outage.md](../runbooks/provider-outage.md) — LLM provider down / rate-limited
- [../runbooks/fail-open.md](../runbooks/fail-open.md) — fail-open security incident
- [../runbooks/oidc-setup.md](../runbooks/oidc-setup.md) — provider-specific OIDC recipes
- [../compliance/mapping.md](../compliance/mapping.md) — control → framework mapping for audit
