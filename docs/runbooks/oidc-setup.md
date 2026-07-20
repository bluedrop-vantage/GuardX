# Runbook — OIDC setup + role provisioning

Applies to any OIDC provider that exposes a JWKS endpoint (Supabase Auth,
Keycloak, Auth0, Okta, Google Workspace, Dex, etc.). GuardX doesn't run the
login flow itself — the console signs users in against your IdP and the
Control API verifies the resulting bearer JWT.

## What GuardX needs

1. A JWKS URL to verify signatures against.
2. A stable issuer (`iss` claim) to reject foreign tokens.
3. An audience (`aud` claim) so tokens minted for *another* app aren't accepted here.
4. A **role claim** — a dotted path pointing at a value that maps to a GuardX role.

Role values GuardX understands: `viewer` | `author` | `reviewer` | `approver` | `admin`.
`guardx-<role>` and `guardx_<role>` prefixes are accepted (so one IdP can host multiple apps).

## Control-API env vars

```sh
GUARDX_OIDC_ENABLED=true
GUARDX_OIDC_ISSUER=https://idp.example.com          # expected `iss`
GUARDX_OIDC_AUDIENCE=guardx-console                 # expected `aud`  (empty → skip)
GUARDX_OIDC_JWKS_URL=https://idp.example.com/.well-known/jwks.json
GUARDX_OIDC_ROLE_CLAIM=app_metadata.guardx_role     # dotted path
GUARDX_OIDC_SUBJECT_CLAIM=sub                       # dotted path
GUARDX_OIDC_LEEWAY_SECONDS=30
GUARDX_OIDC_JWKS_TTL_SECONDS=900
```

Set `GUARDX_OIDC_ENABLED=false` (or unset) to fall back to the API-key
shim — same behavior as pre-OIDC. **Enabling OIDC does not remove
`X-GuardX-Key`** — service tokens (automation plane, `POST /v1/proposals`)
keep working. Bearer wins when both headers are present.

## Console env vars

```sh
# Vite build-time — set via .env.local or CI:
VITE_SUPABASE_URL=https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY=...       # the *anon* key, not service_role
VITE_CONTROL_URL=https://api.guardx.example.com
```

The console reads these at build time. If both `VITE_SUPABASE_URL` and
`VITE_SUPABASE_ANON_KEY` are set, the login page shows the Supabase email/password
tab by default. Manual-JWT and API-key tabs remain available.

## Provider recipes

### Supabase Auth

1. Enable Email/Password (Auth → Providers) or an OAuth provider of your choice.
2. In **Auth → URL Configuration**, add your console's origin as an
   allowed redirect URL.
3. On a signed-in user, set the role claim via the Admin API. Example
   (using the `supabase_admin` role in the SQL editor):

   ```sql
   UPDATE auth.users
   SET raw_app_meta_data =
     jsonb_set(coalesce(raw_app_meta_data, '{}'::jsonb),
               '{guardx_role}', to_jsonb('admin'::text))
   WHERE email = 'jane@yourco.com';
   ```

   Or via the [Management API](https://supabase.com/docs/reference/api/admin-update-user):
   ```sh
   curl -sSf -X PUT "$SUPABASE_URL/auth/v1/admin/users/$USER_ID" \
     -H "Authorization: Bearer $SUPABASE_SECRET_KEY" \
     -H "Content-Type: application/json" \
     -d '{"app_metadata":{"guardx_role":"approver"}}'
   ```

4. Control-API env (using the values already in `.env`):

   ```sh
   GUARDX_OIDC_ENABLED=true
   GUARDX_OIDC_ISSUER=https://<ref>.supabase.co/auth/v1
   GUARDX_OIDC_AUDIENCE=authenticated
   GUARDX_OIDC_JWKS_URL=https://<ref>.supabase.co/auth/v1/.well-known/jwks.json
   GUARDX_OIDC_ROLE_CLAIM=app_metadata.guardx_role
   GUARDX_OIDC_SUBJECT_CLAIM=email
   ```

### Keycloak

1. Create a realm and a `guardx-console` client (public, PKCE).
2. Under **Client Roles** on that client, create `viewer`, `author`, `reviewer`, `approver`, `admin`.
3. Add a client-scope mapper that puts roles into the access token as:
   ```json
   { "resource_access": { "guardx-console": { "roles": ["approver"] } } }
   ```
4. Control-API env:
   ```sh
   GUARDX_OIDC_ENABLED=true
   GUARDX_OIDC_ISSUER=https://keycloak.example.com/realms/yourrealm
   GUARDX_OIDC_AUDIENCE=guardx-console
   GUARDX_OIDC_JWKS_URL=https://keycloak.example.com/realms/yourrealm/protocol/openid-connect/certs
   GUARDX_OIDC_ROLE_CLAIM=resource_access.guardx-console.roles.0
   GUARDX_OIDC_SUBJECT_CLAIM=email
   ```

### Auth0 / Okta

1. Add a **rule** or **hook** that copies your identity provider's group to
   `app_metadata.guardx_role`. Example rule:
   ```js
   function (user, context, callback) {
     const map = { "GuardX Admins": "admin", "GuardX Approvers": "approver" };
     const g = (context.samlConfiguration?.mappings?.groups || user.groups || [])
                 .find(g => map[g]);
     user.app_metadata = user.app_metadata || {};
     user.app_metadata.guardx_role = g ? map[g] : "viewer";
     auth0.users.updateAppMetadata(user.user_id, user.app_metadata)
       .then(() => callback(null, user, context))
       .catch(callback);
   }
   ```
2. Control-API env — same shape as Supabase, with the Auth0/Okta issuer + JWKS URL.

## Verifying the setup

```sh
# 1. Fetch a token from your IdP (or copy one from the console after login).
TOKEN=...

# 2. Try a route that requires a real role.
curl -sSf "$CONTROL/v1/policies/foo?tenant=acme" \
  -H "Authorization: Bearer $TOKEN"
```

Common failure modes and their `detail` messages:

| detail | Cause |
| ----- | ----- |
| `invalid bearer token: JWKS: ...` | JWKS URL wrong / IdP unreachable. Check `GUARDX_OIDC_JWKS_URL`. |
| `invalid bearer token: invalid token: Signature verification failed` | Token was signed by a key not in your JWKS. Check `iss`. |
| `invalid bearer token: invalid token: Invalid audience` | Token's `aud` != `GUARDX_OIDC_AUDIENCE`. |
| `subject claim 'sub' missing` | `GUARDX_OIDC_SUBJECT_CLAIM` points at nothing. Try `email`. |
| `role claim '...' missing/invalid` | The user has no role. Provision one (see recipes). |

## Rotating the JWKS

JWKS is cached for `GUARDX_OIDC_JWKS_TTL_SECONDS` (default 900). After a key
rotation:

- **Supabase / Auth0 / Okta:** the new key appears in the JWKS immediately;
  cache refreshes on the next miss (kid mismatch) or at TTL expiry.
- **Keycloak:** if your realm keeps old keys as `PASSIVE`, no action needed.
  Otherwise, bounce the Control API pods after rotation to force a fresh fetch.

## Removing the API-key shim entirely

Once every human is on OIDC:

1. Remove `GUARDX_API_KEY_ADMIN` from the environment.
2. Leave `GUARDX_API_KEY_SERVICE` set — the automation plane (feed
   ingestor, autotuner, synthesizer) still uses it. That's the intended
   "machine identity" path.

Alternatively, mint a service JWT from your IdP (many providers support
this via a client-credentials grant) and drop the service-token shim too.
That requires either service-account impersonation on the automation side
or a token cache — deferred until an operator asks.
