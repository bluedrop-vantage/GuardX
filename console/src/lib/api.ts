// GuardX Control API client.
//
// Auth headers are provided by the AuthProvider (`useAuth().authHeaders()`).
// Every request goes through `request()` which pulls the current headers so
// a token rotation via supabase-js's autoRefresh is picked up on the very
// next call — no page reload required.

export const TENANT_STORAGE_KEY = "guardx.tenant";
export const BASE_URL = (import.meta.env.VITE_CONTROL_URL as string) || "http://localhost:8080";

export function getTenant(): string {
  return localStorage.getItem(TENANT_STORAGE_KEY) || "acme";
}
export function setTenant(v: string) { localStorage.setItem(TENANT_STORAGE_KEY, v); }

// Set at bootstrap by <App> so `api.*` can access the current auth headers
// without prop-drilling into every hook.
let authHeadersProvider: () => Record<string, string> = () => ({});
export function setAuthHeadersProvider(fn: () => Record<string, string>) {
  authHeadersProvider = fn;
}

export class ApiError extends Error {
  constructor(public status: number, public body: unknown, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const url = new URL(path, BASE_URL);
  const res = await fetch(url.toString(), {
    method,
    headers: {
      "content-type": "application/json",
      ...authHeadersProvider(),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const parsed = text ? safeJson(text) : null;
  if (!res.ok) {
    const msg = (parsed && (parsed as any).detail) || text || res.statusText;
    throw new ApiError(res.status, parsed, typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return parsed as T;
}

function safeJson(s: string): unknown {
  try { return JSON.parse(s); } catch { return s; }
}

export const api = {
  health: () => request<{ status: string }>("GET", "/healthz"),

  // Policies
  listPolicyVersions: (policyId: string) =>
    request<PolicyOut[]>("GET", `/v1/policies/${policyId}?tenant=${encodeURIComponent(getTenant())}`),
  createPolicy: (document: unknown, changeNote?: string) =>
    request<PolicyCreateResult>("POST", `/v1/policies?tenant=${encodeURIComponent(getTenant())}`, { document, change_note: changeNote }),
  submitPolicy: (id: string, version: string, note?: string) =>
    request<{ status: string }>("POST", `/v1/policies/${id}/${version}:submit?tenant=${encodeURIComponent(getTenant())}`, { note }),
  approvePolicy: (id: string, version: string, note?: string) =>
    request<{ status: string; approved_by: string }>("POST", `/v1/policies/${id}/${version}:approve?tenant=${encodeURIComponent(getTenant())}`, { note }),
  rejectPolicy: (id: string, version: string, note?: string) =>
    request<{ status: string }>("POST", `/v1/policies/${id}/${version}:reject?tenant=${encodeURIComponent(getTenant())}`, { note }),

  // Profiles
  availableProfiles: () => request<ProfileAvailable[]>("GET", "/v1/profiles/available"),
  getProfilePack: (spec: string) => request<unknown>("GET", `/v1/profiles/${encodeURIComponent(spec)}`),
  compileFromProfile: (tenant: string, profile: string, appPolicy?: unknown) =>
    request<CompileResult>("POST", "/v1/profiles/compile", { tenant, profile, app_policy: appPolicy }),

  // Bundles
  buildBundle: (env: string) =>
    request<BundleOut>("POST", `/v1/bundles/${env}:build?tenant=${encodeURIComponent(getTenant())}`),

  // Detectors catalog
  listDetectors: () => request<DetectorCatalogRow[]>("GET", "/v1/detectors"),

  // Evidence
  listEvidence: (app: string, sinceSeq = 0, limit = 200) =>
    request<EvidenceEvent[]>("GET",
      `/v1/evidence/events?tenant=${encodeURIComponent(getTenant())}&app=${encodeURIComponent(app)}&since_seq=${sinceSeq}&limit=${limit}`),
  verifyChain: (app: string) =>
    request<ChainVerifyReport>("GET",
      `/v1/evidence/verify?tenant=${encodeURIComponent(getTenant())}&app=${encodeURIComponent(app)}`),

  // Tenants
  createTenant: (slug: string) =>
    request<{ id: string; slug: string }>("POST", "/v1/tenants", { slug }),
};

// ---- Types (mirror server Pydantic shapes) --------------------------------

export type PolicyStatus = "draft" | "in_review" | "approved" | "deprecated" | "revoked";

export interface PolicyOut {
  tenant: string;
  policy_id: string;
  version: string;
  status: PolicyStatus;
  origin: string;
  created_by: string;
  created_at: string;
  approved_by?: string | null;
  approved_at?: string | null;
  document_hash: string;
  document: Record<string, unknown>;
}

export interface LintIssueOut {
  code: string;
  severity: "error" | "warn" | "info";
  message: string;
  path: string;
}

export interface PolicyCreateResult {
  policy: PolicyOut;
  lint: LintIssueOut[];
}

export interface ProfileAvailable {
  id: string;
  version: string;
  parent?: string | null;
  labels: Record<string, string>;
  path: string;
}

export interface OverrideEntry {
  path: string;
  layer: string;
  replaced?: string | null;
}

export interface CompileResult {
  document: Record<string, unknown>;
  overrides: OverrideEntry[];
}

export interface BundleOut {
  tenant: string;
  environment: string;
  bundle_seq: number;
  manifest: Record<string, unknown>;
  manifest_hash: string;
  signature_b64: string;
  signing_key_id: string;
  created_at: string;
}

export interface DetectorCatalogRow {
  detector_id: string;
  version: string;
  scenario: string;
  image_digest: string;
  config_schema: Record<string, unknown>;
  benchmark?: Record<string, unknown> | null;
}

export interface EvidenceEvent {
  event_id: string;
  ts: string;
  tenant: string;
  app: string;
  env: string;
  chain_seq: number;
  request_id: string;
  policy: string;
  bundle_seq: number;
  guard_id?: string | null;
  scenario?: string | null;
  detector?: string | null;
  direction?: string | null;
  verdict: string;
  score?: number | null;
  action_taken?: string | null;
  latency_ms?: number | null;
  evidence_mode: string;
  spans?: unknown[] | null;
  text_hash?: string | null;
  prev_event_hash?: string | null;
  event_hash: string;
  is_shadow: boolean;
}

export interface ChainVerifyReport {
  tenant: string;
  app: string;
  checked: number;
  ok: boolean;
  first_bad_seq?: number | null;
  reason?: string | null;
  head?: { chain_seq: number; event_hash: string } | null;
}
