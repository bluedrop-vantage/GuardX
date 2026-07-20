import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { OIDC_ENABLED, useAuth } from "../lib/auth";

/**
 * Login page — three modes:
 *   • Supabase Auth (email/password) — when VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY set
 *   • Manual JWT — paste a token from any OIDC provider
 *   • API key — dev / service-token fallback
 *
 * Modes shown depend on env config. In prod with Supabase configured,
 * API key mode is hidden from the UI (still accepted by the Control API
 * for automation services).
 */
export function LoginPage() {
  const auth = useAuth();
  const nav = useNavigate();
  const [tab, setTab] = useState<"supabase" | "jwt" | "apikey">(
    OIDC_ENABLED ? "supabase" : "apikey",
  );
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [jwt, setJwt] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (tab === "supabase") {
        await auth.loginSupabase(email, password);
      } else if (tab === "jwt") {
        auth.loginManualJwt(jwt.trim());
      } else {
        auth.loginApiKey(apiKey.trim());
      }
      nav("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{
      display: "grid", placeItems: "center", minHeight: "100vh",
      background: "var(--bg)",
    }}>
      <div className="panel" style={{ width: 380, padding: 24 }}>
        <h1 style={{ color: "var(--accent)", margin: "0 0 4px 0", fontSize: 24 }}>GuardX</h1>
        <div className="muted small" style={{ marginBottom: 16 }}>
          Sign in to the admin console.
        </div>

        <TabBar tab={tab} setTab={setTab} showApiKey={!OIDC_ENABLED || tab === "apikey"} />

        <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {tab === "supabase" && (
            <>
              <FieldLabel label="Email">
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                       required autoComplete="username" style={{ width: "100%" }} />
              </FieldLabel>
              <FieldLabel label="Password">
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                       required autoComplete="current-password" style={{ width: "100%" }} />
              </FieldLabel>
            </>
          )}
          {tab === "jwt" && (
            <FieldLabel label="Paste JWT from your IdP">
              <textarea value={jwt} onChange={(e) => setJwt(e.target.value)}
                        required rows={5} style={{ width: "100%", fontFamily: "var(--mono)" }} />
              <div className="muted small" style={{ marginTop: 6 }}>
                Universal fallback. Works with Keycloak, Auth0, Okta, Dex, or
                any OIDC provider whose JWKS URL is configured server-side.
              </div>
            </FieldLabel>
          )}
          {tab === "apikey" && (
            <FieldLabel label="API key">
              <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                     required autoComplete="off" style={{ width: "100%" }} />
              <div className="muted small" style={{ marginTop: 6 }}>
                Legacy dev / service-token path. Use OIDC for human users.
              </div>
            </FieldLabel>
          )}

          {error && (
            <div className="small" style={{ color: "var(--danger)" }}>{error}</div>
          )}

          <button type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>

          {!OIDC_ENABLED && (
            <div className="muted small" style={{ marginTop: 4 }}>
              OIDC not configured — set <span className="mono">VITE_SUPABASE_URL</span>{" "}
              and <span className="mono">VITE_SUPABASE_ANON_KEY</span> to enable Supabase Auth.
            </div>
          )}
        </form>
      </div>
    </div>
  );
}

function TabBar({ tab, setTab, showApiKey }: {
  tab: "supabase" | "jwt" | "apikey";
  setTab: (t: "supabase" | "jwt" | "apikey") => void;
  showApiKey: boolean;
}) {
  const tabs: Array<{ key: typeof tab; label: string; show: boolean }> = [
    { key: "supabase", label: "Supabase",   show: OIDC_ENABLED },
    { key: "jwt",      label: "Paste JWT",  show: true },
    { key: "apikey",   label: "API key",    show: showApiKey },
  ];
  return (
    <div style={{ display: "flex", gap: 4, marginBottom: 12, borderBottom: "1px solid var(--border)" }}>
      {tabs.filter(t => t.show).map(t => (
        <button
          key={t.key}
          type="button"
          onClick={() => setTab(t.key)}
          className={tab === t.key ? "" : "secondary"}
          style={{
            borderRadius: 0,
            borderBottom: tab === t.key ? "2px solid var(--accent)" : "2px solid transparent",
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function FieldLabel({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label style={{ display: "block" }}>
      <div className="small muted" style={{ marginBottom: 4 }}>{label}</div>
      {children}
    </label>
  );
}
