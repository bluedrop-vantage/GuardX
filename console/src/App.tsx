import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { PoliciesPage } from "./pages/PoliciesPage";
import { PolicyDetail } from "./pages/PolicyDetail";
import { ApprovalQueue } from "./pages/ApprovalQueue";
import { EvidencePage } from "./pages/EvidencePage";
import { OnboardingPage } from "./pages/OnboardingPage";
import { CatalogPage } from "./pages/CatalogPage";
import { HomePage } from "./pages/HomePage";
import { ShadowDeltaPage } from "./pages/ShadowDeltaPage";
import { LoginPage } from "./pages/LoginPage";
import { AuthProvider, OIDC_ENABLED, useAuth } from "./lib/auth";
import { getTenant, setAuthHeadersProvider, setTenant } from "./lib/api";

export function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  );
}

function Shell() {
  const auth = useAuth();
  const [tenant, setTenantState] = useState(getTenant());

  // Wire the api client to pull auth headers from AuthContext on every call
  // so a supabase-js autoRefresh takes effect on the very next request.
  useEffect(() => { setAuthHeadersProvider(auth.authHeaders); }, [auth.authHeaders]);
  useEffect(() => { setTenant(tenant); }, [tenant]);

  if (!auth.ready) return <div style={{ padding: 24 }} className="muted">Loading…</div>;

  return (
    <Routes>
      <Route path="/login" element={
        auth.session ? <Navigate to="/" replace /> : <LoginPage />
      } />
      <Route path="/*" element={
        auth.session
          ? <Authenticated tenant={tenant} setTenant={setTenantState} />
          : <Navigate to="/login" replace />
      } />
    </Routes>
  );
}

function Authenticated({ tenant, setTenant }: { tenant: string; setTenant: (v: string) => void }) {
  const auth = useAuth();
  const loc = useLocation();
  const [showLogout, setShowLogout] = useState(false);
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h1>GuardX</h1>
        <nav>
          <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>Home</NavLink>
          <NavLink to="/onboarding" className={({ isActive }) => (isActive ? "active" : "")}>Onboarding</NavLink>
          <NavLink to="/policies" className={({ isActive }) => (isActive ? "active" : "")}>Policies</NavLink>
          <NavLink to="/approvals" className={({ isActive }) => (isActive ? "active" : "")}>Approval Queue</NavLink>
          <NavLink to="/evidence" className={({ isActive }) => (isActive ? "active" : "")}>Evidence</NavLink>
          <NavLink to="/shadow" className={({ isActive }) => (isActive ? "active" : "")}>Shadow Delta</NavLink>
          <NavLink to="/catalog" className={({ isActive }) => (isActive ? "active" : "")}>Detector Catalog</NavLink>
        </nav>

        <div className="tenant-picker">
          <label>Tenant</label>
          <input value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="acme" />
        </div>

        <div className="tenant-picker">
          <label>Signed in as</label>
          <div className="mono small" style={{ padding: "6px 0", wordBreak: "break-all" }}>
            {auth.session?.subject ?? "—"}
          </div>
          <div className="muted small" style={{ marginBottom: 6 }}>
            Mode: <span className="mono">{auth.session?.mode}</span>
            {OIDC_ENABLED ? "" : " (OIDC off)"}
          </div>
          <button className="secondary" style={{ width: "100%" }}
                  onClick={() => setShowLogout(true)}>
            Sign out
          </button>
          {showLogout && (
            <ConfirmDialog
              title="Sign out?"
              confirmLabel="Sign out"
              onCancel={() => setShowLogout(false)}
              onConfirm={async () => { await auth.logout(); }}
            />
          )}
        </div>
      </aside>

      <main>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/onboarding" element={<OnboardingPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/policies/:id" element={<PolicyDetail />} />
          <Route path="/approvals" element={<ApprovalQueue />} />
          <Route path="/evidence" element={<EvidencePage />} />
          <Route path="/shadow" element={<ShadowDeltaPage />} />
          <Route path="/catalog" element={<CatalogPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      {/* Reference loc to keep linter happy — used to be nav-forward but Navigate covers it. */}
      <span style={{ display: "none" }}>{loc.pathname}</span>
    </div>
  );
}

function ConfirmDialog({ title, confirmLabel, onCancel, onConfirm }: {
  title: string; confirmLabel: string;
  onCancel: () => void; onConfirm: () => void | Promise<void>;
}) {
  return (
    <div style={{
      position: "fixed", inset: 0, display: "grid", placeItems: "center",
      background: "rgba(0,0,0,0.4)", zIndex: 100,
    }}>
      <div className="panel" style={{ width: 340 }}>
        <h3 style={{ marginTop: 0 }}>{title}</h3>
        <div className="gap-8" style={{ display: "flex", justifyContent: "flex-end" }}>
          <button className="secondary" onClick={onCancel}>Cancel</button>
          <button className="danger" onClick={() => Promise.resolve(onConfirm())}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
