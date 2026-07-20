import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, CompileResult, getTenant, ProfileAvailable } from "../lib/api";
import { useApi } from "../lib/useApi";
import { ErrorBox, Loading } from "../components/Loading";

type Step = "profile" | "app" | "compile" | "review" | "submit";

/** One-flow onboarding (spec G4: zero-to-enforcing in <1 day):
 *    1. Pick industry profile
 *    2. Name the app + environment
 *    3. Preview the compiled policy + override trace
 *    4. Submit as draft + auto-submit for review
 */
export function OnboardingPage() {
  const nav = useNavigate();
  const profiles = useApi(() => api.availableProfiles());
  const [step, setStep] = useState<Step>("profile");
  const [profile, setProfile] = useState<string>("");
  const [app, setApp] = useState<string>("claims-bot");
  const [env, setEnv] = useState<string>("prod");
  const [policyId, setPolicyId] = useState<string>("app-policy");
  const [policyVer, setPolicyVer] = useState<string>("1.0.0");
  const [compiled, setCompiled] = useState<CompileResult | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (profiles.loading) return <Loading what="framework profiles" />;
  if (profiles.error) return <ErrorBox error={profiles.error} />;

  async function doCompile() {
    setError(null); setBusy(true);
    try {
      const appPolicy = {
        metadata: { id: policyId, version: policyVer },
        spec: { applies_to: { apps: [app], environments: [env] } },
      };
      const out = await api.compileFromProfile(getTenant(), profile, appPolicy);
      setCompiled(out);
      setStep("review");
    } catch (err) { setError(err); }
    setBusy(false);
  }

  async function submitDraft() {
    if (!compiled) return;
    setError(null); setBusy(true);
    try {
      const res = await api.createPolicy(compiled.document, `onboarding via ${profile}`);
      if (res.lint.some((i) => i.severity === "error")) {
        setError({ message: "Linter errors — fix and retry", lint: res.lint });
        return;
      }
      await api.submitPolicy(policyId, policyVer, "auto-submitted via onboarding");
      nav(`/approvals`);
    } catch (err) { setError(err); }
    setBusy(false);
  }

  return (
    <>
      <div className="page-header">
        <h2>Onboarding — {step}</h2>
        <div className="muted small">tenant: <span className="mono">{getTenant()}</span></div>
      </div>

      <Stepper current={step} />

      {step === "profile" && (
        <ProfilePicker
          rows={profiles.data || []}
          selected={profile}
          onSelect={(p) => setProfile(p)}
          onNext={() => profile && setStep("app")}
        />
      )}
      {step === "app" && (
        <AppForm
          app={app} setApp={setApp}
          env={env} setEnv={setEnv}
          policyId={policyId} setPolicyId={setPolicyId}
          policyVer={policyVer} setPolicyVer={setPolicyVer}
          onBack={() => setStep("profile")}
          onNext={() => { setStep("compile"); doCompile(); }}
        />
      )}
      {(step === "compile" || (step === "review" && !compiled)) && (
        <div className="panel">Compiling {profile}…</div>
      )}
      {step === "review" && compiled && (
        <ReviewPanel
          profile={profile}
          compiled={compiled}
          busy={busy}
          onBack={() => setStep("app")}
          onSubmit={submitDraft}
        />
      )}
      {error && <ErrorBox error={error} />}
    </>
  );
}

function Stepper({ current }: { current: Step }) {
  const steps: [Step, string][] = [
    ["profile", "1. Choose profile"],
    ["app",     "2. Bind to app"],
    ["review",  "3. Review compiled policy"],
    ["submit",  "4. Submit for approval"],
  ];
  const idx = steps.findIndex((s) => s[0] === current);
  return (
    <div className="panel" style={{ display: "flex", gap: 12 }}>
      {steps.map(([k, label], i) => (
        <div key={k} style={{
          flex: 1,
          padding: "6px 10px",
          borderRadius: 6,
          background: i === idx ? "var(--panel-2)" : "transparent",
          border: "1px solid " + (i <= idx ? "var(--accent)" : "var(--border)"),
          color: i === idx ? "var(--text)" : "var(--muted)",
        }}>
          {label}
        </div>
      ))}
    </div>
  );
}

function ProfilePicker({ rows, selected, onSelect, onNext }: {
  rows: ProfileAvailable[]; selected: string; onSelect: (s: string) => void; onNext: () => void;
}) {
  return (
    <div className="panel">
      <p className="muted">
        Pick the framework profile that matches your industry. Guards inherit
        top-down: <span className="mono">baseline ⊕ profile ⊕ your app policy</span>.
      </p>
      <table>
        <thead><tr><th>Pick</th><th>Profile</th><th>Version</th><th>Parent</th><th>Frameworks</th></tr></thead>
        <tbody>
          {rows.map((p) => {
            const spec = `${p.id}@${p.version}`;
            return (
              <tr key={spec}>
                <td>
                  <input type="radio" name="profile" checked={selected === spec}
                         onChange={() => onSelect(spec)} />
                </td>
                <td className="mono">{p.id}</td>
                <td className="mono small">{p.version}</td>
                <td className="mono small">{p.parent || "—"}</td>
                <td className="small">{p.labels.framework || ""}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div style={{ marginTop: 12, display: "flex", justifyContent: "flex-end" }}>
        <button disabled={!selected} onClick={onNext}>Next →</button>
      </div>
    </div>
  );
}

function AppForm(props: {
  app: string; setApp: (s: string) => void;
  env: string; setEnv: (s: string) => void;
  policyId: string; setPolicyId: (s: string) => void;
  policyVer: string; setPolicyVer: (s: string) => void;
  onBack: () => void; onNext: () => void;
}) {
  return (
    <div className="panel">
      <div className="grid-2">
        <label>
          <div className="small muted">Policy id (slug)</div>
          <input value={props.policyId} onChange={(e) => props.setPolicyId(e.target.value)}
                 style={{ width: "100%" }} />
        </label>
        <label>
          <div className="small muted">Policy version</div>
          <input value={props.policyVer} onChange={(e) => props.setPolicyVer(e.target.value)}
                 style={{ width: "100%" }} placeholder="1.0.0" />
        </label>
        <label>
          <div className="small muted">App</div>
          <input value={props.app} onChange={(e) => props.setApp(e.target.value)}
                 style={{ width: "100%" }} />
        </label>
        <label>
          <div className="small muted">Environment</div>
          <input value={props.env} onChange={(e) => props.setEnv(e.target.value)}
                 style={{ width: "100%" }} />
        </label>
      </div>
      <div style={{ marginTop: 12, display: "flex", justifyContent: "space-between" }}>
        <button className="secondary" onClick={props.onBack}>← Back</button>
        <button onClick={props.onNext}>Compile →</button>
      </div>
    </div>
  );
}

function ReviewPanel({ profile, compiled, busy, onBack, onSubmit }: {
  profile: string; compiled: CompileResult; busy: boolean;
  onBack: () => void; onSubmit: () => void;
}) {
  return (
    <>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Compiled policy</h3>
        <p className="small muted">
          Inherited chain: <span className="mono">baseline@1.0.0 ⊕ {profile} ⊕ app-policy</span>.
          Below is the fully-materialized document that will be submitted as a
          draft. Every entry in the override trace shows where this policy
          diverges from framework defaults.
        </p>
        <pre style={{ maxHeight: 400, overflow: "auto" }}>{JSON.stringify(compiled.document, null, 2)}</pre>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Override trace ({compiled.overrides.length} entries)</h3>
        <table>
          <thead><tr><th>Path</th><th>Layer</th><th>Replaces</th></tr></thead>
          <tbody>
            {compiled.overrides.map((o, i) => (
              <tr key={i}>
                <td className="mono small">{o.path}</td>
                <td className="small">{o.layer}</td>
                <td className="small muted">{o.replaced || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <button className="secondary" onClick={onBack}>← Back</button>
        <button onClick={onSubmit} disabled={busy}>
          {busy ? "Submitting…" : "Save draft + submit for review"}
        </button>
      </div>
    </>
  );
}
