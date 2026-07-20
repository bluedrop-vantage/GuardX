import { useState } from "react";
import { api, EvidenceEvent, ChainVerifyReport } from "../lib/api";
import { ErrorBox } from "../components/Loading";

export function EvidencePage() {
  const [app, setApp] = useState("claims-bot");
  const [events, setEvents] = useState<EvidenceEvent[] | null>(null);
  const [chain, setChain] = useState<ChainVerifyReport | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [showShadow, setShowShadow] = useState(true);

  async function load(e?: React.FormEvent) {
    e?.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const rows = await api.listEvidence(app, 0, 500);
      setEvents(rows);
    } catch (err) { setError(err); }
    setBusy(false);
  }

  async function verify() {
    setError(null);
    setBusy(true);
    try {
      setChain(await api.verifyChain(app));
    } catch (err) { setError(err); }
    setBusy(false);
  }

  const shown = (events || []).filter((e) => showShadow || !e.is_shadow);
  const bySc = shown.reduce<Record<string, number>>((acc, e) => {
    if (e.scenario) acc[e.scenario] = (acc[e.scenario] || 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <div className="page-header">
        <h2>Evidence</h2>
      </div>

      <form className="panel" onSubmit={load} style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input value={app} onChange={(e) => setApp(e.target.value)}
               placeholder="app slug (e.g. claims-bot)" style={{ flex: 1 }} />
        <button type="submit" disabled={busy}>Load events</button>
        <button type="button" className="secondary" disabled={busy} onClick={verify}>
          Verify chain
        </button>
        <label className="small" style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <input type="checkbox" checked={showShadow}
                 onChange={(e) => setShowShadow(e.target.checked)} />
          show shadow
        </label>
      </form>

      {error && <ErrorBox error={error} />}

      {chain && (
        <div className="panel" style={{
          borderColor: chain.ok ? "var(--accent)" : "var(--danger)",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>
              <strong>Chain verify:</strong>{" "}
              {chain.ok
                ? <>OK — {chain.checked} events, head <span className="mono small">{chain.head?.event_hash}</span></>
                : <>BROKEN at seq={chain.first_bad_seq}: {chain.reason}</>}
            </span>
          </div>
        </div>
      )}

      {events && (
        <>
          <div className="grid-3" style={{ marginBottom: 12 }}>
            <div className="metric"><div className="label">Total events</div><div className="value">{shown.length}</div></div>
            <div className="metric"><div className="label">FAIL verdicts</div><div className="value">{shown.filter(e => e.verdict === "FAIL").length}</div></div>
            <div className="metric"><div className="label">Shadow events</div><div className="value">{shown.filter(e => e.is_shadow).length}</div></div>
          </div>

          <div className="panel">
            <div className="small muted" style={{ marginBottom: 8 }}>
              by scenario:{" "}
              {Object.entries(bySc).map(([sc, n]) => (
                <span key={sc} style={{ marginRight: 12 }}>
                  <span className="mono">{sc}</span>: {n}
                </span>
              ))}
            </div>
            <table>
              <thead>
                <tr>
                  <th>seq</th><th>ts</th><th>guard</th><th>verdict</th>
                  <th>score</th><th>latency</th><th>event_hash</th>
                </tr>
              </thead>
              <tbody>
                {shown.slice(0, 200).map((e) => (
                  <tr key={e.event_id}>
                    <td className="mono small">{e.chain_seq}</td>
                    <td className="small muted">{e.ts.replace("T", " ").slice(0, 19)}</td>
                    <td className="small">
                      {e.guard_id || "—"}
                      {e.is_shadow && <span className="badge shadow" style={{ marginLeft: 6 }}>shadow</span>}
                    </td>
                    <td><span className={`badge ${e.verdict.toLowerCase()}`}>{e.verdict}</span></td>
                    <td className="mono small">{typeof e.score === "number" ? e.score.toFixed(2) : "—"}</td>
                    <td className="mono small">{e.latency_ms ?? "—"} ms</td>
                    <td className="mono small">{e.event_hash.slice(0, 20)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
