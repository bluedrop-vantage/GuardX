import { useState } from "react";
import { api, EvidenceEvent } from "../lib/api";
import { ErrorBox } from "../components/Loading";

/**
 * Shadow-delta view (spec §5.3 auto-tuner safety net).
 *
 * Groups evidence events by (guard_id, is_shadow) and shows per-guard:
 *   - live vs shadow counts
 *   - live vs shadow FAIL rates
 *   - agreement rate (matching verdicts on the same request_id)
 *
 * When a live guard and a shadow guard both fired for the same request, an
 * agreement of 100% means the shadow verdict tracked the live one perfectly.
 * Divergence is the interesting signal — that's where a proposed policy
 * would have behaved differently.
 */
export function ShadowDeltaPage() {
  const [app, setApp] = useState("claims-bot");
  const [events, setEvents] = useState<EvidenceEvent[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function load(e?: React.FormEvent) {
    e?.preventDefault();
    setError(null);
    setBusy(true);
    try {
      setEvents(await api.listEvidence(app, 0, 2000));
    } catch (err) { setError(err); }
    setBusy(false);
  }

  return (
    <>
      <div className="page-header">
        <h2>Shadow delta</h2>
      </div>
      <div className="panel small muted">
        Per-guard comparison of shadow vs live verdicts. A shadow-mode guard
        (spec §5.3) runs non-blocking; this view surfaces where its verdict
        would have diverged from the live one on the same requests.
      </div>

      <form className="panel" onSubmit={load} style={{ display: "flex", gap: 8 }}>
        <input value={app} onChange={(e) => setApp(e.target.value)}
               placeholder="app slug" style={{ flex: 1 }} />
        <button type="submit" disabled={busy}>Load evidence</button>
      </form>

      {error && <ErrorBox error={error} />}

      {events && <DeltaTable events={events} />}
    </>
  );
}

interface Row {
  guard_id: string;
  live_n: number;
  live_fail: number;
  shadow_n: number;
  shadow_fail: number;
  agreements: number;
  divergences: number;
}

function DeltaTable({ events }: { events: EvidenceEvent[] }) {
  // Group by (request_id, guard_id) to detect same-request agreement.
  const byRequest = new Map<string, Map<string, EvidenceEvent[]>>();
  for (const e of events) {
    if (!e.guard_id) continue;
    const g = e.guard_id;
    const m = byRequest.get(e.request_id) ?? new Map();
    const list = m.get(g) ?? [];
    list.push(e);
    m.set(g, list);
    byRequest.set(e.request_id, m);
  }

  const stats = new Map<string, Row>();
  for (const [, byGuard] of byRequest) {
    for (const [gid, list] of byGuard) {
      const row = stats.get(gid) ?? {
        guard_id: gid,
        live_n: 0, live_fail: 0,
        shadow_n: 0, shadow_fail: 0,
        agreements: 0, divergences: 0,
      };
      const live = list.filter(e => !e.is_shadow);
      const shadow = list.filter(e => e.is_shadow);
      for (const e of live) {
        row.live_n++;
        if (e.verdict === "FAIL") row.live_fail++;
      }
      for (const e of shadow) {
        row.shadow_n++;
        if (e.verdict === "FAIL") row.shadow_fail++;
      }
      // A pair on the same request → check agreement.
      if (live.length > 0 && shadow.length > 0) {
        const l = live[0].verdict;
        const s = shadow[0].verdict;
        if (l === s) row.agreements++; else row.divergences++;
      }
      stats.set(gid, row);
    }
  }

  const rows = Array.from(stats.values()).sort(
    (a, b) => (b.shadow_n + b.live_n) - (a.shadow_n + a.live_n)
  );

  return (
    <div className="panel">
      <table>
        <thead>
          <tr>
            <th>Guard</th>
            <th>Live n</th><th>Live FAIL%</th>
            <th>Shadow n</th><th>Shadow FAIL%</th>
            <th>Agreement</th><th>Divergences</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const lp = r.live_n ? (100 * r.live_fail / r.live_n).toFixed(1) : "—";
            const sp = r.shadow_n ? (100 * r.shadow_fail / r.shadow_n).toFixed(1) : "—";
            const pairs = r.agreements + r.divergences;
            const ag = pairs ? (100 * r.agreements / pairs).toFixed(0) : "—";
            return (
              <tr key={r.guard_id}>
                <td className="mono small">{r.guard_id}</td>
                <td className="mono">{r.live_n}</td>
                <td className="mono">{lp}%</td>
                <td className="mono">{r.shadow_n}</td>
                <td className="mono">{sp}%</td>
                <td className="mono">{ag}{pairs ? "%" : ""}</td>
                <td className="mono" style={{ color: r.divergences ? "var(--warn)" : "inherit" }}>
                  {r.divergences}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.length === 0 && <div className="muted">No guard-tagged events yet.</div>}
    </div>
  );
}
