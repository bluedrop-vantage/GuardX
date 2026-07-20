import { api, DetectorCatalogRow } from "../lib/api";
import { useApi } from "../lib/useApi";
import { ErrorBox, Loading } from "../components/Loading";

export function CatalogPage() {
  const { data, loading, error } = useApi(() => api.listDetectors());
  if (loading) return <Loading what="detectors" />;
  if (error) return <ErrorBox error={error} />;

  return (
    <>
      <div className="page-header">
        <h2>Detector catalog</h2>
      </div>
      <div className="panel small muted" style={{ marginBottom: 12 }}>
        Every detector shows its published benchmark row. Policies can only
        pin detectors that appear here (spec §7).
      </div>
      <table>
        <thead>
          <tr>
            <th>Detector</th>
            <th>Scenario</th>
            <th>Version</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>p95 ms</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {(data || []).map((d: DetectorCatalogRow) => {
            const b: any = d.benchmark || {};
            return (
              <tr key={`${d.detector_id}@${d.version}`}>
                <td className="mono">{d.detector_id}</td>
                <td>{d.scenario}</td>
                <td className="mono">{d.version}</td>
                <td>{fmt(b.precision)}</td>
                <td>{fmt(b.recall)}</td>
                <td>{b.latency_ms_p95 ?? "—"}</td>
                <td className="small muted">{b.note || ""}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function fmt(v: unknown): string {
  if (typeof v === "number") return v.toFixed(3);
  return "—";
}
