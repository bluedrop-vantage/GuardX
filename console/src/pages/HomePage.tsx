import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useApi } from "../lib/useApi";
import { ErrorBox, Loading } from "../components/Loading";

export function HomePage() {
  const health = useApi(() => api.health());
  const detectors = useApi(() => api.listDetectors());
  const profiles = useApi(() => api.availableProfiles());

  return (
    <>
      <div className="page-header">
        <h2>Home</h2>
      </div>

      <div className="grid-3">
        <div className="metric">
          <div className="label">Control API</div>
          <div className="value">
            {health.loading ? "…" : health.data?.status === "ok" ? "OK" : "DOWN"}
          </div>
        </div>
        <div className="metric">
          <div className="label">Detectors</div>
          <div className="value">
            {detectors.loading ? "…" : (detectors.data?.length ?? 0)}
          </div>
        </div>
        <div className="metric">
          <div className="label">Framework profiles</div>
          <div className="value">
            {profiles.loading ? "…" : (profiles.data?.length ?? 0)}
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0 }}>Quick actions</h3>
        <ul style={{ paddingLeft: 20 }}>
          <li>
            <Link to="/onboarding">Onboard a new tenant</Link> — pick an
            industry profile and compile enforcing policies in one flow.
          </li>
          <li><Link to="/policies">Author or review a policy</Link>.</li>
          <li><Link to="/approvals">Approve pending versions</Link>.</li>
          <li><Link to="/evidence">Search evidence + verify chain</Link>.</li>
        </ul>
      </div>

      {(health.error || detectors.error || profiles.error) && (
        <ErrorBox error={health.error ?? detectors.error ?? profiles.error} />
      )}
      {(health.loading || detectors.loading || profiles.loading) && (
        <Loading />
      )}
    </>
  );
}
