import { useState } from "react";
import { Link } from "react-router-dom";
import { api, PolicyOut } from "../lib/api";
import { ErrorBox } from "../components/Loading";

/** M4 first pass: no listAllPolicies endpoint yet — user types a slug and we
 *  fetch its versions. Follow-up: server-side listing per tenant. */
export function PoliciesPage() {
  const [slug, setSlug] = useState("pii-financial-services");
  const [versions, setVersions] = useState<PolicyOut[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  async function search(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const rows = await api.listPolicyVersions(slug);
      setVersions(rows);
    } catch (err) {
      setVersions(null);
      setError(err);
    }
  }

  return (
    <>
      <div className="page-header">
        <h2>Policies</h2>
        <div className="actions">
          <Link to="/onboarding"><button>Compile from profile</button></Link>
        </div>
      </div>

      <form className="panel" onSubmit={search} style={{ display: "flex", gap: 8 }}>
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder="policy id (e.g. pii-financial-services)"
          style={{ flex: 1 }}
        />
        <button type="submit">Load versions</button>
      </form>

      {error && <ErrorBox error={error} />}
      {versions && (
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Status</th>
                <th>Origin</th>
                <th>Created by</th>
                <th>Created at</th>
                <th>Approved by</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {versions.map((v) => (
                <tr key={`${v.policy_id}@${v.version}`}>
                  <td className="mono">{v.version}</td>
                  <td><span className={`badge ${v.status}`}>{v.status}</span></td>
                  <td className="small muted">{v.origin}</td>
                  <td className="small">{v.created_by}</td>
                  <td className="small muted">{v.created_at.replace("T", " ").slice(0, 19)}</td>
                  <td className="small">{v.approved_by || "—"}</td>
                  <td>
                    <Link to={`/policies/${slug}?v=${v.version}`}>view</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
