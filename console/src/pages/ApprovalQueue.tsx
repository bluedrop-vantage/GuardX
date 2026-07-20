import { useState } from "react";
import { api, PolicyOut } from "../lib/api";
import { ErrorBox } from "../components/Loading";

/** M4 first pass: the caller enters a policy slug and we filter to versions
 *  in `in_review` status. A follow-up server endpoint should return the
 *  whole queue for the tenant.
 */
export function ApprovalQueue() {
  const [slug, setSlug] = useState("pii-financial-services");
  const [rows, setRows] = useState<PolicyOut[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function load(e?: React.FormEvent) {
    e?.preventDefault();
    setError(null);
    try {
      const all = await api.listPolicyVersions(slug);
      setRows(all.filter((v) => v.status === "in_review"));
    } catch (err) {
      setRows(null);
      setError(err);
    }
  }

  async function act(v: PolicyOut, kind: "approve" | "reject") {
    setBusy(`${v.policy_id}@${v.version}:${kind}`);
    setError(null);
    try {
      const fn = kind === "approve" ? api.approvePolicy : api.rejectPolicy;
      await fn(v.policy_id, v.version, note || undefined);
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <div className="page-header">
        <h2>Approval queue</h2>
      </div>
      <div className="panel small muted">
        Separation of duty (spec §3.3): whichever principal your API key
        maps to must be a different subject than the one that created the
        version. Admin can override in emergencies — stamped in audit.
      </div>

      <form className="panel" onSubmit={load} style={{ display: "flex", gap: 8 }}>
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder="policy id"
          style={{ flex: 1 }}
        />
        <button type="submit">Load pending</button>
      </form>

      {error && <ErrorBox error={error} />}
      {rows && rows.length === 0 && (
        <div className="panel muted">Nothing in review for <span className="mono">{slug}</span>.</div>
      )}
      {rows && rows.length > 0 && (
        <div className="panel">
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Approval / rejection note (required for audit)"
            rows={2}
            style={{ width: "100%", marginBottom: 12 }}
          />
          <table>
            <thead>
              <tr><th>Version</th><th>Author</th><th>Created</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {rows.map((v) => (
                <tr key={v.version}>
                  <td className="mono">{v.version}</td>
                  <td className="small">{v.created_by}</td>
                  <td className="small muted">{v.created_at.replace("T", " ").slice(0, 19)}</td>
                  <td className="gap-8">
                    <button
                      disabled={busy === `${v.policy_id}@${v.version}:approve`}
                      onClick={() => act(v, "approve")}
                    >Approve</button>
                    <button
                      className="danger"
                      disabled={busy === `${v.policy_id}@${v.version}:reject`}
                      onClick={() => act(v, "reject")}
                    >Reject</button>
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
