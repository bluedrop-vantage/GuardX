import { useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { api, PolicyOut } from "../lib/api";
import { useApi } from "../lib/useApi";
import { ErrorBox, Loading } from "../components/Loading";

export function PolicyDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const [sp] = useSearchParams();
  const activeVersion = sp.get("v") || "";
  const [compareVersion, setCompareVersion] = useState<string>("");

  const versions = useApi(() => api.listPolicyVersions(id), [id]);
  if (versions.loading) return <Loading what={`versions of ${id}`} />;
  if (versions.error) return <ErrorBox error={versions.error} />;
  const rows = versions.data || [];
  const current = rows.find((v) => v.version === activeVersion) || rows[0];
  if (!current) return <div className="muted">No versions found.</div>;
  const compare = rows.find((v) => v.version === compareVersion);

  return (
    <>
      <div className="page-header">
        <h2>{id}<span className="muted"> @ {current.version}</span></h2>
        <div className="actions">
          <span className={`badge ${current.status}`}>{current.status}</span>
        </div>
      </div>

      <div className="panel">
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
          <span className="muted">Compare with:</span>
          <select value={compareVersion} onChange={(e) => setCompareVersion(e.target.value)}>
            <option value="">— none —</option>
            {rows.filter((r) => r.version !== current.version).map((r) => (
              <option key={r.version} value={r.version}>{r.version} ({r.status})</option>
            ))}
          </select>
          <span className="muted small">
            document_hash: <span className="mono">{current.document_hash}</span>
          </span>
        </div>
        {compare
          ? <DiffView older={compare} newer={current} />
          : <DocView doc={current} />}
      </div>
    </>
  );
}

function DocView({ doc }: { doc: PolicyOut }) {
  return (
    <pre>{JSON.stringify(doc.document, null, 2)}</pre>
  );
}

function DiffView({ older, newer }: { older: PolicyOut; newer: PolicyOut }) {
  const olderLines = JSON.stringify(older.document, null, 2).split("\n");
  const newerLines = JSON.stringify(newer.document, null, 2).split("\n");
  // Simple line-diff. Not LCS — good enough to eyeball config-scale docs.
  const set = new Set(olderLines);
  const setN = new Set(newerLines);
  return (
    <div className="diff">
      <div className="side">
        <h4>{older.version}</h4>
        <pre>
          {olderLines.map((l, i) => (
            <div key={i} className={"diff-line " + (setN.has(l) ? "" : "removed")}>{l}</div>
          ))}
        </pre>
      </div>
      <div className="side">
        <h4>{newer.version}</h4>
        <pre>
          {newerLines.map((l, i) => (
            <div key={i} className={"diff-line " + (set.has(l) ? "" : "added")}>{l}</div>
          ))}
        </pre>
      </div>
    </div>
  );
}
