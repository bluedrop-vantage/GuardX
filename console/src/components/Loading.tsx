export function Loading({ what = "" }: { what?: string }) {
  return <div className="muted">Loading {what}…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="panel" style={{ borderColor: "var(--danger)" }}>
      <strong style={{ color: "var(--danger)" }}>Error:</strong> {message}
    </div>
  );
}
