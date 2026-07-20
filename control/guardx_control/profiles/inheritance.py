"""Profile inheritance engine (spec §3.4).

Composition order: `baseline ⊕ industry_profile ⊕ app_policy`.

Deep-merge rules:
  * Objects merge key-by-key. Later layers override earlier layers at the
    scalar leaves.
  * Lists of guards merge by `id` — same id ⇒ deep-merge the guard object;
    new id ⇒ appended in the child's declared position. Removing a parent
    guard is explicit: set `{id: X, __remove__: true}` in the child.
  * Any leaf that is overridden by a later layer is recorded in the returned
    `OverrideTrace` so the console can show auditors exactly where a
    tenant diverged from the framework default.

Only the merged document is signed and shipped — the trace is metadata that
lives alongside the policy record in the registry.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import yaml


@dataclass
class PackRef:
    """A profile pack loaded from disk. `id@version` identifies it."""
    id: str
    version: str
    document: dict[str, Any]


@dataclass
class OverrideTrace:
    """Per-field origin — which layer supplied the current value."""
    entries: list[dict[str, str]] = field(default_factory=list)

    def add(self, path: str, layer: str, value: Any, replaced: str | None) -> None:
        entry: dict[str, Any] = {"path": path, "layer": layer}
        if replaced:
            entry["replaced"] = replaced
        self.entries.append(entry)


# ---- Loader -----------------------------------------------------------------

def _packs_dir() -> Path:
    override = os.environ.get("GUARDX_PROFILES_DIR")
    if override:
        return Path(override)
    # control/guardx_control/profiles/inheritance.py → repo-root/profiles
    return Path(__file__).resolve().parents[3] / "profiles"


@lru_cache(maxsize=32)
def load_pack(spec: str, packs_dir: str | None = None) -> PackRef:
    """Load `<id>@<version>` from the profile packs directory."""
    if "@" not in spec:
        raise ValueError(f"pack spec must be 'id@version', got {spec!r}")
    base = Path(packs_dir) if packs_dir else _packs_dir()
    path = base / f"{spec}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"profile pack not found: {path}")
    doc = yaml.safe_load(path.read_text())
    meta = doc.get("metadata") or {}
    return PackRef(id=meta.get("id", ""), version=str(meta.get("version", "")), document=doc)


def resolve_chain(spec: str) -> list[PackRef]:
    """Return packs in inheritance order (root first).

    A pack may reference a `metadata.parent` that itself resolves to another
    pack, and so on. Cycles are detected and rejected.
    """
    chain: list[PackRef] = []
    seen: set[str] = set()
    cur = spec
    while cur:
        if cur in seen:
            raise ValueError(f"profile cycle detected at {cur!r}")
        seen.add(cur)
        pack = load_pack(cur)
        chain.append(pack)
        cur = ((pack.document.get("metadata") or {}).get("parent") or "").strip()
    chain.reverse()
    return chain


# ---- Merge -----------------------------------------------------------------

_GUARD_LIST_PATH = ("spec", "guards")


def _at(root: Any, path: tuple[Any, ...]) -> Any:
    cur = root
    for step in path:
        cur = cur[step]
    return cur


def merge(
    parent: dict[str, Any],
    child: dict[str, Any],
    *,
    parent_layer: str,
    child_layer: str,
    trace: OverrideTrace,
    path: str = "",
) -> dict[str, Any]:
    """Deep-merge child into parent with override tracking.

    Guards (spec.guards) merge by `id` rather than positionally. Everything
    else deep-merges as objects at every level.
    """
    if not isinstance(parent, dict) or not isinstance(child, dict):
        # Non-dict at a merge point → child wins; record the override.
        trace.add(path or "/", child_layer, child, parent_layer)
        return child

    out: dict[str, Any] = {}
    keys = list(parent) + [k for k in child if k not in parent]
    for k in keys:
        p_here = f"{path}.{k}" if path else k
        if k not in child:
            out[k] = parent[k]
            continue
        if k not in parent:
            out[k] = child[k]
            trace.add(p_here, child_layer, child[k], None)
            continue
        pv, cv = parent[k], child[k]
        if k == "guards" and isinstance(pv, list) and isinstance(cv, list) and p_here.endswith("spec.guards"):
            out[k] = _merge_guards(pv, cv, parent_layer, child_layer, trace, p_here)
            continue
        if isinstance(pv, dict) and isinstance(cv, dict):
            out[k] = merge(pv, cv, parent_layer=parent_layer, child_layer=child_layer,
                           trace=trace, path=p_here)
        elif isinstance(pv, list) and isinstance(cv, list):
            # For non-guard lists: child fully replaces parent.
            out[k] = cv
            if pv != cv:
                trace.add(p_here, child_layer, cv, parent_layer)
        else:
            out[k] = cv
            if pv != cv:
                trace.add(p_here, child_layer, cv, parent_layer)
    return out


def _merge_guards(
    parent_guards: list[dict[str, Any]],
    child_guards: list[dict[str, Any]],
    parent_layer: str,
    child_layer: str,
    trace: OverrideTrace,
    path: str,
) -> list[dict[str, Any]]:
    """Merge guards by `id`. Preserves parent order; appends new child guards."""
    parent_by_id = {g.get("id"): g for g in parent_guards if isinstance(g, dict)}
    child_by_id = {g.get("id"): g for g in child_guards if isinstance(g, dict)}
    out: list[dict[str, Any]] = []

    # Walk parent order first — preserves the framework's guard listing.
    for pg in parent_guards:
        gid = pg.get("id")
        if gid in child_by_id:
            cg = child_by_id[gid]
            if cg.get("__remove__"):
                trace.add(f"{path}[{gid}]", child_layer, "REMOVED", parent_layer)
                continue
            merged = merge(pg, cg, parent_layer=parent_layer, child_layer=child_layer,
                            trace=trace, path=f"{path}[{gid}]")
            out.append(merged)
        else:
            out.append(pg)

    # Then append any brand-new child guards.
    for cg in child_guards:
        gid = cg.get("id")
        if gid in parent_by_id or cg.get("__remove__"):
            continue
        trace.add(f"{path}[{gid}]", child_layer, "ADDED", None)
        out.append(cg)

    return out


# ---- Top-level compile ------------------------------------------------------

def compile_policy(
    tenant_slug: str,
    profile_spec: str | None,
    app_policy: dict[str, Any] | None,
    *,
    baseline_spec: str = "baseline@1.0.0",
) -> tuple[dict[str, Any], OverrideTrace]:
    """Compose a fully-materialized policy from baseline ⊕ profile ⊕ app-policy.

    Returns the compiled policy document + an OverrideTrace. The caller is
    responsible for filling `metadata.id`, `metadata.version`, `metadata.tenant`,
    and running the linter before persisting.
    """
    trace = OverrideTrace()

    layers: list[tuple[str, dict[str, Any]]] = []
    layers.append((baseline_spec, load_pack(baseline_spec).document))
    if profile_spec and profile_spec != baseline_spec:
        for pack in resolve_chain(profile_spec):
            key = f"{pack.id}@{pack.version}"
            if key != baseline_spec:  # already added
                layers.append((key, pack.document))
    if app_policy:
        layers.append(("app-policy", app_policy))

    acc = layers[0][1]
    acc_layer = layers[0][0]
    for name, doc in layers[1:]:
        acc = merge(acc, doc, parent_layer=acc_layer, child_layer=name, trace=trace)
        acc_layer = name

    # Ensure kind=Policy and metadata is applied-to policy-shaped.
    acc = dict(acc)
    acc["kind"] = "Policy"
    md = dict(acc.get("metadata") or {})
    md["tenant"] = tenant_slug
    md.pop("parent", None)             # profile-parent is a compile-time concept
    md["profile"] = profile_spec or ""
    md["status"] = md.get("status", "draft")
    acc["metadata"] = md
    return acc, trace


# ---- Convenience for tests / catalog ---------------------------------------

def list_available_packs(packs_dir: str | None = None) -> Iterable[dict[str, Any]]:
    """Enumerate profile packs on disk. Used by the `/v1/profiles/available` endpoint."""
    base = Path(packs_dir) if packs_dir else _packs_dir()
    if not base.exists():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(base.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text())
            meta = doc.get("metadata") or {}
            out.append({
                "id": meta.get("id", ""),
                "version": str(meta.get("version", "")),
                "parent": meta.get("parent"),
                "labels": meta.get("labels") or {},
                "path": path.name,
            })
        except Exception:  # noqa: BLE001
            continue
    return out
