"""Profile API — list available packs, compile a policy from a profile.

The registry `profiles` table (from M0 migration) holds tenant-authored
profile fragments. On-disk packs at `profiles/*.yaml` are read-only
"framework defaults" shipped with the platform.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..profiles import compile_policy, list_available_packs, load_pack
from .auth import Principal, current_principal

router = APIRouter(prefix="/v1/profiles", tags=["profiles"])


class ProfileAvailable(BaseModel):
    id: str
    version: str
    parent: Optional[str] = None
    labels: dict[str, str] = Field(default_factory=dict)
    path: str


class OverrideEntry(BaseModel):
    path: str
    layer: str
    replaced: Optional[str] = None


class CompileRequest(BaseModel):
    tenant: str
    profile: str = Field(..., description="Profile pack id@version — e.g. glba-nydfs@1.0.0")
    app_policy: Optional[dict[str, Any]] = None


class CompileResponse(BaseModel):
    document: dict[str, Any]
    overrides: list[OverrideEntry]


@router.get("/available", response_model=list[ProfileAvailable])
def available_packs(_: Principal = Depends(current_principal)) -> list[ProfileAvailable]:
    """Enumerate on-disk profile packs. Read-only framework defaults."""
    return [ProfileAvailable(**p) for p in list_available_packs()]


@router.get("/{spec:path}", response_model=dict[str, Any])
def get_pack(spec: str, _: Principal = Depends(current_principal)) -> dict[str, Any]:
    """Return the raw pack document for `id@version`."""
    try:
        return load_pack(spec).document
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))


@router.post("/compile", response_model=CompileResponse)
def compile_from_profile(
    body: CompileRequest,
    _: Principal = Depends(current_principal),
) -> CompileResponse:
    """Compose baseline ⊕ profile ⊕ app_policy → a materialized policy.

    Does NOT persist. Caller reviews the returned document + override trace,
    then submits it via `POST /v1/policies` as a normal draft.
    """
    try:
        doc, trace = compile_policy(
            tenant_slug=body.tenant,
            profile_spec=body.profile,
            app_policy=body.app_policy,
        )
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    return CompileResponse(
        document=doc,
        overrides=[OverrideEntry(**e) for e in trace.entries],
    )
