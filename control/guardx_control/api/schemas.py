from typing import Any, Optional

from pydantic import BaseModel, Field


class PolicyCreate(BaseModel):
    document: dict[str, Any] = Field(..., description="Full canonical policy document")
    change_note: Optional[str] = None


class PolicyActionRequest(BaseModel):
    note: Optional[str] = None


class PolicyOut(BaseModel):
    tenant: str
    policy_id: str
    version: str
    status: str
    origin: str
    created_by: str
    created_at: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    document_hash: str
    document: dict[str, Any]


class LintIssueOut(BaseModel):
    code: str
    severity: str
    message: str
    path: str = ""


class PolicyCreateResult(BaseModel):
    policy: PolicyOut
    lint: list[LintIssueOut]


class BundleBuildRequest(BaseModel):
    environment: str


class BundleOut(BaseModel):
    tenant: str
    environment: str
    bundle_seq: int
    manifest: dict[str, Any]
    manifest_hash: str
    signature_b64: str
    signing_key_id: str
    created_at: str


class ProposalIn(BaseModel):
    document: dict[str, Any]
    origin: str
    origin_ref: dict[str, Any] = Field(default_factory=dict)
    change_note: Optional[str] = None
    change_class: Optional[str] = Field(
        default=None,
        description="monotonic_add | threshold_tune | scope_change | mixed",
    )


class ProposalOut(BaseModel):
    policy: PolicyOut
    lint: list[LintIssueOut]
    auto_approved: bool = False
    auto_approval_rule: Optional[str] = None


class TenantCreate(BaseModel):
    slug: str
