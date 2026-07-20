"""Shared Control API client used by every automation module."""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx


class ControlClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 15.0,
    ):
        self.base_url = (base_url or os.environ.get("GUARDX_CONTROL_BASE_URL", "http://127.0.0.1:8080")).rstrip("/")
        self.api_key = api_key or os.environ.get("GUARDX_SERVICE_KEY", "dev-service-key")
        self._client = httpx.Client(timeout=timeout)

    # ---- policy registry ----

    def get_policy_versions(self, tenant: str, policy_id: str) -> list[dict[str, Any]]:
        r = self._client.get(
            f"{self.base_url}/v1/policies/{policy_id}",
            params={"tenant": tenant},
            headers=self._headers(),
        )
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json()

    def submit_proposal(
        self,
        tenant: str,
        document: dict[str, Any],
        origin: str,
        change_class: Optional[str] = None,
        origin_ref: Optional[dict[str, Any]] = None,
        change_note: Optional[str] = None,
    ) -> dict[str, Any]:
        body = {
            "document": document,
            "origin": origin,
            "origin_ref": origin_ref or {},
            "change_note": change_note,
            "change_class": change_class,
        }
        r = self._client.post(
            f"{self.base_url}/v1/proposals",
            params={"tenant": tenant},
            headers=self._headers(),
            json=body,
        )
        if r.status_code >= 400:
            # Surface the linter body so the caller sees which rule fired.
            raise httpx.HTTPStatusError(
                f"{r.status_code} from /v1/proposals: {r.text[:500]}",
                request=r.request, response=r,
            )
        return r.json()

    # ---- feedback ----

    def list_feedback(self, tenant: str, app: Optional[str] = None,
                      guard_id: Optional[str] = None, since_iso: Optional[str] = None,
                      limit: int = 500) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"tenant": tenant, "limit": limit}
        if app:
            params["app"] = app
        if guard_id:
            params["guard_id"] = guard_id
        if since_iso:
            params["since"] = since_iso
        r = self._client.get(
            f"{self.base_url}/v1/feedback",
            params=params,
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def submit_feedback(self, tenant: str, app: str, source: str, disposition: str,
                        event_id: Optional[str] = None, guard_id: Optional[str] = None,
                        policy: Optional[str] = None, note: Optional[str] = None) -> dict[str, Any]:
        r = self._client.post(
            f"{self.base_url}/v1/feedback",
            headers=self._headers(),
            json={
                "tenant": tenant, "app": app, "source": source,
                "disposition": disposition, "event_id": event_id,
                "guard_id": guard_id, "policy": policy, "note": note,
            },
        )
        r.raise_for_status()
        return r.json()

    # ---- evidence ----

    def list_evidence(self, tenant: str, app: str, since_seq: int = 0,
                      limit: int = 500) -> list[dict[str, Any]]:
        r = self._client.get(
            f"{self.base_url}/v1/evidence/events",
            params={"tenant": tenant, "app": app, "since_seq": since_seq, "limit": limit},
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def _headers(self) -> dict[str, str]:
        return {"X-GuardX-Key": self.api_key}

    def close(self) -> None:
        self._client.close()
