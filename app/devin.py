"""Thin, typed client for the Devin API v3 (organization scope).

Only the surface the autopilot actually needs:
  POST /v3/organizations/{org}/sessions        -> start a remediation
  GET  /v3/organizations/{org}/sessions/{id}   -> poll until terminal

Design note: Devin has no completion webhook, so `wait_for_terminal` lives in the
orchestrator, not here. This module stays a dumb transport so it is trivial to stub in tests.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import settings

# Terminal statuses reported by the Devin API. `blocked` means the session finished its work
# and is now idle waiting for a human - from the pipeline's point of view that is done.
TERMINAL_STATUSES = {"finished", "expired", "blocked", "exit", "error", "suspended", "stopped"}

# Outcomes that mean Devin considers the work order closed.
TERMINAL_OUTCOMES = {"fixed", "no_action_needed", "blocked"}

# Devin returns this JSON blob when the session ends, so the orchestrator can machine-read
# the result instead of scraping free-form chat text. This is the contract that makes the
# whole pipeline programmable rather than "a human reads what Devin said".
REMEDIATION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "outcome": {
            "type": "string",
            "enum": ["fixed", "partial", "no_action_needed", "blocked"],
            "description": "Final disposition of the remediation attempt.",
        },
        "pr_url": {
            "type": ["string", "null"],
            "description": "URL of the pull request that was opened, if any.",
        },
        "files_changed": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Repo-relative paths that were modified.",
        },
        "summary": {
            "type": "string",
            "description": "Two-sentence description of the change, for an engineering leader.",
        },
        "verification": {
            "type": "string",
            "description": "Exact commands run to prove the fix works, and their results.",
        },
        "residual_risk": {
            "type": "string",
            "description": "What a human reviewer still needs to check. 'none' if nothing.",
        },
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["outcome", "summary", "verification", "confidence"],
}


class DevinError(RuntimeError):
    pass


class DevinClient:
    def __init__(self, api_key: str | None = None, org_id: str | None = None) -> None:
        self.api_key = api_key or settings.devin_api_key
        self.org_id = org_id or settings.devin_org_id
        self.base = f"{settings.devin_api_base}/organizations/{self.org_id}"

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def create_session(
        self,
        *,
        prompt: str,
        title: str,
        tags: list[str] | None = None,
        max_acu_limit: int | None = None,
        idempotent: bool = True,
        structured_output_schema: dict | None = None,
    ) -> dict:
        """Start a Devin session.

        `idempotent=True` asks Devin to reuse an equivalent session instead of
        spawning a duplicate; combined with the SQLite unique constraint in db.py this
        gives us at-most-once remediation per issue even under webhook redelivery.
        """
        body: dict[str, Any] = {
            "prompt": prompt,
            "title": title[:200],
            "idempotent": idempotent,
            "tags": (tags or [])[:50],
            "max_acu_limit": max_acu_limit or settings.max_acu_per_session,
        }
        if structured_output_schema:
            body["structured_output_schema"] = structured_output_schema

        with httpx.Client(timeout=60) as client:
            resp = client.post(f"{self.base}/sessions", headers=self._headers, json=body)
        if resp.status_code >= 400:
            raise DevinError(f"create_session {resp.status_code}: {resp.text[:500]}")
        return resp.json()

    def get_session(self, session_id: str) -> dict:
        with httpx.Client(timeout=60) as client:
            resp = client.get(f"{self.base}/sessions/{session_id}", headers=self._headers)
        if resp.status_code >= 400:
            raise DevinError(f"get_session {resp.status_code}: {resp.text[:500]}")
        return resp.json()

    def send_message(self, session_id: str, message: str) -> None:
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                f"{self.base}/sessions/{session_id}/messages",
                headers=self._headers,
                json={"message": message},
            )
        if resp.status_code >= 400:
            raise DevinError(f"send_message {resp.status_code}: {resp.text[:500]}")

    def list_sessions(self, limit: int = 50) -> list[dict]:
        with httpx.Client(timeout=60) as client:
            resp = client.get(
                f"{self.base}/sessions", headers=self._headers, params={"limit": limit}
            )
        if resp.status_code >= 400:
            raise DevinError(f"list_sessions {resp.status_code}: {resp.text[:500]}")
        return resp.json().get("items", [])


def is_terminal(status: str | None) -> bool:
    return (status or "").lower() in TERMINAL_STATUSES


def session_is_terminal(session: dict) -> bool:
    """Decide whether a session is done from the pipeline's point of view.

    Devin sessions do not stop when the work is finished - they idle, waiting for a human to
    say something else, and can keep polishing in the background. Waiting for the API status
    alone would therefore hold a concurrency slot indefinitely on work that is already
    delivered.

    So completion is defined by the *contract*: the session is done when the structured
    output reports a terminal outcome and there is something to review (a PR, or an explicit
    "no change was needed"). The API status is still honoured as an independent signal, which
    is what catches errors and expiry.
    """
    if is_terminal(session.get("status")):
        return True

    structured = session.get("structured_output") or {}
    if isinstance(structured, str):
        import json as _json

        try:
            structured = _json.loads(structured)
        except _json.JSONDecodeError:
            return False

    outcome = (structured.get("outcome") or "").lower()
    if outcome not in TERMINAL_OUTCOMES:
        return False
    if outcome == "no_action_needed":
        return True
    return bool(structured.get("pr_url") or session.get("pull_requests"))
