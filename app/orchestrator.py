"""The autopilot control loop.

Lifecycle of one finding:

    GitHub issue labeled `devin-autofix`
        -> webhook (or scheduled reconcile sweep)
        -> claim (SQLite unique key = idempotency gate)
        -> triage (dispatch or skip-with-reason)
        -> Devin session created with a playbook-specific prompt + structured output schema
        -> poller drives dispatched -> running -> succeeded/failed
        -> result written back to the issue as a comment, PR linked, labels updated

Two things are worth calling out because they are the difference between a demo and
something you could actually run against a real backlog:

1. There is no completion webhook in the Devin API. The orchestrator therefore owns a
   durable state machine in SQLite, and the poller is a *reconciler* - it can be killed and
   restarted at any point and will pick every in-flight session back up.
2. Concurrency and ACU ceilings are enforced before dispatch, so a scanner that suddenly
   reports 200 findings cannot run away with the budget.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from . import db
from .config import settings
from .devin import (REMEDIATION_OUTPUT_SCHEMA, DevinClient, DevinError,
                    session_is_terminal)
from .github_client import GitHubClient, GitHubError
from .triage import build_prompt, triage

log = logging.getLogger("autopilot")

# Budget is finite, so it must be spent on the worst risk first. Anything that ranks
# lower simply stays queued until the next window.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

LABELS = {
    "devin-autofix": ("0E8A16", "Queued for autonomous remediation by Devin"),
    "devin-in-progress": ("FBCA04", "A Devin session is actively remediating this"),
    "devin-fixed": ("1D76DB", "Devin opened a PR that remediates this issue"),
    "devin-needs-human": ("D93F0B", "Escalated: needs an engineering decision"),
}


class Autopilot:
    def __init__(self) -> None:
        self.devin = DevinClient()
        self.github = GitHubClient()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ #
    # ingest
    # ------------------------------------------------------------------ #

    def handle_issue_event(self, payload: dict) -> dict:
        """Entry point for the GitHub `issues` webhook."""
        action = payload.get("action")
        issue = payload.get("issue") or {}
        labels = {label["name"] for label in issue.get("labels", [])}

        if action not in {"labeled", "opened", "reopened"}:
            return {"accepted": False, "reason": f"ignored action '{action}'"}
        if settings.autofix_label not in labels:
            return {"accepted": False, "reason": f"missing '{settings.autofix_label}' label"}

        return self.ingest_issue(issue)

    def ingest_all(self, issues: list[dict]) -> list[dict]:
        """Claim a whole batch first, then dispatch in priority order.

        Claiming and dispatching are deliberately separated here. If we dispatched as we
        walked the list, the session budget would be handed to whatever GitHub happened to
        return first - which is newest-first, not worst-first.
        """
        results = [self.ingest_issue(issue, dispatch_now=False) for issue in issues]
        self.reconcile_once()
        return results

    def ingest_issue(self, issue: dict, dispatch_now: bool = True) -> dict:
        number = issue["number"]
        dedupe_key = f"{settings.github_repo}#{number}"

        decision = triage(issue)

        remediation_id = db.claim_remediation(
            dedupe_key=dedupe_key,
            issue_number=number,
            issue_title=issue.get("title", ""),
            issue_url=issue.get("html_url", ""),
            finding_type=decision.finding_type,
            severity=decision.severity,
            playbook=decision.playbook,
        )
        if remediation_id is None:
            existing = db.get_by_dedupe(dedupe_key)
            db.log_event(existing["id"] if existing else None, "dedupe",
                         f"issue #{number} already claimed; ignoring duplicate trigger")
            return {"accepted": False, "reason": "already claimed (idempotent)",
                    "remediation_id": existing["id"] if existing else None}

        db.log_event(remediation_id, "claimed",
                     f"claimed issue #{number}: {issue.get('title','')}",
                     payload={"severity": decision.severity, "playbook": decision.playbook})

        if not decision.dispatch:
            self._skip(remediation_id, number, decision.reason)
            return {"accepted": True, "dispatched": False, "escalated": True,
                    "remediation_id": remediation_id, "reason": decision.reason}

        if not dispatch_now:
            return {"accepted": True, "dispatched": False, "queued": True,
                    "remediation_id": remediation_id}

        self._dispatch(remediation_id, issue, decision)
        row = db.get(remediation_id) or {}
        return {"accepted": True, "dispatched": row.get("status") == "dispatched",
                "remediation_id": remediation_id}

    # ------------------------------------------------------------------ #
    # dispatch
    # ------------------------------------------------------------------ #

    def _skip(self, remediation_id: int, issue_number: int, reason: str) -> None:
        db.update(remediation_id, status="skipped", skip_reason=reason,
                  completed_at=time.time(), outcome="blocked")
        db.log_event(remediation_id, "skipped", reason, level="warning")
        self._safe_github(
            lambda: self.github.comment(
                issue_number,
                "### Autopilot triage: escalated to a human\n\n"
                f"{reason}\n\n"
                "_No Devin session was started, so no ACUs were spent on this finding._",
            )
        )
        self._safe_github(lambda: self.github.add_labels(issue_number, ["devin-needs-human"]))
        self._safe_github(lambda: self.github.remove_label(issue_number, settings.autofix_label))

    def _dispatch(self, remediation_id: int, issue: dict, decision: Any) -> None:
        number = issue["number"]

        # Take the row out of `queued` atomically. If another worker got there first this
        # returns False and we simply do nothing - that worker owns the dispatch.
        if not db.try_lock_for_dispatch(remediation_id):
            db.log_event(remediation_id, "dispatch_race",
                         f"issue #{number} is already being dispatched by another worker")
            return

        if db.count_active() > settings.max_concurrent_sessions:
            db.log_event(remediation_id, "throttled",
                         f"concurrency cap ({settings.max_concurrent_sessions}) reached; "
                         "staying queued for the next reconcile pass")
            db.release_dispatch_lock(remediation_id)
            return

        if settings.dispatch_paused:
            db.log_event(remediation_id, "dispatch_paused",
                         "operator kill switch is on; staying queued", level="warning")
            db.release_dispatch_lock(remediation_id)
            return

        spent = db.count_dispatched_since(time.time() - 86400)
        if spent >= settings.daily_session_budget:
            db.log_event(remediation_id, "budget_exhausted",
                         f"24h session budget ({settings.daily_session_budget}) spent; "
                         "remaining backlog stays queued until the window rolls over",
                         level="warning")
            db.release_dispatch_lock(remediation_id)
            return

        prompt = build_prompt(issue, decision, settings.github_repo)

        if settings.dry_run:
            db.update(remediation_id, status="dispatched", dispatched_at=time.time(),
                      devin_session_id="dry-run", devin_session_url="")
            db.log_event(remediation_id, "dispatched", "DRY_RUN: session not actually created",
                         payload={"prompt": prompt})
            return

        try:
            session = self.devin.create_session(
                prompt=prompt,
                title=f"[autopilot] #{number} {issue.get('title','')}",
                tags=["autopilot", f"severity:{decision.severity.lower()}",
                      f"playbook:{decision.playbook}", f"issue:{number}"],
                max_acu_limit=settings.max_acu_per_session,
                idempotent=True,
                structured_output_schema=REMEDIATION_OUTPUT_SCHEMA,
            )
        except DevinError as exc:
            db.update(remediation_id, status="failed", error=str(exc), completed_at=time.time())
            db.log_event(remediation_id, "dispatch_failed", str(exc), level="error")
            return

        session_id = session.get("session_id") or session.get("id") or ""
        session_url = session.get("url", "")
        db.update(remediation_id, status="dispatched", dispatched_at=time.time(),
                  devin_session_id=session_id, devin_session_url=session_url)
        db.log_event(remediation_id, "dispatched",
                     f"Devin session {session_id} started for issue #{number}",
                     payload={"session_url": session_url})

        self._safe_github(lambda: self.github.add_labels(number, ["devin-in-progress"]))
        self._safe_github(
            lambda: self.github.comment(
                number,
                "### Autopilot dispatched a Devin session\n\n"
                f"- **Playbook:** `{decision.playbook}`\n"
                f"- **Severity:** {decision.severity}\n"
                f"- **ACU ceiling:** {settings.max_acu_per_session}\n"
                f"- **Session:** {session_url or session_id}\n\n"
                "Devin will investigate, implement a fix, verify it, and open a PR against this issue.",
            )
        )

    # ------------------------------------------------------------------ #
    # disaster recovery
    # ------------------------------------------------------------------ #

    def recover_from_devin(self) -> dict:
        """Rebuild local state from Devin, for when the state store is lost.

        Every session is tagged with the issue it belongs to at dispatch time, which makes
        Devin itself the durable record of what is in flight. Without this, losing the
        database would mean re-dispatching work that is already running - paying twice and
        opening duplicate PRs.
        """
        recovered, adopted = 0, 0
        for session in self.devin.list_sessions(limit=200):
            tags = session.get("tags") or []
            if "autopilot" not in tags:
                continue
            issue_number = next(
                (int(t.split(":", 1)[1]) for t in tags if t.startswith("issue:")), None
            )
            if issue_number is None:
                continue

            severity = next(
                (t.split(":", 1)[1].upper() for t in tags if t.startswith("severity:")), "UNKNOWN"
            )
            playbook = next(
                (t.split(":", 1)[1] for t in tags if t.startswith("playbook:")), "unknown"
            )
            dedupe_key = f"{settings.github_repo}#{issue_number}"
            if db.get_by_dedupe(dedupe_key):
                continue

            try:
                issue = self.github.get_issue(issue_number)
            except GitHubError:
                continue

            remediation_id = db.claim_remediation(
                dedupe_key=dedupe_key,
                issue_number=issue_number,
                issue_title=issue.get("title", ""),
                issue_url=issue.get("html_url", ""),
                finding_type=triage(issue).finding_type,
                severity=severity,
                playbook=playbook,
            )
            if remediation_id is None:
                continue

            status = (session.get("status") or "").lower()
            db.update(
                remediation_id,
                status="running" if not session_is_terminal(session) else "dispatched",
                devin_session_id=session.get("session_id"),
                devin_session_url=session.get("url", ""),
                dispatched_at=time.time(),
            )
            db.log_event(remediation_id, "recovered",
                         f"adopted in-flight Devin session {session.get('session_id')} "
                         f"for issue #{issue_number}")
            recovered += 1
            adopted += 1

        # Escalations leave their evidence on GitHub (label + comment) rather than in a
        # session, so they are recovered from the label instead.
        escalated = 0
        try:
            for issue in self.github.list_open_issues(label="devin-needs-human"):
                dedupe_key = f"{settings.github_repo}#{issue['number']}"
                if db.get_by_dedupe(dedupe_key):
                    continue
                decision = triage(issue)
                remediation_id = db.claim_remediation(
                    dedupe_key=dedupe_key,
                    issue_number=issue["number"],
                    issue_title=issue.get("title", ""),
                    issue_url=issue.get("html_url", ""),
                    finding_type=decision.finding_type,
                    severity=decision.severity,
                    playbook=decision.playbook,
                )
                if remediation_id is None:
                    continue
                db.update(remediation_id, status="skipped", outcome="blocked",
                          skip_reason=decision.reason, completed_at=time.time())
                db.log_event(remediation_id, "recovered",
                             f"re-adopted escalated issue #{issue['number']}")
                recovered += 1
                escalated += 1
        except GitHubError:
            pass

        return {"recovered": recovered, "adopted_sessions": adopted,
                "adopted_escalations": escalated}

    # ------------------------------------------------------------------ #
    # reconcile / poll
    # ------------------------------------------------------------------ #

    def reconcile_once(self) -> dict:
        """One pass of the control loop. Idempotent and safe to call repeatedly."""
        polled = self._poll_in_flight()
        started = self._drain_queue()
        return {"polled": polled, "started": started, "active": db.count_active()}

    def _drain_queue(self) -> int:
        if settings.dispatch_paused:
            return 0
        started = 0
        queued = sorted(
            db.list_by_status("queued"),
            key=lambda r: (SEVERITY_RANK.get((r["severity"] or "UNKNOWN").upper(), 4),
                           r["issue_number"]),
        )
        for row in queued:
            if db.count_active() >= settings.max_concurrent_sessions:
                break
            if db.count_dispatched_since(time.time() - 86400) >= settings.daily_session_budget:
                break
            try:
                issue = self.github.get_issue(row["issue_number"])
            except GitHubError as exc:
                db.log_event(row["id"], "github_error", str(exc), level="error")
                continue
            self._dispatch(row["id"], issue, triage(issue))
            started += 1
        return started

    def _poll_in_flight(self) -> int:
        rows = db.list_by_status("dispatched", "running")
        for row in rows:
            if settings.dry_run or not row["devin_session_id"] or row["devin_session_id"] == "dry-run":
                continue
            try:
                session = self.devin.get_session(row["devin_session_id"])
            except DevinError as exc:
                db.log_event(row["id"], "poll_error", str(exc), level="error")
                continue

            status = (session.get("status") or session.get("status_enum") or "").lower()
            detail = (session.get("status_detail") or "").lower()
            terminal = session_is_terminal(session)  # contract-based, see devin.py

            # Safety valve: a stuck session should not stay "active" forever and
            # block the concurrency slot.
            age_min = (time.time() - (row["dispatched_at"] or time.time())) / 60
            if not terminal and age_min > settings.session_timeout_minutes:
                db.update(row["id"], status="timed_out", completed_at=time.time(),
                          error=f"no terminal status after {int(age_min)} min")
                db.log_event(row["id"], "timeout",
                             f"session {row['devin_session_id']} timed out", level="error")
                continue

            if not terminal:
                if row["status"] != "running":
                    db.update(row["id"], status="running")
                    db.log_event(row["id"], "running",
                                 f"session status: {status}/{detail or 'n/a'}")
                continue

            self._finalize(row, session, status)
        return len(rows)

    def _finalize(self, row: dict, session: dict, status: str) -> None:
        structured = (
            session.get("structured_output")
            or session.get("structured_output_json")
            or {}
        )
        if isinstance(structured, str):
            try:
                structured = json.loads(structured)
            except json.JSONDecodeError:
                structured = {}

        outcome = structured.get("outcome")

        # Three independent sources for the PR, most authoritative first. Devin's own
        # session record is the ground truth; the structured output is self-reported; the
        # GitHub lookup is the backstop for when a session ends without reporting cleanly.
        pr_url = _first_pr_url(session.get("pull_requests")) or structured.get("pr_url")
        if not pr_url:
            pr_url = self._safe_github(
                lambda: self.github.find_pr_referencing(row["issue_number"])
            )

        acu = session.get("acus_consumed", session.get("acu_used"))
        succeeded = outcome in {"fixed", "partial", "no_action_needed"} and status not in {"error"}

        db.update(
            row["id"],
            status="succeeded" if succeeded else "failed",
            completed_at=time.time(),
            outcome=outcome,
            pr_url=pr_url,
            confidence=structured.get("confidence"),
            summary=structured.get("summary"),
            verification=structured.get("verification"),
            residual_risk=structured.get("residual_risk"),
            files_changed=json.dumps(structured.get("files_changed") or []),
            acu_used=float(acu) if acu is not None else None,
            error=None if succeeded else f"devin status={status}",
        )
        db.log_event(
            row["id"],
            "completed" if succeeded else "failed",
            f"session {row['devin_session_id']} finished: status={status} outcome={outcome}",
            level="info" if succeeded else "error",
            payload=structured or None,
        )
        self._report_to_github(row, structured, pr_url, succeeded)

    def _report_to_github(self, row: dict, structured: dict, pr_url: str | None,
                          succeeded: bool) -> None:
        number = row["issue_number"]
        files = structured.get("files_changed") or []
        body = [
            "### Autopilot result",
            "",
            f"- **Outcome:** `{structured.get('outcome', 'unknown')}`",
            f"- **Confidence:** {structured.get('confidence', 'n/a')}",
            f"- **Pull request:** {pr_url or '_none opened_'}",
            f"- **Session:** {row['devin_session_url'] or row['devin_session_id']}",
        ]
        if files:
            body += ["", "**Files changed**", *[f"- `{f}`" for f in files]]
        if structured.get("summary"):
            body += ["", "**What changed**", structured["summary"]]
        if structured.get("verification"):
            body += ["", "**How it was verified**", structured["verification"]]
        if structured.get("residual_risk"):
            body += ["", "**Residual risk for the reviewer**", structured["residual_risk"]]

        self._safe_github(lambda: self.github.comment(number, "\n".join(body)))
        self._safe_github(lambda: self.github.remove_label(number, "devin-in-progress"))
        # Drop the queue label so the remaining `devin-autofix` set always reflects
        # outstanding work rather than everything the system has ever touched.
        self._safe_github(lambda: self.github.remove_label(number, settings.autofix_label))
        self._safe_github(
            lambda: self.github.add_labels(
                number, ["devin-fixed"] if succeeded and pr_url else ["devin-needs-human"]
            )
        )

    # ------------------------------------------------------------------ #
    # background loop
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.reconcile_once()
                except Exception:  # keep the reconciler alive no matter what
                    log.exception("reconcile pass failed")
                self._stop.wait(settings.poll_interval_seconds)

        self._thread = threading.Thread(target=loop, name="autopilot-reconciler", daemon=True)
        self._thread.start()
        log.info("reconciler started (interval=%ss)", settings.poll_interval_seconds)

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ #

    @staticmethod
    def _safe_github(fn: Any) -> Any:
        """GitHub write-backs are best-effort: never let them break the state machine."""
        try:
            return fn()
        except GitHubError as exc:
            log.warning("github write-back failed: %s", exc)
            return None


def _first_pr_url(pull_requests: object) -> str | None:
    """Devin reports PRs on the session record; shapes vary, so normalise defensively."""
    if not pull_requests:
        return None
    if isinstance(pull_requests, str):
        return pull_requests
    if isinstance(pull_requests, dict):
        pull_requests = [pull_requests]
    for item in pull_requests:
        if isinstance(item, str) and item.startswith("http"):
            return item
        if isinstance(item, dict):
            for key in ("url", "html_url", "pr_url", "link"):
                if item.get(key):
                    return str(item[key])
    return None


autopilot = Autopilot()
