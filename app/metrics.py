"""Observability read-model.

The question this has to answer for an engineering leader is not "did the script run",
it is "is this actually burning down risk, and what is it costing me". So the metrics are
deliberately outcome-shaped: backlog burndown, success rate, time-to-remediation, ACU spend,
and the human cost avoided.
"""

from __future__ import annotations

import json
import time
from typing import Any

from pathlib import Path

from . import db
from .config import settings


def _load_costs() -> dict:
    """Observed Devin spend, keyed by issue number. Empty dict when unavailable."""
    path = Path(settings.session_costs_path)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    return {
        "by_issue": {int(k): float(v) for k, v in (raw.get("by_issue") or {}).items()},
        "wasted": {k: float(v) for k, v in (raw.get("wasted") or {}).items()},
        "source": raw.get("_source", ""),
    }

IN_FLIGHT = {"dispatching", "dispatched", "running"}  # holding a concurrency slot
QUEUED = {"queued"}                     # claimed, waiting on concurrency or budget
ACTIVE = IN_FLIGHT | QUEUED             # not yet resolved either way
DONE_OK = {"succeeded"}
DONE_BAD = {"failed", "timed_out"}


def _pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 1) if denominator else 0.0


def summary() -> dict[str, Any]:
    rows = db.list_all(limit=1000)
    total = len(rows)

    by_status: dict[str, int] = {}
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1

    succeeded = sum(1 for r in rows if r["status"] in DONE_OK)
    failed = sum(1 for r in rows if r["status"] in DONE_BAD)
    skipped = by_status.get("skipped", 0)
    active = sum(1 for r in rows if r["status"] in ACTIVE)
    in_flight = sum(1 for r in rows if r["status"] in IN_FLIGHT)
    queued = sum(1 for r in rows if r["status"] in QUEUED)
    attempted = succeeded + failed

    prs = [r["pr_url"] for r in rows if r["pr_url"]]

    # Mean time to remediation: issue claimed -> terminal success.
    durations = [
        r["completed_at"] - r["created_at"]
        for r in rows
        if r["status"] in DONE_OK and r["completed_at"] and r["created_at"]
    ]
    mttr_minutes = round(sum(durations) / len(durations) / 60, 1) if durations else None

    # The Devin API exposes `acus_consumed`, but it reported 0.0 for every session on the
    # plan this was built against. Rather than render a confident 0, the read model reports
    # whether the number is actually available, and the dashboard says so plainly. A cost
    # metric that is silently wrong is worse than one that admits it is missing.
    acus = [r["acu_used"] for r in rows if r["acu_used"]]
    total_acu = round(sum(acus), 2) if acus else 0.0
    acu_reported = bool(acus)

    costs = _load_costs()
    by_issue = costs.get("by_issue", {})
    productive_spend = sum(by_issue.get(r["issue_number"], 0.0) for r in rows)
    # Waste is only meaningful against a run that actually happened. Charged to an empty
    # database it would report spend with no remediation to attribute it to.
    wasted = sum(costs.get("wasted", {}).values()) if productive_spend else 0.0
    total_spend = round(productive_spend + wasted, 2)
    # Fully loaded: waste from the duplicate-dispatch bug is charged against the result,
    # because that is what the run actually cost.
    cost_per_fix = round(total_spend / succeeded, 2) if (succeeded and total_spend) else None
    # Gated on the derived figure rather than on the cost file, so that every consumer --
    # the dashboard card and the Prometheus gauge -- is guarded by the number it renders.
    spend_observed = cost_per_fix is not None

    # Modelled, not measured. Driven by ENGINEER_HOURS_PER_FINDING and
    # ENGINEER_HOURLY_COST_USD so a customer plugs in their own numbers; the dashboard
    # labels it as an assumption rather than an observation.
    hours_saved = round(succeeded * settings.engineer_hours_per_finding, 1)
    cost_avoided = round(hours_saved * settings.engineer_hourly_cost_usd, 0)

    by_severity: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = by_severity.setdefault(row["severity"], {"total": 0, "succeeded": 0})
        bucket["total"] += 1
        if row["status"] in DONE_OK:
            bucket["succeeded"] += 1

    return {
        "generated_at": time.time(),
        "repo": settings.github_repo,
        "totals": {
            "findings_ingested": total,
            "active": active,
            "succeeded": succeeded,
            "failed": failed,
            "skipped_to_human": skipped,
            "pull_requests_opened": len(prs),
            "queued": queued,
            "in_flight": in_flight,
        },
        "rates": {
            "success_rate_pct": _pct(succeeded, attempted),
            "autonomy_rate_pct": _pct(succeeded, total),  # of everything ingested
            "human_escalation_pct": _pct(skipped, total),
        },
        "throughput": {
            "mean_time_to_remediation_minutes": mttr_minutes,
            "in_flight": in_flight,
            "queued": queued,
            "concurrency_cap": settings.max_concurrent_sessions,
            "daily_session_budget": settings.daily_session_budget,
        },
        "cost": {
            "total_acu_used": total_acu,
            "acu_reported_by_api": acu_reported,
            "acu_ceiling_per_session": settings.max_acu_per_session,
            "engineer_hours_saved": hours_saved,
            "engineer_cost_avoided_usd": cost_avoided,
            "engineer_hours_per_finding_assumption": settings.engineer_hours_per_finding,
            "engineer_hourly_cost_usd_assumption": settings.engineer_hourly_cost_usd,
            "is_modelled": True,
            "spend_observed": spend_observed,
            "devin_spend_usd": total_spend,
            "devin_spend_wasted_usd": round(wasted, 2),
            "cost_per_remediation_usd": cost_per_fix,
            "modelled_human_cost_per_finding_usd": round(
                settings.engineer_hours_per_finding * settings.engineer_hourly_cost_usd, 2),
            "spend_source": costs.get("source", ""),
        },
        "by_status": by_status,
        "by_severity": by_severity,
    }


def prometheus() -> str:
    """Plain-text Prometheus exposition so this can be scraped by whatever the customer runs."""
    s = summary()
    lines = [
        "# HELP autopilot_findings_total Findings ingested by the autopilot.",
        "# TYPE autopilot_findings_total counter",
        f"autopilot_findings_total {s['totals']['findings_ingested']}",
        "# HELP autopilot_remediations_succeeded_total Findings remediated with a PR.",
        "# TYPE autopilot_remediations_succeeded_total counter",
        f"autopilot_remediations_succeeded_total {s['totals']['succeeded']}",
        "# HELP autopilot_remediations_failed_total Failed or timed-out remediations.",
        "# TYPE autopilot_remediations_failed_total counter",
        f"autopilot_remediations_failed_total {s['totals']['failed']}",
        "# HELP autopilot_escalated_total Findings routed to a human by triage.",
        "# TYPE autopilot_escalated_total counter",
        f"autopilot_escalated_total {s['totals']['skipped_to_human']}",
        "# HELP autopilot_sessions_active Devin sessions currently in flight.",
        "# TYPE autopilot_sessions_active gauge",
        f"autopilot_sessions_active {s['throughput']['in_flight']}",
        "# HELP autopilot_success_rate_pct Success rate over attempted remediations.",
        "# TYPE autopilot_success_rate_pct gauge",
        f"autopilot_success_rate_pct {s['rates']['success_rate_pct']}",
    ]
    if s["cost"]["spend_observed"]:
        lines += [
            "# HELP autopilot_spend_usd_total Observed Devin spend for these remediations.",
            "# TYPE autopilot_spend_usd_total counter",
            f"autopilot_spend_usd_total {s['cost']['devin_spend_usd']}",
            "# HELP autopilot_cost_per_remediation_usd Fully loaded cost per remediated finding.",
            "# TYPE autopilot_cost_per_remediation_usd gauge",
            f"autopilot_cost_per_remediation_usd {s['cost']['cost_per_remediation_usd']}",
        ]
    # Only export ACU when the API actually populated it; a hard 0 would look like a real
    # measurement to anything scraping this.
    if s["cost"]["acu_reported_by_api"]:
        lines += [
            "# HELP autopilot_acu_used_total Total Devin ACUs consumed.",
            "# TYPE autopilot_acu_used_total counter",
            f"autopilot_acu_used_total {s['cost']['total_acu_used']}",
        ]
    mttr = s["throughput"]["mean_time_to_remediation_minutes"]
    if mttr is not None:
        lines += [
            "# HELP autopilot_mttr_minutes Mean time from finding to merged-ready PR.",
            "# TYPE autopilot_mttr_minutes gauge",
            f"autopilot_mttr_minutes {mttr}",
        ]
    return "\n".join(lines) + "\n"


def table_rows() -> list[dict]:
    rows = db.list_all(limit=200)
    for row in rows:
        try:
            row["files_changed_list"] = json.loads(row["files_changed"] or "[]")
        except json.JSONDecodeError:
            row["files_changed_list"] = []
        row["cost_usd"] = _load_costs().get("by_issue", {}).get(row["issue_number"])
        row["duration_min"] = (
            round((row["completed_at"] - row["created_at"]) / 60, 1)
            if row["completed_at"] and row["created_at"] else None
        )
    return rows
