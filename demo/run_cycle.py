#!/usr/bin/env python3
"""Headless driver for the autopilot control loop.

Same code path as the FastAPI service, without the web layer. Useful for:
  - running the reconciler on a box with no inbound network,
  - CI smoke tests,
  - driving the demo from a terminal.

    python demo/run_cycle.py backfill      # sweep labeled issues -> claim -> triage -> dispatch
    python demo/run_cycle.py reconcile     # one poll + drain pass
    python demo/run_cycle.py watch         # loop until everything reaches a terminal state
    python demo/run_cycle.py report        # print the metrics summary as JSON
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, metrics  # noqa: E402
from app.config import settings  # noqa: E402
from app.github_client import GitHubClient  # noqa: E402
from app.orchestrator import LABELS, autopilot  # noqa: E402


def backfill() -> None:
    db.init_db()
    GitHubClient().ensure_labels(LABELS)
    issues = GitHubClient().list_open_issues(label=settings.autofix_label)
    print(f"[backfill] {len(issues)} open issue(s) labeled '{settings.autofix_label}'")
    autopilot.ingest_all(issues)
    for row in sorted(db.list_all(), key=lambda r: r["issue_number"]):
        print(f"  #{row['issue_number']:<3} {row['status']:<11} {row['severity']:<9} "
              f"{row['issue_title'][:58]}")


def recover() -> None:
    """Rebuild local state from in-flight Devin sessions (see orchestrator.recover_from_devin)."""
    db.init_db()
    print(json.dumps(autopilot.recover_from_devin(), indent=2))


def reconcile() -> None:
    db.init_db()
    print(json.dumps(autopilot.reconcile_once(), indent=2))


def watch() -> None:
    db.init_db()
    while True:
        result = autopilot.reconcile_once()
        summary = metrics.summary()
        print(
            f"[{time.strftime('%H:%M:%S')}] active={result['active']} "
            f"ok={summary['totals']['succeeded']} "
            f"failed={summary['totals']['failed']} "
            f"escalated={summary['totals']['skipped_to_human']} "
            f"PRs={summary['totals']['pull_requests_opened']}",
            flush=True,
        )
        if result["active"] == 0 and not db.list_by_status("queued"):
            print("[watch] nothing left in flight")
            return
        time.sleep(settings.poll_interval_seconds)


def report() -> None:
    db.init_db()
    print(json.dumps(metrics.summary(), indent=2))


COMMANDS = {"backfill": backfill, "recover": recover, "reconcile": reconcile,
            "watch": watch, "report": report}

if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "report"
    if command not in COMMANDS:
        print(f"usage: {sys.argv[0]} [{'|'.join(COMMANDS)}]", file=sys.stderr)
        raise SystemExit(2)
    COMMANDS[command]()
