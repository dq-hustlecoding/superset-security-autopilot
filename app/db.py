"""SQLite-backed state store.

The Devin API has no completion callback, so the orchestrator owns the state machine.
Every transition is persisted here, which is also what powers the observability layer:
the dashboard is a read model over this single table plus an append-only event log.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .config import settings

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS remediations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key        TEXT UNIQUE NOT NULL,   -- idempotency anchor (repo + issue number)
    issue_number      INTEGER NOT NULL,
    issue_title       TEXT NOT NULL,
    issue_url         TEXT NOT NULL,
    finding_type      TEXT NOT NULL,          -- dependency_cve | static_analysis | unknown
    severity          TEXT NOT NULL,          -- HIGH | MODERATE | LOW
    playbook          TEXT NOT NULL,          -- which prompt strategy was selected
    status            TEXT NOT NULL,          -- queued|dispatched|running|succeeded|failed|skipped|timed_out
    skip_reason       TEXT,
    devin_session_id  TEXT,
    devin_session_url TEXT,
    pr_url            TEXT,
    outcome           TEXT,                   -- structured output: fixed|partial|no_action_needed|blocked
    confidence        TEXT,
    summary           TEXT,
    verification      TEXT,
    residual_risk     TEXT,
    files_changed     TEXT,                   -- json array
    acu_used          REAL,
    error             TEXT,
    created_at        REAL NOT NULL,
    dispatched_at     REAL,
    completed_at      REAL
);

CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    remediation_id INTEGER,
    at             REAL NOT NULL,
    level          TEXT NOT NULL,
    kind           TEXT NOT NULL,
    message        TEXT NOT NULL,
    payload        TEXT
);

CREATE INDEX IF NOT EXISTS idx_rem_status ON remediations(status);
CREATE INDEX IF NOT EXISTS idx_events_rem ON events(remediation_id);
"""


def _connect() -> sqlite3.Connection:
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    with _LOCK:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)


# --------------------------------------------------------------------------- #
# writes
# --------------------------------------------------------------------------- #

def claim_remediation(
    *,
    dedupe_key: str,
    issue_number: int,
    issue_title: str,
    issue_url: str,
    finding_type: str,
    severity: str,
    playbook: str,
) -> int | None:
    """Insert a remediation row, or return None if this issue is already claimed.

    This is the idempotency gate. GitHub redelivers webhooks and the nightly scanner
    re-reports findings that are still open; neither should ever cost a second Devin session.
    """
    with db() as conn:
        try:
            cur = conn.execute(
                """INSERT INTO remediations
                   (dedupe_key, issue_number, issue_title, issue_url, finding_type,
                    severity, playbook, status, created_at)
                   VALUES (?,?,?,?,?,?,?, 'queued', ?)""",
                (
                    dedupe_key, issue_number, issue_title, issue_url,
                    finding_type, severity, playbook, time.time(),
                ),
            )
            return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return None


def update(remediation_id: int, **fields: Any) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    with db() as conn:
        conn.execute(
            f"UPDATE remediations SET {cols} WHERE id = ?",
            (*fields.values(), remediation_id),
        )


def log_event(
    remediation_id: int | None,
    kind: str,
    message: str,
    level: str = "info",
    payload: dict | None = None,
) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO events (remediation_id, at, level, kind, message, payload) VALUES (?,?,?,?,?,?)",
            (remediation_id, time.time(), level, kind, message,
             json.dumps(payload) if payload else None),
        )


# --------------------------------------------------------------------------- #
# reads
# --------------------------------------------------------------------------- #

def get(remediation_id: int) -> dict | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM remediations WHERE id = ?", (remediation_id,)).fetchone()
    return dict(row) if row else None


def get_by_dedupe(dedupe_key: str) -> dict | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM remediations WHERE dedupe_key = ?", (dedupe_key,)).fetchone()
    return dict(row) if row else None


def list_all(limit: int = 200) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM remediations ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def list_by_status(*statuses: str) -> list[dict]:
    placeholders = ",".join("?" * len(statuses))
    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM remediations WHERE status IN ({placeholders}) ORDER BY created_at",
            statuses,
        ).fetchall()
    return [dict(r) for r in rows]


def count_dispatched_since(cutoff_ts: float) -> int:
    with db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) c FROM remediations WHERE dispatched_at IS NOT NULL AND dispatched_at >= ?",
            (cutoff_ts,),
        ).fetchone()
    return int(row["c"])


def count_active() -> int:
    """Sessions holding a concurrency slot, including ones mid-dispatch."""
    with db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) c FROM remediations "
            "WHERE status IN ('dispatching','dispatched','running')"
        ).fetchone()
    return int(row["c"])


def recent_events(limit: int = 100) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            """SELECT e.*, r.issue_number FROM events e
               LEFT JOIN remediations r ON r.id = e.remediation_id
               ORDER BY e.at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
