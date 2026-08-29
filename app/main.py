"""FastAPI surface: webhook ingress, control endpoints, and the observability dashboard."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from . import db, metrics
from .config import settings
from .github_client import GitHubClient, verify_signature
from .orchestrator import LABELS, autopilot

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
log = logging.getLogger("autopilot.api")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    if settings.github_token and settings.github_repo:
        try:
            GitHubClient().ensure_labels(LABELS)
        except Exception as exc:  # non-fatal
            log.warning("could not ensure labels: %s", exc)
    autopilot.start()
    log.info("autopilot online repo=%s dry_run=%s", settings.github_repo, settings.dry_run)
    yield
    autopilot.stop()


app = FastAPI(
    title="Superset Security Autopilot",
    description="Event-driven remediation of security debt using the Devin API.",
    version="1.0.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Event ingress
# --------------------------------------------------------------------------- #

@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str | None = Header(default=None),
):
    """Primary trigger: GitHub `issues` events.

    Signature verification is mandatory - this endpoint can spend money, so an
    unauthenticated caller must never be able to reach the dispatcher.
    """
    raw = await request.body()
    if not verify_signature(settings.github_webhook_secret, raw, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="invalid webhook signature")

    payload = json.loads(raw)

    if x_github_event == "ping":
        return {"ok": True, "pong": True}
    if x_github_event != "issues":
        return {"ok": True, "ignored": x_github_event}

    # Return fast; GitHub times out webhook deliveries after 10s and the dispatch path
    # makes several outbound API calls.
    background.add_task(_handle_issue_event, payload)
    return JSONResponse({"ok": True, "queued": True}, status_code=202)


def _handle_issue_event(payload: dict) -> None:
    try:
        result = autopilot.handle_issue_event(payload)
        log.info("webhook handled: %s", result)
    except Exception:
        log.exception("webhook handling failed")


@app.post("/api/reconcile")
def reconcile():
    """Manual kick of the control loop (also runs every POLL_INTERVAL_SECONDS)."""
    return autopilot.reconcile_once()


@app.post("/api/recover")
def recover():
    """Rebuild state from in-flight Devin sessions after a state-store loss."""
    return autopilot.recover_from_devin()


@app.post("/api/backfill")
def backfill():
    """Secondary trigger: sweep GitHub for labeled issues we have not claimed yet.

    This is the path that makes the system robust without public ingress - if the webhook
    is missed, dropped, or the service was down, the next sweep still picks the work up.
    """
    issues = GitHubClient().list_open_issues(label=settings.autofix_label)
    results = autopilot.ingest_all(issues)
    accepted = sum(1 for r in results if r.get("accepted"))
    return {"scanned": len(issues), "newly_claimed": accepted, "results": results}


# --------------------------------------------------------------------------- #
# Observability
# --------------------------------------------------------------------------- #

@app.get("/healthz")
def healthz():
    return {"ok": True, "repo": settings.github_repo, "dry_run": settings.dry_run}


@app.get("/api/metrics")
def api_metrics():
    return metrics.summary()


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    return metrics.prometheus()


@app.get("/api/remediations")
def api_remediations():
    return metrics.table_rows()


@app.get("/api/events")
def api_events():
    return db.recent_events(200)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "m": metrics.summary(),
            "rows": metrics.table_rows(),
            "events": db.recent_events(40),
            "settings": settings,
        },
    )
