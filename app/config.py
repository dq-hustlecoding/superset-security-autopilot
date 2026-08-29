"""Runtime configuration for the Superset Security Autopilot."""

from __future__ import annotations

import os
from pathlib import Path


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader so the control loop can run headless without pydantic."""
    env_file = Path(path)
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _PYDANTIC = True
except ImportError:  # headless mode: stdlib-only fallback
    _PYDANTIC = False

    class SettingsConfigDict(dict):  # type: ignore[no-redef]
        pass

    class BaseSettings:  # type: ignore[no-redef]
        """Tiny stand-in that reads annotated fields from the environment."""

        def __init__(self, **overrides: object) -> None:
            for name, annotation in type(self).__annotations__.items():
                default = getattr(type(self), name, None)
                raw = os.environ.get(name.upper(), overrides.get(name, default))
                setattr(self, name, _coerce(raw, annotation, default))


def _coerce(raw: object, annotation: object, default: object) -> object:
    if raw is None:
        return default
    if isinstance(default, bool) or annotation is bool:
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int) and not isinstance(default, bool):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    return raw


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Devin API ---
    devin_api_key: str = ""
    devin_org_id: str = ""
    devin_api_base: str = "https://api.devin.ai/v3"

    # --- GitHub ---
    github_token: str = ""
    github_repo: str = ""  # "owner/name"
    github_webhook_secret: str = "change-me"
    github_api_base: str = "https://api.github.com"

    # --- Autopilot policy ---
    autofix_label: str = "devin-autofix"
    max_concurrent_sessions: int = 3
    max_acu_per_session: int = 10
    poll_interval_seconds: int = 30

    # Hard ceiling on how many Devin sessions may be started in a rolling 24h window.
    # A scanner that suddenly reports 200 findings must not be able to run away with
    # the budget, so spend is bounded by policy rather than by the size of the backlog.
    daily_session_budget: int = 6


    # Session-level safety valve: sessions older than this are marked timed_out
    session_timeout_minutes: int = 90

    # Never call out to Devin/GitHub; used for local rehearsal of the pipeline.
    dry_run: bool = False

    db_path: str = "data/autopilot.db"


    # Cost model used for the "engineer hours saved" panel on the dashboard.
    # Deliberately conservative and configurable so a customer can plug in their own numbers.
    engineer_hours_per_finding: float = 1.5
    engineer_hourly_cost_usd: float = 95.0

    @property
    def repo_owner(self) -> str:
        return self.github_repo.split("/", 1)[0]

    @property
    def repo_name(self) -> str:
        return self.github_repo.split("/", 1)[1] if "/" in self.github_repo else ""


settings = Settings()
