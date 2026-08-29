#!/usr/bin/env python3
"""Render the dashboard to a standalone HTML file.

Same template the live service serves, without the web layer. Useful for attaching a
point-in-time report to a ticket, emailing a weekly summary, or publishing to a static
bucket where a VP will actually look at it.

    python demo/render_report.py [output.html]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jinja2 import Environment, FileSystemLoader  # noqa: E402

from app import db, metrics  # noqa: E402
from app.config import settings  # noqa: E402

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "data/report.html")


def main() -> None:
    db.init_db()
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).resolve().parent.parent / "app" / "templates")),
        autoescape=True,
    )
    html = env.get_template("dashboard.html").render(
        request=None,
        m=metrics.summary(),
        rows=metrics.table_rows(),
        events=db.recent_events(40),
        settings=settings,
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html)
    print(f"wrote {OUT} ({len(html)} bytes)")


if __name__ == "__main__":
    main()
