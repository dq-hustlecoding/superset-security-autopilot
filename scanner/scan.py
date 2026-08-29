#!/usr/bin/env python3
"""Security scanner -> GitHub issues.

This is the *event source* of the autopilot. It runs on a schedule (GitHub Actions cron,
or `docker compose run scanner`) against the Superset fork and turns raw scanner output
into deduplicated, machine-readable GitHub issues.

Two scanners, deliberately chosen because they represent the two shapes of security debt
every real codebase has:

  1. OSV.dev  - known CVEs in pinned dependencies (supply-chain risk)
  2. Bandit   - static security findings in first-party code (code risk)

Every issue body carries an `<!-- autopilot:{...} -->` metadata block. That contract is what
lets the orchestrator triage mechanically instead of parsing prose written for humans.

Usage:
    python scanner/scan.py --repo-path ../superset-src --github-repo owner/superset
    python scanner/scan.py --repo-path ../superset-src --github-repo owner/superset --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import httpx

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
GITHUB_API = "https://api.github.com"

AUTOFIX_LABEL = os.environ.get("AUTOFIX_LABEL", "devin-autofix")

PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)==([0-9][^\s;#]*)")

# Bandit rules worth an autonomous remediation. Anything else is noise for this demo:
# we would rather run a narrow, high-signal policy than open 266 issues on day one.
BANDIT_POLICY = {
    "B324": {"severity": "HIGH", "title": "Weak hash algorithm used where a secure hash is expected"},
    "B704": {"severity": "MEDIUM", "title": "Potential XSS via markupsafe.Markup on interpolated data"},
    "B310": {"severity": "MEDIUM", "title": "Unaudited urlopen allows unexpected URL schemes"},
}


# --------------------------------------------------------------------------- #
# Scanners
# --------------------------------------------------------------------------- #

def scan_dependencies(repo_path: Path) -> list[dict[str, Any]]:
    """Query OSV.dev for every pinned PyPI requirement in the repo."""
    pins: dict[tuple[str, str], list[str]] = defaultdict(list)
    for req_file in sorted(repo_path.glob("requirements/*.txt")):
        for line in req_file.read_text(errors="ignore").splitlines():
            match = PIN_RE.match(line.strip())
            if match:
                pins[(match.group(1), match.group(2))].append(
                    str(req_file.relative_to(repo_path))
                )

    if not pins:
        return []

    keys = list(pins)
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in keys]
    with httpx.Client(timeout=90) as client:
        resp = client.post(OSV_BATCH_URL, json={"queries": queries})
        resp.raise_for_status()
        results = resp.json()["results"]

        findings: list[dict] = []
        # OSV returns the same real-world vulnerability under several IDs (GHSA-*, PYSEC-*,
        # CVE-*) that alias each other. Filing one issue per ID would triple the backlog and
        # send three Devin sessions at the same bug, so collapse alias groups first.
        seen_aliases: dict[str, set[str]] = {}
        for (name, version), result in zip(keys, results):
            for vuln in result.get("vulns", []):
                detail = client.get(OSV_VULN_URL.format(vuln["id"])).json()
                ids = {vuln["id"], *detail.get("aliases", [])}

                group = seen_aliases.setdefault(name, set())
                if ids & group:
                    continue  # already represented by an earlier alias of the same advisory
                group |= ids

                fixed = _first_fixed_version(detail, name)
                # Prefer the CVE identifier as the canonical name; engineers recognise it.
                canonical = next((i for i in sorted(ids) if i.startswith("CVE-")), vuln["id"])
                findings.append({
                    "kind": "dependency_cve",
                    "package": name,
                    "current_version": version,
                    "fixed_version": fixed,
                    "advisory": canonical,
                    "osv_id": vuln["id"],
                    "aliases": sorted(ids - {canonical}),
                    "severity": _normalize_severity(
                        (detail.get("database_specific") or {}).get("severity", "UNKNOWN")
                    ),
                    "summary": detail.get("summary", ""),
                    "details": (detail.get("details") or "")[:1200],
                    "files": sorted(set(pins[(name, version)])),
                    "is_major_bump": _is_major_bump(version, fixed),
                    "is_runtime_dependency": any(
                        f.endswith("base.txt") for f in pins[(name, version)]
                    ),
                })
    return findings


SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _normalize_severity(value: str) -> str:
    value = (value or "UNKNOWN").upper()
    return "MODERATE" if value == "MEDIUM" else value


def rank(finding: dict) -> tuple:
    """Order the backlog the way a security team would: exploitable and fixable first.

    - severity first,
    - then runtime dependencies ahead of dev-only tooling,
    - then findings that actually have a patch available.
    """
    severity = SEVERITY_RANK.get(finding.get("severity", "UNKNOWN"), 4)
    runtime = 0 if finding.get("is_runtime_dependency") or finding["kind"] == "static_analysis" else 1
    fixable = 0 if (finding["kind"] == "static_analysis" or finding.get("fixed_version")) else 1
    return (severity, runtime, fixable)


def _first_fixed_version(detail: dict, package: str) -> str | None:
    for affected in detail.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if event.get("fixed"):
                    return event["fixed"]
    return None


def _is_major_bump(current: str, fixed: str | None) -> bool:
    if not fixed:
        return False
    try:
        return int(current.split(".")[0]) < int(fixed.split(".")[0])
    except (ValueError, IndexError):
        return False


def scan_static(repo_path: Path) -> list[dict[str, Any]]:
    """Run Bandit and group findings by rule, so one issue == one remediation unit."""
    target = repo_path / "superset"
    out = repo_path.parent / "bandit-report.json"
    subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-o", str(out), "-q"],
        check=False, capture_output=True,
    )
    if not out.exists():
        return []

    report = json.loads(out.read_text())
    grouped: dict[str, list[dict]] = defaultdict(list)
    for result in report.get("results", []):
        if result["test_id"] in BANDIT_POLICY:
            grouped[result["test_id"]].append(result)

    findings = []
    for rule_id, results in grouped.items():
        policy = BANDIT_POLICY[rule_id]
        findings.append({
            "kind": "static_analysis",
            "scanner": "bandit",
            "rule_id": rule_id,
            "rule_name": results[0]["test_name"],
            "severity": policy["severity"],
            "title": policy["title"],
            "count": len(results),
            "locations": [
                f"{r['filename'].split('/superset-src/')[-1]}:{r['line_number']}"
                for r in results
            ],
            "samples": [
                {
                    "location": f"{r['filename'].split('/superset-src/')[-1]}:{r['line_number']}",
                    "code": r["code"].strip(),
                    "issue_text": r["issue_text"],
                }
                for r in results
            ],
        })
    return findings


# --------------------------------------------------------------------------- #
# Issue rendering
# --------------------------------------------------------------------------- #

def fingerprint(finding: dict) -> str:
    if finding["kind"] == "dependency_cve":
        raw = f"dep:{finding['package']}:{finding['advisory']}"  # canonical CVE, alias-collapsed
    else:
        raw = f"static:{finding['rule_id']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def render_issue(finding: dict) -> tuple[str, str]:
    fp = fingerprint(finding)

    if finding["kind"] == "dependency_cve":
        aliases = ", ".join(finding["aliases"]) or "—"
        title = (
            f"[security] {finding['package']} {finding['current_version']} "
            f"is affected by {finding['advisory']}"
        )
        meta = {
            "fingerprint": fp,
            "finding_type": "dependency_cve",
            "severity": finding["severity"],
            "package": finding["package"],
            "current_version": finding["current_version"],
            "fixed_version": finding["fixed_version"],
            "advisory": finding["advisory"],
            "is_major_bump": finding["is_major_bump"],
            "is_runtime_dependency": finding["is_runtime_dependency"],
            "files": finding["files"],
        }
        body = f"""## Vulnerable dependency detected

**{finding['package']} {finding['current_version']}** is affected by **{finding['advisory']}**.

| | |
|---|---|
| Severity | `{finding['severity']}` |
| Advisory | {aliases} |
| Fixed in | `{finding['fixed_version'] or 'no patched release yet'}` |
| Declared in | {', '.join(f'`{f}`' for f in finding['files'])} |
| Scope | {'runtime dependency' if finding['is_runtime_dependency'] else 'development / tooling only'} |
| Also known as | {aliases} |
| Source | [OSV.dev](https://osv.dev/vulnerability/{finding['osv_id']}) |

### Summary
{finding['summary'] or '_No summary provided by the advisory._'}

<details>
<summary>Advisory details</summary>

{finding['details']}

</details>

### Definition of done
- [ ] Every declaration of this pin is updated to a patched version
- [ ] Upstream breaking changes between the two versions are assessed against this codebase
- [ ] Dependency resolution still succeeds

<!-- autopilot:{json.dumps(meta)} -->
"""
        return title, body

    # static analysis
    title = f"[security] {finding['rule_id']}: {finding['title']} ({finding['count']} sites)"
    meta = {
        "fingerprint": fp,
        "finding_type": "static_analysis",
        "severity": finding["severity"],
        "scanner": finding["scanner"],
        "rule_id": finding["rule_id"],
        "rule_name": finding["rule_name"],
        "locations": finding["locations"],
    }
    sample_blocks = "\n".join(
        f"**`{s['location']}`** — {s['issue_text']}\n\n```python\n{s['code']}\n```\n"
        for s in finding["samples"]
    )
    body = f"""## Static security finding

Bandit rule **{finding['rule_id']}** (`{finding['rule_name']}`) is triggered at
**{finding['count']} locations**, severity **{finding['severity']}**.

> Several of these sites are currently silenced with inline suppression comments.
> A suppression hides the finding from the scanner; it does not remove the risk.
> The correct remediation depends on what each call site is actually doing, so this needs
> per-site judgement rather than one blanket transformation.

### Affected locations
{sample_blocks}

### Definition of done
- [ ] Each site is assessed individually for whether the flagged construct guards a security boundary
- [ ] The right fix is applied per site, and the reasoning is recorded in the PR
- [ ] No finding is resolved by adding or keeping a suppression comment
- [ ] The scanner no longer reports {finding['rule_id']} on the changed files

<!-- autopilot:{json.dumps(meta)} -->
"""
    return title, body


# --------------------------------------------------------------------------- #
# GitHub publishing
# --------------------------------------------------------------------------- #

class Publisher:
    LABELS = {
        AUTOFIX_LABEL: ("0E8A16", "Queued for autonomous remediation by Devin"),
        "security": ("B60205", "Security finding"),
        "dependencies": ("0366D6", "Dependency related"),
        "automated-scan": ("5319E7", "Filed by the autopilot scanner"),
    }

    def __init__(self, repo: str, token: str) -> None:
        self.repo = repo
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.client = httpx.Client(timeout=45, headers=self.headers)

    def ensure_labels(self) -> None:
        for name, (color, description) in self.LABELS.items():
            self.client.post(
                f"{GITHUB_API}/repos/{self.repo}/labels",
                json={"name": name, "color": color, "description": description},
            )

    def existing_fingerprints(self) -> set[str]:
        """Dedupe against issues already filed, so re-running the scan is free."""
        found: set[str] = set()
        page = 1
        while True:
            resp = self.client.get(
                f"{GITHUB_API}/repos/{self.repo}/issues",
                params={"state": "all", "per_page": 100, "page": page,
                        "labels": "automated-scan"},
            )
            resp.raise_for_status()
            issues = resp.json()
            if not issues:
                break
            for issue in issues:
                match = re.search(r'"fingerprint":\s*"([0-9a-f]+)"', issue.get("body") or "")
                if match:
                    found.add(match.group(1))
            page += 1
        return found

    def create(self, title: str, body: str, labels: list[str]) -> dict:
        resp = self.client.post(
            f"{GITHUB_API}/repos/{self.repo}/issues",
            json={"title": title, "body": body, "labels": labels},
        )
        resp.raise_for_status()
        return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-path", required=True, help="Local checkout of the target repo")
    parser.add_argument("--github-repo", default=os.environ.get("GITHUB_REPO", ""))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-static", action="store_true")
    parser.add_argument("--skip-deps", action="store_true")
    parser.add_argument(
        "--max-issues", type=int, default=0,
        help="Only file the N highest-ranked findings. 0 = no limit. "
             "Rate-limits how much backlog the autopilot opens in a single run.",
    )
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    findings: list[dict] = []
    if not args.skip_deps:
        deps = scan_dependencies(repo_path)
        print(f"[scan] dependency findings: {len(deps)}", file=sys.stderr)
        findings += deps
    if not args.skip_static:
        static = scan_static(repo_path)
        print(f"[scan] static findings (policy-filtered rules): {len(static)}", file=sys.stderr)
        findings += static

    findings.sort(key=rank)
    if args.max_issues:
        findings = findings[: args.max_issues]
        print(f"[scan] capped to top {args.max_issues} finding(s) by rank", file=sys.stderr)

    rendered = [(f, *render_issue(f)) for f in findings]

    if args.dry_run or not args.github_repo:
        for finding, title, body in rendered:
            print(f"\n=== [{fingerprint(finding)}] {title}\n{body[:400]}...")
        print(f"\n[scan] {len(rendered)} issue(s) would be filed.", file=sys.stderr)
        return 0

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN is required to file issues", file=sys.stderr)
        return 1

    publisher = Publisher(args.github_repo, token)
    publisher.ensure_labels()
    already = publisher.existing_fingerprints()

    created = 0
    for finding, title, body in rendered:
        fp = fingerprint(finding)
        if fp in already:
            print(f"[scan] skip {fp} (already filed)", file=sys.stderr)
            continue
        labels = [AUTOFIX_LABEL, "security", "automated-scan"]
        if finding["kind"] == "dependency_cve":
            labels.append("dependencies")
        issue = publisher.create(title, body, labels)
        created += 1
        print(f"[scan] filed #{issue['number']}: {title}", file=sys.stderr)

    print(f"[scan] created {created} new issue(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
