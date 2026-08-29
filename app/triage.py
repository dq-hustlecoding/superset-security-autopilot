"""Triage: decide *whether* and *how* to spend a Devin session on a finding.

This module is the cost-control layer. Not every security finding deserves an
autonomous agent: some have no upstream patch, some are majors that need a human
architectural decision. Sending those to Devin burns ACUs and produces PRs nobody merges.

Triage runs before dispatch and produces one of:
  - a Playbook (finding is a good autonomous-fix candidate), or
  - a skip decision with a machine-readable reason that gets written back to the issue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Structured metadata block the scanner embeds in every issue body.
# Keeping the contract explicit means triage never has to guess from prose.
META_RE = re.compile(r"<!--\s*autopilot:(?P<json>\{.*?\})\s*-->", re.DOTALL)


@dataclass(frozen=True)
class Decision:
    dispatch: bool
    playbook: str
    finding_type: str
    severity: str
    reason: str = ""


def parse_metadata(issue_body: str) -> dict:
    import json

    match = META_RE.search(issue_body or "")
    if not match:
        return {}
    try:
        return json.loads(match.group("json"))
    except json.JSONDecodeError:
        return {}


def triage(issue: dict) -> Decision:
    meta = parse_metadata(issue.get("body") or "")
    finding_type = meta.get("finding_type", "unknown")
    severity = (meta.get("severity") or "LOW").upper()

    # 1. Upstream has no patch yet -> an agent cannot fix it. Do not burn a session.
    if finding_type == "dependency_cve" and not meta.get("fixed_version"):
        return Decision(
            dispatch=False,
            playbook="none",
            finding_type=finding_type,
            severity=severity,
            reason=(
                "No fixed upstream version is published for this advisory yet. "
                "Autopilot will re-evaluate on the next scan instead of opening a speculative PR."
            ),
        )

    # 2. A major-version jump on a RUNTIME dependency is an architectural decision with
    #    production blast radius, so a human owns it. The same jump on dev-only tooling
    #    (pip, pytest, build tools) is low risk and worth automating - the blast radius is CI.
    #    Encoding that distinction is the difference between an agent that saves time and one
    #    that generates PRs nobody dares to merge.
    if (
        finding_type == "dependency_cve"
        and meta.get("is_major_bump")
        and meta.get("is_runtime_dependency")
    ):
        return Decision(
            dispatch=False,
            playbook="none",
            finding_type=finding_type,
            severity=severity,
            reason=(
                "Remediation requires a major version upgrade of a runtime dependency "
                f"({meta.get('package')} {meta.get('current_version')} -> "
                f"{meta.get('fixed_version')}). That is a breaking-change decision with "
                "production blast radius, so an engineer should own it rather than an agent. "
                "Escalated for human triage."
            ),
        )

    if finding_type == "dependency_cve":
        return Decision(True, "dependency_bump", finding_type, severity)

    if finding_type == "static_analysis":
        return Decision(True, "static_analysis_fix", finding_type, severity)

    return Decision(True, "generic_fix", finding_type, severity)


# --------------------------------------------------------------------------- #
# Prompt construction
# --------------------------------------------------------------------------- #

_COMMON_RULES = """
Operating rules (this session is driven by an automated pipeline, no human is watching):
- Work only inside the repository {repo}. Branch from the default branch.
- Keep the change minimal and reviewable. Do not reformat unrelated code.
- Do NOT silence the finding with a suppression comment (`# noqa`, `# nosec`, ignore-lists).
  Suppressions are what created this backlog in the first place. Fix the root cause.
- Verify your work before opening the PR, then open ONE pull request whose body starts
  with `Fixes #{issue_number}`.
- The PR body must explain the reasoning behind the fix, not just what changed.
- If you conclude the correct action is "no change", do not open a PR. Report that instead.
- Return the structured JSON output describing exactly what you did.
"""

_DEPENDENCY_BUMP = """
You are remediating a known vulnerable dependency in {repo}.

Advisory: {advisory}
Package: {package}
Currently pinned: {current_version}
Minimum safe version: {fixed_version}

Task:
1. Find every place this pin is declared (requirements/*.txt, pyproject.toml, constraints files,
   lockfiles). Update all of them consistently - a partial bump leaves the CVE open.
2. Read the upstream changelog between the pinned and target version and identify any breaking
   change that affects how {repo} uses this package. Search the codebase for those usages.
3. If a breaking change affects this codebase, fix the call sites as part of the same PR.
4. Verify: confirm the dependency set still resolves, and run the narrowest relevant test
   selection. Do not run the entire test suite - it is slow and not needed to prove this change.

{common_rules}
"""

_STATIC_ANALYSIS = """
You are remediating a static security-analysis finding in {repo}.

Rule: {rule_id} ({rule_name}) - severity {severity}
Scanner: {scanner}

Reported locations:
{locations}

Task:
1. Open each reported location and determine the ACTUAL intent of the code. This matters more
   than the rule text: the correct remediation differs depending on whether the flagged code is
   used for a security boundary or for something benign like a cache key or a fingerprint.
2. For each site, choose the appropriate fix:
   - If the construct is genuinely used for security, replace it with a secure equivalent and
     make sure you handle every caller and any persisted/serialized values that depend on it.
   - If it is provably NOT used for security, make that explicit in code (for example by using
     an API that declares the non-security intent) rather than suppressing the warning, and add
     a short comment explaining why it is safe.
3. Do not apply one blanket transformation across all sites. Justify each decision individually
   in the PR body, site by site.
4. Verify: re-run the scanner on the changed files and confirm the finding is gone, and run the
   narrowest relevant test selection for the modules you touched.

{common_rules}
"""

_GENERIC = """
You are remediating an engineering-quality issue in {repo}.

Issue #{issue_number}: {issue_title}

{issue_body}

Task: implement the smallest correct change that resolves the issue, verify it, and open a PR.

{common_rules}
"""


def build_prompt(issue: dict, decision: Decision, repo: str) -> str:
    meta = parse_metadata(issue.get("body") or "")
    common = _COMMON_RULES.format(repo=repo, issue_number=issue["number"])

    if decision.playbook == "dependency_bump":
        return _DEPENDENCY_BUMP.format(
            repo=repo,
            advisory=meta.get("advisory", "unknown"),
            package=meta.get("package", "unknown"),
            current_version=meta.get("current_version", "unknown"),
            fixed_version=meta.get("fixed_version", "unknown"),
            common_rules=common,
        ).strip()

    if decision.playbook == "static_analysis_fix":
        locations = "\n".join(
            f"  - {loc}" for loc in meta.get("locations", [])
        ) or "  - see the issue body"
        return _STATIC_ANALYSIS.format(
            repo=repo,
            rule_id=meta.get("rule_id", "unknown"),
            rule_name=meta.get("rule_name", "unknown"),
            severity=decision.severity,
            scanner=meta.get("scanner", "bandit"),
            locations=locations,
            common_rules=common,
        ).strip()

    return _GENERIC.format(
        repo=repo,
        issue_number=issue["number"],
        issue_title=issue.get("title", ""),
        issue_body=(issue.get("body") or "")[:2000],
        common_rules=common,
    ).strip()
