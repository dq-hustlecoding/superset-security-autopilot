"""Minimal GitHub REST client: read issues, label them, comment results, find PRs."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import httpx

from .config import settings


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token: str | None = None, repo: str | None = None) -> None:
        self.token = token or settings.github_token
        self.repo = repo or settings.github_repo
        self.base = f"{settings.github_api_base}/repos/{self.repo}"

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        with httpx.Client(timeout=45) as client:
            resp = client.request(method, url, headers=self._headers, **kwargs)
        if resp.status_code >= 400:
            raise GitHubError(f"{method} {url} -> {resp.status_code}: {resp.text[:400]}")
        return resp.json() if resp.content else None

    # --- issues ---------------------------------------------------------- #

    def list_open_issues(self, label: str | None = None) -> list[dict]:
        params: dict[str, Any] = {"state": "open", "per_page": 100}
        if label:
            params["labels"] = label
        issues = self._request("GET", f"{self.base}/issues", params=params)
        # The issues endpoint also returns PRs; filter them out.
        return [i for i in issues if "pull_request" not in i]

    def get_issue(self, number: int) -> dict:
        return self._request("GET", f"{self.base}/issues/{number}")

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        return self._request(
            "POST", f"{self.base}/issues",
            json={"title": title, "body": body, "labels": labels},
        )

    def comment(self, number: int, body: str) -> dict:
        return self._request("POST", f"{self.base}/issues/{number}/comments", json={"body": body})

    def add_labels(self, number: int, labels: list[str]) -> Any:
        return self._request("POST", f"{self.base}/issues/{number}/labels", json={"labels": labels})

    def remove_label(self, number: int, label: str) -> None:
        try:
            self._request("DELETE", f"{self.base}/issues/{number}/labels/{label}")
        except GitHubError:
            pass  # label was not present

    def ensure_labels(self, labels: dict[str, tuple[str, str]]) -> None:
        """labels: {name: (color, description)}"""
        for name, (color, description) in labels.items():
            try:
                self._request(
                    "POST", f"{self.base}/labels",
                    json={"name": name, "color": color, "description": description},
                )
            except GitHubError:
                pass  # already exists

    # --- pull requests --------------------------------------------------- #

    def find_pr_referencing(self, issue_number: int) -> str | None:
        """Fallback PR discovery when Devin's structured output omits the PR URL."""
        prs = self._request("GET", f"{self.base}/pulls", params={"state": "all", "per_page": 50})
        needle = f"#{issue_number}"
        for pr in prs:
            haystack = f"{pr.get('title', '')} {pr.get('body') or ''} {pr.get('head', {}).get('ref', '')}"
            if needle in haystack or f"issue-{issue_number}" in haystack:
                return pr["html_url"]
        return None


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Validate GitHub's X-Hub-Signature-256 header (HMAC-SHA256)."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
