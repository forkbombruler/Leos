"""GitHub REST API client for bounded software-engineering workflows."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote, urlencode

from .errors import LeosError

BODY_PREVIEW_LIMIT = 512
DEFAULT_BASE_URL = "https://api.github.com"
PROTECTED_BRANCHES = {"main", "master", "trunk", "release"}


class GitHubAPIError(LeosError):
    """Structured GitHub API failure with redacted response context."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_body_preview: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.response_body_preview = response_body_preview

    def __str__(self) -> str:
        if self.status_code is None:
            return self.message
        return f"{self.message} (status={self.status_code})"


class GitHubRateLimitError(GitHubAPIError):
    """GitHub rate limit was exhausted."""


class GitHubConflictError(GitHubAPIError):
    """GitHub rejected a write due to conflict or optimistic guard mismatch."""


class GitHubNotFoundError(GitHubAPIError):
    """GitHub resource was not found."""


class GitHubAuthError(GitHubAPIError):
    """GitHub authentication or authorization failed."""


@dataclass(frozen=True)
class GitHubHTTPResponse:
    status_code: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


class GitHubTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHTTPResponse: ...


class UrllibGitHubTransport:
    """urllib-based GitHub transport. It never logs headers or request bodies."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHTTPResponse:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
                return GitHubHTTPResponse(
                    status_code=int(response.status),
                    body=response.read(),
                    headers=dict(response.headers.items()),
                )
        except urllib.error.HTTPError as exc:
            return GitHubHTTPResponse(
                status_code=int(exc.code),
                body=exc.read(),
                headers=dict(exc.headers.items()) if exc.headers else {},
            )
        except urllib.error.URLError as exc:
            raise GitHubAPIError(f"GitHub request failed: {_safe_message(str(exc))}") from exc


class GitHubRESTClient:
    """Small GitHub REST client implementing the GitHubClient protocol."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: GitHubTransport | None = None,
        timeout_seconds: float = 30.0,
        user_agent: str = "leos-agent/0.1",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.transport = transport or UrllibGitHubTransport()
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

    def read_issue(self, repo: str, issue_number: int, token: str | None = None) -> dict[str, Any]:
        owner, name = parse_repo(repo)
        data = self._request_json("GET", f"/repos/{owner}/{name}/issues/{issue_number}", token=token)
        return {
            "repo": repo,
            "number": data.get("number", issue_number),
            "title": data.get("title", ""),
            "body": data.get("body", ""),
            "state": data.get("state", "unknown"),
            "html_url": data.get("html_url", ""),
        }

    def create_branch(self, repo: str, branch: str, base: str, token: str | None = None) -> dict[str, Any]:
        owner, name = parse_repo(repo)
        _validate_branch(branch)
        _validate_branch(base)
        base_ref = self._request_json("GET", f"/repos/{owner}/{name}/git/ref/heads/{_quote_path(base)}", token=token)
        base_sha = str(base_ref.get("object", {}).get("sha", ""))
        if not base_sha:
            raise GitHubAPIError("GitHub base branch response did not include a SHA")
        try:
            created = self._request_json(
                "POST",
                f"/repos/{owner}/{name}/git/refs",
                token=token,
                json_body={"ref": f"refs/heads/{branch}", "sha": base_sha},
            )
            return {
                "repo": repo,
                "branch": branch,
                "base": base,
                "sha": str(created.get("object", {}).get("sha", base_sha)),
                "already_exists": False,
            }
        except GitHubAPIError as exc:
            if exc.status_code != 422:
                raise
        existing = self._request_json(
            "GET",
            f"/repos/{owner}/{name}/git/ref/heads/{_quote_path(branch)}",
            token=token,
        )
        return {
            "repo": repo,
            "branch": branch,
            "base": base,
            "sha": str(existing.get("object", {}).get("sha", base_sha)),
            "already_exists": True,
        }

    def delete_branch(self, repo: str, branch: str, token: str | None = None) -> None:
        owner, name = parse_repo(repo)
        _validate_branch(branch)
        if branch in PROTECTED_BRANCHES:
            raise GitHubConflictError(f"Refusing to delete protected branch '{branch}'")
        try:
            self._request_json("DELETE", f"/repos/{owner}/{name}/git/refs/heads/{_quote_path(branch)}", token=token)
        except GitHubNotFoundError:
            return

    def get_file(self, repo: str, path: str, ref: str, token: str | None = None) -> dict[str, Any]:
        owner, name = parse_repo(repo)
        _validate_path(path)
        _validate_ref(ref)
        query = urlencode({"ref": ref})
        data = self._request_json("GET", f"/repos/{owner}/{name}/contents/{_quote_path(path)}?{query}", token=token)
        encoded = str(data.get("content", "")).replace("\n", "")
        encoding = str(data.get("encoding", ""))
        if encoding != "base64":
            raise GitHubAPIError("GitHub file content was not base64 encoded")
        try:
            content = base64.b64decode(encoded).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GitHubAPIError("GitHub file content could not be decoded as UTF-8") from exc
        return {
            "repo": repo,
            "path": path,
            "ref": ref,
            "content": content,
            "sha": data.get("sha", ""),
            "encoding": "base64",
        }

    def update_file(
        self,
        repo: str,
        path: str,
        branch: str,
        content: str,
        message: str,
        *,
        expected_sha: str | None = None,
        expected_previous: str | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        owner, name = parse_repo(repo)
        _validate_path(path)
        _validate_branch(branch)
        if not message:
            raise GitHubAPIError("GitHub update_file requires a non-empty commit message")
        if expected_sha is None and expected_previous is None:
            raise GitHubConflictError("expected_sha or expected_previous is required")
        previous: dict[str, Any] | None = None
        sha = expected_sha
        if expected_previous is not None:
            previous = self.get_file(repo, path, branch, token=token)
            if previous.get("content") != expected_previous:
                raise GitHubConflictError("expected_previous mismatch")
            sha = str(previous.get("sha", ""))
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        body: dict[str, Any] = {
            "message": message,
            "content": encoded,
            "branch": branch,
        }
        if sha:
            body["sha"] = sha
        data = self._request_json(
            "PUT",
            f"/repos/{owner}/{name}/contents/{_quote_path(path)}",
            token=token,
            json_body=body,
        )
        return {
            "repo": repo,
            "path": path,
            "branch": branch,
            "sha": data.get("content", {}).get("sha", ""),
            "commit_sha": data.get("commit", {}).get("sha", ""),
            "previous": previous,
        }

    def open_pr(
        self,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
        *,
        idempotency_key: str | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        owner, name = parse_repo(repo)
        _validate_branch(head)
        _validate_branch(base)
        marker = _idempotency_marker(idempotency_key)
        if idempotency_key:
            query = urlencode({"state": "open", "head": f"{owner}:{head}", "base": base})
            existing = self._request_json("GET", f"/repos/{owner}/{name}/pulls?{query}", token=token)
            if isinstance(existing, list):
                for pr in existing:
                    if isinstance(pr, dict) and marker and marker in str(pr.get("body", "")):
                        return _pr_payload(repo, pr, idempotency_key=idempotency_key, already_exists=True)
        full_body = body
        if marker and marker not in full_body:
            full_body = f"{body}\n\n{marker}"
        created = self._request_json(
            "POST",
            f"/repos/{owner}/{name}/pulls",
            token=token,
            json_body={"title": title, "body": full_body, "head": head, "base": base},
        )
        return _pr_payload(repo, created, idempotency_key=idempotency_key, already_exists=False)

    def close_pr(self, repo: str, pr_number: int, token: str | None = None) -> None:
        owner, name = parse_repo(repo)
        self._request_json(
            "PATCH",
            f"/repos/{owner}/{name}/pulls/{pr_number}",
            token=token,
            json_body={"state": "closed"},
        )

    def comment(self, repo: str, issue_number: int, body: str, token: str | None = None) -> dict[str, Any]:
        owner, name = parse_repo(repo)
        data = self._request_json(
            "POST",
            f"/repos/{owner}/{name}/issues/{issue_number}/comments",
            token=token,
            json_body={"body": body},
        )
        return {
            "repo": repo,
            "id": data.get("id"),
            "issue_number": issue_number,
            "html_url": data.get("html_url", ""),
        }

    def delete_comment(self, repo: str, comment_id: int, token: str | None = None) -> None:
        owner, name = parse_repo(repo)
        try:
            self._request_json("DELETE", f"/repos/{owner}/{name}/issues/comments/{comment_id}", token=token)
        except GitHubNotFoundError:
            return

    def ci_status(self, repo: str, ref: str, token: str | None = None) -> dict[str, Any]:
        owner, name = parse_repo(repo)
        _validate_ref(ref)
        data = self._request_json("GET", f"/repos/{owner}/{name}/commits/{quote(ref, safe='')}/status", token=token)
        state = str(data.get("state", "unknown"))
        if state not in {"success", "failure", "pending", "error"}:
            state = "unknown"
        return {
            "repo": repo,
            "ref": ref,
            "state": state,
            "statuses": data.get("statuses", []),
        }

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> Any:
        body = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        response = self.transport.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            body=body,
            timeout_seconds=self.timeout_seconds,
        )
        if not 200 <= response.status_code < 300:
            self._raise_for_response(response, token=token)
        if not response.body:
            return {}
        try:
            return json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubAPIError("GitHub response was not valid JSON", status_code=response.status_code) from exc

    @staticmethod
    def _raise_for_response(response: GitHubHTTPResponse, *, token: str | None) -> None:
        preview = _body_preview(response.body, token=token)
        message = _extract_error_message(preview)
        status = response.status_code
        remaining = _header(response.headers, "x-ratelimit-remaining")
        if status == 403 and remaining == "0":
            raise GitHubRateLimitError(
                message or "GitHub rate limit exceeded", status_code=status, response_body_preview=preview
            )
        if status in {401, 403}:
            raise GitHubAuthError(
                message or "GitHub authentication failed", status_code=status, response_body_preview=preview
            )
        if status == 404:
            raise GitHubNotFoundError(
                message or "GitHub resource not found", status_code=status, response_body_preview=preview
            )
        if status == 409:
            raise GitHubConflictError(message or "GitHub conflict", status_code=status, response_body_preview=preview)
        raise GitHubAPIError(message or "GitHub API request failed", status_code=status, response_body_preview=preview)


def parse_repo(repo: str) -> tuple[str, str]:
    if "://" in repo:
        raise ValueError("repo must be owner/name, not a URL")
    if repo.startswith("/") or repo.endswith("/") or ".." in repo:
        raise ValueError("repo must be a safe owner/name")
    parts = repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("repo must be owner/name")
    return quote(parts[0], safe=""), quote(parts[1], safe="")


def _validate_branch(branch: str) -> None:
    if not branch or branch.startswith("/") or ".." in branch:
        raise GitHubAPIError("Unsafe GitHub branch name")


def _validate_ref(ref: str) -> None:
    if not ref or ref.startswith("/") or ".." in ref:
        raise GitHubAPIError("Unsafe GitHub ref")


def _validate_path(path: str) -> None:
    if not path or path.startswith("/") or ".." in path.split("/"):
        raise GitHubAPIError("Unsafe GitHub path")


def _quote_path(path: str) -> str:
    return quote(path, safe="/")


def _body_preview(body: bytes, *, token: str | None) -> str:
    try:
        preview = body[:BODY_PREVIEW_LIMIT].decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        preview = "<unreadable response body>"
    if token:
        preview = preview.replace(token, "<redacted>")
    return preview


def _safe_message(message: str) -> str:
    return message.replace("\n", " ")[:BODY_PREVIEW_LIMIT]


def _extract_error_message(preview: str) -> str:
    try:
        data = json.loads(preview)
    except json.JSONDecodeError:
        return preview
    if isinstance(data, dict):
        return str(data.get("message", preview))
    return preview


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _idempotency_marker(idempotency_key: str | None) -> str | None:
    if not idempotency_key:
        return None
    return f"<!-- leos-idempotency-key: {idempotency_key} -->"


def _pr_payload(
    repo: str,
    data: Mapping[str, Any],
    *,
    idempotency_key: str | None,
    already_exists: bool,
) -> dict[str, Any]:
    return {
        "repo": repo,
        "number": data.get("number"),
        "title": data.get("title", ""),
        "state": data.get("state", "unknown"),
        "html_url": data.get("html_url", ""),
        "idempotency_key": idempotency_key,
        "already_exists": already_exists,
    }
