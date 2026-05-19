"""Bounded GitHub tools for software-engineering agent workflows."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .credentials import CredentialError, CredentialVault, SecretHandle
from .enums import CompensationStrategy, Permission, Reversibility, RiskLevel
from .errors import DryRunFailed, LeosError, SecretBoundaryViolation
from .state import WorldState
from .tools import Secret, ToolResult, ToolSpec


class GitHubClient(Protocol):
    def read_issue(self, repo: str, issue_number: int, token: str | None = None) -> dict[str, Any]: ...

    def create_branch(self, repo: str, branch: str, base: str, token: str | None = None) -> dict[str, Any]: ...

    def delete_branch(self, repo: str, branch: str, token: str | None = None) -> None: ...

    def get_file(self, repo: str, path: str, ref: str, token: str | None = None) -> dict[str, Any]: ...

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
    ) -> dict[str, Any]: ...

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
    ) -> dict[str, Any]: ...

    def close_pr(self, repo: str, pr_number: int, token: str | None = None) -> None: ...

    def comment(self, repo: str, issue_number: int, body: str, token: str | None = None) -> dict[str, Any]: ...

    def delete_comment(self, repo: str, comment_id: int, token: str | None = None) -> None: ...

    def ci_status(self, repo: str, ref: str, token: str | None = None) -> dict[str, Any]: ...


@dataclass
class InMemoryGitHubClient:
    issues: dict[tuple[str, int], dict[str, Any]] = field(default_factory=dict)
    branches: dict[tuple[str, str], str] = field(default_factory=dict)
    files: dict[tuple[str, str, str], dict[str, str]] = field(default_factory=dict)
    prs: dict[tuple[str, int], dict[str, Any]] = field(default_factory=dict)
    comments: dict[int, dict[str, Any]] = field(default_factory=dict)
    ci: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    pr_idempotency: dict[tuple[str, str], int] = field(default_factory=dict)
    next_pr: int = 1
    next_comment: int = 1
    accepted_token_count: int = 0
    accepted_token_fingerprints: list[str] = field(default_factory=list)

    def _record_token(self, token: str | None) -> None:
        if token is not None:
            self.accepted_token_count += 1
            self.accepted_token_fingerprints.append(_token_fingerprint(token))

    def seed_issue(self, repo: str, issue_number: int, *, title: str, body: str) -> None:
        self.issues[(repo, issue_number)] = {"repo": repo, "number": issue_number, "title": title, "body": body}

    def seed_file(self, repo: str, branch: str, path: str, content: str) -> str:
        sha = _sha(content)
        self.files[(repo, branch, path)] = {"path": path, "content": content, "sha": sha}
        self.branches.setdefault((repo, branch), sha)
        return sha

    def read_issue(self, repo: str, issue_number: int, token: str | None = None) -> dict[str, Any]:
        self._record_token(token)
        return dict(self.issues[(repo, issue_number)])

    def create_branch(self, repo: str, branch: str, base: str, token: str | None = None) -> dict[str, Any]:
        self._record_token(token)
        base_sha = self.branches.get((repo, base), base)
        self.branches[(repo, branch)] = base_sha
        for (file_repo, file_branch, path), value in list(self.files.items()):
            if file_repo == repo and file_branch == base:
                self.files[(repo, branch, path)] = dict(value)
        return {"repo": repo, "branch": branch, "base": base, "sha": base_sha}

    def delete_branch(self, repo: str, branch: str, token: str | None = None) -> None:
        self._record_token(token)
        self.branches.pop((repo, branch), None)
        for key in list(self.files):
            if key[0] == repo and key[1] == branch:
                del self.files[key]

    def get_file(self, repo: str, path: str, ref: str, token: str | None = None) -> dict[str, Any]:
        self._record_token(token)
        return dict(self.files[(repo, ref, path)])

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
        self._record_token(token)
        key = (repo, branch, path)
        previous = self.files.get(key)
        if expected_sha is not None and (previous or {}).get("sha") != expected_sha:
            raise LeosError("expected_sha mismatch")
        if expected_previous is not None and (previous or {}).get("content", "") != expected_previous:
            raise LeosError("expected_previous mismatch")
        sha = _sha(content)
        self.files[key] = {"path": path, "content": content, "sha": sha}
        self.branches[(repo, branch)] = sha
        return {"repo": repo, "path": path, "branch": branch, "sha": sha, "previous": previous}

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
        self._record_token(token)
        if idempotency_key and (repo, idempotency_key) in self.pr_idempotency:
            number = self.pr_idempotency[(repo, idempotency_key)]
            return dict(self.prs[(repo, number)])
        number = self.next_pr
        self.next_pr += 1
        pr = {
            "repo": repo,
            "number": number,
            "title": title,
            "body": body,
            "head": head,
            "base": base,
            "state": "open",
            "idempotency_key": idempotency_key,
        }
        self.prs[(repo, number)] = pr
        if idempotency_key:
            self.pr_idempotency[(repo, idempotency_key)] = number
        return dict(pr)

    def close_pr(self, repo: str, pr_number: int, token: str | None = None) -> None:
        self._record_token(token)
        self.prs[(repo, pr_number)]["state"] = "closed"

    def comment(self, repo: str, issue_number: int, body: str, token: str | None = None) -> dict[str, Any]:
        self._record_token(token)
        comment_id = self.next_comment
        self.next_comment += 1
        comment = {"id": comment_id, "repo": repo, "issue_number": issue_number, "body": body}
        self.comments[comment_id] = comment
        return dict(comment)

    def delete_comment(self, repo: str, comment_id: int, token: str | None = None) -> None:
        self._record_token(token)
        self.comments.pop(comment_id, None)

    def ci_status(self, repo: str, ref: str, token: str | None = None) -> dict[str, Any]:
        self._record_token(token)
        return dict(self.ci.get((repo, ref), {"repo": repo, "ref": ref, "state": "unknown"}))


def _sha(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _token(arguments: Mapping[str, Any]) -> str | None:
    value = _token_secret(arguments)
    return value.unwrap() if value is not None else None


def _token_secret(arguments: Mapping[str, Any]) -> Secret | None:
    value = arguments.get("token")
    if value is None:
        return None
    if isinstance(value, Secret):
        return value
    raise SecretBoundaryViolation("GitHub token must be passed as Secret, not a plain string")


def _token_or_error(arguments: Mapping[str, Any]) -> tuple[str | None, ToolResult | None]:
    try:
        return _token(arguments), None
    except SecretBoundaryViolation as exc:
        return None, ToolResult(False, str(exc), error=exc)


def _token_with_secret_or_error(arguments: Mapping[str, Any]) -> tuple[str | None, Secret | None, ToolResult | None]:
    try:
        secret = _token_secret(arguments)
        return secret.unwrap() if secret is not None else None, secret, None
    except SecretBoundaryViolation as exc:
        return None, None, ToolResult(False, str(exc), error=exc)


def _require(arguments: Mapping[str, Any], *names: str) -> ToolResult | None:
    missing = [name for name in names if name not in arguments]
    if missing:
        return ToolResult(False, f"Missing required argument(s): {', '.join(missing)}", error=DryRunFailed("missing"))
    return None


class _GitHubToolBase:
    spec: ToolSpec

    def __init__(self, client: GitHubClient, credential_vault: CredentialVault | None = None) -> None:
        self.client = client
        self.credential_vault = credential_vault
        self._rollback_tokens: dict[str, str] = {}

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "No rollback side effect")

    def _remember_rollback_credential(
        self,
        token: str | None,
        token_secret: Secret | None,
        repo: object,
    ) -> dict[str, Any]:
        if token is None and token_secret is None:
            return {}
        if self.credential_vault is not None and token_secret is not None:
            handle = self.credential_vault.put(token_secret, scope=self._credential_scope(repo))
            return {"auth_handle": handle.to_dict()}
        token_id = str(uuid.uuid4())
        self._rollback_tokens[token_id] = str(token)
        return {"auth_token_id": token_id}

    def _rollback_auth_token(self, token: Mapping[str, Any]) -> tuple[str | None, ToolResult | None]:
        if "auth_handle" in token:
            if self.credential_vault is None:
                return None, ToolResult(False, "Credential vault is not available for rollback")
            try:
                handle = SecretHandle.from_dict(dict(token["auth_handle"]))
                secret = self.credential_vault.get(handle, scope=self._credential_scope(token.get("repo", "")))
            except (CredentialError, KeyError, TypeError, ValueError) as exc:
                return None, ToolResult(
                    False,
                    f"Rollback credential unavailable: {type(exc).__name__}",
                    error=exc if isinstance(exc, LeosError) else None,
                )
            return secret.unwrap(), None
        token_id = token.get("auth_token_id")
        if token_id is None:
            return None, None
        return self._rollback_tokens.pop(str(token_id), None), None

    @staticmethod
    def _credential_scope(repo: object) -> str:
        return f"github:{repo}"


def _rollback_token(**items: Any) -> dict[str, Any]:
    return {key: value for key, value in items.items() if value is not None}


def _tool_error(exc: LeosError) -> ToolResult:
    return ToolResult(False, str(exc), error=exc)


class GitHubReadIssueTool(_GitHubToolBase):
    spec = ToolSpec(
        name="github_read_issue",
        description="Read a GitHub issue.",
        permissions=(),
        default_risk=RiskLevel.LOW,
        secrets_allowed=True,
        input_schema={"type": "object", "required": ["repo", "issue_number"]},
        output_schema={"type": "object", "required": ["github_issue"]},
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return _require(arguments, "repo", "issue_number") or ToolResult(True, "Would read GitHub issue")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        token, token_secret, error = _token_with_secret_or_error(arguments)
        if error:
            return error
        try:
            issue = self.client.read_issue(str(arguments["repo"]), int(arguments["issue_number"]), token)
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(True, "Read GitHub issue", observed_state_delta={"github_issue": issue})


class GitHubCreateBranchTool(_GitHubToolBase):
    spec = ToolSpec(
        name="github_create_branch",
        description="Create a GitHub branch from a base ref.",
        permissions=(Permission.WRITE_FILES,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.REVERSIBLE,
        compensation_strategy=CompensationStrategy.UNDO,
        secrets_allowed=True,
        input_schema={"type": "object", "required": ["repo", "branch", "base"]},
        output_schema={"type": "object", "required": ["github_branch"]},
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return _require(arguments, "repo", "branch", "base") or ToolResult(True, "Would create GitHub branch")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        token, token_secret, error = _token_with_secret_or_error(arguments)
        if error:
            return error
        try:
            branch = self.client.create_branch(
                str(arguments["repo"]),
                str(arguments["branch"]),
                str(arguments["base"]),
                token,
            )
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(
            True,
            "Created GitHub branch",
            observed_state_delta={"github_branch": branch},
            rollback_token=_rollback_token(
                repo=arguments["repo"],
                branch=arguments["branch"],
                **self._remember_rollback_credential(token, token_secret, arguments["repo"]),
            ),
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        auth_token, error = self._rollback_auth_token(token)
        if error:
            return error
        try:
            self.client.delete_branch(str(token["repo"]), str(token["branch"]), auth_token)
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(True, "Deleted GitHub branch")


class GitHubGetFileTool(_GitHubToolBase):
    spec = ToolSpec(
        name="github_get_file",
        description="Read a file from GitHub.",
        permissions=(),
        default_risk=RiskLevel.LOW,
        secrets_allowed=True,
        input_schema={"type": "object", "required": ["repo", "path", "ref"]},
        output_schema={"type": "object", "required": ["github_file"]},
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return _require(arguments, "repo", "path", "ref") or ToolResult(True, "Would get GitHub file")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        token, error = _token_or_error(arguments)
        if error:
            return error
        try:
            data = self.client.get_file(str(arguments["repo"]), str(arguments["path"]), str(arguments["ref"]), token)
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(True, "Read GitHub file", observed_state_delta={"github_file": data})


class GitHubUpdateFileTool(_GitHubToolBase):
    spec = ToolSpec(
        name="github_update_file",
        description="Update a GitHub file with optimistic concurrency checks.",
        permissions=(Permission.WRITE_FILES,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.COMPENSATABLE,
        compensation_strategy=CompensationStrategy.COMPENSATE,
        secrets_allowed=True,
        input_schema={"type": "object", "required": ["repo", "path", "branch", "content", "message"]},
        output_schema={"type": "object", "required": ["github_file_updated"]},
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        required = _require(arguments, "repo", "path", "branch", "content", "message")
        if required:
            return required
        if "expected_sha" not in arguments and "expected_previous" not in arguments:
            return ToolResult(
                False, "expected_sha or expected_previous is required", error=DryRunFailed("missing guard")
            )
        return ToolResult(True, "Would update GitHub file")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        token, token_secret, error = _token_with_secret_or_error(arguments)
        if error:
            return error
        try:
            updated = self.client.update_file(
                str(arguments["repo"]),
                str(arguments["path"]),
                str(arguments["branch"]),
                str(arguments["content"]),
                str(arguments["message"]),
                expected_sha=str(arguments["expected_sha"]) if "expected_sha" in arguments else None,
                expected_previous=str(arguments["expected_previous"]) if "expected_previous" in arguments else None,
                token=token,
            )
        except LeosError as exc:
            return ToolResult(False, str(exc), error=exc)
        previous = updated.pop("previous", None)
        return ToolResult(
            True,
            "Updated GitHub file",
            observed_state_delta={"github_file_updated": updated},
            rollback_token={
                "repo": arguments["repo"],
                "path": arguments["path"],
                "branch": arguments["branch"],
                "previous": previous,
                **self._remember_rollback_credential(token, token_secret, arguments["repo"]),
            },
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        previous = token.get("previous")
        if isinstance(previous, dict):
            auth_token, error = self._rollback_auth_token(token)
            if error:
                return error
            try:
                current = self.client.get_file(
                    str(token["repo"]),
                    str(token["path"]),
                    str(token["branch"]),
                    auth_token,
                )
                self.client.update_file(
                    str(token["repo"]),
                    str(token["path"]),
                    str(token["branch"]),
                    str(previous.get("content", "")),
                    "rollback file update",
                    expected_sha=str(current["sha"]),
                    token=auth_token,
                )
            except LeosError as exc:
                return _tool_error(exc)
            return ToolResult(True, "Restored previous GitHub file content")
        return ToolResult(True, "No previous GitHub file content to restore")


class GitHubOpenPRTool(_GitHubToolBase):
    spec = ToolSpec(
        name="github_open_pr",
        description="Open a GitHub pull request.",
        permissions=(Permission.SEND_MESSAGE,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.COMPENSATABLE,
        compensation_strategy=CompensationStrategy.COMPENSATE,
        secrets_allowed=True,
        input_schema={"type": "object", "required": ["repo", "title", "body", "head", "base"]},
        output_schema={"type": "object", "required": ["github_pr"]},
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return _require(arguments, "repo", "title", "body", "head", "base") or ToolResult(True, "Would open GitHub PR")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        token, token_secret, error = _token_with_secret_or_error(arguments)
        if error:
            return error
        try:
            pr = self.client.open_pr(
                str(arguments["repo"]),
                str(arguments["title"]),
                str(arguments["body"]),
                str(arguments["head"]),
                str(arguments["base"]),
                idempotency_key=str(arguments["idempotency_key"]) if arguments.get("idempotency_key") else None,
                token=token,
            )
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(
            True,
            "Opened GitHub PR",
            observed_state_delta={"github_pr": pr},
            rollback_token=_rollback_token(
                repo=arguments["repo"],
                pr_number=pr["number"],
                **self._remember_rollback_credential(token, token_secret, arguments["repo"]),
            ),
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        auth_token, error = self._rollback_auth_token(token)
        if error:
            return error
        try:
            self.client.close_pr(str(token["repo"]), int(token["pr_number"]), auth_token)
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(True, "Closed GitHub PR")


class GitHubCommentTool(_GitHubToolBase):
    spec = ToolSpec(
        name="github_comment",
        description="Comment on a GitHub issue or pull request.",
        permissions=(Permission.SEND_MESSAGE,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.COMPENSATABLE,
        compensation_strategy=CompensationStrategy.COMPENSATE,
        secrets_allowed=True,
        input_schema={"type": "object", "required": ["repo", "issue_number", "body"]},
        output_schema={"type": "object", "required": ["github_comment"]},
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return _require(arguments, "repo", "issue_number", "body") or ToolResult(True, "Would post GitHub comment")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        token, token_secret, error = _token_with_secret_or_error(arguments)
        if error:
            return error
        try:
            comment = self.client.comment(
                str(arguments["repo"]), int(arguments["issue_number"]), str(arguments["body"]), token
            )
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(
            True,
            "Posted GitHub comment",
            observed_state_delta={"github_comment": comment},
            rollback_token=_rollback_token(
                repo=arguments["repo"],
                comment_id=comment["id"],
                **self._remember_rollback_credential(token, token_secret, arguments["repo"]),
            ),
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        auth_token, error = self._rollback_auth_token(token)
        if error:
            return error
        try:
            self.client.delete_comment(str(token["repo"]), int(token["comment_id"]), auth_token)
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(True, "Deleted GitHub comment")


class GitHubCheckCIStatusTool(_GitHubToolBase):
    spec = ToolSpec(
        name="github_check_ci_status",
        description="Check CI status for a GitHub ref.",
        permissions=(),
        default_risk=RiskLevel.LOW,
        secrets_allowed=True,
        input_schema={"type": "object", "required": ["repo", "ref"]},
        output_schema={"type": "object", "required": ["github_ci_status"]},
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return _require(arguments, "repo", "ref") or ToolResult(True, "Would check GitHub CI status")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        token, error = _token_or_error(arguments)
        if error:
            return error
        try:
            status = self.client.ci_status(str(arguments["repo"]), str(arguments["ref"]), token)
        except LeosError as exc:
            return _tool_error(exc)
        return ToolResult(True, "Checked GitHub CI status", observed_state_delta={"github_ci_status": status})
