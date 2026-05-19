"""Deterministic GitHub issue-to-PR planning helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .goals import Goal
from .plans import ActionStep, PlanProposal
from .state import WorldState
from .tools import Secret, ToolRegistry


@dataclass(frozen=True)
class GitHubIssuePlanConfig:
    """Inputs for a bounded GitHub issue remediation plan."""

    repo: str
    issue_number: int
    path: str
    base_branch: str
    branch: str
    new_content: str
    token: Secret | None = None
    commit_message: str | None = None
    pr_title: str | None = None
    pr_body: str | None = None
    idempotency_key: str | None = None
    check_ci: bool = False
    ci_ref: str | None = None

    def __post_init__(self) -> None:
        for name in ("repo", "path", "base_branch", "branch", "new_content"):
            if not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if self.issue_number < 1:
            raise ValueError("issue_number must be >= 1")


class GitHubIssuePlanProvider:
    """Plan GitHub REST tool steps from observed issue and file state.

    The provider deliberately performs no network or tool calls. The first
    proposal observes the issue and target file through the normal transaction
    path. Once those facts are present in WorldState, the second proposal uses
    that evidence to create a branch, update the file with an optimistic guard,
    and open a PR with an idempotency marker.
    """

    _OBSERVE_TOOLS = frozenset({"github_read_issue", "github_get_file"})
    _PR_TOOLS = frozenset({"github_create_branch", "github_update_file", "github_open_pr"})

    def __init__(self, config: GitHubIssuePlanConfig) -> None:
        self.config = config
        self.calls = 0

    def propose(self, goal: Goal, state: WorldState, registry: ToolRegistry) -> list[PlanProposal]:
        self.calls += 1
        available = set(registry.names())
        issue = state.facts.get("github_issue")
        file_data = state.facts.get("github_file")

        if not isinstance(issue, dict) or not isinstance(file_data, dict):
            if not self._OBSERVE_TOOLS.issubset(available):
                return []
            return [self._observe_proposal()]

        required = set(self._PR_TOOLS)
        if self.config.check_ci:
            required.add("github_check_ci_status")
        if not required.issubset(available):
            return []
        return [self._pr_proposal(issue, file_data)]

    def _observe_proposal(self) -> PlanProposal:
        token_args = self._token_args()
        steps = [
            ActionStep(
                "github_read_issue",
                {
                    "repo": self.config.repo,
                    "issue_number": self.config.issue_number,
                    **token_args,
                },
                "Read the GitHub issue before planning a code change.",
            ),
            ActionStep(
                "github_get_file",
                {
                    "repo": self.config.repo,
                    "path": self.config.path,
                    "ref": self.config.base_branch,
                    **token_args,
                },
                "Read the target file so the update can use an optimistic guard.",
            ),
        ]
        if self.config.check_ci:
            steps.append(
                ActionStep(
                    "github_check_ci_status",
                    {
                        "repo": self.config.repo,
                        "ref": self.config.ci_ref or self.config.branch,
                        **token_args,
                    },
                    "Check CI status for the branch after opening the PR.",
                )
            )
        return PlanProposal(
            steps=steps,
            rationale="Observe the GitHub issue and target file before making a consequential change.",
            estimated_cost=0.1,
            expected_benefit=0.4,
        )

    def _pr_proposal(self, issue: dict[str, Any], file_data: dict[str, Any]) -> PlanProposal:
        token_args = self._token_args()
        issue_title = str(issue.get("title") or f"Issue #{self.config.issue_number}")
        expected_previous = str(file_data.get("content", ""))
        idempotency_key = self.config.idempotency_key or self._default_idempotency_key()
        steps = [
            ActionStep(
                "github_create_branch",
                {
                    "repo": self.config.repo,
                    "branch": self.config.branch,
                    "base": self.config.base_branch,
                    **token_args,
                },
                "Create a bounded working branch for the issue.",
            ),
            ActionStep(
                "github_update_file",
                {
                    "repo": self.config.repo,
                    "path": self.config.path,
                    "branch": self.config.branch,
                    "content": self.config.new_content,
                    "message": self.config.commit_message or f"Fix GitHub issue #{self.config.issue_number}",
                    "expected_previous": expected_previous,
                    **token_args,
                },
                "Apply the proposed file update with expected_previous protection.",
            ),
            ActionStep(
                "github_open_pr",
                {
                    "repo": self.config.repo,
                    "title": self.config.pr_title or f"Fix #{self.config.issue_number}: {issue_title}",
                    "body": self.config.pr_body or self._default_pr_body(issue),
                    "head": self.config.branch,
                    "base": self.config.base_branch,
                    "idempotency_key": idempotency_key,
                    **token_args,
                },
                "Open an idempotent pull request for human review.",
                idempotency_key=idempotency_key,
            ),
        ]
        return PlanProposal(
            steps=steps,
            rationale="Use observed issue and file state to update a branch and open a PR.",
            estimated_cost=0.5,
            expected_benefit=1.0,
        )

    def _token_args(self) -> dict[str, Secret]:
        return {"token": self.config.token} if self.config.token is not None else {}

    def _default_idempotency_key(self) -> str:
        safe_path = self.config.path.replace("/", "-")
        safe_branch = self.config.branch.replace("/", "-")
        return f"github-issue-{self.config.issue_number}-{safe_path}-{safe_branch}"

    def _default_pr_body(self, issue: dict[str, Any]) -> str:
        issue_url = str(issue.get("html_url") or "")
        lines = [
            f"Fixes #{self.config.issue_number}.",
            "",
            "Generated by Leos GitHub issue dry-run orchestration.",
        ]
        if issue_url:
            lines.extend(["", f"Issue: {issue_url}"])
        return "\n".join(lines)
