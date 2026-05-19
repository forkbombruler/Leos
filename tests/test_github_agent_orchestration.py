from __future__ import annotations

import base64
import json
import unittest
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from leos_agent import (
    AgentKernel,
    AgentLoop,
    AgentLoopConfig,
    ApprovalGate,
    AuditLog,
    CausalGraph,
    GitHubCreateBranchTool,
    GitHubGetFileTool,
    GitHubHTTPResponse,
    GitHubIssuePlanConfig,
    GitHubIssuePlanProvider,
    GitHubOpenPRTool,
    GitHubReadIssueTool,
    GitHubRESTClient,
    GitHubUpdateFileTool,
    Goal,
    GoalEvaluationStatus,
    Permission,
    PlannerConfig,
    PolicyEngine,
    RiskLevel,
    Secret,
    ToolRegistry,
    WorldState,
)


class RoutingGitHubTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.pull_requests: list[dict[str, Any]] = []
        self.old_content = "# Demo\n"
        self.new_content = "# Demo\n\nFixes issue #42.\n"

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHTTPResponse:
        del timeout_seconds
        parsed = urlparse(url)
        self.calls.append(
            {
                "method": method,
                "path": parsed.path,
                "query": parsed.query,
                "headers": dict(headers),
                "body": body,
            }
        )
        if method == "GET" and parsed.path == "/repos/o/r/issues/42":
            return _json_response(
                {
                    "number": 42,
                    "title": "Fix documentation",
                    "body": "Update README",
                    "state": "open",
                    "html_url": "https://github.com/o/r/issues/42",
                }
            )
        if method == "GET" and parsed.path == "/repos/o/r/contents/README.md":
            sha = "branch-sha" if "agent%2Fissue-42" in parsed.query else "main-sha"
            return _json_response(
                {
                    "content": base64.b64encode(self.old_content.encode("utf-8")).decode("ascii"),
                    "encoding": "base64",
                    "sha": sha,
                }
            )
        if method == "GET" and parsed.path == "/repos/o/r/git/ref/heads/main":
            return _json_response({"object": {"sha": "main-sha"}})
        if method == "POST" and parsed.path == "/repos/o/r/git/refs":
            return _json_response({"object": {"sha": "main-sha"}}, status=201)
        if method == "PUT" and parsed.path == "/repos/o/r/contents/README.md":
            payload = json.loads((body or b"{}").decode("utf-8"))
            decoded = base64.b64decode(str(payload["content"]).encode("ascii")).decode("utf-8")
            if decoded != self.new_content:
                return _json_response({"message": "unexpected content"}, status=400)
            return _json_response({"content": {"sha": "new-sha"}, "commit": {"sha": "commit-sha"}})
        if method == "GET" and parsed.path == "/repos/o/r/pulls":
            return _json_response(self.pull_requests)
        if method == "POST" and parsed.path == "/repos/o/r/pulls":
            payload = json.loads((body or b"{}").decode("utf-8"))
            pr = {
                "number": 9,
                "title": payload["title"],
                "body": payload["body"],
                "state": "open",
                "html_url": "https://github.com/o/r/pull/9",
            }
            self.pull_requests.append(pr)
            return _json_response(pr, status=201)
        return _json_response({"message": f"unexpected route: {method} {parsed.path}"}, status=404)


def _json_response(payload: Any, *, status: int = 200) -> GitHubHTTPResponse:
    return GitHubHTTPResponse(status_code=status, body=json.dumps(payload).encode("utf-8"), headers={})


def _registry(client: GitHubRESTClient) -> ToolRegistry:
    registry = ToolRegistry()
    for tool in (
        GitHubReadIssueTool(client),
        GitHubGetFileTool(client),
        GitHubCreateBranchTool(client),
        GitHubUpdateFileTool(client),
        GitHubOpenPRTool(client),
    ):
        registry.register(tool)
    return registry


class GitHubAgentOrchestrationTests(unittest.TestCase):
    def _kernel(self, registry: ToolRegistry, audit: AuditLog) -> AgentKernel:
        return AgentKernel(
            registry=registry,
            policy=PolicyEngine(
                granted_permissions=(Permission.WRITE_FILES, Permission.SEND_MESSAGE),
                max_auto_risk=RiskLevel.MEDIUM,
            ),
            causal_model=CausalGraph(),
            audit_log=audit,
            approval_gate=ApprovalGate(lambda step: True),
            planner_config=PlannerConfig(max_risk=RiskLevel.MEDIUM),
        )

    def test_issue_to_pr_orchestration_runs_through_agent_loop(self) -> None:
        transport = RoutingGitHubTransport()
        client = GitHubRESTClient(transport=transport)
        audit = AuditLog()
        kernel = self._kernel(_registry(client), audit)
        provider = GitHubIssuePlanProvider(
            GitHubIssuePlanConfig(
                repo="o/r",
                issue_number=42,
                path="README.md",
                base_branch="main",
                branch="agent/issue-42",
                new_content=transport.new_content,
                token=Secret("ghp_test_secret"),
                idempotency_key="issue-42-readme",
            )
        )
        goal = Goal("Fix issue 42", ["PR opened"], stop_conditions=["PR opened or blocked"])

        result = AgentLoop(kernel, provider, config=AgentLoopConfig(max_iterations=2)).run(goal)

        self.assertTrue(result.succeeded)
        self.assertEqual(result.stop_reason, "goal_succeeded")
        self.assertEqual(result.iterations, 2)
        self.assertEqual(len(result.selected_plans), 2)
        self.assertIsNotNone(result.evaluation)
        self.assertIs(result.evaluation.status, GoalEvaluationStatus.SUCCEEDED)
        self.assertEqual(kernel.state.facts["github_pr"]["state"], "open")
        self.assertEqual(kernel.state.facts["github_file_updated"]["commit_sha"], "commit-sha")

        call_methods = [call["method"] for call in transport.calls]
        self.assertEqual(call_methods, ["GET", "GET", "GET", "POST", "GET", "PUT", "GET", "POST"])
        post_pr_body = json.loads(transport.calls[-1]["body"].decode("utf-8"))
        self.assertIn("<!-- leos-idempotency-key: issue-42-readme -->", post_pr_body["body"])

        event_types = [event.event_type for event in audit.events]
        self.assertIn("loop.plan_selected", event_types)
        self.assertIn("loop.goal_evaluated", event_types)
        self.assertIn("step.verified", event_types)
        self.assertNotIn("ghp_test_secret", repr(audit.records()))

    def test_goal_evaluator_unknown_does_not_stop_after_observation_plan(self) -> None:
        transport = RoutingGitHubTransport()
        client = GitHubRESTClient(transport=transport)
        audit = AuditLog()
        kernel = self._kernel(_registry(client), audit)
        provider = GitHubIssuePlanProvider(
            GitHubIssuePlanConfig(
                repo="o/r",
                issue_number=42,
                path="README.md",
                base_branch="main",
                branch="agent/issue-42",
                new_content=transport.new_content,
                idempotency_key="issue-42-readme",
            )
        )
        goal = Goal("Fix issue 42", ["PR opened"], stop_conditions=["PR opened or blocked"])

        result = AgentLoop(kernel, provider, config=AgentLoopConfig(max_iterations=1)).run(goal)

        self.assertFalse(result.succeeded)
        self.assertEqual(result.stop_reason, "max_iterations_reached")
        self.assertEqual(len(result.selected_plans), 1)
        self.assertIn("github_issue", kernel.state.facts)
        self.assertNotIn("github_pr", kernel.state.facts)

    def test_provider_returns_no_plan_when_required_tools_are_missing(self) -> None:
        provider = GitHubIssuePlanProvider(
            GitHubIssuePlanConfig(
                repo="o/r",
                issue_number=42,
                path="README.md",
                base_branch="main",
                branch="agent/issue-42",
                new_content="new",
            )
        )

        proposals = provider.propose(Goal("Fix", ["PR opened"]), WorldState(), ToolRegistry())

        self.assertEqual(proposals, [])


if __name__ == "__main__":
    unittest.main()
