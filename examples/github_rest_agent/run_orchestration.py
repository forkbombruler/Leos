from __future__ import annotations

import base64
import json
import tempfile
from collections.abc import Mapping
from pathlib import Path
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
    GoalEvaluator,
    Permission,
    PlannerConfig,
    PolicyEngine,
    RiskLevel,
    Secret,
    ToolRegistry,
    render_trace_markdown,
)

REPO = "Leos-byte/Leos"
ISSUE_NUMBER = 42
PATH = "README.md"
BASE_BRANCH = "main"
WORK_BRANCH = "leos/issue-42"
OLD_CONTENT = "# Demo\n"
NEW_CONTENT = "# Demo\n\nFixes issue #42.\n"


class DemoGitHubTransport:
    """In-process GitHub REST transport for deterministic dry-run orchestration."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.pull_requests: list[dict[str, object]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHTTPResponse:
        del headers, timeout_seconds
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query
        self.calls.append((method, f"{path}?{query}" if query else path))

        if method == "GET" and path == "/repos/Leos-byte/Leos/issues/42":
            return _json(
                {
                    "number": ISSUE_NUMBER,
                    "title": "Document issue orchestration",
                    "body": "Show the GitHub issue to PR transaction path.",
                    "state": "open",
                    "html_url": "https://github.com/Leos-byte/Leos/issues/42",
                }
            )
        if method == "GET" and path == "/repos/Leos-byte/Leos/contents/README.md" and "ref=leos%2Fissue-42" in query:
            return _json(
                {
                    "content": base64.b64encode(OLD_CONTENT.encode("utf-8")).decode("ascii"),
                    "encoding": "base64",
                    "sha": "readme-branch-sha",
                }
            )
        if method == "GET" and path == "/repos/Leos-byte/Leos/contents/README.md":
            return _json(
                {
                    "content": base64.b64encode(OLD_CONTENT.encode("utf-8")).decode("ascii"),
                    "encoding": "base64",
                    "sha": "readme-old-sha",
                }
            )
        if method == "GET" and path == "/repos/Leos-byte/Leos/git/ref/heads/main":
            return _json({"object": {"sha": "main-sha"}})
        if method == "POST" and path == "/repos/Leos-byte/Leos/git/refs":
            return _json({"object": {"sha": "main-sha"}})
        if method == "PUT" and path == "/repos/Leos-byte/Leos/contents/README.md":
            payload = json.loads((body or b"{}").decode("utf-8"))
            decoded = base64.b64decode(str(payload["content"]).encode("ascii")).decode("utf-8")
            if decoded != NEW_CONTENT:
                return _json({"message": "unexpected content"}, status=400)
            return _json({"content": {"sha": "readme-new-sha"}, "commit": {"sha": "commit-sha"}})
        if method == "GET" and path == "/repos/Leos-byte/Leos/pulls":
            return _json(self.pull_requests)
        if method == "POST" and path == "/repos/Leos-byte/Leos/pulls":
            payload = json.loads((body or b"{}").decode("utf-8"))
            pr = {
                "number": 7,
                "title": payload["title"],
                "body": payload["body"],
                "state": "open",
                "html_url": "https://github.com/Leos-byte/Leos/pull/7",
            }
            self.pull_requests.append(pr)
            return _json(pr)
        return _json({"message": f"unexpected route: {method} {path}"}, status=404)


def _json(payload: object, *, status: int = 200) -> GitHubHTTPResponse:
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


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="leos-github-orchestration-") as tmp:
        audit_path = Path(tmp) / "audit.jsonl"
        audit_log = AuditLog(audit_path)
        transport = DemoGitHubTransport()
        client = GitHubRESTClient(transport=transport)
        registry = _registry(client)
        kernel = AgentKernel(
            registry=registry,
            policy=PolicyEngine(
                granted_permissions=(Permission.WRITE_FILES, Permission.SEND_MESSAGE),
                max_auto_risk=RiskLevel.MEDIUM,
            ),
            causal_model=CausalGraph(),
            audit_log=audit_log,
            approval_gate=ApprovalGate(lambda step: True),
            planner_config=PlannerConfig(max_risk=RiskLevel.MEDIUM),
            allow_network_tools=True,
        )
        provider = GitHubIssuePlanProvider(
            GitHubIssuePlanConfig(
                repo=REPO,
                issue_number=ISSUE_NUMBER,
                path=PATH,
                base_branch=BASE_BRANCH,
                branch=WORK_BRANCH,
                new_content=NEW_CONTENT,
                token=Secret("demo-token"),
                idempotency_key="github-rest-agent-loop-demo",
            )
        )
        goal = Goal(
            description="Open a PR for a GitHub issue using the REST toolchain",
            success_criteria=["PR opened"],
            stop_conditions=["PR opened or blocked by policy"],
        )
        loop = AgentLoop(
            kernel,
            provider,
            config=AgentLoopConfig(max_iterations=2),
            goal_evaluator=GoalEvaluator(),
        )
        result = loop.run(goal)
        trace_path = Path(tmp) / "trace.md"
        trace_path.write_text(render_trace_markdown(audit_log.records()), encoding="utf-8")
        plan_step_names = [step.tool_name for plan in result.selected_plans for step in plan.steps]

        print("github issue agent-loop dry-run orchestration")
        print("client: GitHubRESTClient with DemoGitHubTransport")
        print("no real GitHub write performed")
        print(f"selected plans: {len(result.selected_plans)}")
        print(f"executed steps: {', '.join(plan_step_names)}")
        print(f"rest calls: {len(transport.calls)}")
        print(f"pull request: {kernel.state.facts.get('github_pr', {}).get('html_url')}")
        print(f"goal evaluation: {result.evaluation.status.value if result.evaluation else 'none'}")
        print(f"stop reason: {result.stop_reason}")
        print(f"audit log path: {audit_path}")
        print(f"trace markdown path: {trace_path}")
        print("token not printed")
        return 0 if result.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
