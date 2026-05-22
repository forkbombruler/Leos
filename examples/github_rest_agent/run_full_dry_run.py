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
    GitHubCheckCIStatusTool,
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
    render_trace_html,
    render_trace_markdown,
)

REPO = "Leos-byte/Leos"
ISSUE_NUMBER = 42
TARGET_PATH = "README.md"
BASE_BRANCH = "main"
WORK_BRANCH = "leos/issue-42"
OLD_CONTENT = "# Demo\n"
NEW_CONTENT = "# Demo\n\nFixes issue #42.\n"
IDEMPOTENCY_KEY = "leos-full-dry-run-issue-42"


class FullDryRunGitHubTransport:
    """Deterministic fake GitHub transport; no network calls are made."""

    def __init__(self, *, expected_previous: str = OLD_CONTENT) -> None:
        self.expected_previous = expected_previous
        self.calls: list[dict[str, object]] = []
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
        self.calls.append({"method": method, "path": parsed.path, "query": parsed.query, "body": body})
        path = parsed.path

        if method == "GET" and path == f"/repos/{REPO}/issues/{ISSUE_NUMBER}":
            return _json(
                {
                    "number": ISSUE_NUMBER,
                    "title": "Full dry-run orchestration",
                    "body": "Update the target file and open a PR.",
                    "state": "open",
                    "html_url": f"https://github.com/{REPO}/issues/{ISSUE_NUMBER}",
                }
            )
        if method == "GET" and path == f"/repos/{REPO}/contents/{TARGET_PATH}":
            content = self.expected_previous
            sha = "branch-sha" if "ref=leos%2Fissue-42" in parsed.query else "main-sha"
            return _json(
                {
                    "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                    "encoding": "base64",
                    "sha": sha,
                }
            )
        if method == "GET" and path == f"/repos/{REPO}/git/ref/heads/{BASE_BRANCH}":
            return _json({"object": {"sha": "main-sha"}})
        if method == "POST" and path == f"/repos/{REPO}/git/refs":
            return _json({"object": {"sha": "main-sha"}}, status=201)
        if method == "PUT" and path == f"/repos/{REPO}/contents/{TARGET_PATH}":
            payload = json.loads((body or b"{}").decode("utf-8"))
            decoded = base64.b64decode(str(payload["content"]).encode("ascii")).decode("utf-8")
            if decoded != NEW_CONTENT:
                return _json({"message": "unexpected content"}, status=400)
            return _json({"content": {"sha": "new-sha"}, "commit": {"sha": "commit-sha"}})
        if method == "GET" and path == f"/repos/{REPO}/pulls":
            return _json(self.pull_requests)
        if method == "POST" and path == f"/repos/{REPO}/pulls":
            payload = json.loads((body or b"{}").decode("utf-8"))
            pr = {
                "number": 7,
                "title": payload["title"],
                "body": payload["body"],
                "state": "open",
                "html_url": f"https://github.com/{REPO}/pull/7",
            }
            self.pull_requests.append(pr)
            return _json(pr, status=201)
        if method == "GET" and path == f"/repos/{REPO}/commits/leos%2Fissue-42/status":
            return _json({"state": "success", "statuses": [{"context": "ci/test", "state": "success"}]})
        return _json({"message": f"unexpected route: {method} {path}"}, status=404)


def _json(payload: object, *, status: int = 200) -> GitHubHTTPResponse:
    return GitHubHTTPResponse(status_code=status, body=json.dumps(payload).encode("utf-8"), headers={})


def build_registry(client: GitHubRESTClient) -> ToolRegistry:
    registry = ToolRegistry()
    for tool in (
        GitHubReadIssueTool(client),
        GitHubGetFileTool(client),
        GitHubCreateBranchTool(client),
        GitHubUpdateFileTool(client),
        GitHubOpenPRTool(client),
        GitHubCheckCIStatusTool(client),
    ):
        registry.register(tool)
    return registry


def run(output_dir: Path | None = None) -> dict[str, object]:
    output_root = output_dir or Path(tempfile.mkdtemp(prefix="leos-github-full-dry-run-"))
    output_root.mkdir(parents=True, exist_ok=True)
    audit_path = output_root / "audit.jsonl"
    trace_md_path = output_root / "trace.md"
    trace_html_path = output_root / "trace.html"
    summary_path = output_root / "summary.json"

    audit_log = AuditLog(audit_path)
    transport = FullDryRunGitHubTransport()
    client = GitHubRESTClient(transport=transport)
    kernel = AgentKernel(
        registry=build_registry(client),
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
            path=TARGET_PATH,
            base_branch=BASE_BRANCH,
            branch=WORK_BRANCH,
            new_content=NEW_CONTENT,
            token=Secret("demo-token"),
            idempotency_key=IDEMPOTENCY_KEY,
            check_ci=True,
            ci_ref=WORK_BRANCH,
        )
    )
    goal = Goal(
        "Full GitHub issue-to-PR dry-run",
        ["file updated", "PR opened", "CI passed"],
        criteria=(
            {"key": "github_file_updated", "op": "exists"},
            {"key": "github_pr", "op": "exists"},
            {"key": "github_ci_status", "op": "exists"},
        ),
        stop_conditions=["PR opened and CI passed or blocked"],
    )
    result = AgentLoop(
        kernel,
        provider,
        config=AgentLoopConfig(max_iterations=2),
        goal_evaluator=GoalEvaluator(),
    ).run(goal)

    records = audit_log.records()
    trace_md_path.write_text(render_trace_markdown(records), encoding="utf-8")
    trace_html_path.write_text(render_trace_html(records), encoding="utf-8")
    summary = {
        "succeeded": result.succeeded,
        "stop_reason": result.stop_reason,
        "evaluation_status": result.evaluation.status.value if result.evaluation else None,
        "pull_request_number": kernel.state.facts.get("github_pr", {}).get("number"),
        "ci_state": kernel.state.facts.get("github_ci_status", {}).get("state"),
        "rest_call_count": len(transport.calls),
        "audit_log": str(audit_path),
        "trace_markdown": str(trace_md_path),
        "trace_html": str(trace_html_path),
        "no_real_github_write": True,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary["summary_json"] = str(summary_path)
    return summary


def main() -> int:
    summary = run()
    print("github full dry-run orchestration")
    print("no real GitHub write performed")
    print(f"goal evaluation: {summary['evaluation_status']}")
    print(f"stop reason: {summary['stop_reason']}")
    print(f"pull request: {summary['pull_request_number']}")
    print(f"ci state: {summary['ci_state']}")
    print(f"audit log path: {summary['audit_log']}")
    print(f"trace markdown path: {summary['trace_markdown']}")
    print(f"trace html path: {summary['trace_html']}")
    print(f"summary json path: {summary['summary_json']}")
    print("token not printed")
    return 0 if summary["succeeded"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
