from __future__ import annotations

import unittest

from leos_agent import (
    ActionStep,
    AgentKernel,
    ApprovalGate,
    CausalContract,
    EgressPolicy,
    GitHubCheckCIStatusTool,
    GitHubCommentTool,
    GitHubCreateBranchTool,
    GitHubGetFileTool,
    GitHubOpenPRTool,
    GitHubReadIssueTool,
    GitHubUpdateFileTool,
    Goal,
    InMemoryGitHubClient,
    Permission,
    PolicyConfigurationError,
    PolicyDenied,
    PolicyEngine,
    PolicyRule,
    RiskLevel,
    SandboxPolicy,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)


class _Tool:
    def __init__(self, spec: ToolSpec) -> None:
        self.spec = spec
        self.executed = False

    def dry_run(self, arguments, state):
        return ToolResult(True, "dry")

    def execute(self, arguments, state):
        self.executed = True
        return ToolResult(True, "exec", observed_state_delta={"ok": True})

    def rollback(self, token, state):
        return ToolResult(True, "rollback")


def _contract() -> CausalContract:
    return CausalContract("tool", sets=("ok",), required_observations=("ok",))


def _run_tool(
    tool,
    *,
    profile: str = "production_locked_down",
    approve: bool = True,
    policy: PolicyEngine | None = None,
    arguments: dict | None = None,
):
    registry = ToolRegistry()
    registry.register(tool)
    kernel = AgentKernel(
        registry,
        policy or PolicyEngine.from_profile(profile),
        approval_gate=ApprovalGate(lambda step: approve),
    )
    goal = Goal(
        "g",
        ["ok"],
        criteria=({"key": "ok", "op": "equals", "value": True},),
        stop_conditions=["done"],
    )
    plan = kernel.build_plan(goal, [ActionStep(tool.spec.name, arguments or {}, "run")])
    return kernel, kernel.run(plan)


class ProductionProfileTests(unittest.TestCase):
    def test_workspace_subprocess_runner_blocked(self) -> None:
        tool = _Tool(
            ToolSpec(
                "exec_tool",
                "execute",
                (Permission.EXECUTE_CODE,),
                default_risk=RiskLevel.MEDIUM,
                sandbox_policy=SandboxPolicy.WORKSPACE,
                filesystem_scope="workspace",
                output_schema={"type": "object"},
                causal_contract=_contract(),
            )
        )
        kernel, plan = _run_tool(tool)
        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertFalse(tool.executed)
        self.assertTrue(
            any("workspace subprocess" in str(event.payload.get("reason", "")) for event in kernel.audit_log.events)
        )

    def test_network_tool_blocked_without_egress_policy(self) -> None:
        tool = _Tool(
            ToolSpec(
                "net_tool",
                "network",
                (Permission.NETWORK,),
                default_risk=RiskLevel.LOW,
                network_access=True,
            )
        )
        kernel, plan = _run_tool(tool)
        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertFalse(tool.executed)
        self.assertTrue(any("network" in str(event.payload.get("reason", "")) for event in kernel.audit_log.events))

    def test_network_tool_blocked_when_egress_host_not_allowed(self) -> None:
        tool = _Tool(
            ToolSpec(
                "net_tool",
                "network",
                (Permission.NETWORK,),
                default_risk=RiskLevel.LOW,
                network_access=True,
            )
        )
        policy = PolicyEngine.from_profile("production_locked_down")
        policy.egress_policy = EgressPolicy(allowed_hosts=("api.github.com",))

        kernel, plan = _run_tool(tool, policy=policy, arguments={"host": "example.com"})

        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertFalse(tool.executed)
        self.assertTrue(
            any("egress policy" in str(event.payload.get("reason", "")) for event in kernel.audit_log.events)
        )

    def test_network_tool_with_allowed_egress_reaches_human_gate(self) -> None:
        tool = _Tool(
            ToolSpec(
                "net_tool",
                "network",
                (Permission.NETWORK,),
                default_risk=RiskLevel.LOW,
                network_access=True,
            )
        )
        policy = PolicyEngine.from_profile("production_locked_down")
        policy.egress_policy = EgressPolicy(allowed_hosts=("api.github.com",))

        kernel, plan = _run_tool(tool, policy=policy, approve=False, arguments={"host": "api.github.com"})

        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertFalse(tool.executed)
        self.assertFalse(
            any("egress policy" in str(event.payload.get("reason", "")) for event in kernel.audit_log.events)
        )

    def test_egress_policy_rejects_local_private_and_wildcard_hosts(self) -> None:
        policy = EgressPolicy(allowed_hosts=("localhost", "127.0.0.1", "10.0.0.1", "192.168.1.10", "*"))

        self.assertFalse(policy.allows("localhost"))
        self.assertFalse(policy.allows("127.0.0.1"))
        self.assertFalse(policy.allows("10.0.0.1"))
        self.assertFalse(policy.allows("172.16.0.1"))
        self.assertFalse(policy.allows("192.168.1.10"))
        self.assertFalse(policy.allows("*"))

    def test_github_tools_declare_network_egress_metadata(self) -> None:
        client = InMemoryGitHubClient()
        tools = (
            GitHubReadIssueTool(client),
            GitHubCreateBranchTool(client),
            GitHubGetFileTool(client),
            GitHubUpdateFileTool(client),
            GitHubOpenPRTool(client),
            GitHubCommentTool(client),
            GitHubCheckCIStatusTool(client),
        )

        for tool in tools:
            self.assertTrue(tool.spec.network_access, tool.spec.name)
            self.assertEqual(tool.spec.egress_host, "api.github.com")
            self.assertTrue(tool.spec.egress_methods, tool.spec.name)

    def test_production_blocks_github_tool_without_egress_policy(self) -> None:
        client = InMemoryGitHubClient()
        client.seed_issue("o/r", 1, title="t", body="b")
        tool = GitHubReadIssueTool(client)

        kernel, plan = _run_tool(tool, arguments={"repo": "o/r", "issue_number": 1})

        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertTrue(
            any("egress policy" in str(event.payload.get("reason", "")) for event in kernel.audit_log.events)
        )

    def test_production_blocks_github_tool_with_wrong_egress_host(self) -> None:
        client = InMemoryGitHubClient()
        client.seed_issue("o/r", 1, title="t", body="b")
        tool = GitHubReadIssueTool(client)
        policy = PolicyEngine.from_profile("production_locked_down")
        policy.egress_policy = EgressPolicy(allowed_hosts=("example.com",))

        kernel, plan = _run_tool(tool, policy=policy, arguments={"repo": "o/r", "issue_number": 1})

        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertTrue(
            any("api.github.com" in str(event.payload.get("reason", "")) for event in kernel.audit_log.events)
        )

    def test_medium_tool_without_causal_contract_blocked_in_production(self) -> None:
        tool = _Tool(ToolSpec("medium", "m", (), default_risk=RiskLevel.MEDIUM, output_schema={"type": "object"}))
        kernel, plan = _run_tool(tool)
        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertFalse(tool.executed)
        self.assertTrue(any(event.event_type == "causal_contract.missing" for event in kernel.audit_log.events))

    def test_medium_tool_without_timeout_blocked(self) -> None:
        tool = _Tool(
            ToolSpec(
                "no_timeout",
                "m",
                (),
                default_risk=RiskLevel.MEDIUM,
                timeout_ms=0,
                output_schema={"type": "object"},
                causal_contract=_contract(),
            )
        )
        _, plan = _run_tool(tool)
        self.assertEqual(plan.steps[0].status.value, "blocked")

    def test_unknown_tool_blocked(self) -> None:
        registry = ToolRegistry()
        kernel = AgentKernel(registry, PolicyEngine.from_profile("production_locked_down"))
        goal = Goal(
            "g",
            ["ok"],
            criteria=({"key": "ok", "op": "exists"},),
            stop_conditions=["done"],
        )
        plan = kernel.build_plan(goal, [ActionStep("missing", {}, "run")])
        result = kernel.run(plan)
        self.assertEqual(result.steps[0].status.value, "blocked")
        self.assertTrue(any("unknown tool" in event.message.lower() for event in kernel.audit_log.events))

    def test_policy_as_code_auto_approval_rejected(self) -> None:
        with self.assertRaises(PolicyConfigurationError):
            PolicyRule.from_mapping({"name": "bad", "when": {"tool": "x"}, "decision": "approved"})

    def test_high_risk_action_cannot_auto_run(self) -> None:
        tool = _Tool(
            ToolSpec(
                "high",
                "h",
                (),
                default_risk=RiskLevel.HIGH,
                output_schema={"type": "object"},
                causal_contract=_contract(),
            )
        )
        _, plan = _run_tool(tool, approve=False)
        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertFalse(tool.executed)

    def test_approval_cannot_bypass_missing_causal_contract(self) -> None:
        tool = _Tool(ToolSpec("medium", "m", (), default_risk=RiskLevel.MEDIUM, output_schema={"type": "object"}))
        _, plan = _run_tool(tool, approve=True)
        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertFalse(tool.executed)

    def test_github_create_branch_has_production_causal_contract(self) -> None:
        client = InMemoryGitHubClient()
        tool = GitHubCreateBranchTool(client)
        policy = PolicyEngine.from_profile("production_locked_down")
        policy.egress_policy = EgressPolicy(allowed_hosts=("api.github.com",))

        kernel, plan = _run_tool(
            tool,
            approve=True,
            policy=policy,
            arguments={"repo": "o/r", "branch": "feature", "base": "main"},
        )

        self.assertEqual(plan.steps[0].status.value, "verified")
        self.assertIn(("o/r", "feature"), client.branches)
        self.assertFalse(any(event.event_type == "causal_contract.missing" for event in kernel.audit_log.events))

    def test_production_still_requires_approval_for_github_write_after_egress(self) -> None:
        client = InMemoryGitHubClient()
        tool = GitHubCreateBranchTool(client)
        policy = PolicyEngine.from_profile("production_locked_down")
        policy.egress_policy = EgressPolicy(allowed_hosts=("api.github.com",))

        kernel, plan = _run_tool(
            tool,
            approve=False,
            policy=policy,
            arguments={"repo": "o/r", "branch": "feature", "base": "main"},
        )

        self.assertEqual(plan.steps[0].status.value, "blocked")
        self.assertNotIn(("o/r", "feature"), client.branches)
        self.assertTrue(any(event.event_type == "approval.rejected" for event in kernel.audit_log.events))

    def test_developer_local_warns_for_missing_causal_contract(self) -> None:
        tool = _Tool(ToolSpec("medium", "m", (), default_risk=RiskLevel.MEDIUM))
        kernel, plan = _run_tool(tool, profile="developer_local")
        self.assertEqual(plan.steps[0].status.value, "verified")
        self.assertTrue(tool.executed)
        self.assertTrue(
            any(event.event_type == "step.causal_contract_missing_warning" for event in kernel.audit_log.events)
        )

    def test_production_requires_typed_goal_criteria(self) -> None:
        registry = ToolRegistry()
        kernel = AgentKernel(registry, PolicyEngine.from_profile("production_locked_down"))
        with self.assertRaises(PolicyDenied):
            kernel.build_plan(Goal("g", ["ok"], stop_conditions=["done"]), [])

    def test_validate_policy_profile_cli_target_exists(self) -> None:
        self.assertIsInstance(PolicyEngine.from_profile("production_locked_down"), PolicyEngine)


if __name__ == "__main__":
    unittest.main()
