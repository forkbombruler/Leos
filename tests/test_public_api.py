"""Verify public API surface completeness."""

from __future__ import annotations

import unittest


class PublicAPITests(unittest.TestCase):
    def test_core_exports_structured_llm_planner(self) -> None:
        from leos_agent.core import StructuredLLMPlanner  # noqa: F401

    def test_core_exports_model_request(self) -> None:
        from leos_agent.core import ModelRequest  # noqa: F401

    def test_core_exports_prompt_registry(self) -> None:
        from leos_agent.core import PromptRegistry  # noqa: F401

    def test_core_exports_workspace_sandbox_runner(self) -> None:
        from leos_agent.core import WorkspaceSubprocessSandboxRunner  # noqa: F401

    def test_package_exports_structured_llm_planner(self) -> None:
        import leos_agent

        self.assertTrue(hasattr(leos_agent, "StructuredLLMPlanner"))

    def test_package_exports_model_request(self) -> None:
        import leos_agent

        self.assertTrue(hasattr(leos_agent, "ModelRequest"))

    def test_package_exports_sandbox_command_tool(self) -> None:
        import leos_agent

        self.assertTrue(hasattr(leos_agent, "SandboxCommandTool"))

    def test_core_exports_model_usage(self) -> None:
        from leos_agent.core import ModelUsage  # noqa: F401

    def test_core_exports_model_client(self) -> None:
        from leos_agent.core import ModelClient  # noqa: F401

    def test_core_exports_sandbox_result(self) -> None:
        from leos_agent.core import SandboxResult  # noqa: F401

    def test_core_exports_sandbox_runner_protocol(self) -> None:
        from leos_agent.core import SandboxRunner  # noqa: F401

    def test_core_exports_fake_model_client(self) -> None:
        from leos_agent.core import FakeModelClient  # noqa: F401

    def test_core_exports_llm_planner_adapter(self) -> None:
        from leos_agent.core import LLMPlannerAdapter  # noqa: F401

    def test_core_exports_validate_llm_proposals(self) -> None:
        from leos_agent.core import validate_llm_proposals  # noqa: F401

    def test_core_exports_container_sandbox_runner(self) -> None:
        from leos_agent.core import ContainerSandboxRunner  # noqa: F401

    def test_core_exports_microvm_sandbox_runner(self) -> None:
        from leos_agent.core import MicroVMSandboxRunner  # noqa: F401

    def test_core_exports_sandbox_unavailable(self) -> None:
        from leos_agent.core import SandboxUnavailable  # noqa: F401

    def test_core_exports_sandbox_command_dataclass(self) -> None:
        from leos_agent.core import SandboxCommand  # noqa: F401

    def test_core_exports_network_fetch_tool(self) -> None:
        from leos_agent.core import NetworkFetchTool  # noqa: F401

    def test_core_exports_browser_read_tool(self) -> None:
        from leos_agent.core import BrowserReadTool  # noqa: F401

    def test_core_exports_tool_manifest_loader(self) -> None:
        from leos_agent.core import load_tool_manifest_file  # noqa: F401

    def test_package_exports_network_fetch_tool(self) -> None:
        import leos_agent

        self.assertTrue(hasattr(leos_agent, "NetworkFetchTool"))

    def test_package_exports_browser_read_tool(self) -> None:
        import leos_agent

        self.assertTrue(hasattr(leos_agent, "BrowserReadTool"))

    def test_package_exports_proof_and_eval_api(self) -> None:
        import leos_agent

        self.assertTrue(hasattr(leos_agent, "generate_proofs"))
        self.assertTrue(hasattr(leos_agent, "run_safety_evals"))
        self.assertTrue(hasattr(leos_agent, "default_dev_registry"))

    def test_core_exports_causal_contract_api(self) -> None:
        from leos_agent.core import CausalContract, DockerSandboxRunner, URLSafetyPolicy  # noqa: F401

    def test_core_exports_agent_loop_api(self) -> None:
        from leos_agent.core import (  # noqa: F401
            AgentLoop,
            AgentLoopConfig,
            AgentLoopResult,
            DeterministicProposalProvider,
        )

    def test_core_exports_goal_evaluator_api(self) -> None:
        from leos_agent.core import GoalEvaluation, GoalEvaluationStatus, GoalEvaluator  # noqa: F401

    def test_core_exports_model_adapters(self) -> None:
        from leos_agent.core import AnthropicModelClient, LocalHTTPModelClient, OpenAIModelClient  # noqa: F401

    def test_core_exports_github_tools(self) -> None:
        from leos_agent.core import (  # noqa: F401
            GitHubCheckCIStatusTool,
            GitHubCommentTool,
            GitHubCreateBranchTool,
            GitHubGetFileTool,
            GitHubOpenPRTool,
            GitHubReadIssueTool,
            GitHubUpdateFileTool,
            InMemoryGitHubClient,
        )

    def test_core_exports_github_rest_client(self) -> None:
        from leos_agent.core import (  # noqa: F401
            GitHubAPIError,
            GitHubAuthError,
            GitHubConflictError,
            GitHubHTTPResponse,
            GitHubNotFoundError,
            GitHubRateLimitError,
            GitHubRESTClient,
            GitHubTransport,
            UrllibGitHubTransport,
        )

    def test_core_exports_github_issue_plan_provider(self) -> None:
        from leos_agent.core import GitHubIssuePlanConfig, GitHubIssuePlanProvider  # noqa: F401

    def test_core_exports_extensibility_infrastructure(self) -> None:
        from leos_agent.core import (  # noqa: F401
            CredentialError,
            CredentialExpiredError,
            CredentialRevokedError,
            CredentialScopeError,
            CredentialVault,
            CriterionEvaluation,
            CriterionRule,
            DomainEvaluator,
            EvaluatorRegistry,
            InMemoryCredentialVault,
            InMemoryRuntimeStore,
            JsonlRuntimeStore,
            RuntimeStore,
            RuntimeStoreError,
            SecretHandle,
            SQLiteRuntimeStore,
            ToolManifestRegistry,
            ToolManifestRegistryError,
        )

    def test_core_exports_sanitization_api(self) -> None:
        from leos_agent.core import (  # noqa: F401
            SanitizationError,
            SanitizationMode,
            assert_no_secrets,
            redact_secrets,
            safe_json_dumps,
            sanitize_for_boundary,
        )

    def test_package_exports_new_runtime_api(self) -> None:
        import leos_agent

        self.assertTrue(hasattr(leos_agent, "AgentLoop"))
        self.assertTrue(hasattr(leos_agent, "GoalEvaluator"))
        self.assertTrue(hasattr(leos_agent, "GitHubIssuePlanProvider"))
        self.assertTrue(hasattr(leos_agent, "GitHubRESTClient"))
        self.assertTrue(hasattr(leos_agent, "ToolManifestRegistry"))
        self.assertTrue(hasattr(leos_agent, "EvaluatorRegistry"))
        self.assertTrue(hasattr(leos_agent, "InMemoryRuntimeStore"))
        self.assertTrue(hasattr(leos_agent, "SQLiteRuntimeStore"))
        self.assertTrue(hasattr(leos_agent, "InMemoryCredentialVault"))
        self.assertTrue(hasattr(leos_agent, "LocalHTTPModelClient"))
        self.assertTrue(hasattr(leos_agent, "InMemoryGitHubClient"))
        self.assertTrue(hasattr(leos_agent, "redact_secrets"))
        self.assertTrue(hasattr(leos_agent, "assert_no_secrets"))

    def test_core_exports_network_observation_helpers(self) -> None:
        from leos_agent.core import DNSResolver, make_untrusted_observation  # noqa: F401


if __name__ == "__main__":
    unittest.main()
