"""Command-line interface for the Leos agent kernel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditAnomalyDetector
from .core import (
    ActionStep,
    AgentKernel,
    ApprovalGate,
    AuditLog,
    CausalHypothesis,
    CausalWorldModel,
    Goal,
    PolicyEngine,
    Secret,
    StepStatus,
    WorldState,
    default_registry,
    load_policy_from_file,
    manifest_to_json,
    replay_audit_log,
    sign_policy,
    validate_policy_config,
    verify_policy_manifest,
)
from .manifest import validate_task_file
from .policy import InteractiveApprovalGate
from .task_queue import TaskQueue, TaskRunner


def build_demo_agent(workspace: Path, auto_approve: bool) -> AgentKernel:
    registry = default_registry(workspace)
    policy = PolicyEngine()
    causal = CausalWorldModel(
        [
            CausalHypothesis(
                action_name="safe_file_write",
                affected_variables=["file_written"],
                rationale="Writing a file should update the last written file path.",
                confidence=0.9,
            )
        ]
    )
    approval = ApprovalGate(lambda step: auto_approve)
    return AgentKernel(registry=registry, policy=policy, causal_model=causal, approval_gate=approval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Leos autonomous-agent kernel.")
    sub = parser.add_subparsers(dest="command")

    validate_parser = sub.add_parser("validate-policy", help="Validate a policy configuration file.")
    validate_parser.add_argument("file", help="Path to a policy JSON file.")
    validate_parser.add_argument(
        "--policy-secret", default=None, help="Secret key for verifying a signed policy manifest."
    )

    list_parser = sub.add_parser("list-tools", help="List available tools in the registry.")
    list_parser.add_argument(
        "--workspace", default=".leos-workspace", help="Workspace root for workspace-scoped tools."
    )

    dryrun_parser = sub.add_parser("dry-run", help="Dry-run a tool against a clean world state.")
    dryrun_parser.add_argument("tool", help="Tool name.")
    dryrun_parser.add_argument("--args", default="{}", help="Tool arguments as JSON.")
    dryrun_parser.add_argument(
        "--workspace", default=".leos-workspace", help="Workspace root for workspace-scoped tools."
    )

    replay_parser = sub.add_parser("replay", help="Replay an audit log and reconstruct world state.")
    replay_parser.add_argument("file", help="Path to a JSONL audit log file.")
    replay_parser.add_argument("--no-verify", action="store_true", help="Skip hash-chain integrity verification.")

    run_parser = sub.add_parser("run", help="Run a goal with steps from a JSON file.")
    run_parser.add_argument("file", help="Path to a goal JSON file.")
    run_parser.add_argument("--workspace", default=".leos-workspace", help="Sandbox workspace root.")
    run_parser.add_argument(
        "--auto-approve", action="store_true", help="Auto-approve actions that require human approval."
    )
    run_parser.add_argument(
        "--profile", default="developer_local", help="Policy profile name or path to a signed policy manifest."
    )
    run_parser.add_argument("--policy-secret", default=None, help="Secret key for verifying a signed policy manifest.")
    run_parser.add_argument(
        "--principal", default=None, help="Principal (user) identity for per-user capability grants."
    )
    run_parser.add_argument(
        "--secret",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        help="Secret value injected into step arguments (repeatable).",
    )

    sign_parser = sub.add_parser("sign-policy", help="Sign a policy configuration and output a signed manifest.")
    sign_parser.add_argument("file", help="Path to a policy JSON file.")
    sign_parser.add_argument("--secret", required=True, help="Secret key for signing.")
    sign_parser.add_argument("--output", default=None, help="Output file path (default: stdout).")

    audit_check_parser = sub.add_parser("audit-check", help="Run anomaly detection over an audit log.")
    audit_check_parser.add_argument("file", help="Path to a JSONL audit log file.")

    vtask_parser = sub.add_parser("validate-task", help="Validate a task JSON file without executing.")
    vtask_parser.add_argument("file", help="Path to a task JSON file.")
    vtask_parser.add_argument("--workspace", default=".leos-workspace", help="Workspace root.")

    inspect_parser = sub.add_parser("inspect-audit", help="Replay audit log with anomaly detection.")
    inspect_parser.add_argument("file", help="Path to a JSONL audit log file.")

    manifest_parser = sub.add_parser("manifest", help="Output registered tool manifests as JSON.")
    manifest_parser.add_argument("--workspace", default=".leos-workspace", help="Workspace root.")

    _qdemo = sub.add_parser("queue-demo", help="Demonstrate task queue lifecycle.")

    parser.add_argument("--workspace", default=".leos-workspace", help="Sandbox workspace for reversible file actions.")
    parser.add_argument("--auto-approve", action="store_true", help="Approve demo actions that require human approval.")
    args = parser.parse_args()

    if args.command == "validate-policy":
        return _validate_policy(args.file, secret=args.policy_secret)
    if args.command == "list-tools":
        return _list_tools(args.workspace)
    if args.command == "dry-run":
        return _dry_run(args.tool, args.args, args.workspace)
    if args.command == "replay":
        return _replay(args.file, verify=not args.no_verify)
    if args.command == "run":
        return _run(
            args.file,
            args.workspace,
            args.auto_approve,
            args.profile,
            secret=args.policy_secret,
            principal=args.principal,
            cli_secrets=args.secret,
        )
    if args.command == "sign-policy":
        return _sign_policy(args.file, args.secret, args.output)
    if args.command == "audit-check":
        return _audit_check(args.file)
    if args.command == "validate-task":
        return _validate_task(args.file, args.workspace)
    if args.command == "inspect-audit":
        return _inspect_audit(args.file)
    if args.command == "manifest":
        return _manifest(args.workspace)
    if args.command == "queue-demo":
        return _queue_demo()

    agent = build_demo_agent(Path(args.workspace), auto_approve=args.auto_approve)
    goal = Goal(
        description="Create a hello file through a transactionally verified action.",
        success_criteria=["hello.txt exists in the sandbox workspace"],
        constraints=["Do not write outside the sandbox workspace"],
        stop_conditions=["Stop after file verification or policy denial"],
    )
    plan = agent.build_plan(
        goal,
        [
            ActionStep(
                tool_name="safe_file_write",
                arguments={
                    "path": "hello.txt",
                    "content": "Hello from Leos agent.\n",
                    "file_written": str(Path(args.workspace).resolve() / "hello.txt"),
                },
                reason="Demonstrate permissioned, reversible, verified action.",
            )
        ],
    )
    result = agent.run(plan)
    for step in result.steps:
        print(f"{step.tool_name}: {step.status.value} risk={step.risk.value}")
    return 0 if all(step.status is StepStatus.VERIFIED for step in result.steps) else 1


def _validate_policy(file_path: str, *, secret: str | None = None) -> int:
    try:
        with open(file_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON: {exc}", file=sys.stderr)
        return 2

    if secret is not None:
        try:
            verify_policy_manifest(data, secret)
        except Exception as exc:
            print(f"Signature verification failed: {exc}", file=sys.stderr)
            return 3
        policy_data = data.get("policy", data)
    else:
        policy_data = data

    issues = validate_policy_config(policy_data)
    if not issues:
        msg = "Policy configuration is valid."
        if secret is not None:
            msg += " Signature verified."
        print(msg)
        return 0
    for issue in issues:
        print(f"Issue: {issue.get('reason', 'unknown')}: {issue.get('message', '')}", file=sys.stderr)
    return 1


def _list_tools(workspace: str) -> int:
    registry = default_registry(Path(workspace))
    for name in registry.names():
        spec = registry.get(name).spec
        permissions = ", ".join(p.value for p in spec.permissions) if spec.permissions else "none"
        print(
            f"{spec.name:20s}  risk={spec.default_risk.value:<8s}  "
            f"rev={(spec.reversibility.value if spec.reversibility else '?'):<12s}  perm={permissions}"
        )
        print(f"  {spec.description}")
    return 0


def _dry_run(tool_name: str, args_json: str, workspace: str) -> int:
    registry = default_registry(Path(workspace))
    try:
        tool = registry.get(tool_name)
    except KeyError:
        names = ", ".join(registry.names())
        print(f"Error: unknown tool '{tool_name}'. Available: {names}", file=sys.stderr)
        return 1
    try:
        arguments = json.loads(args_json)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid --args JSON: {exc}", file=sys.stderr)
        return 2
    result = tool.dry_run(arguments, WorldState())
    status = "OK" if result.ok else "FAIL"
    print(f"{status}: {result.message}")
    if result.data:
        for k, v in result.data.items():
            print(f"  {k}: {v}")
    if result.error:
        print(f"  error: {result.error}")
    return 0 if result.ok else 1


def _replay(file_path: str, *, verify: bool) -> int:
    path = Path(file_path)
    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    log = AuditLog(path=path)
    result = replay_audit_log(log, verify_integrity=verify)
    if not result.ok:
        print(f"Integrity: FAIL ({len(result.errors)} issue(s))")
        for err in result.errors:
            print(
                f"  [{err.get('index')}] {err.get('reason')}: "
                f"expected={err.get('expected')} observed={err.get('observed')}"
            )
        return 1
    if verify:
        print("Integrity: OK")
    print(f"Applied events: {result.applied_events}")

    if result.goals:
        print(f"Goals: {len(result.goals)}")
        for gid, gdata in sorted(result.goals.items()):
            print(f"  {gid}: {gdata.get('status', 'unknown')}")
    if result.tasks:
        print(f"Tasks: {len(result.tasks)}")
        for tid, tdata in sorted(result.tasks.items()):
            print(f"  {tid}: {tdata.get('status', 'unknown')}")
    if result.blocked_steps:
        print(f"Blocked steps: {len(result.blocked_steps)}")
        for bs in result.blocked_steps:
            print(f"  {bs.get('tool', '?')}: {bs.get('decision', '?')} - {bs.get('reason', '?')}")
    if result.failed_steps:
        print(f"Failed steps: {len(result.failed_steps)}")
        for fs in result.failed_steps:
            print(f"  {fs.get('tool', '?')}: {fs.get('error_type', '?')}")
    if result.rollbacks:
        manual = [r for r in result.rollbacks if r.get("type") == "manual_recovery"]
        print(f"Rollbacks: {len(result.rollbacks)}" + (f" (manual recovery: {len(manual)})" if manual else ""))
    state = result.state
    if state.facts:
        print("Facts:")
        for k, v in sorted(state.facts.items()):
            trust = state.trust.get(k, "?")
            print(f"  {k} = {v!r}  [{trust}]")
    if state.assumptions:
        print("Assumptions:")
        for k, v in sorted(state.assumptions.items()):
            print(f"  {k} = {v!r}")
    return 0


def _run(
    file_path: str,
    workspace: str,
    auto_approve: bool,
    profile: str,
    *,
    secret: str | None = None,
    principal: str | None = None,
    cli_secrets: list[str] | None = None,
) -> int:
    path = Path(file_path)
    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON: {exc}", file=sys.stderr)
        return 2

    schema_issues = validate_task_file(data)
    if schema_issues:
        for issue in schema_issues:
            print(f"Error: {issue['path']}: {issue['reason']}", file=sys.stderr)
        return 2

    goal_data = data["goal"]
    steps_data = data["steps"]
    steps_data = data.get("steps")
    if not isinstance(goal_data, dict):
        print("Error: missing or invalid 'goal' in file", file=sys.stderr)
        return 2
    if not isinstance(steps_data, list):
        print("Error: missing or invalid 'steps' in file", file=sys.stderr)
        return 2

    try:
        goal = Goal(
            description=goal_data["description"],
            success_criteria=goal_data["success_criteria"],
            constraints=goal_data.get("constraints", ()),
            stop_conditions=goal_data.get("stop_conditions", ()),
            priority=goal_data.get("priority", 5),
        )
    except KeyError as exc:
        print(f"Error: missing required goal field: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: invalid goal: {exc}", file=sys.stderr)
        return 2

    steps = []
    for i, step_data in enumerate(steps_data):
        try:
            steps.append(
                ActionStep(
                    tool_name=step_data["tool_name"],
                    arguments=step_data["arguments"],
                    reason=step_data["reason"],
                )
            )
        except KeyError as exc:
            print(f"Error: step[{i}] missing required field: {exc}", file=sys.stderr)
            return 2

    if cli_secrets:
        for entry in cli_secrets:
            if "=" not in entry:
                print(f"Error: --secret must be KEY=VALUE, got: {entry}", file=sys.stderr)
                return 2
            key, value = entry.split("=", 1)
            for step in steps:
                step.arguments[key] = Secret(value)

    ws = Path(workspace)
    registry = default_registry(ws)
    if secret is not None:
        try:
            policy = load_policy_from_file(Path(profile), secret, principal=principal)
        except Exception as exc:
            print(f"Error: failed to load signed policy manifest '{profile}': {exc}", file=sys.stderr)
            return 2
    else:
        try:
            policy = PolicyEngine.from_profile(profile, principal=principal)
        except Exception as exc:
            print(f"Error: invalid profile '{profile}': {exc}", file=sys.stderr)
            return 2
    causal = CausalWorldModel(
        [
            CausalHypothesis(
                action_name="safe_file_write",
                affected_variables=["file_written"],
                rationale="Writing a file should update the last written file path.",
                confidence=0.9,
            )
        ]
    )
    approval = ApprovalGate(lambda step: True) if auto_approve else InteractiveApprovalGate()
    agent = AgentKernel(registry=registry, policy=policy, causal_model=causal, approval_gate=approval)

    plan = agent.build_plan(goal, steps)
    result = agent.run(plan)
    progress = agent.transactions.track_progress(result)
    for step in result.steps:
        reason_str = ""
        blocked_events = [
            e
            for e in agent.audit_log.events
            if e.event_type == "step.blocked" and e.payload.get("tool") == step.tool_name
        ]
        if blocked_events and blocked_events[-1].payload.get("reason"):
            reason_str = f" ({blocked_events[-1].payload['reason']})"
        print(f"{step.tool_name}: {step.status.value} risk={step.risk.value}{reason_str}")
    print(
        f"Progress: {progress.verified_steps}/{progress.total_steps} verified, "
        f"{progress.blocked_steps} blocked, {progress.failed_steps} failed, "
        f"{progress.rolled_back_steps} rolled-back [{progress.phase}]"
    )
    return 0 if all(step.status is StepStatus.VERIFIED for step in result.steps) else 1


def _sign_policy(file_path: str, secret: str, output: str | None) -> int:
    try:
        with open(file_path) as f:
            policy_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON: {exc}", file=sys.stderr)
        return 2
    manifest = sign_policy(policy_data, secret)
    output_json = manifest_to_json(manifest)
    if output:
        Path(output).write_text(output_json, encoding="utf-8")
        print(f"Signed manifest written to {output}")
    else:
        sys.stdout.write(output_json)
    return 0


def _audit_check(file_path: str) -> int:
    path = Path(file_path)
    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    log = AuditLog(path=path)
    detector = AuditAnomalyDetector()
    findings = detector.detect(log.records())
    if not findings:
        print("No anomalies detected.")
        return 0
    for f in findings:
        print(f"[{f.severity.upper()}] {f.rule}: {f.message}")
        if f.evidence:
            print(f"  evidence: {json.dumps(f.evidence)}")
    return 1


def _validate_task(file_path: str, workspace: str) -> int:
    path = Path(file_path)
    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON: {exc}", file=sys.stderr)
        return 2
    issues = validate_task_file(data)
    if issues:
        for issue in issues:
            print(f"Issue: {issue['path']}: {issue['message']}", file=sys.stderr)
        return 1
    registry = default_registry(Path(workspace))
    for step in data.get("steps", []):
        tool_name = step.get("tool_name", "")
        if tool_name not in registry.names():
            print(f"Unknown tool: {tool_name}", file=sys.stderr)
            return 1
        tool = registry.get(tool_name)
        args = step.get("arguments", {})
        input_issues = tool.spec.validate_input(args)
        if input_issues:
            for issue in input_issues:
                print(
                    f"Input issue ({tool_name}): {issue['path']}: {issue['message']}",
                    file=sys.stderr,
                )
            return 1
    print("Task file is valid.")
    return 0


def _inspect_audit(file_path: str) -> int:
    path = Path(file_path)
    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2
    log = AuditLog(path=path)
    result = replay_audit_log(log, verify_integrity=True)
    detector = AuditAnomalyDetector()
    findings = detector.detect(log.records())
    status = "OK" if result.ok else "FAIL"
    print(f"Integrity: {status}")
    print(f"Applied events: {result.applied_events}")
    if result.goals:
        print(f"Goals: {len(result.goals)}")
    if result.tasks:
        print(f"Tasks: {len(result.tasks)}")
    if result.blocked_steps:
        print(f"Blocked steps: {len(result.blocked_steps)}")
    if result.failed_steps:
        print(f"Failed steps: {len(result.failed_steps)}")
    if result.rollbacks:
        manual = [r for r in result.rollbacks if r.get("type") == "manual_recovery"]
        print(f"Rollbacks: {len(result.rollbacks)}" + (f" (manual recovery: {len(manual)})" if manual else ""))
    if findings:
        print(f"Anomalies: {len(findings)}")
        for f_finding in findings:
            print(f"  [{f_finding.severity.upper()}] {f_finding.rule}: {f_finding.message}")
    else:
        print("Anomalies: none")
    if result.state.facts:
        print(f"Facts: {len(result.state.facts)} key(s)")
    return 0 if result.ok else 1


def _manifest(workspace: str) -> int:
    registry = default_registry(Path(workspace))
    manifests = [registry.get(name).spec.manifest() for name in registry.names()]
    output = json.dumps(
        [{k: v.value if hasattr(v, "value") else v for k, v in m.__dict__.items()} for m in manifests],
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    print(output)
    return 0


def _queue_demo() -> int:
    registry = default_registry(Path(".leos-workspace"))
    kernel = AgentKernel(registry=registry, policy=PolicyEngine(), audit_log=AuditLog())
    queue = TaskQueue()
    runner = TaskRunner(queue, kernel, worker_id="demo")
    plan = kernel.build_plan(
        Goal(description="Queue demo", success_criteria=["ok"], stop_conditions=["done"]),
        [ActionStep("echo", {"message": "queued"}, "demo")],
    )
    task = queue.enqueue(plan)
    print(f"Enqueued: {task.task_id}")
    result = runner.run_next()
    if result:
        print(f"Status: {result.status.value}")
        return 0
    print("No task processed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
