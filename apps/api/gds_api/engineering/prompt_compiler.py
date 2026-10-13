"""Phase 18 (Continuation Prompt 5), Part 5: the one real Prompt Compiler - every real
engineering prompt this platform ever sends to a provider is assembled here, from
structured inputs, never concatenated ad hoc at a call site. Mirrors this codebase's own
established "one canonical place" discipline (gds_api.capabilities.broker for capability
evaluation, gds_api.repository.git_exec for git invocation) applied to prompt assembly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PROMPT_VERSION = "1.0.0"

_SYSTEM_INSTRUCTIONS = """You are an autonomous software engineering agent operating \
inside the GDS Security OS platform, working inside a real, isolated git worktree. You \
may read, create, and edit files within this workspace only - you have no access to \
anything outside it, and no ability to run shell commands. Make the smallest, most \
direct change that satisfies the objective. Do not attempt to run tests, linters, or \
git commands yourself - a separate, governed review pipeline does that after you finish. \
When you are done, report a short, factual summary of what you changed and why."""


@dataclass
class RepositoryContext:
    display_name: str
    default_branch: str
    current_branch: str | None


@dataclass
class PolicyContext:
    forbidden_paths: tuple[str, ...] = ()
    allowed_paths: tuple[str, ...] = ()
    maximum_changed_files: int = 25
    maximum_changed_lines: int = 1000
    required_tests: bool = False
    review_requirement: bool = False


@dataclass
class PromptInputs:
    """Every real structured input Part 5 names. Optional fields default to empty/None
    rather than being silently omitted from the compiled prompt's own audit trail -
    compile() records which sections were actually present."""

    objective: str
    repository: RepositoryContext
    policy: PolicyContext
    workspace_path: str
    agent_instructions: str | None = None
    developer_instructions: str | None = None
    coding_standards: str | None = None
    project_conventions: str | None = None
    security_rules: str | None = None
    review_requirements: str | None = None
    capability_decision_summary: str | None = None
    extra_context: dict[str, str] = field(default_factory=dict)


@dataclass
class CompiledPrompt:
    text: str
    version: str
    sections_included: tuple[str, ...]


def compile_prompt(inputs: PromptInputs) -> CompiledPrompt:
    sections: list[str] = [_SYSTEM_INSTRUCTIONS]
    included: list[str] = ["system_instructions"]

    sections.append(
        "## Repository\n"
        f"- Name: {inputs.repository.display_name}\n"
        f"- Default branch: {inputs.repository.default_branch}\n"
        f"- Current branch: {inputs.repository.current_branch or 'unknown'}\n"
        f"- Your workspace root: {inputs.workspace_path}"
    )
    included.append("repository_context")

    policy_lines = [
        f"- Maximum changed files this session may touch: {inputs.policy.maximum_changed_files}",
        f"- Maximum changed lines this session may touch: {inputs.policy.maximum_changed_lines}",
    ]
    if inputs.policy.forbidden_paths:
        policy_lines.append(
            f"- Forbidden paths (never touch): {', '.join(inputs.policy.forbidden_paths)}"
        )
    if inputs.policy.allowed_paths:
        policy_lines.append(
            f"- Allowed paths (touch only these): {', '.join(inputs.policy.allowed_paths)}"
        )
    if inputs.policy.required_tests:
        policy_lines.append("- This repository requires real test coverage for behavioral changes.")
    sections.append("## Repository policy\n" + "\n".join(policy_lines))
    included.append("repository_policy")

    if inputs.security_rules:
        sections.append(f"## Security rules\n{inputs.security_rules}")
        included.append("security_rules")

    if inputs.coding_standards:
        sections.append(f"## Coding standards\n{inputs.coding_standards}")
        included.append("coding_standards")

    if inputs.project_conventions:
        sections.append(f"## Project conventions\n{inputs.project_conventions}")
        included.append("project_conventions")

    if inputs.developer_instructions:
        sections.append(f"## Developer instructions\n{inputs.developer_instructions}")
        included.append("developer_instructions")

    if inputs.agent_instructions:
        sections.append(f"## Supervising agent instructions\n{inputs.agent_instructions}")
        included.append("agent_instructions")

    if inputs.capability_decision_summary:
        sections.append(f"## Authorization\n{inputs.capability_decision_summary}")
        included.append("capability_decision_summary")

    if inputs.review_requirements:
        sections.append(f"## Review requirements\n{inputs.review_requirements}")
        included.append("review_requirements")

    for key, value in inputs.extra_context.items():
        sections.append(f"## {key}\n{value}")
        included.append(f"extra:{key}")

    sections.append(f"## Objective\n{inputs.objective}")
    included.append("objective")

    return CompiledPrompt(
        text="\n\n".join(sections), version=PROMPT_VERSION, sections_included=tuple(included)
    )
