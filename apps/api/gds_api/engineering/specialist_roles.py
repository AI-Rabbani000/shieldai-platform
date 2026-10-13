"""Phase 19 (Continuation Prompt 6), Part 3: the Specialist Engineering Agent registry -
a real, named prompt/scope profile, never a third code-writing mechanism alongside
Phase 18's real Claude Code/OpenAI Codex providers (ADR 0029). A specialist is exactly
what Phase 18's PromptInputs already supports (developer_instructions/security_rules/
etc.) plus a real default provider and a real default risk estimate - every specialist
ultimately runs through the exact same AIProvider interface, workspace isolation, patch
extraction, and automated review Phase 18 already built and live-verified.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SpecialistRole:
    key: str
    display_name: str
    focus: str
    default_provider: str
    default_risk: str  # low|medium|high
    prompt_specialization: str


SPECIALIST_ROLES: dict[str, SpecialistRole] = {
    "application": SpecialistRole(
        key="application",
        display_name="Application Engineer",
        focus="General application logic and feature implementation.",
        default_provider="claude",
        default_risk="low",
        prompt_specialization="Focus on clear, direct application logic. Prefer small, "
        "well-scoped changes over broad refactors.",
    ),
    "backend": SpecialistRole(
        key="backend",
        display_name="Backend Engineer",
        focus="Server-side logic, data models, business rules.",
        default_provider="claude",
        default_risk="low",
        prompt_specialization="Focus on backend/server-side code - data models, business "
        "logic, internal services. Preserve existing API contracts unless the task "
        "explicitly asks you to change them.",
    ),
    "frontend": SpecialistRole(
        key="frontend",
        display_name="Frontend Engineer",
        focus="User interface and client-side behavior.",
        default_provider="claude",
        default_risk="low",
        prompt_specialization="Focus on UI/client-side code. Match the project's own "
        "existing component and styling conventions rather than introducing new ones.",
    ),
    "api": SpecialistRole(
        key="api",
        display_name="API Engineer",
        focus="Public/internal API surface and contracts.",
        default_provider="claude",
        default_risk="medium",
        prompt_specialization="Focus on API endpoints and their real request/response "
        "contracts. Any breaking change to an existing contract must be called out "
        "explicitly in your final summary.",
    ),
    "database": SpecialistRole(
        key="database",
        display_name="Database Engineer",
        focus="Schema, migrations, data integrity.",
        default_provider="claude",
        default_risk="high",
        prompt_specialization="Focus on schema/migration correctness and data integrity. "
        "Never write a migration that could lose real data without calling it out "
        "explicitly.",
    ),
    "infrastructure": SpecialistRole(
        key="infrastructure",
        display_name="Infrastructure Engineer",
        focus="Deployment, configuration, environment setup.",
        default_provider="claude",
        default_risk="medium",
        prompt_specialization="Focus on infrastructure/configuration files. Never touch "
        "real credentials or secrets - if a change seems to require one, stop and "
        "report it instead.",
    ),
    "security": SpecialistRole(
        key="security",
        display_name="Security Engineer",
        focus="Security-relevant code paths and hardening.",
        default_provider="claude",
        default_risk="high",
        prompt_specialization="Focus on real security properties - authentication, "
        "authorization, input validation, secret handling. Prefer the smallest change "
        "that closes a real gap.",
    ),
    "testing": SpecialistRole(
        key="testing",
        display_name="Testing Engineer",
        focus="Automated test coverage.",
        default_provider="claude",
        default_risk="low",
        prompt_specialization="Focus on real, meaningful automated tests for the "
        "behavior described - never a test that merely asserts a mock was called.",
    ),
    "documentation": SpecialistRole(
        key="documentation",
        display_name="Documentation Engineer",
        focus="Real, accurate documentation of what the code actually does.",
        default_provider="claude",
        default_risk="low",
        prompt_specialization="Focus on documentation that accurately reflects the real "
        "code - never describe planned or aspirational behavior as if it already exists.",
    ),
    "devops": SpecialistRole(
        key="devops",
        display_name="DevOps Engineer",
        focus="Build, CI, and operational tooling.",
        default_provider="claude",
        default_risk="medium",
        prompt_specialization="Focus on build/CI/operational tooling files. Preserve "
        "existing pipeline behavior unless the task explicitly asks you to change it.",
    ),
    "refactoring": SpecialistRole(
        key="refactoring",
        display_name="Refactoring Engineer",
        focus="Structural improvement without behavior change.",
        default_provider="claude",
        default_risk="medium",
        prompt_specialization="Focus on structural improvement only - the real, "
        "observable behavior of the code must not change. If you cannot be sure "
        "behavior is preserved, make a smaller, safer change instead.",
    ),
    "code_review": SpecialistRole(
        key="code_review",
        display_name="Code Review Agent",
        focus="Reviewing another task's real patch for correctness and risk.",
        default_provider="claude",
        default_risk="low",
        prompt_specialization="Focus on reviewing the described real change for "
        "correctness, real risk, and adherence to the repository's own conventions - "
        "report findings, do not silently fix issues yourself.",
    ),
}


def get_specialist_role(key: str) -> SpecialistRole:
    role = SPECIALIST_ROLES.get(key)
    if role is None:
        raise ValueError(
            f"Unknown specialist role '{key}' - real roles are: "
            f"{', '.join(sorted(SPECIALIST_ROLES))}"
        )
    return role
