"""Phase 17 (Continuation Prompt 4), Part 3: the Repository Provider abstraction - real
for `local` (a real, already-existing local git repository), honestly Planned for every
real hosted provider (GitHub, GitLab, Azure DevOps, Bitbucket). Mirrors Phase 14's
AgentManifest/PlannedAgentManifest discipline: a Planned provider's methods raise
rather than silently no-op or fabricate a result - never a fake success.

Every real git subprocess call goes through gds_api.repository.git_exec.run_git, the
one place this codebase shells out to the real `git` CLI (no GitPython dependency - see
docs/reviews/phase-17-repository-audit.md, Finding 6). Synchronous, matching this
codebase's established blocking-I/O convention (`asyncio.to_thread`-wrapped by every
real caller - Finding 3) - never called at import time, only from inside a real tool
executor or activity (Finding 2's Temporal-sandbox lesson).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from gds_api.repository.git_exec import run_git


class RepositoryProviderType(StrEnum):
    LOCAL = "local"
    GITHUB = "github"
    GITLAB = "gitlab"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"


# The only provider with a real, operational implementation this phase - see Part 3's
# own instruction ("Only Local Repository needs to be operational now").
OPERATIONAL_PROVIDERS: tuple[RepositoryProviderType, ...] = (RepositoryProviderType.LOCAL,)


class RepositoryProviderNotOperational(Exception):
    def __init__(self, provider: str) -> None:
        self.provider = provider
        super().__init__(
            f"Provider '{provider}' is Planned, not operational this phase - only "
            "'local' has a real implementation."
        )


@dataclass
class RepositoryStatusFacts:
    """A real, freshly-queried snapshot - never a cached assumption. `Repository.status`
    is set from this at registration and on-demand refresh, never continuously mirrored
    (see gds_api.models.Repository's own docstring)."""

    exists: bool
    is_git_repository: bool
    current_branch: str | None
    head_commit: str | None
    default_branch: str | None
    remote_url: str | None
    detail: str


class LocalRepositoryProvider:
    """The one real, operational provider. Every method is read-only against
    `working_directory` - verification only, never a mutation. Real repository
    operations (read/search/diff/etc.) happen against an isolated worktree, never here -
    see gds_api.repository.worktree_manager."""

    provider_type = RepositoryProviderType.LOCAL

    def verify(self, working_directory: str) -> RepositoryStatusFacts:
        path = Path(working_directory)
        if not path.exists() or not path.is_dir():
            return RepositoryStatusFacts(
                exists=False,
                is_git_repository=False,
                current_branch=None,
                head_commit=None,
                default_branch=None,
                remote_url=None,
                detail=(
                    f"working_directory does not exist or is not a directory: {working_directory}"
                ),
            )

        inside = run_git(["rev-parse", "--is-inside-work-tree"], cwd=str(path))
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return RepositoryStatusFacts(
                exists=True,
                is_git_repository=False,
                current_branch=None,
                head_commit=None,
                default_branch=None,
                remote_url=None,
                detail="working_directory exists but is not a real git repository "
                f"(git rev-parse failed: {inside.stderr.strip()[:200]})",
            )

        branch_result = run_git(["branch", "--show-current"], cwd=str(path))
        current_branch = branch_result.stdout.strip() or None

        head_result = run_git(["rev-parse", "HEAD"], cwd=str(path))
        head_commit = head_result.stdout.strip() if head_result.returncode == 0 else None

        remote_result = run_git(["remote", "get-url", "origin"], cwd=str(path))
        remote_url = remote_result.stdout.strip() if remote_result.returncode == 0 else None

        default_branch = self._resolve_default_branch(path, current_branch)

        detail = "ok" if head_commit else "real git repository with no commits yet"
        return RepositoryStatusFacts(
            exists=True,
            is_git_repository=True,
            current_branch=current_branch,
            head_commit=head_commit,
            default_branch=default_branch,
            remote_url=remote_url,
            detail=detail,
        )

    def _resolve_default_branch(self, path: Path, current_branch: str | None) -> str | None:
        # A real remote HEAD symref is the authoritative answer when one exists.
        symref = run_git(["symbolic-ref", "refs/remotes/origin/HEAD"], cwd=str(path))
        if symref.returncode == 0 and symref.stdout.strip():
            return symref.stdout.strip().removeprefix("refs/remotes/origin/")
        # No remote (common for a purely local repository, confirmed live for this
        # project's own repo during Phase 17 verification) - fall back to whichever of
        # main/master really exists, then to the current branch. Never fabricated.
        for candidate in ("main", "master"):
            check = run_git(
                ["show-ref", "--verify", "--quiet", f"refs/heads/{candidate}"], cwd=str(path)
            )
            if check.returncode == 0:
                return candidate
        return current_branch


class PlannedRepositoryProvider:
    """github/gitlab/azure_devops/bitbucket - a real taxonomy entry with no operational
    implementation. Every method raises RepositoryProviderNotOperational rather than
    silently no-oping or returning a fabricated result."""

    def __init__(self, provider_type: RepositoryProviderType) -> None:
        self.provider_type = provider_type

    def verify(self, working_directory: str) -> RepositoryStatusFacts:
        raise RepositoryProviderNotOperational(self.provider_type.value)


def get_provider(
    provider_type: RepositoryProviderType,
) -> LocalRepositoryProvider | PlannedRepositoryProvider:
    if provider_type == RepositoryProviderType.LOCAL:
        return LocalRepositoryProvider()
    return PlannedRepositoryProvider(provider_type)
