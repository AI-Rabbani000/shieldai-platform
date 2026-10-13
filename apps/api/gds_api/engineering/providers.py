"""Phase 18 (Continuation Prompt 5), Part 2: the provider-independent AIProvider
interface every real engineering-execution provider implements identically, so
gds_api.engineering.orchestrator never knows which provider is running a given session.
Two real implementations exist this phase (claude_provider.ClaudeProvider,
openai_provider.OpenAIProvider) - both registered in PROVIDER_REGISTRY, both satisfying
this exact contract, both real (no third, unimplemented provider is registered - "Future
Providers" in the build prompt's own architecture diagram is a documented extension
point, not code that exists yet).
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from decimal import Decimal


@dataclass
class ProviderEvent:
    """One real, streamed unit of progress from a provider - mapped by
    gds_api.engineering.orchestrator into the real SSE vocabulary Part 7 specifies
    (engineering.thinking, .tool_execution, etc.) via gds_api.events.publish_mission_event.
    type is one of: thinking|tool_use|assistant_text|file_change|error|result."""

    type: str
    data: dict[str, object] = field(default_factory=dict)


@dataclass
class ProviderHandle:
    """Returned by start()/resume() - the real, live handle stream() reads from and
    cancel()/shutdown() act on. provider_session_id is the real, provider-native session
    identifier (the claude CLI's own session id, or an OpenAI response id) once known -
    None until the provider's own first real event reveals it."""

    session_id: uuid.UUID
    provider_session_id: str | None
    pid: int | None


@dataclass
class ProviderResult:
    """The real, final accounting for a completed provider run - written onto the owning
    EngineeringSession row by the orchestrator, never estimated."""

    exit_code: int
    stdout: str
    stderr: str
    reasoning_summary: str
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    provider_session_id: str | None
    metadata: dict[str, object]


class ProviderError(Exception):
    pass


class ProviderTimeoutError(ProviderError):
    pass


class AIProvider(ABC):
    """Part 2's exact contract - every method here is real (no method silently
    no-ops); a provider that cannot yet support a given call raises ProviderError with a
    real, honest reason rather than fabricating success."""

    name: str

    @abstractmethod
    async def start(
        self, *, session_id: uuid.UUID, prompt: str, workspace_path: str
    ) -> ProviderHandle: ...

    @abstractmethod
    def stream(self, handle: ProviderHandle) -> AsyncIterator[ProviderEvent]: ...

    @abstractmethod
    async def result(self, handle: ProviderHandle) -> ProviderResult:
        """Blocks until the real run this handle refers to has fully finished (stream()
        must be fully consumed first, or this waits for the same real completion
        signal) and returns its final, real accounting."""
        ...

    @abstractmethod
    async def cancel(self, handle: ProviderHandle) -> None: ...

    @abstractmethod
    async def resume(
        self, *, session_id: uuid.UUID, provider_session_id: str, prompt: str, workspace_path: str
    ) -> ProviderHandle: ...

    @abstractmethod
    async def health(self) -> bool: ...

    @abstractmethod
    def capabilities(self) -> tuple[str, ...]: ...

    @abstractmethod
    def token_limit(self) -> int: ...

    @abstractmethod
    def cost(self, *, input_tokens: int, output_tokens: int) -> Decimal: ...

    @abstractmethod
    def metadata(self) -> dict[str, object]: ...

    @abstractmethod
    async def shutdown(self) -> None: ...


def get_provider(name: str) -> AIProvider:
    from gds_api.engineering.claude_provider import ClaudeProvider
    from gds_api.engineering.openai_provider import OpenAIProvider

    registry: dict[str, type[AIProvider]] = {
        "claude": ClaudeProvider,
        "openai": OpenAIProvider,
    }
    provider_cls = registry.get(name)
    if provider_cls is None:
        raise ProviderError(f"Unknown provider '{name}' - real providers are: claude, openai")
    return provider_cls()
