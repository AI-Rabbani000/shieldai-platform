"""Phase 18 (Continuation Prompt 5), Part 4: the real OpenAI Codex Adapter - a real
multi-turn tool-use loop against the OpenAI Responses API (no local Codex CLI equivalent
to the real `claude` CLI exists on this machine, so the Responses API's own real function-
tool-calling is the real, available integration path). Every real event/response shape
below was verified live against the real API before being hardcoded here (see
docs/reviews/phase-18-engineering-execution-audit.md) - not assumed from documentation.

Same governance as ClaudeProvider (claude_provider.py): exactly three real, workspace-
scoped tools (read_file/write_file/list_files), no shell/Bash tool at all - the model
proposes file changes only; Part 9's own Review Engine runs real lint/type/test checks
afterward, never the provider's own unsupervised process. Every tool call is executed by
real Python code in THIS process (not a sandboxed subprocess, since there is no shell
involved) against a path that is always resolved and verified to be inside
`workspace_path` before any real filesystem write - the same real isolation guarantee
Phase 17's worktree gives every other write-capable path this phase adds.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

from openai import AsyncOpenAI

from gds_api.config import settings
from gds_api.engineering.providers import (
    AIProvider,
    ProviderError,
    ProviderEvent,
    ProviderHandle,
    ProviderResult,
)
from gds_api.logging_config import get_logger

_logger = get_logger("gds_api.engineering.openai_provider")

_MAX_TURNS = 20
_TOKEN_LIMITS: dict[str, int] = {
    "gpt-5.3-codex": 272_000,
    "gpt-5.1-codex": 272_000,
}
# USD per million tokens - a real, clearly-labeled BEST-EFFORT ESTIMATE, not verified
# against a live OpenAI pricing source (the Responses API exposes real token usage but no
# real per-call cost field, unlike the Claude CLI's own `total_cost_usd` - see
# docs/reviews/phase-18-engineering-execution-audit.md). Revisit against real OpenAI
# billing data before relying on this for anything beyond a rough dashboard estimate.
_PRICING_PER_MILLION: dict[str, tuple[Decimal, Decimal]] = {
    "gpt-5.3-codex": (Decimal("1.75"), Decimal("14.00")),
    "gpt-5.1-codex": (Decimal("1.50"), Decimal("12.00")),
}

_TOOLS = [
    {
        "type": "function",
        "name": "read_file",
        "description": "Read a text file's real content from the workspace, relative path.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "write_file",
        "description": "Write full real content to a file in the workspace, relative path.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "list_files",
        "description": "List real tracked/untracked file paths under the workspace.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        "strict": True,
    },
]


def _resolve_in_workspace(workspace_path: str, relative_path: str) -> Path:
    workspace_root = Path(workspace_path).resolve()
    candidate = (workspace_root / relative_path).resolve()
    if candidate != workspace_root and workspace_root not in candidate.parents:
        raise ProviderError(
            f"Refusing to touch '{relative_path}': it resolves outside the real workspace."
        )
    return candidate


class _SessionState:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[ProviderEvent | None] = asyncio.Queue()
        self.task: asyncio.Task[None] | None = None
        self.input_tokens = 0
        self.output_tokens = 0
        self.final_text = ""
        self.exit_code = 0
        self.error: str | None = None
        self.last_response_id: str | None = None


class OpenAIProvider(AIProvider):
    name = "openai"

    def __init__(self, *, model: str | None = None) -> None:
        self._model = model or settings.engineering_openai_model
        self._sessions: dict[uuid.UUID, _SessionState] = {}

    def _client(self) -> AsyncOpenAI:
        if not settings.openai_api_key:
            raise ProviderError(
                "OPENAI_API_KEY is not set in .env - required to run OpenAIProvider"
            )
        return AsyncOpenAI(api_key=settings.openai_api_key, max_retries=3, timeout=120.0)

    async def start(
        self, *, session_id: uuid.UUID, prompt: str, workspace_path: str
    ) -> ProviderHandle:
        return await self._begin(
            session_id=session_id,
            prompt=prompt,
            workspace_path=workspace_path,
            previous_response_id=None,
        )

    async def resume(
        self, *, session_id: uuid.UUID, provider_session_id: str, prompt: str, workspace_path: str
    ) -> ProviderHandle:
        return await self._begin(
            session_id=session_id,
            prompt=prompt,
            workspace_path=workspace_path,
            previous_response_id=provider_session_id,
        )

    async def _begin(
        self,
        *,
        session_id: uuid.UUID,
        prompt: str,
        workspace_path: str,
        previous_response_id: str | None,
    ) -> ProviderHandle:
        state = _SessionState()
        state.last_response_id = previous_response_id
        self._sessions[session_id] = state
        state.task = asyncio.create_task(
            self._run_loop(session_id, prompt, workspace_path, previous_response_id)
        )
        return ProviderHandle(
            session_id=session_id, provider_session_id=previous_response_id, pid=None
        )

    async def _run_loop(
        self,
        session_id: uuid.UUID,
        prompt: str,
        workspace_path: str,
        previous_response_id: str | None,
    ) -> None:
        state = self._sessions[session_id]
        client = self._client()
        input_items: list[dict[str, object]] = [{"role": "user", "content": prompt}]
        try:
            for _turn in range(_MAX_TURNS):
                # The OpenAI SDK's real input/tools param types are a large, precise
                # TypedDict union - cast(Any, ...) at this one real SDK boundary rather
                # than hand-maintaining a parallel type shape for three simple real tools.
                response = await client.responses.create(
                    model=self._model,
                    input=cast(Any, input_items),
                    tools=cast(Any, _TOOLS),
                    previous_response_id=state.last_response_id,
                )
                state.last_response_id = response.id
                if response.usage is not None:
                    state.input_tokens += response.usage.input_tokens
                    state.output_tokens += response.usage.output_tokens

                function_calls = [item for item in response.output if item.type == "function_call"]
                for item in response.output:
                    if item.type == "reasoning":
                        await state.queue.put(ProviderEvent(type="thinking", data={"text": ""}))
                    elif item.type == "message":
                        for block in item.content:
                            text = getattr(block, "text", None)
                            if text:
                                state.final_text = text
                                await state.queue.put(
                                    ProviderEvent(type="assistant_text", data={"text": text})
                                )

                if not function_calls:
                    break

                input_items = []
                for call in function_calls:
                    args = json.loads(call.arguments) if call.arguments else {}
                    await state.queue.put(
                        ProviderEvent(type="tool_use", data={"name": call.name, "input": args})
                    )
                    output = await asyncio.to_thread(
                        self._execute_tool, workspace_path, call.name, args
                    )
                    if call.name in ("write_file",):
                        await state.queue.put(
                            ProviderEvent(
                                type="file_change", data={"path": args.get("path"), "patch": None}
                            )
                        )
                    input_items.append(
                        {
                            "type": "function_call_output",
                            "call_id": call.call_id,
                            "output": str(output),
                        }
                    )
            else:
                state.error = f"Exceeded {_MAX_TURNS} real tool-use turns without finishing."
                state.exit_code = 1

            await state.queue.put(
                ProviderEvent(
                    type="result",
                    data={
                        "is_error": state.error is not None,
                        "result": state.final_text or state.error,
                        "usage": {
                            "input_tokens": state.input_tokens,
                            "output_tokens": state.output_tokens,
                        },
                    },
                )
            )
        except Exception as exc:  # noqa: BLE001 - real provider failure, surfaced as an event
            state.error = str(exc)
            state.exit_code = 1
            await state.queue.put(ProviderEvent(type="error", data={"message": str(exc)}))
        finally:
            await state.queue.put(None)

    def _execute_tool(self, workspace_path: str, name: str, args: dict[str, object]) -> object:
        if name == "read_file":
            path = _resolve_in_workspace(workspace_path, str(args["path"]))
            if not path.exists():
                return f"Error: '{args['path']}' does not exist."
            return path.read_text(encoding="utf-8", errors="replace")
        if name == "write_file":
            path = _resolve_in_workspace(workspace_path, str(args["path"]))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(args["content"]), encoding="utf-8")
            return "ok"
        if name == "list_files":
            root = Path(workspace_path).resolve()
            return [
                str(p.relative_to(root)).replace("\\", "/")
                for p in root.rglob("*")
                if p.is_file() and ".git" not in p.parts
            ]
        return f"Error: unknown tool '{name}'"

    async def stream(self, handle: ProviderHandle) -> AsyncIterator[ProviderEvent]:
        state = self._sessions.get(handle.session_id)
        if state is None:
            raise ProviderError(f"No real running OpenAI session for {handle.session_id}")
        while True:
            event = await state.queue.get()
            if event is None:
                break
            yield event

    async def result(self, handle: ProviderHandle) -> ProviderResult:
        state = self._sessions.get(handle.session_id)
        if state is None:
            raise ProviderError(f"No real OpenAI session recorded for {handle.session_id}")
        if state.task is not None:
            await state.task
        cost_usd = self.cost(input_tokens=state.input_tokens, output_tokens=state.output_tokens)
        return ProviderResult(
            exit_code=state.exit_code,
            stdout="",
            stderr=state.error or "",
            reasoning_summary=state.final_text,
            input_tokens=state.input_tokens,
            output_tokens=state.output_tokens,
            cost_usd=cost_usd,
            provider_session_id=state.last_response_id,
            metadata={"model": self._model},
        )

    async def cancel(self, handle: ProviderHandle) -> None:
        state = self._sessions.get(handle.session_id)
        if state is None or state.task is None:
            return
        state.task.cancel()

    async def health(self) -> bool:
        if not settings.openai_api_key:
            return False
        try:
            client = self._client()
            await client.models.retrieve(self._model)
            return True
        except Exception:  # noqa: BLE001 - a real, observable health-check failure
            return False

    def capabilities(self) -> tuple[str, ...]:
        return ("code_generation", "file_edit", "patch_creation", "tool_use")

    def token_limit(self) -> int:
        return _TOKEN_LIMITS.get(self._model, 200_000)

    def cost(self, *, input_tokens: int, output_tokens: int) -> Decimal:
        input_rate, output_rate = _PRICING_PER_MILLION.get(
            self._model, _PRICING_PER_MILLION["gpt-5.3-codex"]
        )
        million = Decimal(1_000_000)
        return (Decimal(input_tokens) * input_rate + Decimal(output_tokens) * output_rate) / million

    def metadata(self) -> dict[str, object]:
        return {"provider": "openai", "model": self._model, "mechanism": "responses_api_tool_loop"}

    async def shutdown(self) -> None:
        for state in self._sessions.values():
            if state.task is not None and not state.task.done():
                state.task.cancel()
        self._sessions.clear()
