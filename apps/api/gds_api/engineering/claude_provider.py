"""Phase 18 (Continuation Prompt 5), Part 3: the real Claude Code Adapter - a subprocess
wrapper around the actual, installed `claude` CLI (v2.1.212+) in headless mode, per the
user's own explicit decision this session (real CLI subprocess, not a custom Anthropic
tool-use loop). Every real flag/event shape below was verified live against the actual
CLI before being hardcoded here (see docs/reviews/phase-18-engineering-execution-audit.md)
- not assumed from documentation alone.

Real isolation: the child process's cwd is always the Workspace's own worktree path
(Phase 17) and no `--add-dir` is ever passed, so the CLI can only ever read/write inside
that already-isolated worktree - the same structural guarantee Phase 17's `git worktree
--detach` gives every other repository operation, extended to a real write-capable
process for the first time. `--tools Edit,Write,Read,Glob,Grep` deliberately excludes
Bash - the agent proposes file changes only; running real lint/type/test checks against
those changes is Part 9's own Review Engine's job (a separately governed, auditable step),
never something the agent's own subprocess does unsupervised.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from collections.abc import AsyncIterator
from decimal import Decimal

from gds_api.engineering.providers import (
    AIProvider,
    ProviderError,
    ProviderEvent,
    ProviderHandle,
    ProviderResult,
    ProviderTimeoutError,
)
from gds_api.logging_config import get_logger

_logger = get_logger("gds_api.engineering.claude_provider")

_DEFAULT_MODEL = "claude-sonnet-5"
_ALLOWED_TOOLS = "Edit,Write,Read,Glob,Grep"
_DEFAULT_MAX_BUDGET_USD = "2.00"
_START_TIMEOUT_SECONDS = 900
_TOKEN_LIMITS: dict[str, int] = {
    "claude-sonnet-5": 200_000,
    "claude-haiku-4-5": 200_000,
    "claude-opus-4-8": 200_000,
}
# USD per million tokens - a real fallback estimate only, used when a run somehow never
# reaches a real `result` event with its own authoritative `total_cost_usd` (e.g. a crash
# mid-stream) - never the primary source when the CLI's own real figure is available.
_PRICING_PER_MILLION: dict[str, tuple[Decimal, Decimal]] = {
    "claude-sonnet-5": (Decimal("2.00"), Decimal("10.00")),
    "claude-haiku-4-5": (Decimal("1.00"), Decimal("5.00")),
}


class ClaudeProvider(AIProvider):
    name = "claude"

    def __init__(
        self, *, model: str = _DEFAULT_MODEL, max_budget_usd: str = _DEFAULT_MAX_BUDGET_USD
    ) -> None:
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._processes: dict[uuid.UUID, asyncio.subprocess.Process] = {}
        self._final_results: dict[uuid.UUID, dict[str, object]] = {}
        self._provider_session_ids: dict[uuid.UUID, str] = {}

    def _claude_binary(self) -> str:
        binary = shutil.which("claude")
        if binary is None:
            raise ProviderError(
                "The real 'claude' CLI is not installed/on PATH - ClaudeProvider cannot run."
            )
        return binary

    async def start(
        self, *, session_id: uuid.UUID, prompt: str, workspace_path: str
    ) -> ProviderHandle:
        args = [
            self._claude_binary(),
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--permission-mode",
            "acceptEdits",
            "--tools",
            _ALLOWED_TOOLS,
            "--session-id",
            str(session_id),
            "--model",
            self._model,
            "--max-budget-usd",
            self._max_budget_usd,
            "--verbose",
        ]
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=workspace_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes[session_id] = process
        return ProviderHandle(
            session_id=session_id, provider_session_id=str(session_id), pid=process.pid
        )

    async def resume(
        self, *, session_id: uuid.UUID, provider_session_id: str, prompt: str, workspace_path: str
    ) -> ProviderHandle:
        args = [
            self._claude_binary(),
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--permission-mode",
            "acceptEdits",
            "--tools",
            _ALLOWED_TOOLS,
            "--resume",
            provider_session_id,
            "--model",
            self._model,
            "--max-budget-usd",
            self._max_budget_usd,
            "--verbose",
        ]
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=workspace_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes[session_id] = process
        return ProviderHandle(
            session_id=session_id, provider_session_id=provider_session_id, pid=process.pid
        )

    async def stream(self, handle: ProviderHandle) -> AsyncIterator[ProviderEvent]:
        process = self._processes.get(handle.session_id)
        if process is None or process.stdout is None:
            raise ProviderError(f"No real running Claude process for session {handle.session_id}")

        try:
            async with asyncio.timeout(_START_TIMEOUT_SECONDS):
                async for raw_line in process.stdout:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        _logger.warning(
                            "claude_provider.malformed_stream_line",
                            session_id=str(handle.session_id),
                        )
                        continue
                    for provider_event in _translate_event(event):
                        yield provider_event
                    if event.get("type") == "system" and event.get("subtype") == "init":
                        real_session_id = event.get("session_id")
                        if isinstance(real_session_id, str):
                            self._provider_session_ids[handle.session_id] = real_session_id
                    if event.get("type") == "result":
                        self._final_results[handle.session_id] = event
        except TimeoutError as exc:
            process.kill()
            raise ProviderTimeoutError(
                f"Claude Code session {handle.session_id} exceeded {_START_TIMEOUT_SECONDS}s"
            ) from exc

        await process.wait()

    async def result(self, handle: ProviderHandle) -> ProviderResult:
        process = self._processes.get(handle.session_id)
        if process is None:
            raise ProviderError(f"No real Claude process recorded for session {handle.session_id}")
        await process.wait()
        stderr_bytes = await process.stderr.read() if process.stderr else b""
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        final = self._final_results.get(handle.session_id, {})
        usage = final.get("usage") if isinstance(final.get("usage"), dict) else {}
        input_tokens = int(usage.get("input_tokens", 0)) if isinstance(usage, dict) else 0
        output_tokens = int(usage.get("output_tokens", 0)) if isinstance(usage, dict) else 0
        real_cost = final.get("total_cost_usd")
        cost_usd = (
            Decimal(str(real_cost))
            if isinstance(real_cost, int | float)
            else self.cost(input_tokens=input_tokens, output_tokens=output_tokens)
        )
        reasoning_summary = str(final.get("result", "")) if final else ""
        provider_session_id = self._provider_session_ids.get(
            handle.session_id, handle.provider_session_id
        )

        return ProviderResult(
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout="",
            stderr=stderr,
            reasoning_summary=reasoning_summary,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            provider_session_id=provider_session_id,
            metadata={"model": self._model, "raw_result_event": final},
        )

    async def cancel(self, handle: ProviderHandle) -> None:
        process = self._processes.get(handle.session_id)
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except TimeoutError:
            process.kill()
            await process.wait()

    async def health(self) -> bool:
        try:
            binary = self._claude_binary()
        except ProviderError:
            return False

        def _check() -> bool:
            import subprocess

            result = subprocess.run(
                [binary, "--version"], capture_output=True, timeout=15, check=False
            )
            return result.returncode == 0

        return await asyncio.to_thread(_check)

    def capabilities(self) -> tuple[str, ...]:
        return ("code_generation", "file_edit", "patch_creation", "tool_use", "session_resume")

    def token_limit(self) -> int:
        return _TOKEN_LIMITS.get(self._model, 200_000)

    def cost(self, *, input_tokens: int, output_tokens: int) -> Decimal:
        input_rate, output_rate = _PRICING_PER_MILLION.get(
            self._model, _PRICING_PER_MILLION[_DEFAULT_MODEL]
        )
        million = Decimal(1_000_000)
        return (Decimal(input_tokens) * input_rate + Decimal(output_tokens) * output_rate) / million

    def metadata(self) -> dict[str, object]:
        return {"provider": "claude", "model": self._model, "mechanism": "cli_subprocess"}

    async def shutdown(self) -> None:
        for process in self._processes.values():
            if process.returncode is None:
                process.terminate()
        self._processes.clear()


def _translate_event(event: dict[str, object]) -> list[ProviderEvent]:
    """Real stream-json -> ProviderEvent translation, per the exact schema captured live
    (docs/reviews/phase-18-engineering-execution-audit.md). Never invents an event type
    the real CLI didn't actually emit."""
    event_type = event.get("type")
    events: list[ProviderEvent] = []

    if event_type == "assistant":
        message = event.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                block_type = block.get("type")
                if block_type == "thinking":
                    events.append(
                        ProviderEvent(type="thinking", data={"text": block.get("thinking", "")})
                    )
                elif block_type == "tool_use":
                    events.append(
                        ProviderEvent(
                            type="tool_use",
                            data={"name": block.get("name"), "input": block.get("input", {})},
                        )
                    )
                elif block_type == "text":
                    events.append(
                        ProviderEvent(type="assistant_text", data={"text": block.get("text", "")})
                    )
    elif event_type == "user":
        message = event.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        tool_use_result = event.get("tool_use_result")
        structured_patch = None
        if isinstance(tool_use_result, dict):
            structured_patch = tool_use_result.get("structuredPatch")
        if structured_patch:
            file_path = (
                tool_use_result.get("filePath") if isinstance(tool_use_result, dict) else None
            )
            events.append(
                ProviderEvent(
                    type="file_change", data={"path": file_path, "patch": structured_patch}
                )
            )
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    events.append(
                        ProviderEvent(type="tool_result", data={"content": block.get("content")})
                    )
    elif event_type == "result":
        events.append(
            ProviderEvent(
                type="result",
                data={
                    "is_error": event.get("is_error"),
                    "result": event.get("result"),
                    "total_cost_usd": event.get("total_cost_usd"),
                    "usage": event.get("usage"),
                },
            )
        )
        if event.get("is_error"):
            events.append(
                ProviderEvent(type="error", data={"message": str(event.get("result", ""))})
            )

    return events
