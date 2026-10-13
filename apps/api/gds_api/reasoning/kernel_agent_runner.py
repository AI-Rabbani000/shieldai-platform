#!/usr/bin/env python3
"""
Kernel Agent Runner — wraps GPT-4.1 reasoning with kernel-managed memory.

Each agent invocation:
1. Creates a kernel APCB (process) with unique PID
2. Allocates system prompt (importance=1.0, never paged)
3. Allocates user goal (importance=0.8)
4. Runs GPT-4.1 with function calling
5. Tool results get importance=0.5 (paged first when context fills)
6. When context exceeds 128K, cold segments auto-page to Redis swap
"""
import sys
import os
import logging
import time
import uuid
import asyncio
import inspect
import json
from typing import Dict, Any, Optional

logger = logging.getLogger("gds.kernel.agent_runner")

# Import tools — try tool_gateway first, then kernel_bridge as fallback
TOOL_REGISTRY = {}
execute_tool = None

try:
    from gds_api.tool_gateway import TOOL_REGISTRY as _TR, execute_tool as _et
    TOOL_REGISTRY = _TR
    execute_tool = _et
    logger.info("Tools loaded from tool_gateway: %d tools" % len(TOOL_REGISTRY))
except Exception as e:
    logger.warning("tool_gateway import failed: %s" % e)
    try:
        from gds_api.reasoning.kernel_bridge import TOOL_REGISTRY as _TR2, execute_tool as _et2
        TOOL_REGISTRY = _TR2
        execute_tool = _et2
        logger.info("Tools loaded from kernel_bridge: %d tools" % len(TOOL_REGISTRY))
    except Exception as e2:
        logger.warning("kernel_bridge import also failed: %s" % e2)

# Import kernel for memory management
KERNEL_AVAILABLE = False
MemorySegmentType = None
try:
    from gds_kernel.kernel_router import get_kernel
    from gds_kernel.memory import MemorySegmentType as _MST
    MemorySegmentType = _MST
    KERNEL_AVAILABLE = True
except Exception as e:
    logger.warning("Kernel not available: %s" % e)


async def _safe_execute_tool(tool_name, tool_args):
    """Execute a tool, handling both sync and async execute_tool functions."""
    if execute_tool is None:
        return {"error": "No tool executor available"}
    try:
        # Both supported adapters accept payload by keyword. Never retry after
        # TypeError: the executor may have already performed a side effect.
        result = execute_tool(tool_name, payload=tool_args)
        if inspect.isawaitable(result):
            result = await result
        return result
    except Exception as e:
        logger.error("Tool %s failed: %s" % (tool_name, e))
        return {"error": str(e)}


def _serialize_result(result):
    """Make sure result is JSON-serializable (no coroutines, no objects)."""
    if isinstance(result, dict):
        return {k: _serialize_result(v) for k, v in result.items()}
    elif isinstance(result, list):
        return [_serialize_result(v) for v in result]
    elif isinstance(result, (str, int, float, bool, type(None))):
        return result
    else:
        return str(result)


async def run_kernel_agent_runner(
    agent_id: str,
    goal: str,
    context: Optional[Dict[str, Any]] = None,
    model: str = "gpt-4.1",
    max_iterations: int = 10,
) -> Dict[str, Any]:
    """Run an agent using kernel-managed memory."""
    start_time = time.time()
    context = context or {}
    pid = "agent-%s-%s" % (agent_id, uuid.uuid4().hex[:8])

    kernel = None
    mem = None
    if KERNEL_AVAILABLE:
        try:
            kernel = get_kernel()
            mem = getattr(kernel, 'memory')
        except Exception as e:
            logger.warning("Could not get kernel: %s" % e)

    tool_calls = []
    iterations = 0
    agent_response = ""
    success = True
    error_message = None

    # Allocate memory in kernel
    if mem:
        try:
            tool_names = ", ".join(TOOL_REGISTRY.keys()) if TOOL_REGISTRY else "none"
            system_prompt = (
                "You are %s, an AI security agent for GDS OS. "
                "You have access to real security tools. "
                "Analyze the request and decide which tools to use. "
                "Available tools: %s"
            ) % (agent_id, tool_names)

            mem.allocate(
                process_id=pid,
                content=system_prompt,
                segment_type=MemorySegmentType.SYSTEM_PROMPT,
                importance=1.0
            )
            mem.allocate(
                process_id=pid,
                content=goal,
                segment_type=MemorySegmentType.CONVERSATION,
                importance=0.8
            )
            logger.info("Kernel memory allocated for %s" % pid)
        except Exception as e:
            logger.warning("Kernel memory allocation failed: %s" % e)

    # Build tool definitions for GPT-4.1
    tool_defs = []
    if TOOL_REGISTRY:
        for tool_name, tool_spec in TOOL_REGISTRY.items():
            if callable(tool_spec):
                desc = (tool_spec.__doc__ or "Execute %s" % tool_name)[:200]
                params = {"type": "object", "properties": {}}
            elif hasattr(tool_spec, "get"):
                desc = tool_spec.get("description", "Execute %s" % tool_name)
                params = tool_spec.get("parameters", {"type": "object", "properties": {}})
            else:
                desc = "Execute %s" % tool_name
                params = {"type": "object", "properties": {}}
            tool_defs.append({
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": desc,
                    "parameters": params
                }
            })

    # GPT-4.1 function calling loop
    try:
        import openai
        from dotenv import load_dotenv
        load_dotenv("/opt/.env")
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        messages = [
            {"role": "system", "content": "You are %s, an AI security agent. Use tools to accomplish the goal." % agent_id},
            {"role": "user", "content": goal}
        ]

        if context:
            for key, value in context.items():
                if isinstance(value, str):
                    messages.append({"role": "user", "content": "Context - %s: %s" % (key, value)})

        for iteration in range(max_iterations):
            iterations += 1

            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tool_defs if tool_defs else None,
                tool_choice="auto" if tool_defs else None,
                temperature=0.1,
                max_tokens=4096
            )

            msg = response.choices[0].message

            if msg.tool_calls:
                messages.append(msg)
                for tc in msg.tool_calls:
                    tool_name = tc.function.name
                    try:
                        tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                    except Exception:
                        tool_args = {}

                    logger.info("Iteration %d: calling %s" % (iteration, tool_name))

                    # Execute tool — handles both sync and async execute_tool
                    result = await _safe_execute_tool(tool_name, tool_args)
                    result_str = str(result)

                    # Serialize result to ensure JSON-safe
                    result = _serialize_result(result)

                    tool_calls.append({
                        "tool": tool_name,
                        "tool_name": tool_name,
                        "args": tool_args,
                        "arguments": tool_args,
                        "result": result,
                        "duration_ms": 0
                    })

                    # Allocate tool result in kernel memory
                    if mem:
                        try:
                            mem.allocate(
                                process_id=pid,
                                content="Tool %s result: %s" % (tool_name, result_str[:2000]),
                                segment_type=MemorySegmentType.TOOL_RESULT,
                                importance=0.5
                            )
                        except Exception as e:
                            logger.debug("Memory alloc failed: %s" % e)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_str[:4000]
                    })
            else:
                agent_response = msg.content or ""
                break

        # Build context from kernel memory
        if mem:
            try:
                stats = mem.get_memory_stats(pid)
                logger.info("Kernel context for %s: %s" % (pid, json.dumps(stats)[:200]))
            except Exception as e:
                logger.debug("Stats failed: %s" % e)

    except Exception as e:
        success = False
        error_message = str(e)
        agent_response = "Agent execution failed: %s" % e
        logger.error("Kernel agent runner failed: %s" % e)

    duration_ms = int((time.time() - start_time) * 1000)

    return {
        "success": success,
        "agent_id": agent_id,
        "goal": goal,
        "summary": agent_response,
        "response": agent_response,
        "tool_calls": tool_calls,
        "iterations": iterations,
        "duration_ms": duration_ms,
        "pid": pid,
        "error": error_message,
        "kernel_managed": mem is not None,
    }
