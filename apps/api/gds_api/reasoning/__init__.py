"""GDS OS Reasoning Engine — LLM-powered agentic loop.

Agents use OpenAI GPT-4.1 function calling to decide which tools to use
and in what order. No pre-programmed routing — agents REASON.
"""
from gds_api.reasoning.agent_loop import AgenticLoop, AgentResult
from gds_api.reasoning.tool_definitions import get_tool_definitions, get_tool_names
from gds_api.reasoning.prompts import get_agent_prompt, list_agents, AGENT_REGISTRY

__all__ = [
    "AgenticLoop", "AgentResult",
    "get_tool_definitions", "get_tool_names",
    "get_agent_prompt", "list_agents", "AGENT_REGISTRY"
]
