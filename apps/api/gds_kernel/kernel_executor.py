"""
GDS Agent Kernel — Executor Bridge
====================================
Connects the new kernel to the existing VPS agent runtime.
Wraps the existing agent_loop.py functions as kernel executors.

When a process is dispatched by the scheduler, the kernel calls the
registered executor, which runs the existing GPT-4.1 function calling
loop but routes tool calls through the sandbox instead of directly.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Dict, Optional, Any

logger = logging.getLogger("gds.kernel.executor")

# Import the kernel
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gds_kernel.unified_kernel import GDSUnifiedKernel
from gds_kernel.process import AgentProcessControlBlock as APCB, ProcessState, ProcessPriority

# Environment
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GPT_MODEL = os.getenv("GPT_MODEL", "gpt-4.1")


class KernelExecutor:
    """
    Bridges the kernel scheduler with the existing VPS agent runtime.
    
    When the kernel dispatches a process, this executor:
    1. Builds the LLM prompt from the kernel's memory manager
    2. Calls OpenAI GPT-4.1 with function calling
    3. Routes tool calls through the kernel's sandbox
    4. Stores results back in the kernel's memory manager
    5. Handles approval gates through the kernel's syscall interface
    """

    def __init__(self, kernel: GDSUnifiedKernel):
        self.kernel = kernel
        self.openai_client = None
        self._init_openai()
        
        # Register this executor for all agents
        self._register_executors()
    
    def _init_openai(self):
        """Initialize the OpenAI client."""
        try:
            from openai import OpenAI
            self.openai_client = OpenAI(api_key=OPENAI_API_KEY)
            logger.info("OpenAI client initialized for kernel executor")
        except ImportError:
            logger.error("openai package not installed — kernel executor will use stub mode")
        except Exception as e:
            logger.error(f"Failed to init OpenAI client: {e}")
    
    def _register_executors(self):
        """Register this executor for all known agent IDs."""
        agent_ids = [
            "ai-chief-ciso", "ai-soc-director", "ai-incident-commander",
            "ai-cloud-director", "ai-vuln-director", "ai-remediation-director",
            "ai-threat-hunter", "ai-compliance-director", "ai-risk-director",
            "ai-devsecops-director", "ai-identity-director", "ai-threat-intel-director",
            "ai-ciem-director", "ai-zero-trust-architect", "ai-security-director",
            "ai-red-team-director", "ai-dark-web-monitor", "ai-predictive-risk-director",
            "ai-executive-advisor", "ai-gasci-orchestrator", "ai-audit-director",
            "ai-llm-security-director", "ai-agent-security-director",
        ]
        for agent_id in agent_ids:
            self.kernel.register_agent_executor(agent_id, self.execute_agent)
    
    async def execute_agent(self, apcb: APCB, syscall_interface=None) -> Dict[str, Any]:
        """
        Execute an agent process using the kernel's infrastructure.
        
        This replaces the existing agent_loop.py with a kernel-managed
        execution that routes through the sandbox and memory manager.
        """
        logger.info(f"Executing agent {apcb.agent_id} for task {apcb.task_name} (PID: {apcb.pid})")
        
        # Build the system prompt from kernel memory
        context_prompt = self.kernel.memory.build_context_prompt(apcb.pid)
        
        if not context_prompt:
            # Default system prompt if none allocated
            context_prompt = f"You are {apcb.agent_id}. Your task: {apcb.task_name}. Goal: {apcb.goal}"
        
        # Get available tools from the sandbox
        tool_drivers = self.kernel.sandbox.list_drivers()
        openai_tools = self._build_openai_tools(tool_drivers)
        
        # Build messages
        messages = [
            {"role": "system", "content": context_prompt},
            {"role": "user", "content": f"Execute task: {apcb.task_name}\nGoal: {apcb.goal}"},
        ]
        
        # Request LLM compute from the arbitrator
        llm_result = self.kernel.syscall.sys_llm_request(apcb.pid, estimated_tokens=5000)
        if not llm_result.success:
            return {"error": f"LLM compute denied: {llm_result.error}"}
        
        total_input_tokens = 0
        total_output_tokens = 0
        tool_calls_made = []
        
        # GPT-4.1 function calling loop (max 10 iterations)
        for iteration in range(10):
            # Update heartbeat
            self.kernel.scheduler.update_heartbeat(apcb.pid)
            
            try:
                if self.openai_client is None:
                    # Stub mode — no OpenAI API key
                    return {
                        "status": "stub_mode",
                        "message": "OpenAI client not available. Set OPENAI_API_KEY.",
                        "tool_calls": tool_calls_made,
                        "llm_usage": {"input_tokens": 0, "output_tokens": 0},
                    }
                
                response = self.openai_client.chat.completions.create(
                    model=GPT_MODEL,
                    messages=messages,
                    tools=openai_tools if openai_tools else None,
                    tool_choice="auto" if openai_tools else None,
                    max_tokens=4096,
                    temperature=0.1,
                )
                
                msg = response.choices[0].message
                total_input_tokens += response.usage.prompt_tokens
                total_output_tokens += response.usage.completion_tokens
                
                # Record LLM usage
                self.kernel.syscall.sys_llm_record(
                    apcb.pid,
                    response.usage.prompt_tokens,
                    response.usage.completion_tokens
                )
                
                # If no tool calls, we're done
                if not msg.tool_calls:
                    messages.append({"role": "assistant", "content": msg.content})
                    final_response = msg.content or ""
                    
                    # Store in kernel memory
                    self.kernel.syscall.sys_mem_alloc(
                        apcb.pid, final_response, "working", 0.7
                    )
                    
                    return {
                        "status": "completed",
                        "response": final_response,
                        "tool_calls": tool_calls_made,
                        "iterations": iteration + 1,
                        "llm_usage": {
                            "input_tokens": total_input_tokens,
                            "output_tokens": total_output_tokens,
                        },
                    }
                
                # Process tool calls through the sandbox
                messages.append({
                    "role": "assistant",
                    "content": msg.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                })
                
                for tc in msg.tool_calls:
                    tool_name = tc.function.name
                    try:
                        tool_args = json.loads(tc.function.arguments)
                    except:
                        tool_args = {}
                    
                    # Execute through the sandbox
                    logger.info(f"Agent {apcb.agent_id} calling tool: {tool_name}")
                    apcb.current_tool = tool_name
                    apcb.tools_called.append(tool_name)
                    
                    result = await self.kernel.syscall.sys_tool_call(
                        apcb.pid, tool_name, tool_args
                    )
                    
                    tool_output = json.dumps(result.data if result.success else {"error": result.error})
                    tool_calls_made.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "success": result.success,
                    })
                    
                    # Store tool result in kernel memory
                    self.kernel.syscall.sys_mem_alloc(
                        apcb.pid, f"Tool: {tool_name}\nResult: {tool_output[:2000]}",
                        "tool_result", 0.6
                    )
                    
                    # Add to conversation
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": tool_output[:4000],  # Truncate for context
                    })
                    
                    # Update heartbeat after each tool
                    self.kernel.scheduler.update_heartbeat(apcb.pid)
                
            except Exception as e:
                logger.error(f"Agent execution error at iteration {iteration}: {e}", exc_info=True)
                return {
                    "status": "error",
                    "error": str(e),
                    "tool_calls": tool_calls_made,
                    "llm_usage": {
                        "input_tokens": total_input_tokens,
                        "output_tokens": total_output_tokens,
                    },
                }
        
        # Max iterations reached
        return {
            "status": "max_iterations",
            "tool_calls": tool_calls_made,
            "iterations": 10,
            "llm_usage": {
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
            },
        }
    
    def _build_openai_tools(self, tool_drivers: list) -> list:
        """Convert kernel tool drivers to OpenAI function calling format."""
        tools = []
        for driver in tool_drivers:
            tools.append({
                "type": "function",
                "function": {
                    "name": driver["tool_id"],
                    "description": driver["description"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target host, URL, or identifier"},
                        },
                        "required": ["target"] if "network" in driver.get("capabilities", []) else [],
                    },
                },
            })
        return tools


def initialize_kernel_with_executors() -> GDSUnifiedKernel:
    """
    Initialize the kernel with all executors registered.
    Call this from the VPS FastAPI startup.
    """
    kernel = GDSUnifiedKernel()
    kernel.boot()
    
    # Wire in the executor
    executor = KernelExecutor(kernel)
    
    logger.info("Kernel initialized with executors — ready for agent dispatch")
    return kernel
