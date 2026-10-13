"""The Core LLM Reasoning Loop — GDS OS Agentic Engine.

Agents use OpenAI GPT-4.1 function calling to decide which tools to use
and in what order. No pre-programmed routing — agents REASON.
"""
import os, sys, json, asyncio, time, logging
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("gds.reasoning")

try:
    from openai import AsyncOpenAI
except ImportError:
    logger.error("openai package not installed. Run: pip install openai")
    raise

# Import tool gateway functions directly (this is what the module actually exports)
from gds_api.tool_gateway import execute_tool, list_tools, TOOL_REGISTRY
from gds_api.reasoning.prompts import get_agent_prompt, AGENT_REGISTRY
from gds_api.reasoning.tool_definitions import get_tool_definitions, get_tool_names
from gds_api.reasoning.kernel_agent_loop import run_kernel_agent


@dataclass
class ToolCall:
    """Record of a single tool call made by the agent."""
    tool_name: str
    arguments: dict
    result: dict
    duration_ms: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass 
class AgentResult:
    """Final result of an agent mission."""
    agent_id: str
    goal: str
    success: bool
    summary: str
    tool_calls: list
    iterations: int
    duration_ms: int
    error: Optional[str] = None
    kernel_managed: bool = False


# Tool name mapping: OpenAI function name → TOOL_REGISTRY key
TOOL_NAME_MAP = {
    "security_headers_check": "check_url_security_headers",
    "cisa_kev_check": "check_cisa_kev",
    "osv_check": "search_osv",
    # These already match TOOL_REGISTRY keys directly:
    # nmap_scan, nuclei_scan, semgrep_scan, trivy_scan, nikto_scan,
    # sqlmap_scan, masscan_scan, subfinder_scan, httpx_probe (note: httpx_scan not httpx_probe),
    "httpx_scan": "httpx_probe",
    # ffuf_scan, gobuster_scan, wpscan_scan — all match directly
}

# Parameter name mapping: OpenAI tool param name → tool_gateway param name
# Some tools expect "url" instead of "target", or "domain" instead of "target"
PARAM_MAP = {
    "check_url_security_headers": {"target": "url", "target_url": "url"},
    "check_url_headers": {"target": "url", "target_url": "url"},
    "check_domain_security": {"target": "domain", "target_url": "domain"},
    "nmap_scan": {"target": "target"},  # nmap uses "target" — matches
    "nuclei_scan": {"target": "target"},  # nuclei uses "target" — matches
    "httpx_probe": {"target": "target"},
    "subfinder_scan": {"target": "domain"},
    "gobuster_scan": {"target": "url"},
    "ffuf_scan": {"target": "url"},
    "nikto_scan": {"target": "target", "target_url": "target"},
    "wpscan_scan": {"target": "url"},
    "check_cisa_kev": {},  # no params needed
    "search_osv": {"target": "package", "package_name": "package"},
}


class AgenticLoop:
    """The core reasoning engine — agents that THINK, not just execute."""
    
    MAX_ITERATIONS = 10
    MODEL = "gpt-4.1"
    
    def __init__(self, agent_id: str, model: str = None):
        self.agent_id = agent_id
        self.model = model or self.MODEL
        self.client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        self.tool_registry = TOOL_REGISTRY
        self.execute_tool_fn = execute_tool
        self.get_prompt = get_agent_prompt
        self.get_tools = get_tool_definitions
        self.get_tool_names = get_tool_names
        
        if agent_id not in AGENT_REGISTRY:
            logger.warning(f"Unknown agent: {agent_id}. Using default prompt.")
    
    async def run(self, goal: str, context: dict = None) -> AgentResult:
        """Execute the agent loop: Observe → Reason → Act → Verify → Loop."""
        start_time = time.time()
        tool_calls = []
        
        system_prompt = self.get_prompt(self.agent_id)
        context_str = json.dumps(context or {}, indent=2) if context else "None"
        
        user_message = f"""## GOAL
{goal}

## CONTEXT
{context_str}

## INSTRUCTIONS
Use your available tools to accomplish this goal. Think step by step.
Explain your reasoning before each tool call. After getting results,
analyze them and decide the next step. When done, provide a summary.
"""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
        
        tools = self.get_tools(self.agent_id)
        tool_names = self.get_tool_names(self.agent_id)
        
        logger.info(f"Agent {self.agent_id} starting: {goal[:100]}")
        logger.info(f"Available tools: {tool_names}")
        
        last_error = None
        
        for iteration in range(self.MAX_ITERATIONS):
            logger.info(f"Iteration {iteration + 1}/{self.MAX_ITERATIONS}")
            
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=0.1,
                    max_tokens=4096,
                )
                
                msg = response.choices[0].message
                
                if msg.tool_calls:
                    messages.append({
                        "role": "assistant",
                        "content": msg.content,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments
                                }
                            }
                            for tc in msg.tool_calls
                        ]
                    })
                    
                    for tool_call in msg.tool_calls:
                        tool_name = tool_call.function.name
                        try:
                            args = json.loads(tool_call.function.arguments)
                        except json.JSONDecodeError:
                            args = {}
                        
                        logger.info(f"  Tool: {tool_name}({json.dumps(args)[:200]})")
                        
                        tool_start = time.time()
                        try:
                            result = await self._execute_tool(tool_name, args)
                            duration_ms = int((time.time() - tool_start) * 1000)
                            
                            tool_calls.append(ToolCall(
                                tool_name=tool_name, arguments=args,
                                result=result, duration_ms=duration_ms
                            ))
                            
                            logger.info(f"  Result: {json.dumps(result)[:200]}")
                            
                            result_str = json.dumps(result) if isinstance(result, (dict, list)) else str(result)
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": result_str[:4000]
                            })
                            
                        except Exception as e:
                            duration_ms = int((time.time() - tool_start) * 1000)
                            error_result = {"error": str(e), "tool": tool_name}
                            
                            tool_calls.append(ToolCall(
                                tool_name=tool_name, arguments=args,
                                result=error_result, duration_ms=duration_ms
                            ))
                            
                            logger.error(f"  Error: {e}")
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": json.dumps(error_result)
                            })
                    
                    continue
                
                # No tool call → agent is done
                summary = msg.content or "No summary provided."
                total_ms = int((time.time() - start_time) * 1000)
                
                logger.info(f"Done in {iteration + 1} iterations, {total_ms}ms")
                
                return AgentResult(
                    agent_id=self.agent_id, goal=goal, success=True,
                    summary=summary, tool_calls=tool_calls,
                    iterations=iteration + 1, duration_ms=total_ms
                )
                
            except Exception as e:
                last_error = str(e)
                logger.error(f"Iteration {iteration + 1} error: {e}")
                
                if "api_key" in str(e).lower() or "authentication" in str(e).lower():
                    break
                
                messages.append({
                    "role": "system",
                    "content": f"Error: {e}. Try a different approach."
                })
                continue
        
        total_ms = int((time.time() - start_time) * 1000)
        return AgentResult(
            agent_id=self.agent_id, goal=goal, success=False,
            summary=f"Max iterations or error: {last_error}",
            tool_calls=tool_calls, iterations=self.MAX_ITERATIONS,
            duration_ms=total_ms, error=last_error
        )
    
    async def _execute_tool(self, tool_name: str, args: dict) -> dict:
        """Execute a tool through the tool gateway."""
        
        # Tools handled directly
        if tool_name == "store_finding":
            return await self._store_finding(args)
        elif tool_name == "get_findings":
            return await self._get_findings(args)
        elif tool_name == "aws_iam_scan":
            return await self._aws_iam_scan(args)
        
        # Map OpenAI tool name to TOOL_REGISTRY key
        gateway_name = TOOL_NAME_MAP.get(tool_name, tool_name)
        
        # Verify tool exists
        if gateway_name not in self.tool_registry:
            return {"error": f"Tool {tool_name} not in TOOL_REGISTRY (tried {gateway_name})",
                    "available": list(self.tool_registry.keys())[:20]}
        
        # Apply parameter name mapping
        param_map = PARAM_MAP.get(gateway_name, {})
        mapped_args = {}
        for k, v in args.items():
            mapped_key = param_map.get(k, k)
            mapped_args[mapped_key] = v
        # Also try common fallbacks
        if "url" not in mapped_args and "target" in mapped_args:
            if gateway_name in ("check_url_security_headers", "check_url_headers", "gobuster_scan", "ffuf_scan", "wpscan_scan"):
                mapped_args["url"] = mapped_args["target"]
            elif gateway_name in ("check_domain_security", "subfinder_scan"):
                mapped_args["domain"] = mapped_args["target"]
        
        try:
            result = await self.execute_tool_fn(gateway_name, payload=mapped_args)
            
            if isinstance(result, str):
                try:
                    return json.loads(result)
                except:
                    return {"result": result}
            elif isinstance(result, dict):
                return result
            else:
                return {"result": str(result)}
                
        except Exception as e:
            return {"error": f"Tool failed: {str(e)}", "tool": gateway_name}
    
    async def _store_finding(self, args: dict) -> dict:
        """Store a security finding in PostgreSQL."""
        try:
            from sqlalchemy import create_engine, text
            DB_URL = os.getenv("DATABASE_URL", "")
            engine = create_engine(DB_URL)
            
            with engine.connect() as conn:
                # Wrap details in valid JSON (DB column is JSONB)
                details_raw = args.get("details", "{}")
                if isinstance(details_raw, dict):
                    details_json = json.dumps(details_raw)
                elif isinstance(details_raw, str):
                    # If it's a plain string, wrap in a JSON object
                    try:
                        json.loads(details_raw)  # Already valid JSON?
                        details_json = details_raw
                    except:
                        details_json = json.dumps({"description": details_raw})
                else:
                    details_json = json.dumps({"description": str(details_raw)})
                
                conn.execute(text("""
                    INSERT INTO security_findings (scanner, title, severity, target, details, remediation, status, detected_at)
                    VALUES (:s, :t, :se, :tg, CAST(:d AS JSONB), :r, 'open', NOW())
                """), {
                    "s": args.get("scanner", "agent"),
                    "t": args.get("title", "Untitled"),
                    "se": args.get("severity", "info"),
                    "tg": args.get("target", ""),
                    "d": details_json,
                    "r": args.get("remediation", "")
                })
                conn.commit()
            
            return {"success": True, "message": "Finding stored"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _get_findings(self, args: dict) -> dict:
        """Retrieve findings from PostgreSQL."""
        try:
            from sqlalchemy import create_engine, text
            DB_URL = os.getenv("DATABASE_URL", "")
            engine = create_engine(DB_URL)
            
            status = args.get("status", "open")
            severity = args.get("severity")
            
            query = "SELECT id, scanner, title, severity, target, status, detected_at FROM security_findings"
            conditions = []
            params = {}
            
            if status != "all":
                conditions.append("status = :status")
                params["status"] = status
            
            if severity:
                conditions.append("severity = :severity")
                params["severity"] = severity
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY detected_at DESC LIMIT 50"
            
            with engine.connect() as conn:
                result = conn.execute(text(query), params)
                findings = [
                    {"id": str(row[0]), "scanner": row[1], "title": row[2], 
                     "severity": row[3], "target": row[4], "status": row[5]}
                    for row in result
                ]
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            return {"error": str(e)}
    
    async def _aws_iam_scan(self, args: dict) -> dict:
        """AWS IAM scan using boto3."""
        try:
            import boto3
            AWS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
            AWS_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY")
            AWS_REGION = os.environ.get("AWS_REGION", "eu-west-2")
            
            iam = boto3.client('iam', region_name=AWS_REGION,
                              aws_access_key_id=AWS_KEY,
                              aws_secret_access_key=AWS_SECRET)
            
            check_type = args.get("check_type", "all")
            findings = []
            
            if check_type in ("users", "mfa", "all"):
                users = iam.list_users()
                for user in users['Users']:
                    username = user['UserName']
                    mfa = iam.list_mfa_devices(UserName=username)
                    if not mfa['MFADevices']:
                        findings.append({
                            "title": f"No MFA for user {username}",
                            "severity": "high",
                            "target": f"aws:iam:{username}"
                        })
            
            if check_type in ("policy", "all"):
                try:
                    iam.get_account_password_policy()
                except:
                    findings.append({
                        "title": "No IAM password policy set",
                        "severity": "high",
                        "target": "aws:iam:account"
                    })
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            pass  # Memory stats are non-critical
        
            return {"error": str(e)}
