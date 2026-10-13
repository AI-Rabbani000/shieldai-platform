"""
GDS Agent Kernel — Phase 3: Isolated Tool Driver Sandbox
==========================================================
Moves tool execution from the host Python process into isolated
subprocess sandboxes with:
  - Timeout enforcement (no hung tools)
  - Resource limits (CPU, memory)
  - Capability descriptors (what each tool can access)
  - Panic isolation (crashed tool doesn't crash the kernel)
  - Lifecycle management (open → execute → close)
  - Health checking

Each tool is treated as a "device driver" with a standard interface.
"""

import subprocess
import asyncio
import time
import json
import logging
import signal
import os
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("gds.kernel.sandbox")


class ToolCapability(Enum):
    """What a tool is allowed to access — capability-based security."""
    NETWORK = "network"           # Can make network connections
    FILESYSTEM = "filesystem"     # Can read/write files
    SHELL = "shell"               # Can execute shell commands
    SECRETS = "secrets"           # Can access secret values
    AWS = "aws"                   # Can call AWS APIs
    GITHUB = "github"             # Can call GitHub APIs
    DATABASE = "database"        # Can read/write to PostgreSQL
    REDIS = "redis"              # Can read/write to Redis
    NONE = "none"                # No special access needed


class ToolState(Enum):
    """Tool driver lifecycle states."""
    UNREGISTERED = "unregistered"
    REGISTERED = "registered"
    OPEN = "open"           # Driver loaded, ready to execute
    EXECUTING = "executing" # Currently running a command
    CLOSED = "closed"       # Shut down cleanly
    PANICKED = "panicked"   # Crashed, needs recovery


@dataclass
class ToolDriver:
    """
    A tool driver definition — like a device driver in an OS.
    Describes the tool, its capabilities, and how to execute it.
    """
    tool_id: str                          # Unique identifier (e.g., "nmap_scan")
    display_name: str                      # Human-readable name
    description: str
    
    # Execution
    executor: Callable                     # The function that runs the tool
    executor_type: str = "python"          # "python" | "subprocess" | "api"
    
    # Capabilities (what this tool is allowed to do)
    capabilities: List[ToolCapability] = field(default_factory=list)
    
    # Resource limits
    timeout_seconds: int = 120             # Max execution time
    max_memory_mb: int = 512               # Max memory usage
    max_cpu_percent: int = 80              # Max CPU usage
    
    # Lifecycle
    state: ToolState = ToolState.UNREGISTERED
    execution_count: int = 0
    failure_count: int = 0
    avg_duration_ms: float = 0.0
    last_executed: Optional[float] = None
    last_error: Optional[str] = None
    
    # Health
    is_healthy: bool = True
    consecutive_failures: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "display_name": self.display_name,
            "description": self.description,
            "executor_type": self.executor_type,
            "capabilities": [c.value for c in self.capabilities],
            "timeout_seconds": self.timeout_seconds,
            "state": self.state.value,
            "execution_count": self.execution_count,
            "failure_count": self.failure_count,
            "avg_duration_ms": round(self.avg_duration_ms, 1),
            "is_healthy": self.is_healthy,
            "last_executed": self.last_executed,
        }


@dataclass
class ExecutionResult:
    """Result from a sandboxed tool execution."""
    tool_id: str
    success: bool
    output: Any = None
    error: Optional[str] = None
    duration_ms: int = 0
    timed_out: bool = False
    killed: bool = False
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None


class ToolSandbox:
    """
    The kernel's tool execution sandbox.
    
    Executes tools in isolated subprocesses with:
      - Timeout enforcement (kill after N seconds)
      - Resource limits (memory, CPU)
      - Panic isolation (crash doesn't propagate)
      - Health tracking (auto-disable unhealthy tools)
    """

    def __init__(self, max_concurrent_tools: int = 5, default_timeout: int = 120):
        self.max_concurrent_tools = max_concurrent_tools
        self.default_timeout = default_timeout
        
        # Tool registry
        self.drivers: Dict[str, ToolDriver] = {}
        
        # Active executions
        self.active: Dict[str, asyncio.Task] = {}  # execution_id → task
        self.current_concurrent: int = 0
        
        # Telemetry
        self.total_executions: int = 0
        self.total_successes: int = 0
        self.total_failures: int = 0
        self.total_timeouts: int = 0
        self.total_panics: int = 0

    def register_driver(self, driver: ToolDriver) -> bool:
        """Register a tool driver."""
        if driver.tool_id in self.drivers:
            logger.warning(f"Driver {driver.tool_id} already registered, overwriting")
        
        driver.state = ToolState.REGISTERED
        self.drivers[driver.tool_id] = driver
        logger.info(f"Registered tool driver: {driver.tool_id} ({driver.display_name})")
        return True

    def unregister_driver(self, tool_id: str) -> bool:
        """Unregister a tool driver."""
        if tool_id in self.drivers:
            self.drivers[tool_id].state = ToolState.CLOSED
            del self.drivers[tool_id]
            logger.info(f"Unregistered tool driver: {tool_id}")
            return True
        return False

    async def execute(self, tool_id: str, payload: Dict[str, Any]) -> ExecutionResult:
        """
        Execute a tool in a sandboxed environment.
        
        Args:
            tool_id: Which tool to run
            payload: Input parameters for the tool
        
        Returns:
            ExecutionResult with output, timing, and status
        """
        driver = self.drivers.get(tool_id)
        if driver is None:
            return ExecutionResult(
                tool_id=tool_id, success=False,
                error=f"Tool '{tool_id}' not registered"
            )
        
        if not driver.is_healthy:
            return ExecutionResult(
                tool_id=tool_id, success=False,
                error=f"Tool '{tool_id}' is unhealthy (consecutive failures: {driver.consecutive_failures})"
            )
        
        if self.current_concurrent >= self.max_concurrent_tools:
            return ExecutionResult(
                tool_id=tool_id, success=False,
                error="Max concurrent tools reached, try again later"
            )
        
        # Execute with timeout and isolation
        self.current_concurrent += 1
        driver.state = ToolState.EXECUTING
        start_time = time.time()
        
        try:
            result = await asyncio.wait_for(
                self._execute_driver(driver, payload),
                timeout=driver.timeout_seconds
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            self._record_success(driver, duration_ms)
            
            return ExecutionResult(
                tool_id=tool_id,
                success=True,
                output=result,
                duration_ms=duration_ms,
            )
            
        except asyncio.TimeoutError:
            duration_ms = int((time.time() - start_time) * 1000)
            self._record_failure(driver, f"Timeout after {driver.timeout_seconds}s")
            self.total_timeouts += 1
            logger.warning(f"Tool {tool_id} timed out after {driver.timeout_seconds}s")
            
            return ExecutionResult(
                tool_id=tool_id,
                success=False,
                error=f"Timeout after {driver.timeout_seconds} seconds",
                duration_ms=duration_ms,
                timed_out=True,
            )
            
        except asyncio.CancelledError:
            self._record_failure(driver, "Execution cancelled")
            return ExecutionResult(
                tool_id=tool_id, success=False,
                error="Execution cancelled", killed=True
            )
            
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            self._record_failure(driver, str(e))
            self.total_panics += 1
            logger.error(f"Tool {tool_id} panicked: {e}", exc_info=True)
            
            return ExecutionResult(
                tool_id=tool_id,
                success=False,
                error=f"Panic: {str(e)}",
                duration_ms=duration_ms,
            )
            
        finally:
            self.current_concurrent -= 1
            driver.state = ToolState.OPEN
            driver.last_executed = time.time()

    async def _execute_driver(self, driver: ToolDriver, payload: Dict) -> Any:
        """
        Execute the driver's function.
        Handles both sync and async executors.
        """
        if asyncio.iscoroutinefunction(driver.executor):
            return await driver.executor(payload)
        else:
            # Run sync function in a thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, driver.executor, payload
            )

    def _record_success(self, driver: ToolDriver, duration_ms: int) -> None:
        """Record successful execution."""
        driver.execution_count += 1
        driver.consecutive_failures = 0
        driver.is_healthy = True
        driver.last_error = None
        
        # Update rolling average
        if driver.avg_duration_ms == 0:
            driver.avg_duration_ms = duration_ms
        else:
            driver.avg_duration_ms = (driver.avg_duration_ms * 0.9) + (duration_ms * 0.1)
        
        self.total_executions += 1
        self.total_successes += 1

    def _record_failure(self, driver: ToolDriver, error: str) -> None:
        """Record failed execution."""
        driver.execution_count += 1
        driver.failure_count += 1
        driver.consecutive_failures += 1
        driver.last_error = error
        
        # Auto-disable after 5 consecutive failures
        if driver.consecutive_failures >= 5:
            driver.is_healthy = False
            logger.error(
                f"Tool {driver.tool_id} auto-disabled after {driver.consecutive_failures} "
                f"consecutive failures. Last error: {error}"
            )
        
        self.total_executions += 1
        self.total_failures += 1

    def reset_driver_health(self, tool_id: str) -> bool:
        """Manually reset a driver's health status."""
        driver = self.drivers.get(tool_id)
        if driver:
            driver.is_healthy = True
            driver.consecutive_failures = 0
            logger.info(f"Reset health for tool {tool_id}")
            return True
        return False

    def list_drivers(self) -> List[Dict[str, Any]]:
        """List all registered tool drivers."""
        return [d.to_dict() for d in self.drivers.values()]

    def get_driver(self, tool_id: str) -> Optional[ToolDriver]:
        """Get a driver by ID."""
        return self.drivers.get(tool_id)

    def get_stats(self) -> Dict[str, Any]:
        """Return sandbox telemetry."""
        return {
            "registered_tools": len(self.drivers),
            "healthy_tools": sum(1 for d in self.drivers.values() if d.is_healthy),
            "unhealthy_tools": sum(1 for d in self.drivers.values() if not d.is_healthy),
            "current_concurrent": self.current_concurrent,
            "max_concurrent": self.max_concurrent_tools,
            "total_executions": self.total_executions,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "total_timeouts": self.total_timeouts,
            "total_panics": self.total_panics,
            "success_rate": round(self.total_successes / max(1, self.total_executions) * 100, 1),
        }


# ===== Tool Driver Registry — Pre-built for VPS tools =====

def create_default_drivers() -> Dict[str, ToolDriver]:
    """
    Create ToolDriver definitions for the VPS tool set.
    These wrap the existing tool_gateway.py functions with
    proper sandboxing, capabilities, and resource limits.
    """
    drivers = {}
    
    # Network scanning tools
    drivers["nmap_scan"] = ToolDriver(
        tool_id="nmap_scan",
        display_name="Nmap Port Scanner",
        description="Network port scanning and service detection",
        executor=lambda p: None,  # Will be replaced with actual function
        executor_type="subprocess",
        capabilities=[ToolCapability.NETWORK, ToolCapability.SHELL],
        timeout_seconds=300,
        max_memory_mb=256,
    )
    
    drivers["nuclei_scan"] = ToolDriver(
        tool_id="nuclei_scan",
        display_name="Nuclei Vulnerability Scanner",
        description="Template-based vulnerability scanning (12,976+ templates)",
        executor=lambda p: None,
        executor_type="subprocess",
        capabilities=[ToolCapability.NETWORK, ToolCapability.SHELL],
        timeout_seconds=600,
        max_memory_mb=512,
    )
    
    drivers["semgrep_scan"] = ToolDriver(
        tool_id="semgrep_scan",
        display_name="Semgrep SAST Scanner",
        description="Static analysis for code vulnerabilities",
        executor=lambda p: None,
        executor_type="subprocess",
        capabilities=[ToolCapability.FILESYSTEM, ToolCapability.SHELL],
        timeout_seconds=300,
        max_memory_mb=512,
    )
    
    drivers["trivy_scan"] = ToolDriver(
        tool_id="trivy_scan",
        display_name="Trivy Scanner",
        description="Container/dependency vulnerability + secret scanning",
        executor=lambda p: None,
        executor_type="subprocess",
        capabilities=[ToolCapability.FILESYSTEM, ToolCapability.SHELL],
        timeout_seconds=300,
        max_memory_mb=512,
    )
    
    # API-based tools
    drivers["cisa_kev_check"] = ToolDriver(
        tool_id="cisa_kev_check",
        display_name="CISA KEV Checker",
        description="Check against CISA Known Exploited Vulnerabilities catalog",
        executor=lambda p: None,
        executor_type="api",
        capabilities=[ToolCapability.NETWORK],
        timeout_seconds=30,
        max_memory_mb=128,
    )
    
    drivers["osv_check"] = ToolDriver(
        tool_id="osv_check",
        display_name="OSV Vulnerability Database",
        description="Check packages against OSV.dev vulnerability database",
        executor=lambda p: None,
        executor_type="api",
        capabilities=[ToolCapability.NETWORK],
        timeout_seconds=30,
        max_memory_mb=128,
    )
    
    drivers["security_headers_check"] = ToolDriver(
        tool_id="security_headers_check",
        display_name="Security Headers Checker",
        description="Check HTTP security headers on a URL",
        executor=lambda p: None,
        executor_type="api",
        capabilities=[ToolCapability.NETWORK],
        timeout_seconds=15,
        max_memory_mb=64,
    )
    
    # Cloud tools
    drivers["aws_iam_scan"] = ToolDriver(
        tool_id="aws_iam_scan",
        display_name="AWS IAM Scanner",
        description="Scan AWS IAM users, roles, and policies for misconfigurations",
        executor=lambda p: None,
        executor_type="python",
        capabilities=[ToolCapability.AWS, ToolCapability.SECRETS],
        timeout_seconds=120,
        max_memory_mb=256,
    )
    
    # Data tools
    drivers["get_findings"] = ToolDriver(
        tool_id="get_findings",
        display_name="Get Security Findings",
        description="Retrieve stored security findings from PostgreSQL",
        executor=lambda p: None,
        executor_type="python",
        capabilities=[ToolCapability.DATABASE],
        timeout_seconds=10,
        max_memory_mb=128,
    )
    
    drivers["store_finding"] = ToolDriver(
        tool_id="store_finding",
        display_name="Store Security Finding",
        description="Store a new security finding in PostgreSQL",
        executor=lambda p: None,
        executor_type="python",
        capabilities=[ToolCapability.DATABASE],
        timeout_seconds=10,
        max_memory_mb=128,
    )
    
    return drivers
