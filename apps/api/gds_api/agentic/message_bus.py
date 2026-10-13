"""GDS OS Agentic Layer — Priority 2: Agent Message Bus.

Redis pub/sub-based message passing between agents. Enables:
- Agent A detects threat → publishes message → Agent B receives
- Agent B plans response → requests Agent C to execute containment
- Correlation IDs track multi-agent conversations
- Priority-based message routing
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

import redis.asyncio as aioredis

from gds_api.config import settings

logger = logging.getLogger("gds_api.agentic.message_bus")


# ============================================================================
# MESSAGE TYPES
# ============================================================================

class MessageType:
    THREAT_DETECTED = "threat_detected"
    VULN_FOUND = "vulnerability_found"
    INCIDENT_CREATED = "incident_created"
    REMEDIATION_REQUEST = "remediation_request"
    REMEDIATION_COMPLETE = "remediation_complete"
    COMPLIANCE_VIOLATION = "compliance_violation"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    AGENT_STATUS = "agent_status"
    HANDOFF = "task_handoff"
    ESCALATION = "escalation"
    COORDINATION = "coordination"
    QUERY = "query"
    RESPONSE = "response"
    BROADCAST = "broadcast"


# ============================================================================
# AGENT MESSAGE BUS
# ============================================================================

class AgentMessageBus:
    """Redis pub/sub message bus for agent-to-agent communication.

    Channels:
    - gds:bus:threats    — threat detections, incidents
    - gds:bus:remediation — fix requests, completions
    - gds:bus:approvals  — human-in-the-loop approval requests
    - gds:bus:coordination — agent-to-agent coordination
    - gds:bus:broadcast   — system-wide broadcasts
    """

    CHANNELS = {
        "threats": "gds:bus:threats",
        "remediation": "gds:bus:remediation",
        "approvals": "gds:bus:approvals",
        "coordination": "gds:bus:coordination",
        "broadcast": "gds:bus:broadcast",
        "compliance": "gds:bus:compliance",
    }

    MESSAGE_STORE_PREFIX = "gds:bus:msg"

    def __init__(self, redis: aioredis.Redis | None = None):
        self._redis = redis
        self._owned_redis = False
        self._subscriptions: dict[str, list[Callable]] = {}
        self._pubsub_tasks: dict[str, asyncio.Task] = {}

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis and not self._owned_redis:
            return self._redis
        self._redis = aioredis.Redis(
            host=settings.redis_host, port=settings.redis_port,
            decode_responses=True,
        )
        self._owned_redis = True
        return self._redis

    async def publish(
        self,
        channel: str,
        message_type: str,
        from_agent: str,
        to_agent: str | None = None,
        subject: str = "",
        payload: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        priority: int = 0,
    ) -> dict[str, Any]:
        """Publish a message to a channel."""
        if channel not in self.CHANNELS:
            raise ValueError(f"Unknown channel: {channel}. Available: {list(self.CHANNELS.keys())}")

        message_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        message = {
            "message_id": message_id,
            "type": message_type,
            "channel": channel,
            "from_agent": from_agent,
            "to_agent": to_agent or "*",
            "subject": subject,
            "payload": json.dumps(payload or {}),
            "correlation_id": correlation_id or str(uuid.uuid4()),
            "priority": priority,
            "timestamp": now,
        }

        r = await self._get_redis()
        # Store message for history
        await r.hset(f"{self.MESSAGE_STORE_PREFIX}:{message_id}", mapping=message)
        await r.expire(f"{self.MESSAGE_STORE_PREFIX}:{message_id}", 86400)  # 24h TTL

        # Publish to channel
        await r.publish(self.CHANNELS[channel], json.dumps(message))

        logger.info("message_published", message_id=message_id, channel=channel,
                     type=message_type, from_agent=from_agent, to_agent=to_agent or "broadcast")

        return {"message_id": message_id, "channel": channel, "status": "published"}

    async def subscribe(
        self,
        channel: str,
        handler: Callable[[dict[str, Any]], Awaitable[None]],
        agent_id: str = "",
    ) -> str:
        """Subscribe to a channel with an async handler."""
        if channel not in self.CHANNELS:
            raise ValueError(f"Unknown channel: {channel}")

        if channel not in self._subscriptions:
            self._subscriptions[channel] = []
        self._subscriptions[channel].append(handler)

        # Start pubsub listener if not already running
        if channel not in self._pubsub_tasks:
            sub_id = f"sub-{channel}-{agent_id}-{uuid.uuid4().hex[:6]}"
            task = asyncio.create_task(self._listen(channel), name=sub_id)
            self._pubsub_tasks[channel] = task
            logger.info("subscription_started", channel=channel, agent_id=agent_id)
            return sub_id

        return f"sub-{channel}-{agent_id}"

    async def _listen(self, channel: str):
        """Listen for messages on a channel and dispatch to handlers."""
        r = await self._get_redis()
        pubsub = r.pubsub()
        await pubsub.subscribe(self.CHANNELS[channel])

        logger.info("bus_listening", channel=channel)

        try:
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=5.0)
                if not message:
                    continue
                if message["type"] != "message":
                    continue

                try:
                    msg_data = json.loads(message["data"])
                    # Dispatch to all handlers for this channel
                    handlers = self._subscriptions.get(channel, [])
                    for handler in handlers:
                        try:
                            await handler(msg_data)
                        except Exception as e:
                            logger.error("handler_error", channel=channel, error=str(e))
                except json.JSONDecodeError:
                    logger.warning("invalid_message_format", channel=channel)

        except asyncio.CancelledError:
            pass
        finally:
            await pubsub.unsubscribe(self.CHANNELS[channel])
            await pubsub.close()

    async def get_message(self, message_id: str) -> dict[str, Any] | None:
        """Retrieve a stored message by ID."""
        r = await self._get_redis()
        data = await r.hgetall(f"{self.MESSAGE_STORE_PREFIX}:{message_id}")
        if not data:
            return None
        data["payload"] = json.loads(data.get("payload", "{}"))
        return data

    async def get_correlation_chain(self, correlation_id: str) -> list[dict[str, Any]]:
        """Get all messages in a conversation thread by correlation ID."""
        r = await self._get_redis()
        # Scan for messages with this correlation_id
        messages = []
        async for key in r.scan_iter(f"{self.MESSAGE_STORE_PREFIX}:*"):
            data = await r.hgetall(key)
            if data.get("correlation_id") == correlation_id:
                data["payload"] = json.loads(data.get("payload", "{}"))
                messages.append(data)
        # Sort by timestamp
        messages.sort(key=lambda m: m.get("timestamp", ""))
        return messages

    async def request_response(
        self,
        channel: str,
        message_type: str,
        from_agent: str,
        to_agent: str,
        subject: str,
        payload: dict[str, Any],
        timeout: float = 30.0,
    ) -> dict[str, Any] | None:
        """Send a message and wait for a response (request-response pattern)."""
        correlation_id = str(uuid.uuid4())
        response_future: asyncio.Future = asyncio.get_event_loop().create_future()

        async def response_handler(msg: dict[str, Any]):
            if msg.get("correlation_id") == correlation_id and msg.get("type") == MessageType.RESPONSE:
                if not response_future.done():
                    response_future.set_result(msg)

        await self.subscribe(channel, response_handler, from_agent)
        await self.publish(
            channel=channel, message_type=message_type,
            from_agent=from_agent, to_agent=to_agent,
            subject=subject, payload=payload,
            correlation_id=correlation_id,
        )

        try:
            return await asyncio.wait_for(response_future, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("request_response_timeout", to_agent=to_agent, subject=subject)
            return None

    async def get_bus_stats(self) -> dict[str, Any]:
        """Get message bus statistics."""
        r = await self._get_redis()
        pubsub_channels = await r.pubsub_numsub(*self.CHANNELS.values())
        return {
            "channels": {ch: count for ch, count in
                          zip(self.CHANNELS.values(), pubsub_channels) if isinstance(pubsub_channels, list)},
            "subscriptions": {ch: len(handlers) for ch, handlers in self._subscriptions.items()},
        }


# ============================================================================
# CONVENIENCE: AGENT COMMUNICATOR
# ============================================================================

class AgentCommunicator:
    """Wraps the message bus for a single agent's communication needs.

    Each agent gets its own communicator instance for clean scoping.
    """

    def __init__(self, agent_id: str, agent_name: str, bus: AgentMessageBus):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.bus = bus

    async def alert(self, subject: str, payload: dict[str, Any], severity: str = "high"):
        """Broadcast a security alert."""
        channel = "threats" if severity in ("critical", "high") else "broadcast"
        return await self.bus.publish(
            channel=channel, message_type=MessageType.THREAT_DETECTED,
            from_agent=self.agent_id, subject=subject,
            payload={**payload, "severity": severity},
        )

    async def request_remediation(self, finding_id: str, finding_data: dict[str, Any], to_agent: str = ""):
        """Request another agent to remediate a finding."""
        return await self.bus.publish(
            channel="remediation", message_type=MessageType.REMEDIATION_REQUEST,
            from_agent=self.agent_id, to_agent=to_agent or None,
            subject=f"Remediate finding {finding_id}",
            payload={"finding_id": finding_id, **finding_data},
        )

    async def request_approval(self, action: str, risk_level: str, payload: dict[str, Any]):
        """Request human approval for a high-risk action."""
        return await self.bus.publish(
            channel="approvals", message_type=MessageType.APPROVAL_REQUEST,
            from_agent=self.agent_id, subject=f"Approval required: {action}",
            payload={"action": action, "risk_level": risk_level, **payload},
        )

    async def handoff(self, to_agent: str, task_type: str, task_data: dict[str, Any]):
        """Hand off a task to another agent."""
        return await self.bus.publish(
            channel="coordination", message_type=MessageType.HANDOFF,
            from_agent=self.agent_id, to_agent=to_agent,
            subject=f"Task handoff: {task_type}",
            payload={"task_type": task_type, **task_data},
        )

    async def escalate(self, reason: str, current_severity: str, to_agent: str = ""):
        """Escalate an issue to a higher-level agent or human."""
        return await self.bus.publish(
            channel="coordination", message_type=MessageType.ESCALATION,
            from_agent=self.agent_id, to_agent=to_agent or None,
            subject=f"Escalation: {reason}",
            payload={"reason": reason, "current_severity": current_severity},
        )

    async def coordinate(self, to_agent: str, subject: str, payload: dict[str, Any]):
        """Send a coordination message to another agent."""
        return await self.bus.publish(
            channel="coordination", message_type=MessageType.COORDINATION,
            from_agent=self.agent_id, to_agent=to_agent,
            subject=subject, payload=payload,
        )

    async def listen(self, channel: str, handler: Callable[[dict[str, Any]], Awaitable[None]]):
        """Subscribe to a channel."""
        return await self.bus.subscribe(channel, handler, self.agent_id)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["MessageType", "AgentMessageBus", "AgentCommunicator"]
