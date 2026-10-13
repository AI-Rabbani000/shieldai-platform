"""GDS OS Agentic Layer — Priority 7: Real-Time Threat Streaming.

Provides real-time threat streaming capabilities to clients via Server-Sent Events (SSE)
and WebSockets. Ensures security operations center (SOC) analysts and clients see live
operational updates rather than static dashboard data.

Uses Redis Streams (XADD/XREAD) for persistence and historical playback, combined
with Redis Pub/Sub for multi-instance event propagation and real-time push.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis

from gds_api.config import settings

logger = logging.getLogger("gds_api.agentic.threat_stream")

# ============================================================================
# CONSTANTS & REDIS KEYS
# ============================================================================

STREAM_KEY_PREFIX = "gds:stream:"
PUBSUB_KEY_PREFIX = "gds:pubsub:"
DEFAULT_MAX_STREAM_LEN = 1000


def get_stream_key(channel: str) -> str:
    """Get the Redis Stream key for a given channel name (e.g. gds:stream:alerts)."""
    return f"{STREAM_KEY_PREFIX}{channel}"


def get_pubsub_channel(channel: str) -> str:
    """Get the Redis Pub/Sub channel key for a given channel name (e.g. gds:pubsub:alerts)."""
    return f"{PUBSUB_KEY_PREFIX}{channel}"


# ============================================================================
# STREAM CHANNELS
# ============================================================================


class StreamChannel:
    """Constants for real-time threat stream channels in GDS OS."""

    ALERTS = "alerts"
    INCIDENTS = "incidents"
    RISK_SCORES = "risk_scores"
    AGENT_ACTIVITY = "agent_activity"
    ATTACK_GRAPH = "attack_graph"
    THREAT_INTEL = "threat_intel"
    COMPLIANCE = "compliance"

    ALL: list[str] = [
        ALERTS,
        INCIDENTS,
        RISK_SCORES,
        AGENT_ACTIVITY,
        ATTACK_GRAPH,
        THREAT_INTEL,
        COMPLIANCE,
    ]


# ============================================================================
# STREAM EVENT
# ============================================================================


@dataclass
class StreamEvent:
    """Dataclass representing a real-time threat stream event.

    Contains standard event envelope metadata along with channel, event_type,
    and structured payload data. Supports dictionary interface for compatibility.
    """

    channel: str
    event_type: str
    data: dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=lambda: time.time())
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        """Convert StreamEvent to a standard dictionary representation."""
        return {
            "event_id": self.event_id,
            "channel": self.channel,
            "event_type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp,
            "iso_timestamp": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StreamEvent:
        """Construct a StreamEvent instance from a dictionary."""
        return cls(
            event_id=str(data.get("event_id", uuid.uuid4())),
            channel=str(data.get("channel", StreamChannel.ALERTS)),
            event_type=str(data.get("event_type", "unknown")),
            data=data.get("data", {}) if isinstance(data.get("data"), dict) else {},
            timestamp=float(data.get("timestamp", time.time())),
            severity=str(data.get("severity", "info")),
        )

    def to_json(self) -> str:
        """Serialize StreamEvent to a JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_json(cls, json_str: str) -> StreamEvent:
        """Deserialize a StreamEvent from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


# ============================================================================
# SSE FORMATTER
# ============================================================================


class SSEFormatter:
    """Formatter for Server-Sent Events (SSE) compliant streaming output."""

    @staticmethod
    def format_event(event: StreamEvent | dict[str, Any]) -> str:
        """Format an event object or dictionary into SSE wire protocol format.

        Outputs:
        id: <event_id>
        event: <event_type>
        data: <json payload>
        """
        if isinstance(event, StreamEvent):
            event_dict = event.to_dict()
        elif isinstance(event, dict):
            event_dict = event
        else:
            event_dict = {"data": str(event)}

        event_id = event_dict.get("event_id")
        event_type = event_dict.get("event_type")
        json_payload = json.dumps(event_dict, default=str)

        lines: list[str] = []
        if event_id:
            lines.append(f"id: {event_id}")
        if event_type:
            lines.append(f"event: {event_type}")
        lines.append(f"data: {json_payload}")

        return "\n".join(lines) + "\n\n"

    @staticmethod
    def format_heartbeat() -> str:
        """Format a comment heartbeat line to keep idle SSE connections alive."""
        return ": heartbeat\n\n"


# ============================================================================
# THREAT STREAM HUB
# ============================================================================


class ThreatStreamHub:
    """Central Hub for Real-Time Security Operations and Threat Streaming.

    Coordinates live updates across WebSockets and Server-Sent Events (SSE).
    Uses Redis Streams (XADD/XREAD) for persistence and event history (max 1000 items),
    and Redis Pub/Sub for cross-process broadcasting.
    """

    def __init__(self, redis: aioredis.Redis | None = None):
        self._redis = redis
        self._owned_redis = False

        # WebSocket connection tracking:
        # _ws_clients maps websocket -> set of subscribed channel names
        self._ws_clients: dict[Any, set[str]] = {}
        # _channel_ws maps channel -> set of subscribed websockets
        self._channel_ws: dict[str, set[Any]] = {ch: set() for ch in StreamChannel.ALL}
        # _ws_all_channels holds websockets subscribed to all channels ("*" or "all")
        self._ws_all_channels: set[Any] = set()

        # SSE in-memory subscriber queues per channel
        self._sse_subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {
            ch: set() for ch in StreamChannel.ALL
        }
        self._sse_all_channels: set[asyncio.Queue[dict[str, Any]]] = set()

        # Lock for thread-safe state modification
        self._lock = asyncio.Lock()

        # Operational metrics tracking
        self._total_broadcasts = 0
        self._total_ws_connected = 0
        self._total_sse_subscriptions = 0
        self._channel_counts: dict[str, int] = {ch: 0 for ch in StreamChannel.ALL}

        # Background Pub/Sub listener handles
        self._pubsub_task: asyncio.Task[None] | None = None
        self._pubsub_client: Any = None

    async def _get_redis(self) -> aioredis.Redis:
        """Retrieve active Redis connection or lazy-initialize a new client."""
        if self._redis and not self._owned_redis:
            return self._redis
        if self._redis is None:
            self._redis = aioredis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                decode_responses=True,
            )
            self._owned_redis = True
        return self._redis

    async def broadcast(
        self,
        channel: str,
        event_type: str,
        data: dict[str, Any],
        severity: str = "info",
    ) -> StreamEvent:
        """Broadcast a new threat event to connected WebSocket clients and SSE streams.

        Persists event to Redis Stream (XADD maxlen 1000) and publishes to
        Redis Pub/Sub for multi-instance sync.

        Args:
            channel: Target channel name (from StreamChannel)
            event_type: Specific event identifier
            data: Structured event payload
            severity: Event severity level ('info', 'warning', 'high', 'critical')

        Returns:
            StreamEvent object constructed for this broadcast.
        """
        event = StreamEvent(
            channel=channel,
            event_type=event_type,
            data=data,
            severity=severity,
        )
        event_dict = event.to_dict()
        payload_json = json.dumps(event_dict, default=str)

        r = await self._get_redis()

        # 1. Persist to Redis Stream with max 1000 length capped
        stream_key = get_stream_key(channel)
        try:
            await r.xadd(
                stream_key,
                {"payload": payload_json},
                maxlen=DEFAULT_MAX_STREAM_LEN,
                approximate=True,
            )
        except Exception as exc:
            logger.error("Failed to append event to Redis Stream %s: %s", stream_key, exc)

        # 2. Publish to Redis Pub/Sub for cross-instance broadcasting
        pubsub_channel = get_pubsub_channel(channel)
        try:
            await r.publish(pubsub_channel, payload_json)
        except Exception as exc:
            logger.error("Failed to publish event to Redis Pub/Sub %s: %s", pubsub_channel, exc)

        # 3. Local dispatch to directly attached WebSocket and SSE clients
        await self._dispatch_local(channel, event_dict)

        # Update telemetry stats
        async with self._lock:
            self._total_broadcasts += 1
            self._channel_counts[channel] = self._channel_counts.get(channel, 0) + 1

        return event

    async def _dispatch_local(self, channel: str, event_dict: dict[str, Any]) -> None:
        """Deliver event payload to local WebSocket clients and active SSE subscriber queues."""
        target_websockets: set[Any] = set()
        async with self._lock:
            if channel in self._channel_ws:
                target_websockets.update(self._channel_ws[channel])
            target_websockets.update(self._ws_all_channels)

        for ws in target_websockets:
            await self._send_websocket(ws, event_dict)

        target_queues: list[asyncio.Queue[dict[str, Any]]] = []
        async with self._lock:
            if channel in self._sse_subscribers:
                target_queues.extend(self._sse_subscribers[channel])
            target_queues.extend(self._sse_all_channels)

        for q in target_queues:
            try:
                q.put_nowait(event_dict)
            except asyncio.QueueFull:
                logger.warning("SSE subscriber queue full, dropping event for channel %s", channel)

    async def _send_websocket(self, websocket: Any, event_dict: dict[str, Any]) -> None:
        """Send event dictionary to a WebSocket connection safely."""
        try:
            if hasattr(websocket, "send_json"):
                await websocket.send_json(event_dict)
            elif hasattr(websocket, "send_text"):
                await websocket.send_text(json.dumps(event_dict, default=str))
            elif callable(websocket):
                await websocket(event_dict)
        except Exception as exc:
            logger.warning("Failed sending message to WebSocket client: %s", exc)
            await self.remove_websocket_client(websocket)

    async def add_websocket_client(self, websocket: Any, channels: list[str]) -> None:
        """Register a WebSocket client and track subscriptions per channel.

        Args:
            websocket: Active WebSocket connection object
            channels: List of channel names to subscribe to (or ['all'] / ['*'])
        """
        async with self._lock:
            channel_set = set(channels)
            self._ws_clients[websocket] = channel_set

            if "all" in channel_set or "*" in channel_set:
                self._ws_all_channels.add(websocket)
            else:
                for ch in channel_set:
                    if ch in self._channel_ws:
                        self._channel_ws[ch].add(websocket)
                    else:
                        self._channel_ws.setdefault(ch, set()).add(websocket)

            self._total_ws_connected += 1
            logger.info("Added WebSocket client for channels: %s", channels)

    async def remove_websocket_client(self, websocket: Any) -> None:
        """Unregister a WebSocket client connection and cleanup channel tracking.

        Args:
            websocket: WebSocket connection object to remove
        """
        async with self._lock:
            if websocket in self._ws_clients:
                subscribed_channels = self._ws_clients.pop(websocket)
                self._ws_all_channels.discard(websocket)
                for ch in subscribed_channels:
                    if ch in self._channel_ws:
                        self._channel_ws[ch].discard(websocket)
                logger.info("Removed WebSocket client")

    async def subscribe_client(
        self,
        channel: str,
        last_event_id: str = "$",
    ) -> AsyncGenerator[str, None]:
        """Subscribe an SSE client generator to a channel for real-time streaming.

        Yields formatted SSE strings for new events and periodic heartbeats.

        Args:
            channel: Stream channel name or '*' / 'all' for all channels
            last_event_id: Stream entry ID to catch up from if reconnecting

        Yields:
            Formatted SSE string event payloads or heartbeat comment lines.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)

        async with self._lock:
            if channel in ("all", "*"):
                self._sse_all_channels.add(queue)
            elif channel in self._sse_subscribers:
                self._sse_subscribers[channel].add(queue)
            else:
                self._sse_subscribers.setdefault(channel, set()).add(queue)
            self._total_sse_subscriptions += 1

        logger.info("SSE client subscribed to channel %s", channel)

        try:
            # Historical catch-up via Redis stream if reconnecting with last_event_id
            if last_event_id and last_event_id != "$":
                recent = await self.get_recent_events(channel, limit=20)
                for past_event in recent:
                    yield SSEFormatter.format_event(past_event)

            # Continuous live streaming loop with idle keep-alive heartbeat
            while True:
                try:
                    event_dict = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield SSEFormatter.format_event(event_dict)
                except asyncio.TimeoutError:
                    yield SSEFormatter.format_heartbeat()

        finally:
            async with self._lock:
                if channel in ("all", "*"):
                    self._sse_all_channels.discard(queue)
                elif channel in self._sse_subscribers:
                    self._sse_subscribers[channel].discard(queue)
            logger.info("SSE client unsubscribed from channel %s", channel)

    async def get_recent_events(
        self,
        channel: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieve recent events from the specified channel's Redis stream.

        Args:
            channel: Target stream channel name
            limit: Maximum number of recent events to return

        Returns:
            List of event dictionaries ordered chronologically (oldest to newest).
        """
        r = await self._get_redis()
        stream_key = get_stream_key(channel)

        try:
            raw_entries = await r.xrevrange(stream_key, count=limit)
        except Exception as exc:
            logger.error("Error reading XREVRANGE from %s: %s", stream_key, exc)
            return []

        events: list[dict[str, Any]] = []
        for entry_id, fields in raw_entries:
            payload_str = fields.get("payload")
            if payload_str:
                try:
                    event_dict = json.loads(payload_str)
                    if isinstance(event_dict, dict):
                        if "event_id" not in event_dict:
                            event_dict["event_id"] = entry_id
                        events.append(event_dict)
                        continue
                except json.JSONDecodeError:
                    pass

            # Fallback envelope for non-JSON stream entries
            events.append({
                "event_id": entry_id,
                "channel": fields.get("channel", channel),
                "event_type": fields.get("event_type", "unknown"),
                "data": fields,
                "timestamp": time.time(),
                "severity": fields.get("severity", "info"),
            })

        # Reverse entries so returned list is chronological (oldest to newest)
        events.reverse()
        return events

    async def get_stream_stats(self) -> dict[str, Any]:
        """Get operational statistics for the threat stream hub.

        Returns:
            Dictionary with connection counts, event totals, and Redis stream key lengths.
        """
        r = await self._get_redis()
        stream_lengths: dict[str, int] = {}

        for ch in StreamChannel.ALL:
            try:
                length = await r.xlen(get_stream_key(ch))
                stream_lengths[ch] = length
            except Exception:
                stream_lengths[ch] = 0

        async with self._lock:
            active_ws = len(self._ws_clients)
            active_sse = sum(
                len(q_set) for q_set in self._sse_subscribers.values()
            ) + len(self._sse_all_channels)

            return {
                "active_websocket_connections": active_ws,
                "active_sse_subscribers": active_sse,
                "total_events_broadcast": self._total_broadcasts,
                "total_ws_connected_cumulative": self._total_ws_connected,
                "total_sse_subscriptions_cumulative": self._total_sse_subscriptions,
                "channel_broadcast_counts": dict(self._channel_counts),
                "redis_stream_lengths": stream_lengths,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    # ========================================================================
    # CONVENIENCE BROADCAST HELPERS
    # ========================================================================

    async def broadcast_alert(
        self, data: dict[str, Any], severity: str = "high"
    ) -> StreamEvent:
        """Broadcast a security alert event to the ALERTS channel."""
        return await self.broadcast(
            channel=StreamChannel.ALERTS,
            event_type="alert_triggered",
            data=data,
            severity=severity,
        )

    async def broadcast_incident(
        self, data: dict[str, Any], severity: str = "critical"
    ) -> StreamEvent:
        """Broadcast an incident timeline event to the INCIDENTS channel."""
        return await self.broadcast(
            channel=StreamChannel.INCIDENTS,
            event_type="incident_updated",
            data=data,
            severity=severity,
        )

    async def broadcast_risk_score(
        self, data: dict[str, Any], severity: str = "info"
    ) -> StreamEvent:
        """Broadcast a risk score change event to the RISK_SCORES channel."""
        return await self.broadcast(
            channel=StreamChannel.RISK_SCORES,
            event_type="risk_score_changed",
            data=data,
            severity=severity,
        )

    async def broadcast_agent_activity(
        self, data: dict[str, Any], severity: str = "info"
    ) -> StreamEvent:
        """Broadcast agent task activity event to the AGENT_ACTIVITY channel."""
        return await self.broadcast(
            channel=StreamChannel.AGENT_ACTIVITY,
            event_type="agent_activity_logged",
            data=data,
            severity=severity,
        )

    async def broadcast_attack_graph(
        self, data: dict[str, Any], severity: str = "warning"
    ) -> StreamEvent:
        """Broadcast an attack graph update event to the ATTACK_GRAPH channel."""
        return await self.broadcast(
            channel=StreamChannel.ATTACK_GRAPH,
            event_type="attack_graph_updated",
            data=data,
            severity=severity,
        )

    async def broadcast_threat_intel(
        self, data: dict[str, Any], severity: str = "info"
    ) -> StreamEvent:
        """Broadcast threat intelligence update to the THREAT_INTEL channel."""
        return await self.broadcast(
            channel=StreamChannel.THREAT_INTEL,
            event_type="intel_feed_updated",
            data=data,
            severity=severity,
        )

    async def broadcast_compliance(
        self, data: dict[str, Any], severity: str = "info"
    ) -> StreamEvent:
        """Broadcast compliance status change to the COMPLIANCE channel."""
        return await self.broadcast(
            channel=StreamChannel.COMPLIANCE,
            event_type="compliance_status_changed",
            data=data,
            severity=severity,
        )


__all__ = [
    "StreamChannel",
    "StreamEvent",
    "SSEFormatter",
    "ThreatStreamHub",
    "get_stream_key",
    "get_pubsub_channel",
]
