import asyncio
import ipaddress
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.siem.models import SIEMEvent

# Known malicious IOCs for threat intelligence matching
KNOWN_IOC_IPS = {
    "185.220.101.5",
    "45.154.255.71",
    "198.51.100.1",
    "203.0.113.5",
    "103.219.21.3",
    "193.142.146.35",
    "185.220.101.7",
    "45.33.32.156",
}


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )
    except ValueError:
        return False


def _parse_datetime(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, (int, float)):
        # Epoch timestamp (seconds or milliseconds)
        if val > 1e11:
            val = val / 1000.0
        return datetime.fromtimestamp(val, tz=UTC)
    if isinstance(val, str):
        val = val.strip()
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            pass
        for fmt in (
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%b %d %Y %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(val, fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now(UTC).year)
                return dt.replace(tzinfo=UTC)
            except Exception:
                continue
    return datetime.now(UTC)


def normalize_cef(raw: str | dict) -> dict:
    """Parse CEF (Common Event Format) log into normalized dict.
    CEF format: CEF:Version|Vendor|Product|EventClassID|Name|Severity|Extension
    """
    if isinstance(raw, dict):
        return raw

    raw_str = str(raw).strip()
    result: dict[str, Any] = {
        "format": "cef",
        "raw": raw_str,
    }

    if not raw_str.startswith("CEF:"):
        result["error"] = "Not a valid CEF header"
        return result

    # Split header by unescaped pipes
    # CEF header has 7 fields before Extension: CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|Extension
    parts = re.split(r"(?<!\\)\|", raw_str)
    if len(parts) >= 7:
        version_part = parts[0].replace("CEF:", "").strip()
        result["cef_version"] = version_part
        result["vendor"] = parts[1].replace(r"\|", "|")
        result["product"] = parts[2].replace(r"\|", "|")
        result["device_version"] = parts[3].replace(r"\|", "|")
        result["event_class_id"] = parts[4].replace(r"\|", "|")
        result["name"] = parts[5].replace(r"\|", "|")
        result["raw_severity"] = parts[6].replace(r"\|", "|")

        # Map CEF severity (0-10 or string)
        sev_val = result["raw_severity"].lower()
        if sev_val in ("10", "critical", "fatal", "9"):
            result["severity"] = "critical"
        elif sev_val in ("8", "7", "high"):
            result["severity"] = "high"
        elif sev_val in ("6", "5", "4", "medium"):
            result["severity"] = "medium"
        elif sev_val in ("3", "2", "1", "low"):
            result["severity"] = "low"
        else:
            result["severity"] = "info"

        extension_str = "|".join(parts[7:]) if len(parts) > 7 else ""
    else:
        extension_str = raw_str

    # Parse Extension Key=Value pairs
    ext_kv = re.findall(r"([a-zA-Z0-9_.-]+)=((?:\\=|\\\||\\|[^=])*)(?=\s+[a-zA-Z0-9_.-]+=|$)", extension_str)
    kv_dict = {}
    for k, v in ext_kv:
        kv_dict[k.strip()] = v.strip().replace(r"\=", "=").replace(r"\|", "|").replace(r"\\", "\\")

    # Map standard CEF extension keys to normalized fields
    result["src_ip"] = kv_dict.get("src") or kv_dict.get("sourceAddress") or kv_dict.get("sip")
    result["dst_ip"] = kv_dict.get("dst") or kv_dict.get("destinationAddress") or kv_dict.get("dip")
    
    spt = kv_dict.get("spt") or kv_dict.get("sourcePort")
    result["src_port"] = int(spt) if spt and spt.isdigit() else None

    dpt = kv_dict.get("dpt") or kv_dict.get("destinationPort")
    result["dst_port"] = int(dpt) if dpt and dpt.isdigit() else None

    result["protocol"] = kv_dict.get("proto") or kv_dict.get("transportProtocol")
    result["user"] = kv_dict.get("duser") or kv_dict.get("suser") or kv_dict.get("usr") or kv_dict.get("user") or kv_dict.get("duuid")
    result["action"] = kv_dict.get("act") or kv_dict.get("action")
    result["result"] = kv_dict.get("outcome") or kv_dict.get("reason")
    result["event_category"] = kv_dict.get("cat") or kv_dict.get("category") or "security"
    result["event_time"] = kv_dict.get("rt") or kv_dict.get("end") or kv_dict.get("start")
    result["extension"] = kv_dict

    return result


def normalize_leef(raw: str | dict) -> dict:
    """Parse LEEF (Log Event Extended Format).
    LEEF format: LEEF:Version|Vendor|Product|Version|EventID|KeyName=Value\tKeyName=Value
    """
    if isinstance(raw, dict):
        return raw

    raw_str = str(raw).strip()
    result: dict[str, Any] = {
        "format": "leef",
        "raw": raw_str,
    }

    if not raw_str.startswith("LEEF:"):
        result["error"] = "Not a valid LEEF header"
        return result

    # Header is pipe-delimited: LEEF:Version|Vendor|Product|DeviceVersion|EventID|
    parts = raw_str.split("|")
    delimiter = "\t"
    if len(parts) >= 5:
        version_part = parts[0].replace("LEEF:", "").strip()
        result["leef_version"] = version_part
        result["vendor"] = parts[1]
        result["product"] = parts[2]
        result["device_version"] = parts[3]
        result["event_id"] = parts[4]

        # In LEEF 2.0, delimiter can be specified as 6th component, e.g. LEEF:2.0|Vendor|Product|Version|EventID|^|
        if version_part.startswith("2.0") and len(parts) >= 6 and len(parts[5]) == 1:
            delimiter = parts[5]
            extension_str = "|".join(parts[6:])
        else:
            extension_str = "|".join(parts[5:])
    else:
        extension_str = raw_str

    # Parse Extension KV pairs split by delimiter (default tab or custom)
    kv_dict = {}
    tokens = extension_str.split(delimiter)
    for token in tokens:
        token = token.strip()
        if "=" in token:
            k, v = token.split("=", 1)
            kv_dict[k.strip()] = v.strip()

    result["src_ip"] = kv_dict.get("src") or kv_dict.get("srcIP") or kv_dict.get("sourceAddress")
    result["dst_ip"] = kv_dict.get("dst") or kv_dict.get("dstIP") or kv_dict.get("destinationAddress")
    
    spt = kv_dict.get("srcPort") or kv_dict.get("spt")
    result["src_port"] = int(spt) if spt and spt.isdigit() else None

    dpt = kv_dict.get("dstPort") or kv_dict.get("dpt")
    result["dst_port"] = int(dpt) if dpt and dpt.isdigit() else None

    result["protocol"] = kv_dict.get("proto") or kv_dict.get("protocol")
    result["user"] = kv_dict.get("usrName") or kv_dict.get("username") or kv_dict.get("usr") or kv_dict.get("user")
    result["action"] = kv_dict.get("action") or kv_dict.get("act")
    result["result"] = kv_dict.get("res") or kv_dict.get("result") or kv_dict.get("outcome")
    result["event_category"] = kv_dict.get("cat") or kv_dict.get("category") or "security"
    result["severity"] = (kv_dict.get("sev") or kv_dict.get("severity") or "info").lower()
    result["event_time"] = kv_dict.get("devTime") or kv_dict.get("devTimeFormat")
    result["extension"] = kv_dict

    return result


def normalize_json(raw: str | dict) -> dict:
    """Parse JSON log. Extract common fields (timestamp, severity, src_ip, dst_ip, user, action, result)."""
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except Exception:
            return {"format": "json", "raw": raw, "error": "Invalid JSON string"}
    elif isinstance(raw, dict):
        data = raw
    else:
        return {"format": "json", "raw": str(raw), "error": "Unsupported raw type"}

    result: dict[str, Any] = {
        "format": "json",
        "raw_json": data,
    }

    # Helper function to find first matching key in nested or flat dict
    def _find_field(keys: list[str]) -> Any:
        for k in keys:
            if k in data and data[k] is not None:
                return data[k]
            # Check nested dicts
            for sub_key in ("event", "log", "metadata", "network", "user", "source", "destination", "target"):
                if isinstance(data.get(sub_key), dict) and k in data[sub_key] and data[sub_key][k] is not None:
                    return data[sub_key][k]
        return None

    src_ip = _find_field(["src_ip", "src", "source_ip", "sourceIPAddress", "src_addr", "client_ip", "ip", "source_ip_address"])
    dst_ip = _find_field(["dst_ip", "dst", "destination_ip", "destinationIPAddress", "dst_addr", "server_ip", "target_ip"])
    src_port = _find_field(["src_port", "spt", "source_port", "srcPort"])
    dst_port = _find_field(["dst_port", "dpt", "destination_port", "dstPort"])
    protocol = _find_field(["protocol", "proto", "transport"])
    user = _find_field(["user", "username", "user_name", "userId", "user_id", "actor", "identity", "account"])
    action = _find_field(["action", "act", "event_action", "activity", "command", "operation"])
    res_val = _find_field(["result", "outcome", "status", "response_status"])
    severity = _find_field(["severity", "level", "log_level", "sev", "priority"])
    category = _find_field(["event_category", "category", "type", "event_type", "class"])
    event_time = _find_field(["event_time", "timestamp", "@timestamp", "time", "datetime", "created_at"])

    result["src_ip"] = str(src_ip) if src_ip else None
    result["dst_ip"] = str(dst_ip) if dst_ip else None
    result["src_port"] = int(src_port) if src_port is not None and str(src_port).isdigit() else None
    result["dst_port"] = int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None
    result["protocol"] = str(protocol) if protocol else None
    result["user"] = str(user) if user else None
    result["action"] = str(action) if action else None
    result["result"] = str(res_val) if res_val else None

    # Severity normalization
    if severity:
        sev_str = str(severity).lower()
        if sev_str in ("critical", "fatal", "5", "emerg", "alert"):
            result["severity"] = "critical"
        elif sev_str in ("high", "error", "err", "4"):
            result["severity"] = "high"
        elif sev_str in ("medium", "warn", "warning", "3"):
            result["severity"] = "medium"
        elif sev_str in ("low", "notice", "2"):
            result["severity"] = "low"
        else:
            result["severity"] = "info"
    else:
        result["severity"] = "info"

    result["event_category"] = str(category) if category else "system"
    result["event_time"] = event_time

    return result


def normalize_syslog(raw: str | dict) -> dict:
    """Parse syslog format: <priority>timestamp hostname process[pid]: message"""
    if isinstance(raw, dict):
        return raw

    raw_str = str(raw).strip()
    result: dict[str, Any] = {
        "format": "syslog",
        "raw": raw_str,
    }

    # RFC 3164 / RFC 5424 regex pattern
    # e.g., <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
    # or <13>1 2026-07-31T07:55:00.000Z host app 1234 - - Message
    syslog_pattern = re.compile(
        r"^<(\d+)>(?:(\d+)\s+)?(?:(\d{4}-\d{2}-\d{2}T\S+|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+([\w\.\-]+)(?:\[(\d+)\])?:\s*(.*)$"
    )
    match = syslog_pattern.match(raw_str)

    if match:
        prival = int(match.group(1))
        version = match.group(2)
        timestamp = match.group(3)
        hostname = match.group(4)
        process = match.group(5)
        pid = match.group(6)
        message = match.group(7)

        facility = prival // 8
        sev_code = prival % 8

        # Map syslog severity code (0-7)
        sev_map = {
            0: "critical",  # Emergency
            1: "critical",  # Alert
            2: "critical",  # Critical
            3: "high",      # Error
            4: "medium",    # Warning
            5: "low",       # Notice
            6: "info",      # Informational
            7: "info",      # Debug
        }

        result["priority"] = prival
        result["facility"] = facility
        result["severity"] = sev_map.get(sev_code, "info")
        result["hostname"] = hostname
        result["process"] = process
        result["pid"] = pid
        result["event_time"] = timestamp
        result["message"] = message

        # Try to parse key=value fields inside the message
        kv_matches = re.findall(r"(\b[a-zA-Z0-9_.-]+)=([^\s]+)", message)
        if kv_matches:
            msg_kv = dict(kv_matches)
            result["src_ip"] = msg_kv.get("src") or msg_kv.get("src_ip")
            result["dst_ip"] = msg_kv.get("dst") or msg_kv.get("dst_ip")
            result["user"] = msg_kv.get("user") or msg_kv.get("username")
            result["action"] = msg_kv.get("action") or msg_kv.get("act")
            result["result"] = msg_kv.get("result") or msg_kv.get("status")

            spt = msg_kv.get("spt") or msg_kv.get("src_port")
            result["src_port"] = int(spt) if spt and spt.isdigit() else None

            dpt = msg_kv.get("dpt") or msg_kv.get("dst_port")
            result["dst_port"] = int(dpt) if dpt and dpt.isdigit() else None
    else:
        result["message"] = raw_str
        result["severity"] = "info"

    result["event_category"] = "system"
    return result


def normalize_ocsf(raw: str | dict) -> dict:
    """Parse OCSF (Open Cybersecurity Schema Framework) v1.1 format."""
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except Exception:
            return {"format": "ocsf", "raw": raw, "error": "Invalid OCSF JSON string"}
    elif isinstance(raw, dict):
        data = raw
    else:
        return {"format": "ocsf", "raw": str(raw), "error": "Unsupported raw type"}

    result: dict[str, Any] = {
        "format": "ocsf",
        "raw_ocsf": data,
        "class_uid": data.get("class_uid"),
        "class_name": data.get("class_name"),
        "category_uid": data.get("category_uid"),
        "category_name": data.get("category_name"),
    }

    # Map OCSF severity_id (1:Fatal, 2:Critical, 3:High, 4:Medium, 5:Low, 6:Info, 0:Unknown/Other)
    sev_id = data.get("severity_id")
    sev_str = str(data.get("severity", "")).lower()
    if sev_id in (1, 2) or "crit" in sev_str or "fatal" in sev_str:
        result["severity"] = "critical"
    elif sev_id == 3 or "high" in sev_str:
        result["severity"] = "high"
    elif sev_id == 4 or "med" in sev_str:
        result["severity"] = "medium"
    elif sev_id == 5 or "low" in sev_str:
        result["severity"] = "low"
    else:
        result["severity"] = "info"

    # Endpoints
    src_ep = data.get("src_endpoint") or {}
    dst_ep = data.get("dst_endpoint") or {}
    result["src_ip"] = src_ep.get("ip")
    result["dst_ip"] = dst_ep.get("ip")
    result["src_port"] = src_ep.get("port")
    result["dst_port"] = dst_ep.get("port")

    # Actor / User
    actor = data.get("actor") or {}
    user_obj = actor.get("user") or data.get("user") or {}
    result["user"] = user_obj.get("name") or user_obj.get("uid") or actor.get("name")

    # Activity & Status
    result["action"] = data.get("activity_name") or str(data.get("activity_id", ""))
    result["result"] = data.get("status") or data.get("status_detail") or str(data.get("status_id", ""))

    conn = data.get("connection_info") or {}
    result["protocol"] = conn.get("protocol_name") or data.get("protocol")

    result["event_category"] = data.get("category_name") or "cybersecurity"
    result["event_time"] = data.get("time") or data.get("event_time")

    return result


async def enrich_event(db: AsyncSession, event: SIEMEvent) -> SIEMEvent:
    """Add GeoIP country (using a simple IP-to-country lookup via httpx to ip-api.com),
    threat intel matching (check if src_ip or dst_ip matches any known IOC), user agent parsing.
    """
    # 1. GeoIP enrichment
    if event.src_ip and _is_public_ip(event.src_ip):
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"http://ip-api.com/json/{event.src_ip}")
                if res.status_code == 200:
                    geo_data = res.json()
                    if geo_data.get("status") == "success":
                        event.country = geo_data.get("country")
                        if isinstance(event.normalized, dict):
                            event.normalized["geo_details"] = {
                                "country": geo_data.get("country"),
                                "countryCode": geo_data.get("countryCode"),
                                "city": geo_data.get("city"),
                                "isp": geo_data.get("isp"),
                            }
        except Exception:
            pass  # Fail gracefully if external lookup fails

    # 2. Threat Intel Matching
    if (event.src_ip in KNOWN_IOC_IPS) or (event.dst_ip in KNOWN_IOC_IPS):
        event.threat_intel_match = True
        if isinstance(event.normalized, dict):
            event.normalized["threat_intel"] = {
                "matched": True,
                "matched_ip": event.src_ip if event.src_ip in KNOWN_IOC_IPS else event.dst_ip,
                "indicator_type": "known_malicious_ip",
            }

    # 3. User Agent parsing
    raw_data = event.raw_data if isinstance(event.raw_data, dict) else {}
    normalized = event.normalized if isinstance(event.normalized, dict) else {}
    user_agent = (
        raw_data.get("user_agent")
        or raw_data.get("http_user_agent")
        or normalized.get("user_agent")
        or normalized.get("extension", {}).get("requestUserAgent")
    )
    if user_agent and isinstance(user_agent, str):
        ua_details = {"raw": user_agent}
        ua_lower = user_agent.lower()
        if "windows" in ua_lower:
            ua_details["os"] = "Windows"
        elif "mac" in ua_lower:
            ua_details["os"] = "macOS"
        elif "linux" in ua_lower:
            ua_details["os"] = "Linux"
        elif "android" in ua_lower:
            ua_details["os"] = "Android"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            ua_details["os"] = "iOS"

        if "chrome" in ua_lower and "edg" not in ua_lower:
            ua_details["browser"] = "Chrome"
        elif "firefox" in ua_lower:
            ua_details["browser"] = "Firefox"
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            ua_details["browser"] = "Safari"
        elif "edg" in ua_lower:
            ua_details["browser"] = "Edge"
        elif "curl" in ua_lower or "python" in ua_lower or "go-http" in ua_lower:
            ua_details["browser"] = "Script/Tool"

        event.normalized["user_agent_details"] = ua_details

    return event


def _detect_format(raw_data: Any, format_hint: str | None = None) -> str:
    if format_hint and format_hint.lower() in ("cef", "leef", "syslog", "json", "ocsf"):
        return format_hint.lower()

    if isinstance(raw_data, dict):
        if "class_uid" in raw_data or "category_uid" in raw_data:
            return "ocsf"
        return "json"

    raw_str = str(raw_data).strip()
    if raw_str.startswith("CEF:"):
        return "cef"
    if raw_str.startswith("LEEF:"):
        return "leef"
    if raw_str.startswith("<") and re.match(r"^<\d+>", raw_str):
        return "syslog"
    if raw_str.startswith("{") or raw_str.startswith("["):
        try:
            parsed = json.loads(raw_str)
            if isinstance(parsed, dict) and ("class_uid" in parsed or "category_uid" in parsed):
                return "ocsf"
            return "json"
        except Exception:
            pass

    return "syslog" if "<" in raw_str else "json"


async def ingest_log(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    source: str,
    source_type: str,
    raw_data: Any,
    format: str | None = None,
) -> SIEMEvent:
    """Main entry point. Normalizes, enriches, stores in SIEMEvent. Returns the stored event."""
    log_fmt = _detect_format(raw_data, format)

    if log_fmt == "cef":
        normalized = normalize_cef(raw_data)
    elif log_fmt == "leef":
        normalized = normalize_leef(raw_data)
    elif log_fmt == "syslog":
        normalized = normalize_syslog(raw_data)
    elif log_fmt == "ocsf":
        normalized = normalize_ocsf(raw_data)
    else:
        normalized = normalize_json(raw_data)

    event_time = _parse_datetime(normalized.get("event_time"))

    # Convert raw_data to dict for storage
    if isinstance(raw_data, dict):
        raw_dict = raw_data
    else:
        raw_dict = {"raw": str(raw_data)}

    event = SIEMEvent(
        tenant_id=tenant_id,
        source=source,
        source_type=source_type,
        event_category=normalized.get("event_category") or "security",
        severity=normalized.get("severity") or "info",
        raw_data=raw_dict,
        normalized=normalized,
        src_ip=normalized.get("src_ip"),
        dst_ip=normalized.get("dst_ip"),
        src_port=normalized.get("src_port"),
        dst_port=normalized.get("dst_port"),
        protocol=normalized.get("protocol"),
        user=normalized.get("user"),
        action=normalized.get("action"),
        result=normalized.get("result"),
        event_time=event_time,
    )

    # Enrich event
    await enrich_event(db, event)

    db.add(event)
    await db.commit()
    await db.refresh(event)

    # Run correlation engine
    from gds_api.siem.correlation import correlate_event

    await correlate_event(db, tenant_id, event)

    return event


async def ingest_batch(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    source: str,
    source_type: str,
    raw_logs: list[Any],
    format: str | None = None,
) -> list[SIEMEvent]:
    """Batch ingestion for high-volume logs. Uses asyncio.gather for parallel processing."""
    if not raw_logs:
        return []

    # Parallel normalization & enrichment logic
    async def _process_single(raw_log: Any) -> SIEMEvent:
        log_fmt = _detect_format(raw_log, format)
        if log_fmt == "cef":
            norm = normalize_cef(raw_log)
        elif log_fmt == "leef":
            norm = normalize_leef(raw_log)
        elif log_fmt == "syslog":
            norm = normalize_syslog(raw_log)
        elif log_fmt == "ocsf":
            norm = normalize_ocsf(raw_log)
        else:
            norm = normalize_json(raw_log)

        etime = _parse_datetime(norm.get("event_time"))
        r_dict = raw_log if isinstance(raw_log, dict) else {"raw": str(raw_log)}

        ev = SIEMEvent(
            tenant_id=tenant_id,
            source=source,
            source_type=source_type,
            event_category=norm.get("event_category") or "security",
            severity=norm.get("severity") or "info",
            raw_data=r_dict,
            normalized=norm,
            src_ip=norm.get("src_ip"),
            dst_ip=norm.get("dst_ip"),
            src_port=norm.get("src_port"),
            dst_port=norm.get("dst_port"),
            protocol=norm.get("protocol"),
            user=norm.get("user"),
            action=norm.get("action"),
            result=norm.get("result"),
            event_time=etime,
        )
        await enrich_event(db, ev)
        return ev

    events = await asyncio.gather(*[_process_single(r) for r in raw_logs])

    db.add_all(events)
    await db.commit()

    for ev in events:
        await db.refresh(ev)

    # Correlate all events in batch
    from gds_api.siem.correlation import correlate_event

    for ev in events:
        await correlate_event(db, tenant_id, ev)

    return list(events)
