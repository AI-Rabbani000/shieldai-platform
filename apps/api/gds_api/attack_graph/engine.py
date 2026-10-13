"""GDS OS W9 — Attack Path Graph Engine.

Models attack paths through infrastructure using graph theory:
DFS path enumeration, choke point detection, blast radius calculation.
"""
from __future__ import annotations

import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base


# ============================================================================
# MODELS
# ============================================================================

class AttackGraphNode(Base):
    __tablename__ = "attack_graph_nodes"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    graph_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("attack_graphs.id"), default=None)
    node_type: Mapped[str] = mapped_column(String(50))  # asset, vulnerability, identity, network, service
    label: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    is_entry_point: Mapped[bool] = mapped_column(Boolean, default=False)
    is_target: Mapped[bool] = mapped_column(Boolean, default=False)
    mitre_technique: Mapped[str | None] = mapped_column(String(50), default=None)
    mitre_tactic: Mapped[str | None] = mapped_column(String(50), default=None)
    risk_score: Mapped[float] = mapped_column(default=0.0)
    properties: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AttackGraphEdge(Base):
    __tablename__ = "attack_graph_edges"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    graph_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("attack_graphs.id"), default=None)
    from_node_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_graph_nodes.id"))
    to_node_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_graph_nodes.id"))
    relationship: Mapped[str] = mapped_column(String(100))  # exploits, accesses, trusts, reaches
    weight: Mapped[float] = mapped_column(default=1.0)
    confidence: Mapped[float] = mapped_column(default=0.8)
    attack_step: Mapped[str | None] = mapped_column(String(200), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AttackGraph(Base):
    __tablename__ = "attack_graphs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    total_nodes: Mapped[int] = mapped_column(Integer, default=0)
    total_edges: Mapped[int] = mapped_column(Integer, default=0)
    total_paths: Mapped[int] = mapped_column(Integer, default=0)
    critical_paths: Mapped[int] = mapped_column(Integer, default=0)
    avg_path_risk: Mapped[float] = mapped_column(default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AttackPath(Base):
    __tablename__ = "attack_paths"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    graph_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_graphs.id"))
    name: Mapped[str] = mapped_column(String(200))
    node_sequence: Mapped[list] = mapped_column(JSONB, default=list)  # list of node IDs
    node_labels: Mapped[list] = mapped_column(JSONB, default=list)  # human-readable
    total_risk: Mapped[float] = mapped_column(default=0.0)
    is_critical: Mapped[bool] = mapped_column(Boolean, default=False)
    path_length: Mapped[int] = mapped_column(Integer, default=0)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    choke_points: Mapped[list] = mapped_column(JSONB, default=list)
    blast_radius: Mapped[float] = mapped_column(default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ChokePoint(Base):
    __tablename__ = "attack_choke_points"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    graph_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_graphs.id"))
    node_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_graph_nodes.id"))
    node_label: Mapped[str] = mapped_column(String(200))
    paths_through: Mapped[int] = mapped_column(Integer, default=0)
    total_paths: Mapped[int] = mapped_column(Integer, default=0)
    coverage_pct: Mapped[float] = mapped_column(default=0.0)
    mitigation: Mapped[str | None] = mapped_column(Text, default=None)
    mitigated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ============================================================================
# GRAPH OPERATIONS
# ============================================================================

def build_adjacency_list(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> dict[str, list[str]]:
    """Build adjacency list from nodes and edges."""
    adj: dict[str, list[str]] = {n["id"]: [] for n in nodes}
    for edge in edges:
        src = str(edge["from_node_id"])
        dst = str(edge["to_node_id"])
        if src in adj:
            adj[src].append(dst)
    return adj


def find_all_paths(
    adj: dict[str, list[str]], entry_points: list[str], target_points: list[str],
    max_depth: int = 15,
) -> list[list[str]]:
    """DFS path enumeration from entry points to targets."""
    all_paths: list[list[str]] = []
    target_set = set(target_points)

    def dfs(node: str, current_path: list[str], visited: set[str]):
        if len(current_path) > max_depth:
            return
        if node in target_set and len(current_path) > 1:
            all_paths.append(list(current_path))
            return
        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                dfs(neighbor, current_path + [neighbor], visited | {neighbor})

    for entry in entry_points:
        dfs(entry, [entry], {entry})

    return all_paths


def find_choke_points(
    paths: list[list[str]], total_nodes: list[str],
) -> list[dict[str, Any]]:
    """Find nodes that appear in ALL critical paths — highest-impact mitigation targets."""
    if not paths:
        return []

    # Count how many paths each node appears in (excluding entry/target)
    node_path_count: dict[str, int] = defaultdict(int)
    for path in paths:
        intermediate = path[1:-1] if len(path) > 2 else []
        for node in intermediate:
            node_path_count[node] += 1

    total_paths = len(paths)
    choke_points: list[dict[str, Any]] = []
    for node_id, count in node_path_count.items():
        coverage = (count / total_paths) * 100 if total_paths > 0 else 0
        if coverage >= 50:  # appears in at least 50% of paths
            choke_points.append({
                "node_id": node_id,
                "paths_through": count,
                "total_paths": total_paths,
                "coverage_pct": round(coverage, 1),
            })

    choke_points.sort(key=lambda x: x["coverage_pct"], reverse=True)
    return choke_points


def calculate_blast_radius(
    adj: dict[str, list[str]], start_node: str, max_depth: int = 10,
) -> dict[str, Any]:
    """BFS to calculate blast radius from a compromised node."""
    visited: set[str] = {start_node}
    queue: deque[tuple[str, int]] = deque([(start_node, 0)])
    affected: list[str] = [start_node]
    by_depth: dict[int, list[str]] = {0: [start_node]}

    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                affected.append(neighbor)
                queue.append((neighbor, depth + 1))
                if depth + 1 not in by_depth:
                    by_depth[depth + 1] = []
                by_depth[depth + 1].append(neighbor)

    return {
        "start_node": start_node,
        "total_affected": len(affected),
        "affected_nodes": affected,
        "max_depth_reached": max(by_depth.keys()),
        "by_depth": {str(k): v for k, v in sorted(by_depth.items())},
    }


def score_path(
    path: list[str], node_risks: dict[str, float],
) -> float:
    """Aggregate risk score along a path (max of node risks + length penalty)."""
    if not path:
        return 0.0
    risks = [node_risks.get(node, 0.0) for node in path]
    max_risk = max(risks) if risks else 0.0
    avg_risk = sum(risks) / len(risks) if risks else 0.0
    # Weighted: 70% max + 30% avg
    return round(max_risk * 0.7 + avg_risk * 0.3, 2)


def build_graph_from_findings(
    db: AsyncSession, tenant_id: uuid.UUID, graph_name: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an attack graph from a set of vulnerability findings."""
    graph = AttackGraph(tenant_id=tenant_id, name=graph_name)
    db.add(graph)
    db.flush()

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_risks: dict[str, float] = {}

    for f in findings:
        asset_name = f.get("asset_name", "unknown")
        vuln_title = f.get("title", "vulnerability")
        severity = f.get("severity", "medium")
        cve = f.get("cve_id", "")
        mitre = f.get("mitre_technique", "")

        # Node 1: Asset
        asset_id = str(uuid.uuid4())
        nodes.append({
            "id": asset_id, "node_type": "asset", "label": asset_name,
            "severity": severity, "is_entry_point": f.get("is_internet_facing", False),
            "mitre_technique": mitre,
            "risk_score": {"critical": 90, "high": 70, "medium": 40, "low": 15}.get(severity, 40),
        })
        node_risks[asset_id] = nodes[-1]["risk_score"]

        # Node 2: Vulnerability
        vuln_id = str(uuid.uuid4())
        nodes.append({
            "id": vuln_id, "node_type": "vulnerability", "label": vuln_title,
            "severity": severity, "is_entry_point": False,
            "mitre_technique": mitre,
            "risk_score": {"critical": 95, "high": 75, "medium": 45, "low": 20}.get(severity, 45),
        })
        node_risks[vuln_id] = nodes[-1]["risk_score"]

        # Edge: vulnerability exploits asset
        edges.append({
            "from_node_id": vuln_id, "to_node_id": asset_id,
            "relationship": "exploits", "weight": 1.0,
            "attack_step": f"{vuln_title} on {asset_name}",
        })

    # Persist nodes
    for n in nodes:
        node = AttackGraphNode(
            tenant_id=tenant_id, graph_id=graph.id,
            node_type=n["node_type"], label=n["label"], severity=n["severity"],
            is_entry_point=n["is_entry_point"], mitre_technique=n.get("mitre_technique"),
            risk_score=n["risk_score"],
        )
        db.add(node)

    db.flush()

    # Map node IDs for edges
    # (In production, we'd use the actual DB node IDs; for now use the generated IDs)
    entry_points = [n["id"] for n in nodes if n["is_entry_point"]]
    target_points = [n["id"] for n in nodes if n["node_type"] == "asset" and not n["is_entry_point"]]

    adj = build_adjacency_list(nodes, edges)
    paths = find_all_paths(adj, entry_points, target_points)
    chokes = find_choke_points(paths, [n["id"] for n in nodes])

    # Score paths
    scored_paths = []
    for path in paths:
        risk = score_path(path, node_risks)
        scored_paths.append({
            "path": path,
            "risk": risk,
            "is_critical": risk >= 70,
            "labels": [next((n["label"] for n in nodes if n["id"] == nid), nid) for nid in path],
        })

    scored_paths.sort(key=lambda x: x["risk"], reverse=True)

    # Update graph stats
    graph.total_nodes = len(nodes)
    graph.total_edges = len(edges)
    graph.total_paths = len(scored_paths)
    graph.critical_paths = sum(1 for p in scored_paths if p["is_critical"])
    graph.avg_path_risk = sum(p["risk"] for p in scored_paths) / max(len(scored_paths), 1)

    return {
        "graph_id": str(graph.id),
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "total_paths": len(scored_paths),
        "critical_paths": sum(1 for p in scored_paths if p["is_critical"]),
        "avg_path_risk": round(graph.avg_path_risk, 2),
        "entry_points": entry_points,
        "targets": target_points,
        "choke_points": chokes,
        "top_paths": scored_paths[:10],
    }


def export_graph(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Export graph in node/edge format for frontend rendering."""
    return {
        "nodes": [
            {
                "id": n["id"],
                "label": n.get("label", n["id"]),
                "type": n.get("node_type", "unknown"),
                "severity": n.get("severity", "medium"),
                "risk_score": n.get("risk_score", 0),
                "is_entry_point": n.get("is_entry_point", False),
                "is_target": n.get("is_target", False),
                "mitre": n.get("mitre_technique", ""),
            }
            for n in nodes
        ],
        "edges": [
            {
                "source": str(e["from_node_id"]),
                "target": str(e["to_node_id"]),
                "relationship": e.get("relationship", "connects"),
                "weight": e.get("weight", 1.0),
                "attack_step": e.get("attack_step", ""),
            }
            for e in edges
        ],
    }


def graph_stats(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]],
    paths: list[dict[str, Any]], choke_points: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate graph statistics."""
    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "total_paths": len(paths),
        "critical_paths": sum(1 for p in paths if p.get("is_critical", False)),
        "choke_points": len(choke_points),
        "avg_risk": round(sum(p.get("risk", 0) for p in paths) / max(len(paths), 1), 2),
        "max_risk": max((p.get("risk", 0) for p in paths), default=0),
        "entry_points": sum(1 for n in nodes if n.get("is_entry_point")),
        "targets": sum(1 for n in nodes if n.get("is_target")),
    }
