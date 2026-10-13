"""GDS OS W9 — Attack Path Graph API Routes."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.attack_graph.engine import (
    AttackGraph, AttackGraphNode, AttackGraphEdge, AttackPath, ChokePoint,
    build_adjacency_list, find_all_paths, find_choke_points, calculate_blast_radius,
    score_path, build_graph_from_findings, export_graph, graph_stats,
)
from gds_api.db import get_db
from gds_api.security import CurrentUser

router = APIRouter(prefix="/attack-graph", tags=["attack-graph"])


class BuildGraphRequest(BaseModel):
    name: str
    findings: list[dict[str, Any]]


class MitigateRequest(BaseModel):
    node_id: str
    mitigation: str = "Choke point mitigated"


@router.post("/build")
async def build_graph(
    req: BuildGraphRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Build an attack graph from a set of findings."""
    if not req.findings:
        raise HTTPException(status_code=400, detail="No findings provided")
    return await build_graph_from_findings(db, user.tenant_id, req.name, req.findings)


@router.get("/paths")
async def list_paths(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    """List all attack paths."""
    stmt = (
        select(AttackPath)
        .where(AttackPath.tenant_id == user.tenant_id)
        .order_by(AttackPath.total_risk.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    paths = result.scalars().all()
    return {
        "total": len(paths),
        "paths": [
            {
                "id": str(p.id),
                "name": p.name,
                "node_labels": p.node_labels,
                "total_risk": p.total_risk,
                "is_critical": p.is_critical,
                "path_length": p.path_length,
                "mitre_techniques": p.mitre_techniques,
                "blast_radius": p.blast_radius,
            }
            for p in paths
        ],
    }


@router.get("/paths/{path_id}")
async def get_path(
    path_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Get a specific attack path with full node sequence."""
    stmt = select(AttackPath).where(
        AttackPath.id == path_id,
        AttackPath.tenant_id == user.tenant_id,
    )
    result = await db.execute(stmt)
    path = result.scalar_one_or_none()
    if not path:
        raise HTTPException(status_code=404, detail="Path not found")
    return {
        "id": str(path.id),
        "name": path.name,
        "node_sequence": path.node_sequence,
        "node_labels": path.node_labels,
        "total_risk": path.total_risk,
        "is_critical": path.is_critical,
        "path_length": path.path_length,
        "mitre_techniques": path.mitre_techniques,
        "choke_points": path.choke_points,
        "blast_radius": path.blast_radius,
        "created_at": path.created_at.isoformat() if path.created_at else None,
    }


@router.get("/choke-points")
async def list_choke_points(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    """List all choke points across graphs."""
    stmt = (
        select(ChokePoint)
        .where(ChokePoint.tenant_id == user.tenant_id)
        .order_by(ChokePoint.coverage_pct.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    chokes = result.scalars().all()
    return {
        "total": len(chokes),
        "choke_points": [
            {
                "id": str(c.id),
                "node_label": c.node_label,
                "paths_through": c.paths_through,
                "total_paths": c.total_paths,
                "coverage_pct": c.coverage_pct,
                "mitigated": c.mitigated,
                "mitigation": c.mitigation,
            }
            for c in chokes
        ],
    }


@router.get("/blast-radius/{node_id}")
async def get_blast_radius(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Calculate blast radius from a specific node."""
    # Fetch all edges for tenant
    edge_stmt = select(AttackGraphEdge).where(AttackGraphEdge.tenant_id == user.tenant_id)
    edge_result = await db.execute(edge_stmt)
    edges = edge_result.scalars().all()

    adj: dict[str, list[str]] = {}
    for e in edges:
        src = str(e.from_node_id)
        dst = str(e.to_node_id)
        if src not in adj:
            adj[src] = []
        adj[src].append(dst)

    return calculate_blast_radius(adj, node_id)


@router.post("/mitigate")
async def mitigate_choke_point(
    req: MitigateRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Mark a choke point as mitigated and recalculate paths."""
    stmt = select(ChokePoint).where(
        ChokePoint.node_id == uuid.UUID(req.node_id),
        ChokePoint.tenant_id == user.tenant_id,
    )
    result = await db.execute(stmt)
    choke = result.scalar_one_or_none()
    if not choke:
        raise HTTPException(status_code=404, detail="Choke point not found")
    choke.mitigated = True
    choke.mitigation = req.mitigation
    await db.commit()
    return {
        "node_id": req.node_id,
        "mitigated": True,
        "mitigation": req.mitigation,
        "message": "Choke point mitigated — attack paths will be recalculated on next graph build",
    }


@router.get("/visualization")
async def get_visualization(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Export graph in node/edge format for frontend rendering."""
    node_stmt = select(AttackGraphNode).where(AttackGraphNode.tenant_id == user.tenant_id)
    edge_stmt = select(AttackGraphEdge).where(AttackGraphEdge.tenant_id == user.tenant_id)

    nodes_result = await db.execute(node_stmt)
    edges_result = await db.execute(edge_stmt)
    nodes = nodes_result.scalars().all()
    edges = edges_result.scalars().all()

    node_dicts = [
        {
            "id": str(n.id), "node_type": n.node_type, "label": n.label,
            "severity": n.severity, "is_entry_point": n.is_entry_point,
            "is_target": n.is_target, "mitre_technique": n.mitre_technique,
            "risk_score": n.risk_score,
        }
        for n in nodes
    ]
    edge_dicts = [
        {
            "from_node_id": str(e.from_node_id), "to_node_id": str(e.to_node_id),
            "relationship": e.relationship, "weight": e.weight,
            "attack_step": e.attack_step,
        }
        for e in edges
    ]
    return export_graph(node_dicts, edge_dicts)


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Graph statistics — total nodes, edges, paths, critical paths, avg risk."""
    node_stmt = select(AttackGraphNode).where(AttackGraphNode.tenant_id == user.tenant_id)
    edge_stmt = select(AttackGraphEdge).where(AttackGraphEdge.tenant_id == user.tenant_id)
    path_stmt = select(AttackPath).where(AttackPath.tenant_id == user.tenant_id)
    choke_stmt = select(ChokePoint).where(ChokePoint.tenant_id == user.tenant_id)

    nodes = (await db.execute(node_stmt)).scalars().all()
    edges = (await db.execute(edge_stmt)).scalars().all()
    paths = (await db.execute(path_stmt)).scalars().all()
    chokes = (await db.execute(choke_stmt)).scalars().all()

    node_dicts = [
        {"id": str(n.id), "is_entry_point": n.is_entry_point, "is_target": n.is_target, "severity": n.severity, "risk_score": n.risk_score}
        for n in nodes
    ]
    path_dicts = [{"risk": p.total_risk, "is_critical": p.is_critical} for p in paths]
    choke_dicts = [{"coverage_pct": c.coverage_pct} for c in chokes]

    return graph_stats(node_dicts, list(edge_dicts), path_dicts, choke_dicts)
