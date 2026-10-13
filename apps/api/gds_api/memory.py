"""Memory service: all four tiers, all real, backed by infra already running since
Phase 1.

- Working memory: Redis, key `mission:{id}:state`, TTL-bound.
- Episodic memory: Postgres - missions/mission_tasks ARE the episodic store; queried
  directly from gds_api.missions, no separate store needed here.
- Semantic memory: Qdrant collection `gds_knowledge`, embeddings from a local
  sentence-transformers model (all-MiniLM-L6-v2, 384-dim, CPU-only, no external key).
  KnowledgeDocument (Postgres) holds the source text; Qdrant holds the vector + a
  pointer back via qdrant_point_id - the same "pointer" pattern Evidence uses for MinIO.
- Relationship memory: Neo4j - Tenant/User/Mission/Tool nodes, real edges written as
  missions run.
"""

import asyncio
import uuid
from functools import lru_cache

from fastapi import APIRouter, Depends
from qdrant_client import AsyncQdrantClient
from qdrant_client.http.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.config import settings
from gds_api.db import get_db
from gds_api.models import KnowledgeDocument, Mission
from gds_api.schemas import (
    AgentToolEdgeOut,
    MemoryOverviewOut,
    RelationshipGraphOut,
    RelationshipMemoryOut,
    WorkingMemoryEntryOut,
)
from gds_api.security import CurrentUser, require_permission

KNOWLEDGE_COLLECTION = "gds_knowledge"
EMBEDDING_DIM = 384  # all-MiniLM-L6-v2's output size

router = APIRouter(prefix="/memory", tags=["memory"])

_qdrant = AsyncQdrantClient(host=settings.qdrant_host, port=settings.qdrant_http_port)


def _get_redis() -> Redis:
    # A fresh client per call, not a module-level singleton: redis-py's async connection
    # pool binds its transport to whichever event loop first used it, which breaks
    # ("Event loop is closed") once a different loop reuses it - exactly what the test
    # suite hits, since each test's asyncio.run() is its own loop. Same root cause as
    # gds_api.db's NullPool fix for the SQLAlchemy engine; uvicorn only ever runs one
    # loop, so this costs nothing there either.
    return Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


@lru_cache(maxsize=1)
def _embedding_model():  # type: ignore[no-untyped-def]
    # Imported lazily: loading the model is a slow, one-time cost that shouldn't happen
    # at module import for code paths (most of the API) that never touch semantic memory.
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer("all-MiniLM-L6-v2")


async def _embed(text: str) -> list[float]:
    # SentenceTransformer.encode() is synchronous/CPU-bound; run off the event loop so it
    # doesn't block other requests, matching the pattern evidence.py uses for MinIO.
    def _run() -> list[float]:
        return _embedding_model().encode(text).tolist()  # type: ignore[no-any-return]

    return await asyncio.to_thread(_run)


# ---- Working memory (Redis) ------------------------------------------------------


def _working_key(mission_id: uuid.UUID) -> str:
    return f"mission:{mission_id}:state"


async def set_working_memory(
    mission_id: uuid.UUID, data: dict[str, object], ttl_seconds: int = 3600
) -> None:
    import json

    async with _get_redis() as r:
        await r.set(_working_key(mission_id), json.dumps(data), ex=ttl_seconds)


async def get_working_memory(mission_id: uuid.UUID) -> dict[str, object] | None:
    import json

    async with _get_redis() as r:
        raw = await r.get(_working_key(mission_id))
    return json.loads(raw) if raw else None


async def clear_working_memory(mission_id: uuid.UUID) -> bool:
    async with _get_redis() as r:
        deleted = await r.delete(_working_key(mission_id))
    return bool(deleted)


# ---- Semantic memory (Qdrant + Postgres) ------------------------------------------


async def _ensure_knowledge_collection() -> None:
    if not await _qdrant.collection_exists(KNOWLEDGE_COLLECTION):
        await _qdrant.create_collection(
            KNOWLEDGE_COLLECTION,
            vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE),
        )


async def add_knowledge_document(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    title: str,
    content: str,
    document_type: str = "manual",
    source_mission_id: uuid.UUID | None = None,
) -> KnowledgeDocument:
    await _ensure_knowledge_collection()
    vector = await _embed(content)
    point_id = uuid.uuid4()

    await _qdrant.upsert(
        KNOWLEDGE_COLLECTION,
        points=[
            PointStruct(
                id=str(point_id),
                vector=vector,
                payload={"tenant_id": str(tenant_id), "title": title},
            )
        ],
    )

    doc = KnowledgeDocument(
        tenant_id=tenant_id,
        title=title,
        content=content,
        qdrant_point_id=point_id,
        created_by_user_id=user_id,
        document_type=document_type,
        source_mission_id=source_mission_id,
    )
    db.add(doc)
    await db.flush()
    return doc


async def search_knowledge(
    db: AsyncSession, *, tenant_id: uuid.UUID, query: str, limit: int = 3
) -> list[dict[str, object]]:
    await _ensure_knowledge_collection()
    vector = await _embed(query)

    result = await _qdrant.query_points(
        KNOWLEDGE_COLLECTION,
        query=vector,
        limit=limit,
        query_filter=Filter(
            must=[FieldCondition(key="tenant_id", match=MatchValue(value=str(tenant_id)))]
        ),
    )
    if not result.points:
        return []

    point_ids = [uuid.UUID(p.id) for p in result.points]  # type: ignore[arg-type]
    scores_by_point_id = {uuid.UUID(p.id): p.score for p in result.points}  # type: ignore[arg-type]
    rows = (
        await db.execute(
            select(KnowledgeDocument).where(KnowledgeDocument.qdrant_point_id.in_(point_ids))
        )
    ).scalars()

    return [
        {
            "id": str(doc.id),
            "title": doc.title,
            "content": doc.content,
            "score": scores_by_point_id.get(doc.qdrant_point_id),
        }
        for doc in rows
    ]


# ---- Relationship memory (Neo4j) --------------------------------------------------


async def record_mission_relationships(
    *,
    mission_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    tool_names: list[str],
    agent_names: list[str] | None = None,
) -> None:
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        async with driver.session() as session:
            await session.run(
                """
                MERGE (t:Tenant {id: $tenant_id})
                MERGE (u:User {id: $user_id})
                MERGE (m:Mission {id: $mission_id})
                MERGE (m)-[:BELONGS_TO]->(t)
                MERGE (u)-[:REQUESTED]->(m)
                """,
                tenant_id=str(tenant_id),
                user_id=str(user_id),
                mission_id=str(mission_id),
            )
            for tool_name in tool_names:
                await session.run(
                    """
                    MATCH (m:Mission {id: $mission_id})
                    MERGE (tool:Tool {name: $tool_name})
                    MERGE (m)-[:EXECUTED]->(tool)
                    """,
                    mission_id=str(mission_id),
                    tool_name=tool_name,
                )
            for agent_name in agent_names or []:
                await session.run(
                    """
                    MATCH (m:Mission {id: $mission_id})
                    MERGE (a:Agent {name: $agent_name})
                    MERGE (m)-[:HANDLED_BY]->(a)
                    """,
                    mission_id=str(mission_id),
                    agent_name=agent_name,
                )
    finally:
        await driver.close()


# ---- Phase 20 (Continuation Prompt 7 / EDP-007), Part 12: Finding correlation -----
#
# New Neo4j node/relationship types layered onto the existing agent-tool graph above
# (Tenant/User/Mission/Tool/Agent, unchanged) - not a new graph store, per the Phase
# 20.1 pre-build audit's own reuse plan (section 26 item 8, section 27 item 5). Real
# writes only, at the exact real state-transition points that already exist:
# tool_gateway._auto_fix_finding (Finding -> MissionPlan) and
# merge_coordinator.commit_mission (MissionPlan -> Commit, once a real commit lands).
# "Attack path" and "detection" (the other two links EDP-007's own chain names) are
# real free-text properties already on Finding (Part 9) - copied onto the Finding
# node's own properties, never modelled as separate fabricated node types.


async def record_finding_remediation_edge(
    *,
    finding_id: uuid.UUID,
    tenant_id: uuid.UUID,
    finding_title: str,
    finding_status: str,
    attack_path: str | None,
    detection_coverage: str | None,
    mission_plan_id: uuid.UUID,
    objective: str,
) -> None:
    """Called once, from tool_gateway._auto_fix_finding, the real moment a Finding is
    routed into a real remediation MissionPlan."""
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        async with driver.session() as session:
            await session.run(
                """
                MERGE (t:Tenant {id: $tenant_id})
                MERGE (f:Finding {id: $finding_id})
                SET f.title = $finding_title, f.status = $finding_status,
                    f.attack_path = $attack_path, f.detection_coverage = $detection_coverage
                MERGE (f)-[:BELONGS_TO]->(t)
                MERGE (mp:MissionPlan {id: $mission_plan_id})
                SET mp.objective = $objective
                MERGE (f)-[:REMEDIATED_BY]->(mp)
                """,
                tenant_id=str(tenant_id),
                finding_id=str(finding_id),
                finding_title=finding_title,
                finding_status=finding_status,
                attack_path=attack_path,
                detection_coverage=detection_coverage,
                mission_plan_id=str(mission_plan_id),
                objective=objective,
            )
    finally:
        await driver.close()


async def record_remediation_commit_edge(
    *, mission_plan_id: uuid.UUID, finding_id: uuid.UUID, commit_hash: str
) -> None:
    """Called once, from merge_coordinator.commit_mission, the real moment a
    finding-linked MissionPlan's real commit lands and the finding advances to
    awaiting_retest."""
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        async with driver.session() as session:
            await session.run(
                """
                MERGE (mp:MissionPlan {id: $mission_plan_id})
                MERGE (c:Commit {hash: $commit_hash})
                MERGE (mp)-[:PRODUCED]->(c)
                MERGE (f:Finding {id: $finding_id})
                SET f.status = 'awaiting_retest'
                MERGE (f)-[:AWAITING_RETEST_SINCE]->(c)
                """,
                mission_plan_id=str(mission_plan_id),
                commit_hash=commit_hash,
                finding_id=str(finding_id),
            )
    finally:
        await driver.close()


async def get_finding_correlation(
    finding_id: uuid.UUID, tenant_id: uuid.UUID
) -> dict[str, object] | None:
    """The real read side of the correlation chain above - a single Cypher traversal
    from one real Finding node through its (optional) real MissionPlan and (optional)
    real Commit. Returns None if the Finding has no correlation node yet (never
    routed through auto_fix_finding) - the caller falls back to Postgres-only data
    in that case, never fabricating graph data that doesn't exist."""
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        async with driver.session() as session:
            result = await session.run(
                """
                MATCH (f:Finding {id: $finding_id})-[:BELONGS_TO]->(:Tenant {id: $tenant_id})
                OPTIONAL MATCH (f)-[:REMEDIATED_BY]->(mp:MissionPlan)
                OPTIONAL MATCH (mp)-[:PRODUCED]->(c:Commit)
                OPTIONAL MATCH (f)-[:AWAITING_RETEST_SINCE]->(c)
                RETURN f, mp, c
                """,
                finding_id=str(finding_id),
                tenant_id=str(tenant_id),
            )
            record = await result.single()
    finally:
        await driver.close()

    if record is None:
        return None
    finding_node = record["f"]
    mission_plan_node = record["mp"]
    commit_node = record["c"]
    return {
        "finding_title": finding_node.get("title"),
        "finding_status": finding_node.get("status"),
        "attack_path": finding_node.get("attack_path"),
        "detection_coverage": finding_node.get("detection_coverage"),
        "mission_plan_id": mission_plan_node.get("id") if mission_plan_node else None,
        "remediation_objective": mission_plan_node.get("objective") if mission_plan_node else None,
        "commit_hash": commit_node.get("hash") if commit_node else None,
    }


# ---- Phase 20 (Continuation Prompt 7 / EDP-007), Part 13: Memory/Learning ----------
#
# Real graph traceability for lessons, mirroring Part 12's correlation-engine
# precedent immediately above - the KnowledgeDocument/Qdrant row is the one real
# source of truth (and the one real thing search_knowledge() actually queries); this
# Neo4j edge only adds "which real Mission produced this real lesson" for graph
# traversal, layered onto the existing agent-tool graph, not a new store.


async def record_lesson_edge(
    *, mission_id: uuid.UUID, tenant_id: uuid.UUID, lesson_id: uuid.UUID, lesson_type: str
) -> None:
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        async with driver.session() as session:
            await session.run(
                """
                MERGE (t:Tenant {id: $tenant_id})
                MERGE (m:Mission {id: $mission_id})
                MERGE (m)-[:BELONGS_TO]->(t)
                MERGE (l:Lesson {id: $lesson_id})
                SET l.lesson_type = $lesson_type
                MERGE (m)-[:PRODUCED_LESSON]->(l)
                """,
                tenant_id=str(tenant_id),
                mission_id=str(mission_id),
                lesson_id=str(lesson_id),
                lesson_type=lesson_type,
            )
    finally:
        await driver.close()


async def _tenant_relationship_summary(tenant_id: uuid.UUID) -> RelationshipMemoryOut:
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        async with driver.session() as session:
            result = await session.run(
                """
                MATCH (t:Tenant {id: $tenant_id})<-[:BELONGS_TO]-(m:Mission)
                OPTIONAL MATCH (m)-[e:EXECUTED]->(tool:Tool)
                OPTIONAL MATCH (m)-[h:HANDLED_BY]->(agent:Agent)
                RETURN
                    count(DISTINCT m) AS mission_nodes,
                    count(DISTINCT tool) AS tool_nodes,
                    count(DISTINCT agent) AS agent_nodes,
                    count(e) AS executed_edges,
                    count(h) AS handled_by_edges
                """,
                tenant_id=str(tenant_id),
            )
            record = await result.single()
    finally:
        await driver.close()

    if record is None:
        return RelationshipMemoryOut(
            mission_nodes=0, tool_nodes=0, agent_nodes=0, executed_edges=0, handled_by_edges=0
        )
    return RelationshipMemoryOut(
        mission_nodes=record["mission_nodes"],
        tool_nodes=record["tool_nodes"],
        agent_nodes=record["agent_nodes"],
        executed_edges=record["executed_edges"],
        handled_by_edges=record["handled_by_edges"],
    )


async def _tenant_agent_tool_topology(tenant_id: uuid.UUID) -> RelationshipGraphOut:
    """Phase 12.3: the real topology _tenant_relationship_summary above only ever
    collapses to aggregate counts. There's no stored Agent-[:USED]->Tool edge (agents and
    tools only connect via a shared Mission), so this returns a real Cypher aggregation
    over that shared structure - which agent and tool have really co-occurred on the same
    real missions, and how many - rather than fabricating a direct edge that isn't
    actually stored."""
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        async with driver.session() as session:
            result = await session.run(
                """
                MATCH (t:Tenant {id: $tenant_id})<-[:BELONGS_TO]-(m:Mission)
                MATCH (m)-[:HANDLED_BY]->(a:Agent)
                MATCH (m)-[:EXECUTED]->(tool:Tool)
                RETURN a.name AS agent_name, tool.name AS tool_name,
                       count(DISTINCT m) AS mission_count
                ORDER BY mission_count DESC
                """,
                tenant_id=str(tenant_id),
            )
            records = [record async for record in result]
    finally:
        await driver.close()

    return RelationshipGraphOut(
        edges=[
            AgentToolEdgeOut(
                agent_name=record["agent_name"],
                tool_name=record["tool_name"],
                mission_count=record["mission_count"],
            )
            for record in records
        ]
    )


@router.get("/overview", response_model=MemoryOverviewOut)
async def get_memory_overview(
    current_user: CurrentUser = Depends(require_permission("knowledge:read")),
    db: AsyncSession = Depends(get_db),
) -> MemoryOverviewOut:
    """Real, tenant-scoped snapshot across three of the four memory tiers (episodic
    memory is missions/mission_tasks themselves - see Mastermind, not repeated here)."""
    tenant_mission_ids = {
        row[0]
        for row in (
            await db.execute(select(Mission.id).where(Mission.tenant_id == current_user.tenant_id))
        ).all()
    }

    working_entries: list[WorkingMemoryEntryOut] = []
    async with _get_redis() as r:
        async for key in r.scan_iter(match="mission:*:state"):
            parts = key.split(":")
            if len(parts) != 3:
                continue
            try:
                mission_id = uuid.UUID(parts[1])
            except ValueError:
                continue
            if mission_id not in tenant_mission_ids:
                continue
            ttl = await r.ttl(key)
            working_entries.append(WorkingMemoryEntryOut(mission_id=mission_id, ttl_seconds=ttl))

    relationship_memory = await _tenant_relationship_summary(current_user.tenant_id)

    knowledge_count = (
        await db.execute(
            select(func.count(KnowledgeDocument.id)).where(
                KnowledgeDocument.tenant_id == current_user.tenant_id
            )
        )
    ).scalar_one()

    return MemoryOverviewOut(
        working_memory=working_entries,
        relationship_memory=relationship_memory,
        knowledge_document_count=knowledge_count,
    )


@router.get("/graph", response_model=RelationshipGraphOut)
async def get_relationship_graph(
    current_user: CurrentUser = Depends(require_permission("knowledge:read")),
) -> RelationshipGraphOut:
    """Phase 12.3: renders the real Neo4j relationship data /overview above only ever
    aggregates to counts - which real agents and tools have actually worked together, and
    on how many real missions."""
    return await _tenant_agent_tool_topology(current_user.tenant_id)
