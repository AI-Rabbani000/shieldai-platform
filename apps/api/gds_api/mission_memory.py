"""Phase 20 (Continuation Prompt 7 / EDP-007), Part 13: Memory/Learning Integration.

The Phase 20.1 pre-build audit (section 8) found no per-mission "lessons learned"/
playbook persistence anywhere in this codebase - Prompt 7 Part 13's requirement
(decisions, failed approaches, successful techniques, reusable playbooks) is net-new
persistence, added as new fields/rows in the existing Qdrant+Neo4j+Postgres stores
(gds_api.memory), not a new memory service.

The read side needs no new code at all: gds_api.workflows.activities' existing
Phase 10.2 memory-informed planning already runs a real semantic
gds_api.memory.search_knowledge() query against every new mission's objective and
feeds the hits into that mission's own planning prompt - a Lesson is simply a
KnowledgeDocument with document_type set to one of the values below, so it is
automatically retrievable by every future mission's own first-decision search with
zero additional plumbing. This module defines the one real, fail-closed write-side
vocabulary; gds_api.tool_gateway.record_mission_lesson is the one real write path.
"""

from __future__ import annotations

from enum import StrEnum


class LessonType(StrEnum):
    DECISION = "decision"
    FAILED_APPROACH = "failed_approach"
    SUCCESSFUL_TECHNIQUE = "successful_technique"
    PLAYBOOK = "playbook"


LESSON_TYPES: frozenset[str] = frozenset(member.value for member in LessonType)

# The full set of real KnowledgeDocument.document_type values - "manual" is the
# pre-existing, unchanged behavior (a human- or add_knowledge-tool-created document);
# the 4 lesson types above are this sub-phase's new, additive vocabulary.
DOCUMENT_TYPES: frozenset[str] = frozenset({"manual"}) | LESSON_TYPES


class InvalidLessonType(ValueError):
    def __init__(self, lesson_type: str) -> None:
        self.lesson_type = lesson_type
        super().__init__(
            f"'{lesson_type}' is not one of the {len(LESSON_TYPES)} authoritative lesson types"
        )


def validate_lesson_type(lesson_type: str) -> None:
    if lesson_type not in LESSON_TYPES:
        raise InvalidLessonType(lesson_type)
