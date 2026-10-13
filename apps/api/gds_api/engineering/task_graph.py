"""Phase 19 (Continuation Prompt 6), Part 2: real Task Graph (DAG) utilities - pure,
deterministic logic over a real MissionPlan's real EngineeringTask rows. No AI call
here; this module only ever reasons about dependency structure real rows already have.
"""

from __future__ import annotations

from dataclasses import dataclass


class TaskGraphError(Exception):
    pass


class CyclicDependencyError(TaskGraphError):
    pass


class UnknownDependencyError(TaskGraphError):
    pass


@dataclass
class GraphNode:
    task_key: str
    depends_on: tuple[str, ...]


def validate_graph(nodes: list[GraphNode]) -> None:
    """Real, structural validation - every real dependency must reference a real task
    in the same graph, and the graph must be a real DAG (no cycles). Raises immediately
    on the first real problem found; never silently drops an invalid edge."""
    keys = {n.task_key for n in nodes}
    for node in nodes:
        for dep in node.depends_on:
            if dep not in keys:
                raise UnknownDependencyError(
                    f"Task '{node.task_key}' depends on unknown task '{dep}'"
                )
    topological_order(nodes)  # raises CyclicDependencyError if not a real DAG


def topological_order(nodes: list[GraphNode]) -> list[str]:
    """Real Kahn's-algorithm topological sort. Returns task_keys in a real, valid
    execution order (dependencies always precede dependents)."""
    in_degree: dict[str, int] = {n.task_key: 0 for n in nodes}
    dependents: dict[str, list[str]] = {n.task_key: [] for n in nodes}
    for node in nodes:
        for dep in node.depends_on:
            if dep not in dependents:
                raise UnknownDependencyError(
                    f"Task '{node.task_key}' depends on unknown task '{dep}'"
                )
            dependents[dep].append(node.task_key)
            in_degree[node.task_key] += 1

    ready = sorted([key for key, degree in in_degree.items() if degree == 0])
    order: list[str] = []
    while ready:
        current = ready.pop(0)
        order.append(current)
        for dependent in sorted(dependents[current]):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                ready.append(dependent)
        ready.sort()

    if len(order) != len(nodes):
        remaining = sorted(set(in_degree) - set(order))
        raise CyclicDependencyError(
            f"Real cyclic dependency detected among tasks: {', '.join(remaining)}"
        )
    return order


def ready_tasks(nodes: list[GraphNode], completed: set[str]) -> list[str]:
    """Real tasks whose every real dependency is already in `completed` - the actual,
    live scheduling question the Parallel Execution Engine (Part 5) asks repeatedly as
    tasks finish, not just once at plan time."""
    return sorted(
        n.task_key
        for n in nodes
        if n.task_key not in completed and all(dep in completed for dep in n.depends_on)
    )
