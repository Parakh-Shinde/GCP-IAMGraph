from __future__ import annotations

from collections.abc import Iterable
from itertools import pairwise

from .models import Finding


def _node_kind(node_id: str) -> str:
    """Classify an attack-path node."""

    principal_prefixes = (
        "user:",
        "group:",
        "serviceAccount:",
        "domain:",
        "allUsers",
        "allAuthenticatedUsers",
    )

    if node_id.startswith(principal_prefixes):
        return "principal"

    if node_id.startswith("roles/"):
        return "role"

    if node_id.startswith(
        (
            "organizations/",
            "folders/",
            "projects/",
        )
    ):
        return "resource"

    if "." in node_id and " " not in node_id:
        return "permission"

    return "action"


def build_attack_graph(
    findings: Iterable[Finding],
) -> dict[str, object]:
    """Convert security findings into a directed attack graph."""

    nodes: dict[str, dict[str, str]] = {}
    edges: dict[
        tuple[str, str, str],
        dict[str, str],
    ] = {}

    for finding in findings:
        path = finding.attack_path

        for node_id in path:
            nodes[node_id] = {
                "id": node_id,
                "label": node_id,
                "kind": _node_kind(node_id),
            }

        for source, target in pairwise(path):
            key = (
                source,
                target,
                finding.rule_id,
            )

            edges[key] = {
                "source": source,
                "target": target,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "principal": finding.principal,
                "resource": finding.resource,
            }

    return {
        "version": "1.0",
        "nodes": sorted(
            nodes.values(),
            key=lambda node: node["id"],
        ),
        "edges": sorted(
            edges.values(),
            key=lambda edge: (
                edge["rule_id"],
                edge["source"],
                edge["target"],
            ),
        ),
    }
