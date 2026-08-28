from __future__ import annotations

import json
from collections.abc import Iterable
from itertools import pairwise
from typing import cast

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


def _dot_quote(value: str) -> str:
    """Quote a string safely for Graphviz DOT."""

    return json.dumps(
        value,
        ensure_ascii=False,
    )


def as_dot(
    graph: dict[str, object],
) -> str:
    """Render an attack graph using Graphviz DOT."""

    nodes = cast(
        list[dict[str, str]],
        graph.get("nodes", []),
    )
    edges = cast(
        list[dict[str, str]],
        graph.get("edges", []),
    )

    node_styles = {
        "principal": (
            "ellipse",
            "#DBEAFE",
        ),
        "role": (
            "box",
            "#FEF3C7",
        ),
        "resource": (
            "folder",
            "#DCFCE7",
        ),
        "permission": (
            "diamond",
            "#FCE7F3",
        ),
        "action": (
            "box",
            "#F3F4F6",
        ),
    }

    severity_colours = {
        "critical": "#DC2626",
        "high": "#EA580C",
        "medium": "#CA8A04",
        "low": "#2563EB",
    }

    lines = [
        'digraph "GCP IAMGraph" {',
        '  rankdir="LR";',
        ('  graph [fontname="Arial", bgcolor="white"];'),
        ('  node [fontname="Arial", style="filled"];'),
        ('  edge [fontname="Arial", fontsize="10"];'),
    ]

    for node in nodes:
        node_id = node["id"]
        label = node["label"]
        kind = node["kind"]

        shape, colour = node_styles.get(
            kind,
            node_styles["action"],
        )

        lines.append(
            f"  {_dot_quote(node_id)} "
            f"[label={_dot_quote(label)}, "
            f'shape="{shape}", '
            f'fillcolor="{colour}"];'
        )

    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        rule_id = edge["rule_id"]
        severity = edge["severity"]

        colour = severity_colours.get(
            severity,
            "#4B5563",
        )
        label = f"{rule_id} ({severity})"

        lines.append(
            f"  {_dot_quote(source)} -> "
            f"{_dot_quote(target)} "
            f"[label={_dot_quote(label)}, "
            f'color="{colour}"];'
        )

    lines.append("}")

    return "\n".join(lines) + "\n"
