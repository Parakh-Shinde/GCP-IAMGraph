from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, cast

from .models import Finding

TOOL_NAME = "GCP IAMGraph"
TOOL_VERSION = "0.1.0"

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/"
    "sarif/v2.1.0/cs01/schemas/"
    "sarif-schema-2.1.0.json"
)

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def build_report(
    findings: list[Finding],
    resource_count: int,
    source_path: str | None = None,
) -> dict[str, object]:
    """Build a serializable security report."""

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": (datetime.now(timezone.utc).isoformat()),
        "source_path": (source_path or "gcp-iamgraph-input.json"),
        "summary": {
            "resources_analyzed": resource_count,
            "total_findings": len(findings),
            "by_severity": dict(Counter(item.severity for item in findings)),
        },
        "findings": [item.to_dict() for item in findings],
    }


def as_json(
    report: dict[str, object],
) -> str:
    """Render a report as JSON."""

    return json.dumps(
        report,
        indent=2,
    )


def as_markdown(
    report: dict[str, object],
) -> str:
    """Render a report as Markdown."""

    summary = cast(
        dict[str, Any],
        report["summary"],
    )
    findings = cast(
        list[dict[str, Any]],
        report["findings"],
    )

    lines = [
        "# GCP IAMGraph Security Report",
        "",
        (f"- Resources analyzed: {summary['resources_analyzed']}"),
        (f"- Findings: {summary['total_findings']}"),
        "",
    ]

    for finding in findings:
        attack_path = " → ".join(finding["attack_path"])

        lines.extend(
            [
                (f"## [{finding['severity'].upper()}] {finding['title']}"),
                "",
                (f"**Rule:** `{finding['rule_id']}`  "),
                (f"**Principal:** `{finding['principal']}`  "),
                (f"**Resource:** `{finding['resource']}`  "),
                (f"**Attack path:** {attack_path}"),
                "",
                finding["description"],
                "",
                "**Evidence**",
                *[f"- {item}" for item in finding["evidence"]],
                "",
                (f"**Remediation:** {finding['remediation']}"),
                "",
            ]
        )

    return "\n".join(lines)


def _sarif_rule(
    finding: dict[str, Any],
) -> dict[str, object]:
    """Build one SARIF reporting descriptor."""

    severity = finding["severity"]

    return {
        "id": finding["rule_id"],
        "name": finding["rule_id"],
        "shortDescription": {
            "text": finding["title"],
        },
        "fullDescription": {
            "text": finding["description"],
        },
        "defaultConfiguration": {
            "level": SARIF_LEVELS.get(
                severity,
                "warning",
            ),
        },
        "help": {
            "text": finding["remediation"],
            "markdown": (f"**Remediation:** {finding['remediation']}"),
        },
        "properties": {
            "severity": severity,
            "references": finding["references"],
        },
    }


def _sarif_result(
    finding: dict[str, Any],
    source_path: str,
) -> dict[str, object]:
    """Build one SARIF result with a physical location."""

    source_uri = source_path.replace(
        "\\",
        "/",
    )

    return {
        "ruleId": finding["rule_id"],
        "level": SARIF_LEVELS.get(
            finding["severity"],
            "warning",
        ),
        "message": {
            "text": finding["title"],
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": source_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": 1,
                    },
                },
                "logicalLocations": [
                    {
                        "name": finding["resource"],
                        "fullyQualifiedName": (finding["resource"]),
                        "kind": "resource",
                    }
                ],
            }
        ],
        "properties": {
            "severity": finding["severity"],
            "principal": finding["principal"],
            "resource": finding["resource"],
            "attackPath": finding["attack_path"],
            "evidence": finding["evidence"],
            "remediation": finding["remediation"],
            "references": finding["references"],
        },
    }


def as_sarif(
    report: dict[str, object],
) -> str:
    """Render a report as SARIF 2.1.0."""

    findings = cast(
        list[dict[str, Any]],
        report["findings"],
    )
    source_path = cast(
        str,
        report.get(
            "source_path",
            "gcp-iamgraph-input.json",
        ),
    )

    rules_by_id: dict[
        str,
        dict[str, object],
    ] = {}

    for finding in findings:
        rule_id = finding["rule_id"]

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _sarif_rule(finding)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "rules": [
                            rules_by_id[rule_id] for rule_id in sorted(rules_by_id)
                        ],
                    }
                },
                "results": [
                    _sarif_result(
                        finding,
                        source_path,
                    )
                    for finding in findings
                ],
            }
        ],
    }

    return json.dumps(
        sarif,
        indent=2,
    )
