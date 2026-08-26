from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from .models import Finding


def build_report(findings: list[Finding], resource_count: int) -> dict[str, object]:
    return {
        "tool": "GCP IAMGraph",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "resources_analyzed": resource_count,
            "total_findings": len(findings),
            "by_severity": dict(Counter(item.severity for item in findings)),
        },
        "findings": [item.to_dict() for item in findings],
    }


def as_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2)


def as_markdown(report: dict[str, object]) -> str:
    summary = report["summary"]
    lines = [
        "# GCP IAMGraph Security Report",
        "",
        f"- Resources analyzed: {summary['resources_analyzed']}",
        f"- Findings: {summary['total_findings']}",
        "",
    ]
    for finding in report["findings"]:
        lines.extend([
            f"## [{finding['severity'].upper()}] {finding['title']}",
            "",
            f"**Rule:** `{finding['rule_id']}`  ",
            f"**Principal:** `{finding['principal']}`  ",
            f"**Resource:** `{finding['resource']}`  ",
            f"**Attack path:** {' → '.join(finding['attack_path'])}",
            "",
            finding["description"],
            "",
            "**Evidence**",
            *[f"- {item}" for item in finding["evidence"]],
            "",
            f"**Remediation:** {finding['remediation']}",
            "",
        ])
    return "\n".join(lines)

