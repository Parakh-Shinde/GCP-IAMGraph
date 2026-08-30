from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detections import analyze
from .graph import as_dot, build_attack_graph
from .parser import (
    InputError,
    load_cloud_asset_inventory,
    load_deny_policies,
    load_environment,
    load_role_definitions,
)
from .reporting import (
    as_json,
    as_markdown,
    as_sarif,
    build_report,
)


def _write_output(
    path: str,
    content: str,
    output_type: str,
) -> None:
    """Write CLI output and convert filesystem failures into clean errors."""

    try:
        Path(path).write_text(
            content,
            encoding="utf-8",
        )
    except OSError as exc:
        raise InputError(f"Unable to write {output_type} file '{path}': {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze GCP IAM data for dangerous access and attack paths"
    )
    parser.add_argument(
        "input",
        help="Path to GCP IAM input data",
    )
    parser.add_argument(
        "--input-format",
        choices=(
            "iamgraph",
            "cai",
        ),
        default="iamgraph",
        help="Input format: IAMGraph JSON or Cloud Asset Inventory JSONL",
    )
    parser.add_argument(
        "--format",
        choices=(
            "json",
            "markdown",
            "sarif",
        ),
        default="json",
        help="Security report output format",
    )
    parser.add_argument(
        "--output",
        help="Write the security report to this file",
    )
    parser.add_argument(
        "--graph-output",
        help="Write the generated attack graph to this file",
    )
    parser.add_argument(
        "--graph-format",
        choices=(
            "json",
            "dot",
        ),
        default="json",
        help="Attack-graph output format",
    )
    parser.add_argument(
        "--fail-on",
        choices=(
            "none",
            "high",
            "critical",
        ),
        default="none",
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.input_format == "cai":
            resources = load_cloud_asset_inventory(args.input)
            role_definitions = []
            deny_policies = []
        else:
            resources = load_environment(args.input)
            role_definitions = load_role_definitions(args.input)
            deny_policies = load_deny_policies(args.input)

        findings = analyze(
            resources,
            role_definitions,
            deny_policies,
        )
    except (InputError, ValueError) as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 2

    if args.graph_output:
        graph = build_attack_graph(findings)

        if args.graph_format == "dot":
            graph_rendered = as_dot(graph)
        else:
            graph_rendered = (
                json.dumps(
                    graph,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )

        try:
            _write_output(
                args.graph_output,
                graph_rendered,
                "attack graph",
            )
        except InputError as exc:
            print(
                f"error: {exc}",
                file=sys.stderr,
            )
            return 2

    report = build_report(
        findings,
        len(resources),
        source_path=args.input,
    )

    if args.format == "markdown":
        rendered = as_markdown(report)
    elif args.format == "sarif":
        rendered = as_sarif(report)
    else:
        rendered = as_json(report)

    if args.output:
        try:
            _write_output(
                args.output,
                rendered + "\n",
                "security report",
            )
        except InputError as exc:
            print(
                f"error: {exc}",
                file=sys.stderr,
            )
            return 2
    else:
        print(rendered)

    severities = {item.severity for item in findings}

    if args.fail_on == "critical" and "critical" in severities:
        return 1

    if args.fail_on == "high" and severities.intersection(
        {
            "high",
            "critical",
        }
    ):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
