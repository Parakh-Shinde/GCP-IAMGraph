from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detections import analyze
from .graph import build_attack_graph
from .parser import (
    InputError,
    load_environment,
    load_role_definitions,
)
from .reporting import (
    as_json,
    as_markdown,
    build_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Analyze GCP IAM data for dangerous access and attack paths")
    )
    parser.add_argument(
        "input",
        help=("Path to a GCP IAMGraph JSON environment"),
    )
    parser.add_argument(
        "--format",
        choices=(
            "json",
            "markdown",
        ),
        default="json",
    )
    parser.add_argument(
        "--output",
        help="Write the security report to this file",
    )
    parser.add_argument(
        "--graph-output",
        help=("Write the generated attack graph as JSON to this file"),
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
        resources = load_environment(args.input)
        role_definitions = load_role_definitions(args.input)
        findings = analyze(
            resources,
            role_definitions,
        )
    except (InputError, ValueError) as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 2

    if args.graph_output:
        graph = build_attack_graph(findings)

        graph_json = json.dumps(
            graph,
            indent=2,
            sort_keys=True,
        )

        Path(args.graph_output).write_text(
            graph_json + "\n",
            encoding="utf-8",
        )

    report = build_report(
        findings,
        len(resources),
    )

    rendered = as_markdown(report) if args.format == "markdown" else as_json(report)

    if args.output:
        Path(args.output).write_text(
            rendered + "\n",
            encoding="utf-8",
        )
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
