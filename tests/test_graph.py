import json
from pathlib import Path

from gcp_iamgraph.cli import main
from gcp_iamgraph.detections import analyze
from gcp_iamgraph.graph import build_attack_graph
from gcp_iamgraph.models import Resource


def test_build_attack_graph_from_findings():
    principal = "user:admin@example.test"

    project = Resource.from_dict(
        {
            "name": "projects/payments-prod",
            "type": "project",
            "display_name": "payments-prod",
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [principal],
                }
            ],
        }
    )

    findings = analyze([project])
    graph = build_attack_graph(findings)

    assert graph["version"] == "1.0"

    node_ids = {node["id"] for node in graph["nodes"]}

    assert principal in node_ids
    assert "roles/owner" in node_ids
    assert project.name in node_ids
    assert "Broad resource control" in node_ids

    edge_pairs = {
        (
            edge["source"],
            edge["target"],
        )
        for edge in graph["edges"]
    }

    assert (
        principal,
        "roles/owner",
    ) in edge_pairs

    assert (
        "roles/owner",
        project.name,
    ) in edge_pairs

    assert (
        project.name,
        "Broad resource control",
    ) in edge_pairs

    assert all(edge["rule_id"] == "GCP-IAM-001" for edge in graph["edges"])


def test_cli_writes_attack_graph(
    tmp_path,
    capsys,
):
    input_path = Path(__file__).parents[1] / "examples" / "vulnerable-environment.json"

    output_path = tmp_path / "attack-graph.json"

    exit_code = main(
        [
            str(input_path),
            "--graph-output",
            str(output_path),
        ]
    )

    capsys.readouterr()

    graph = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert output_path.exists()
    assert graph["version"] == "1.0"
    assert graph["nodes"]
    assert graph["edges"]

    assert all(
        {
            "id",
            "label",
            "kind",
        }
        <= node.keys()
        for node in graph["nodes"]
    )

    assert all(
        {
            "source",
            "target",
            "rule_id",
            "severity",
            "principal",
            "resource",
        }
        <= edge.keys()
        for edge in graph["edges"]
    )
