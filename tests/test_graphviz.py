from pathlib import Path

from gcp_iamgraph.cli import main
from gcp_iamgraph.detections import analyze
from gcp_iamgraph.graph import (
    as_dot,
    build_attack_graph,
)
from gcp_iamgraph.models import Resource


def test_attack_graph_can_be_rendered_as_dot():
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

    graph = build_attack_graph(analyze([project]))
    rendered = as_dot(graph)

    assert rendered.startswith('digraph "GCP IAMGraph" {')
    assert 'rankdir="LR";' in rendered
    assert '"user:admin@example.test"' in rendered
    assert '"roles/owner"' in rendered
    assert '"projects/payments-prod"' in rendered
    assert '"user:admin@example.test" -> "roles/owner"' in rendered
    assert "GCP-IAM-001" in rendered
    assert rendered.endswith("}\n")


def test_cli_writes_dot_attack_graph(
    tmp_path,
    capsys,
):
    input_path = Path(__file__).parents[1] / "examples" / "vulnerable-environment.json"
    output_path = tmp_path / "attack-graph.dot"

    exit_code = main(
        [
            str(input_path),
            "--graph-format",
            "dot",
            "--graph-output",
            str(output_path),
        ]
    )

    capsys.readouterr()

    rendered = output_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output_path.exists()
    assert rendered.startswith('digraph "GCP IAMGraph" {')
    assert 'rankdir="LR";' in rendered
    assert "GCP-IAM-001" in rendered
    assert "GCP-IAM-008" in rendered
    assert rendered.endswith("}\n")
