import json
from pathlib import Path

from gcp_iamgraph.cli import main
from gcp_iamgraph.detections import analyze
from gcp_iamgraph.models import Resource
from gcp_iamgraph.reporting import (
    as_sarif,
    build_report,
)


def test_report_can_be_rendered_as_sarif():
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
    report = build_report(
        findings,
        resource_count=1,
    )

    sarif = json.loads(as_sarif(report))

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]

    assert driver["name"] == "GCP IAMGraph"
    assert driver["version"] == "0.2.0"

    rules = {rule["id"]: rule for rule in driver["rules"]}

    assert "GCP-IAM-001" in rules

    result = run["results"][0]

    physical_location = result["locations"][0]["physicalLocation"]

    assert physical_location["artifactLocation"]["uri"] == "gcp-iamgraph-input.json"
    assert physical_location["region"]["startLine"] == 1

    assert result["ruleId"] == "GCP-IAM-001"
    assert result["level"] == "error"
    assert result["message"]["text"] == ("Broad primitive role: roles/owner")
    assert (
        result["locations"][0]["logicalLocations"][0]["name"]
        == "projects/payments-prod"
    )
    assert result["properties"]["principal"] == (principal)


def test_cli_writes_sarif_report(
    tmp_path,
    capsys,
):
    input_path = Path(__file__).parents[1] / "examples" / "vulnerable-environment.json"
    output_path = tmp_path / "iam-findings.sarif"

    exit_code = main(
        [
            str(input_path),
            "--format",
            "sarif",
            "--output",
            str(output_path),
        ]
    )

    capsys.readouterr()

    sarif = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert output_path.exists()
    assert sarif["version"] == "2.1.0"

    run = sarif["runs"][0]

    assert run["tool"]["driver"]["name"] == ("GCP IAMGraph")
    assert run["tool"]["driver"]["rules"]
    assert run["results"]

    first_result = run["results"][0]

    assert (
        first_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == input_path.as_posix()
    )

    rule_ids = {result["ruleId"] for result in run["results"]}

    assert "GCP-IAM-001" in rule_ids
    assert "GCP-IAM-008" in rule_ids
