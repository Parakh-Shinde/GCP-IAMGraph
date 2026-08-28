import json

from gcp_iamgraph.cli import main


def test_cli_analyzes_custom_role(
    tmp_path,
    capsys,
):
    input_path = tmp_path / "environment.json"

    input_path.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "name": "projects/test",
                        "type": "project",
                        "bindings": [
                            {
                                "role": ("projects/test/roles/dangerousOperator"),
                                "members": ["user:developer@example.test"],
                            }
                        ],
                    }
                ],
                "role_definitions": [
                    {
                        "name": ("projects/test/roles/dangerousOperator"),
                        "title": "Dangerous Operator",
                        "permissions": [("resourcemanager.projects.setIamPolicy")],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main([str(input_path)])
    output = json.loads(capsys.readouterr().out)

    rule_ids = {finding["rule_id"] for finding in output["findings"]}

    assert exit_code == 0
    assert output["summary"]["total_findings"] == 2
    assert rule_ids == {
        "GCP-IAM-003",
        "GCP-IAM-007",
    }
