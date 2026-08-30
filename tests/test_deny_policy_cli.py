import json

from gcp_iamgraph.cli import main

PRINCIPAL = "user:attacker@example.test"
PERMISSION = "resourcemanager.projects.setIamPolicy"
ORGANIZATION = "organizations/987654"
PROJECT = "projects/payments-prod"


def _environment_document(
    *,
    deny_policy=None,
):
    document = {
        "resources": [
            {
                "name": ORGANIZATION,
                "type": "organization",
            },
            {
                "name": PROJECT,
                "type": "project",
                "parent": ORGANIZATION,
                "bindings": [
                    {
                        "role": ("roles/resourcemanager.projectIamAdmin"),
                        "members": [PRINCIPAL],
                    }
                ],
            },
        ]
    }

    if deny_policy is not None:
        document["deny_policies"] = [deny_policy]

    return document


def _deny_policy(
    *,
    exception_principals=None,
):
    return {
        "name": "policies/deny-project-iam",
        "parent": ORGANIZATION,
        "display_name": "Deny project IAM changes",
        "rules": [
            {
                "denied_principals": [PRINCIPAL],
                "denied_permissions": [PERMISSION],
                "exception_principals": (exception_principals or []),
            }
        ],
    }


def _run_cli(
    tmp_path,
    document,
):
    input_path = tmp_path / "environment.json"
    output_path = tmp_path / "report.json"

    input_path.write_text(
        json.dumps(document),
        encoding="utf-8",
    )

    exit_code = main(
        [
            str(input_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    report = json.loads(output_path.read_text(encoding="utf-8"))

    return exit_code, report


def _rule_ids(report):
    return {finding["rule_id"] for finding in report["findings"]}


def test_cli_reports_confirmed_iam_escalation_without_deny(
    tmp_path,
    capsys,
):
    exit_code, report = _run_cli(
        tmp_path,
        _environment_document(),
    )

    capsys.readouterr()
    rule_ids = _rule_ids(report)

    assert exit_code == 0
    assert report["summary"]["resources_analyzed"] == 2
    assert "GCP-IAM-003" in rule_ids
    assert "GCP-IAM-007" in rule_ids


def test_cli_applies_inherited_deny_policy(
    tmp_path,
    capsys,
):
    exit_code, report = _run_cli(
        tmp_path,
        _environment_document(
            deny_policy=_deny_policy(),
        ),
    )

    capsys.readouterr()
    rule_ids = _rule_ids(report)

    assert exit_code == 0
    assert report["summary"]["resources_analyzed"] == 2
    assert "GCP-IAM-003" not in rule_ids
    assert "GCP-IAM-007" not in rule_ids


def test_cli_applies_deny_principal_exception(
    tmp_path,
    capsys,
):
    exit_code, report = _run_cli(
        tmp_path,
        _environment_document(
            deny_policy=_deny_policy(
                exception_principals=[PRINCIPAL],
            ),
        ),
    )

    capsys.readouterr()
    rule_ids = _rule_ids(report)

    assert exit_code == 0
    assert "GCP-IAM-003" in rule_ids
    assert "GCP-IAM-007" in rule_ids
