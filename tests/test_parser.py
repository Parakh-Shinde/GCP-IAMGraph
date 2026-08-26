import json

import pytest

from gcp_iamgraph.parser import (
    InputError,
    load_environment,
    load_role_definitions,
)


def test_loads_valid_environment(tmp_path):
    path = tmp_path / "gcp.json"
    path.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "name": "projects/test",
                        "type": "project",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    resources = load_environment(path)

    assert resources[0].name == "projects/test"


def test_rejects_unknown_parent(tmp_path):
    path = tmp_path / "gcp.json"
    path.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "name": "projects/test",
                        "type": "project",
                        "parent": "folders/missing",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InputError):
        load_environment(path)


def test_loads_custom_role_definitions(tmp_path):
    path = tmp_path / "gcp.json"
    path.write_text(
        json.dumps(
            {
                "resources": [],
                "role_definitions": [
                    {
                        "name": ("projects/payments-prod/roles/deploymentOperator"),
                        "title": "Deployment Operator",
                        "stage": "GA",
                        "permissions": [
                            "iam.serviceAccounts.actAs",
                            "compute.instances.create",
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    roles = load_role_definitions(path)

    assert len(roles) == 1
    assert roles[0].title == "Deployment Operator"
    assert roles[0].stage == "GA"
    assert roles[0].is_custom is True
    assert "iam.serviceAccounts.actAs" in roles[0].permissions


def test_rejects_invalid_role_definitions(tmp_path):
    path = tmp_path / "gcp.json"
    path.write_text(
        json.dumps(
            {
                "resources": [],
                "role_definitions": "not-an-array",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        InputError,
        match="role_definitions",
    ):
        load_role_definitions(path)
