import json

import pytest

from gcp_iamgraph.parser import (
    InputError,
    load_deny_policies,
    load_environment,
    load_role_definitions,
)


def _write_document(
    tmp_path,
    document,
):
    path = tmp_path / "gcp.json"
    path.write_text(
        json.dumps(document),
        encoding="utf-8",
    )
    return path


def test_loads_valid_environment(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [
                {
                    "name": "projects/test",
                    "type": "project",
                }
            ]
        },
    )

    resources = load_environment(path)

    assert len(resources) == 1
    assert resources[0].name == "projects/test"


def test_rejects_unknown_parent(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [
                {
                    "name": "projects/test",
                    "type": "project",
                    "parent": "folders/missing",
                }
            ]
        },
    )

    with pytest.raises(
        InputError,
        match="Unknown parent",
    ):
        load_environment(path)


def test_loads_custom_role_definitions(tmp_path):
    path = _write_document(
        tmp_path,
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
        },
    )

    roles = load_role_definitions(path)

    assert len(roles) == 1
    assert roles[0].title == "Deployment Operator"
    assert roles[0].stage == "GA"
    assert roles[0].is_custom is True
    assert "iam.serviceAccounts.actAs" in roles[0].permissions


def test_rejects_invalid_role_definitions(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [],
            "role_definitions": "not-an-array",
        },
    )

    with pytest.raises(
        InputError,
        match="role_definitions",
    ):
        load_role_definitions(path)


def test_loads_deny_policies(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [
                {
                    "name": "organizations/987654",
                    "type": "organization",
                }
            ],
            "deny_policies": [
                {
                    "name": "policies/deny-project-iam",
                    "parent": "organizations/987654",
                    "display_name": "Deny project IAM changes",
                    "rules": [
                        {
                            "denied_principals": ["user:developer@example.test"],
                            "denied_permissions": [
                                ("resourcemanager.projects.setIamPolicy")
                            ],
                            "exception_principals": [
                                "user:security-admin@example.test"
                            ],
                            "exception_permissions": ["resourcemanager.projects.get"],
                        }
                    ],
                }
            ],
        },
    )

    policies = load_deny_policies(path)

    assert len(policies) == 1

    policy = policies[0]

    assert policy.name == "policies/deny-project-iam"
    assert policy.parent == "organizations/987654"
    assert policy.display_name == "Deny project IAM changes"
    assert len(policy.rules) == 1
    assert policy.rules[0].denied_principals == ("user:developer@example.test",)
    assert policy.rules[0].denied_permissions == (
        "resourcemanager.projects.setIamPolicy",
    )


def test_missing_deny_policies_defaults_to_empty(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [],
        },
    )

    assert load_deny_policies(path) == []


def test_rejects_non_array_deny_policies(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [],
            "deny_policies": "not-an-array",
        },
    )

    with pytest.raises(
        InputError,
        match="deny_policies",
    ):
        load_deny_policies(path)


def test_rejects_invalid_deny_policy(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [
                {
                    "name": "organizations/987654",
                    "type": "organization",
                }
            ],
            "deny_policies": [
                {
                    "name": "policies/invalid",
                    "parent": "organizations/987654",
                    "rules": [],
                }
            ],
        },
    )

    with pytest.raises(
        InputError,
        match="Invalid deny policy",
    ):
        load_deny_policies(path)


def test_rejects_unknown_deny_policy_parent(tmp_path):
    path = _write_document(
        tmp_path,
        {
            "resources": [],
            "deny_policies": [
                {
                    "name": "policies/deny-project-iam",
                    "parent": "organizations/missing",
                    "rules": [
                        {
                            "denied_principals": ["user:developer@example.test"],
                            "denied_permissions": [
                                ("resourcemanager.projects.setIamPolicy")
                            ],
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(
        InputError,
        match="Unknown deny policy parent",
    ):
        load_deny_policies(path)


def test_rejects_duplicate_deny_policy_names(tmp_path):
    policy = {
        "name": "policies/duplicate",
        "parent": "organizations/987654",
        "rules": [
            {
                "denied_principals": ["user:developer@example.test"],
                "denied_permissions": ["resourcemanager.projects.setIamPolicy"],
            }
        ],
    }

    path = _write_document(
        tmp_path,
        {
            "resources": [
                {
                    "name": "organizations/987654",
                    "type": "organization",
                }
            ],
            "deny_policies": [
                policy,
                policy,
            ],
        },
    )

    with pytest.raises(
        InputError,
        match="Deny policy names must be unique",
    ):
        load_deny_policies(path)
