import pytest

from gcp_iamgraph.models import (
    DenyPolicy,
    DenyRule,
    RoleDefinition,
)


def test_loads_custom_role_definition():
    role = RoleDefinition.from_dict(
        {
            "name": ("projects/payments-prod/roles/deploymentOperator"),
            "title": "Deployment Operator",
            "stage": "GA",
            "permissions": [
                "iam.serviceAccounts.actAs",
                "compute.instances.create",
            ],
        }
    )

    assert role.name == ("projects/payments-prod/roles/deploymentOperator")
    assert role.title == "Deployment Operator"
    assert role.stage == "GA"
    assert role.permissions == frozenset(
        {
            "iam.serviceAccounts.actAs",
            "compute.instances.create",
        }
    )
    assert role.is_custom is True


def test_loads_deny_policy_definition():
    policy = DenyPolicy.from_dict(
        {
            "name": "policies/deny-project-iam",
            "parent": "organizations/987654",
            "display_name": "Deny project IAM changes",
            "rules": [
                {
                    "denied_principals": ["user:developer@example.test"],
                    "exception_principals": ["user:security-admin@example.test"],
                    "denied_permissions": [("resourcemanager.projects.setIamPolicy")],
                    "exception_permissions": ["resourcemanager.projects.get"],
                    "condition": {
                        "title": "Production only",
                        "expression": ("resource.name.startsWith('projects/prod-')"),
                    },
                }
            ],
        }
    )

    assert policy.name == "policies/deny-project-iam"
    assert policy.parent == "organizations/987654"
    assert policy.display_name == ("Deny project IAM changes")
    assert len(policy.rules) == 1

    rule = policy.rules[0]

    assert rule.denied_principals == ("user:developer@example.test",)
    assert rule.exception_principals == ("user:security-admin@example.test",)
    assert rule.denied_permissions == ("resourcemanager.projects.setIamPolicy",)
    assert rule.exception_permissions == ("resourcemanager.projects.get",)
    assert rule.condition == {
        "title": "Production only",
        "expression": ("resource.name.startsWith('projects/prod-')"),
    }


def test_deny_rule_requires_denied_principal():
    with pytest.raises(
        ValueError,
        match="denied principal",
    ):
        DenyRule.from_dict(
            {
                "denied_permissions": ["resourcemanager.projects.setIamPolicy"],
            }
        )


def test_deny_rule_requires_denied_permission():
    with pytest.raises(
        ValueError,
        match="denied permission",
    ):
        DenyRule.from_dict(
            {
                "denied_principals": ["user:developer@example.test"],
            }
        )


def test_deny_policy_requires_rule():
    with pytest.raises(
        ValueError,
        match="at least one rule",
    ):
        DenyPolicy.from_dict(
            {
                "name": "policies/empty",
                "parent": "organizations/987654",
                "rules": [],
            }
        )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            {
                "denied_principals": ("user:developer@example.test"),
                "denied_permissions": ["resourcemanager.projects.setIamPolicy"],
            },
            "denied_principals",
        ),
        (
            {
                "denied_principals": ["user:developer@example.test"],
                "denied_permissions": [123],
            },
            "denied_permissions",
        ),
        (
            {
                "denied_principals": ["user:developer@example.test"],
                "denied_permissions": ["resourcemanager.projects.setIamPolicy"],
                "condition": "not-an-object",
            },
            "condition",
        ),
    ],
)
def test_deny_rule_rejects_invalid_fields(
    data,
    message,
):
    with pytest.raises(
        TypeError,
        match=message,
    ):
        DenyRule.from_dict(data)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            {
                "name": "",
                "parent": "organizations/987654",
                "rules": [{}],
            },
            "name",
        ),
        (
            {
                "name": "policies/test",
                "parent": 123,
                "rules": [{}],
            },
            "parent",
        ),
        (
            {
                "name": "policies/test",
                "parent": "organizations/987654",
                "rules": "not-an-array",
            },
            "rules",
        ),
        (
            {
                "name": "policies/test",
                "parent": "organizations/987654",
                "display_name": "",
                "rules": [
                    {
                        "denied_principals": ["user:developer@example.test"],
                        "denied_permissions": [
                            ("resourcemanager.projects.setIamPolicy")
                        ],
                    }
                ],
            },
            "display_name",
        ),
    ],
)
def test_deny_policy_rejects_invalid_fields(
    data,
    message,
):
    with pytest.raises(
        TypeError,
        match=message,
    ):
        DenyPolicy.from_dict(data)
