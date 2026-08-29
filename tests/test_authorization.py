import pytest

from gcp_iamgraph.authorization import (
    AuthorizationEngine,
    Decision,
)
from gcp_iamgraph.models import (
    DenyPolicy,
    Resource,
    RoleDefinition,
)

PRINCIPAL = "user:developer@example.test"
PERMISSION = "resourcemanager.projects.setIamPolicy"
ORGANIZATION = "organizations/987654"
PROJECT = "projects/payments-prod"


def _resources(
    *,
    role: str = "roles/resourcemanager.projectIamAdmin",
    condition=None,
):
    return [
        Resource.from_dict(
            {
                "name": ORGANIZATION,
                "type": "organization",
                "bindings": [
                    {
                        "role": role,
                        "members": [PRINCIPAL],
                        "condition": condition,
                    }
                ],
            }
        ),
        Resource.from_dict(
            {
                "name": PROJECT,
                "type": "project",
                "parent": ORGANIZATION,
            }
        ),
    ]


def _deny_policy(
    *,
    denied_principals=None,
    denied_permissions=None,
    exception_principals=None,
    exception_permissions=None,
    condition=None,
    parent=ORGANIZATION,
):
    return DenyPolicy.from_dict(
        {
            "name": "policies/deny-project-iam",
            "parent": parent,
            "display_name": "Deny project IAM changes",
            "rules": [
                {
                    "denied_principals": (denied_principals or [PRINCIPAL]),
                    "denied_permissions": (denied_permissions or [PERMISSION]),
                    "exception_principals": (exception_principals or []),
                    "exception_permissions": (exception_permissions or []),
                    "condition": condition,
                }
            ],
        }
    )


def test_allows_effective_inherited_permission():
    engine = AuthorizationEngine(_resources())

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.ALLOW
    assert len(result.allow_evidence) == 1
    assert result.allow_evidence[0].inherited is True
    assert result.allow_evidence[0].conditioned is False
    assert result.deny_evidence == ()


def test_unconditional_deny_overrides_allow():
    engine = AuthorizationEngine(
        _resources(),
        [_deny_policy()],
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.DENY
    assert result.allow_evidence
    assert result.deny_evidence
    assert result.deny_evidence[0].inherited is True
    assert result.deny_evidence[0].conditioned is False


def test_principal_exception_prevents_deny():
    engine = AuthorizationEngine(
        _resources(),
        [
            _deny_policy(
                exception_principals=[PRINCIPAL],
            )
        ],
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.ALLOW
    assert result.allow_evidence
    assert result.deny_evidence == ()


def test_permission_exception_prevents_deny():
    engine = AuthorizationEngine(
        _resources(),
        [
            _deny_policy(
                exception_permissions=[PERMISSION],
            )
        ],
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.ALLOW
    assert result.deny_evidence == ()


def test_conditional_deny_returns_unknown():
    engine = AuthorizationEngine(
        _resources(),
        [
            _deny_policy(
                condition={
                    "title": "Production only",
                    "expression": ("resource.name.startsWith('projects/prod-')"),
                }
            )
        ],
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.UNKNOWN
    assert result.allow_evidence
    assert result.deny_evidence
    assert result.deny_evidence[0].conditioned is True


def test_conditional_allow_returns_unknown():
    engine = AuthorizationEngine(
        _resources(
            condition={
                "title": "Business hours",
                "expression": "request.time < timestamp('2030-01-01')",
            }
        )
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.UNKNOWN
    assert result.allow_evidence[0].conditioned is True


def test_missing_authorization_evidence_returns_unknown():
    engine = AuthorizationEngine(_resources())

    result = engine.evaluate(
        "user:unknown@example.test",
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.UNKNOWN
    assert result.allow_evidence == ()
    assert result.deny_evidence == ()


def test_non_applicable_deny_policy_is_ignored():
    resources = [
        *_resources(),
        Resource.from_dict(
            {
                "name": "projects/unrelated",
                "type": "project",
                "parent": ORGANIZATION,
            }
        ),
    ]
    policy = _deny_policy(
        parent="projects/unrelated",
    )
    engine = AuthorizationEngine(
        resources,
        [policy],
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.ALLOW
    assert result.deny_evidence == ()


def test_custom_role_permission_can_be_allowed():
    custom_role = "projects/payments-prod/roles/deploymentOperator"
    resources = _resources(role=custom_role)
    definitions = [
        RoleDefinition.from_dict(
            {
                "name": custom_role,
                "title": "Deployment Operator",
                "permissions": [PERMISSION],
            }
        )
    ]
    engine = AuthorizationEngine(
        resources,
        role_definitions=definitions,
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert result.decision is Decision.ALLOW
    assert result.allow_evidence


def test_decision_output_is_structured_and_serializable():
    engine = AuthorizationEngine(
        _resources(),
        [_deny_policy()],
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )
    output = result.to_dict()

    assert output["decision"] == "DENY"
    assert output["principal"] == PRINCIPAL
    assert output["permission"] == PERMISSION
    assert output["resource"] == PROJECT
    assert output["allow_evidence"]
    assert output["deny_evidence"]
    assert output["notes"]


def test_rejects_unknown_evaluation_resource():
    engine = AuthorizationEngine(_resources())

    with pytest.raises(
        ValueError,
        match="Unknown resource",
    ):
        engine.evaluate(
            PRINCIPAL,
            PERMISSION,
            "projects/missing",
        )


def test_rejects_unknown_deny_policy_parent():
    policy = _deny_policy(
        parent="folders/missing",
    )

    with pytest.raises(
        ValueError,
        match="Unknown deny policy parent",
    ):
        AuthorizationEngine(
            _resources(),
            [policy],
        )


def test_evidence_order_is_deterministic():
    first_policy = DenyPolicy.from_dict(
        {
            "name": "policies/z-policy",
            "parent": ORGANIZATION,
            "rules": [
                {
                    "denied_principals": [PRINCIPAL],
                    "denied_permissions": [PERMISSION],
                }
            ],
        }
    )
    second_policy = DenyPolicy.from_dict(
        {
            "name": "policies/a-policy",
            "parent": ORGANIZATION,
            "rules": [
                {
                    "denied_principals": [PRINCIPAL],
                    "denied_permissions": [PERMISSION],
                }
            ],
        }
    )
    engine = AuthorizationEngine(
        _resources(),
        [
            first_policy,
            second_policy,
        ],
    )

    result = engine.evaluate(
        PRINCIPAL,
        PERMISSION,
        PROJECT,
    )

    assert [item.source for item in result.deny_evidence] == [
        "policies/a-policy#rule-1",
        "policies/z-policy#rule-1",
    ]
