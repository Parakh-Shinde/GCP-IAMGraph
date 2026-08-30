from gcp_iamgraph.detections import analyze
from gcp_iamgraph.models import (
    DenyPolicy,
    Resource,
)


def _multi_hop_impersonation_environment():
    developer = "user:developer@example.test"
    broker_principal = "serviceAccount:broker@payments-prod.iam.gserviceaccount.com"
    privileged_principal = (
        "serviceAccount:privileged@payments-prod.iam.gserviceaccount.com"
    )

    organization = Resource.from_dict(
        {
            "name": "organizations/987654",
            "type": "organization",
        }
    )
    project = Resource.from_dict(
        {
            "name": "projects/payments-prod",
            "type": "project",
            "parent": organization.name,
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [privileged_principal],
                }
            ],
        }
    )
    broker = Resource.from_dict(
        {
            "name": (
                "projects/payments-prod/"
                "serviceAccounts/"
                "broker@payments-prod."
                "iam.gserviceaccount.com"
            ),
            "type": "service_account",
            "display_name": ("broker@payments-prod.iam.gserviceaccount.com"),
            "parent": project.name,
            "bindings": [
                {
                    "role": ("roles/iam.serviceAccountTokenCreator"),
                    "members": [developer],
                }
            ],
        }
    )
    privileged = Resource.from_dict(
        {
            "name": (
                "projects/payments-prod/"
                "serviceAccounts/"
                "privileged@payments-prod."
                "iam.gserviceaccount.com"
            ),
            "type": "service_account",
            "display_name": ("privileged@payments-prod.iam.gserviceaccount.com"),
            "parent": project.name,
            "bindings": [
                {
                    "role": ("roles/iam.serviceAccountTokenCreator"),
                    "members": [broker_principal],
                }
            ],
        }
    )

    return (
        developer,
        broker_principal,
        organization,
        project,
        broker,
        privileged,
    )


def _impersonation_deny_policy(
    principal,
    *,
    exception_principals=None,
    condition=None,
):
    return DenyPolicy.from_dict(
        {
            "name": "policies/deny-impersonation",
            "parent": "organizations/987654",
            "rules": [
                {
                    "denied_principals": [principal],
                    "denied_permissions": [("iam.serviceAccounts.getAccessToken")],
                    "exception_principals": (exception_principals or []),
                    "condition": condition,
                }
            ],
        }
    )


def test_deny_suppresses_impersonation_path():
    (
        developer,
        _,
        organization,
        project,
        broker,
        privileged,
    ) = _multi_hop_impersonation_environment()
    policy = _impersonation_deny_policy(developer)

    findings = analyze(
        [
            organization,
            project,
            broker,
            privileged,
        ],
        deny_policies=[policy],
    )

    assert not any(
        item.rule_id == "GCP-IAM-005" and item.principal == developer
        for item in findings
    )


def test_conditional_deny_suppresses_confirmed_impersonation():
    (
        developer,
        _,
        organization,
        project,
        broker,
        privileged,
    ) = _multi_hop_impersonation_environment()
    policy = _impersonation_deny_policy(
        developer,
        condition={
            "title": "Production only",
            "expression": ("resource.name.startsWith('projects/payments-prod')"),
        },
    )

    findings = analyze(
        [
            organization,
            project,
            broker,
            privileged,
        ],
        deny_policies=[policy],
    )

    assert not any(
        item.rule_id == "GCP-IAM-005" and item.principal == developer
        for item in findings
    )


def test_impersonation_exception_preserves_confirmed_path():
    (
        developer,
        _,
        organization,
        project,
        broker,
        privileged,
    ) = _multi_hop_impersonation_environment()
    policy = _impersonation_deny_policy(
        developer,
        exception_principals=[developer],
    )

    findings = analyze(
        [
            organization,
            project,
            broker,
            privileged,
        ],
        deny_policies=[policy],
    )

    finding = next(
        item
        for item in findings
        if (item.rule_id == "GCP-IAM-005" and item.principal == developer)
    )

    assert len(finding.evidence) == 3
    assert (
        sum("iam.serviceAccounts.getAccessToken" in item for item in finding.evidence)
        == 2
    )


def test_deny_on_intermediate_hop_breaks_multi_hop_path():
    (
        developer,
        broker_principal,
        organization,
        project,
        broker,
        privileged,
    ) = _multi_hop_impersonation_environment()
    policy = _impersonation_deny_policy(broker_principal)

    findings = analyze(
        [
            organization,
            project,
            broker,
            privileged,
        ],
        deny_policies=[policy],
    )

    assert not any(
        item.rule_id == "GCP-IAM-005" and item.principal == developer
        for item in findings
    )
