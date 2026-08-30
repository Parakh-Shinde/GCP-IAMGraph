from pathlib import Path

from gcp_iamgraph.detections import analyze
from gcp_iamgraph.models import (
    DenyPolicy,
    Resource,
)
from gcp_iamgraph.parser import load_environment

EXAMPLES = Path(__file__).parents[1] / "examples"


def test_vulnerable_environment_exposes_key_risks():
    findings = analyze(load_environment(EXAMPLES / "vulnerable-environment.json"))
    rule_ids = {item.rule_id for item in findings}

    assert {
        "GCP-IAM-001",
        "GCP-IAM-002",
        "GCP-IAM-003",
        "GCP-IAM-004",
        "GCP-IAM-005",
    } <= rule_ids

    impersonation = next(item for item in findings if item.rule_id == "GCP-IAM-005")

    assert impersonation.principal == "user:developer@example.test"
    assert (
        "serviceAccount:"
        "deployment@payments-prod."
        "iam.gserviceaccount.com" in impersonation.attack_path
    )


def test_hardened_environment_has_no_findings():
    findings = analyze(load_environment(EXAMPLES / "hardened-environment.json"))

    assert findings == []


def test_public_authenticated_access_is_high_not_critical():
    resource = Resource.from_dict(
        {
            "name": "projects/test",
            "type": "project",
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["allAuthenticatedUsers"],
                }
            ],
        }
    )

    finding = next(
        item for item in analyze([resource]) if item.rule_id == "GCP-IAM-002"
    )

    assert finding.severity == "high"


def test_actas_and_compute_create_reaches_privileged_service_account():
    developer = "user:developer@example.test"
    service_account = "serviceAccount:runtime@payments-prod.iam.gserviceaccount.com"

    project = Resource.from_dict(
        {
            "name": "projects/payments-prod",
            "type": "project",
            "display_name": "payments-prod",
            "bindings": [
                {
                    "role": "roles/editor",
                    "members": [developer],
                },
                {
                    "role": "roles/owner",
                    "members": [service_account],
                },
            ],
        }
    )

    runtime_service_account = Resource.from_dict(
        {
            "name": (
                "projects/payments-prod/"
                "serviceAccounts/"
                "runtime@payments-prod."
                "iam.gserviceaccount.com"
            ),
            "type": "service_account",
            "display_name": ("runtime@payments-prod.iam.gserviceaccount.com"),
            "parent": "projects/payments-prod",
            "bindings": [
                {
                    "role": ("roles/iam.serviceAccountUser"),
                    "members": [developer],
                }
            ],
        }
    )

    findings = analyze(
        [
            project,
            runtime_service_account,
        ]
    )

    finding = next(item for item in findings if item.rule_id == "GCP-IAM-006")

    assert finding.severity == "critical"
    assert finding.principal == developer
    assert finding.resource == project.name
    assert "iam.serviceAccounts.actAs" in finding.attack_path
    assert "compute.instances.create" in finding.attack_path
    assert service_account in finding.attack_path


def test_set_iam_policy_can_escalate_to_project_owner():
    attacker = "user:attacker@example.test"

    project = Resource.from_dict(
        {
            "name": "projects/payments-prod",
            "type": "project",
            "display_name": "payments-prod",
            "bindings": [
                {
                    "role": ("roles/resourcemanager.projectIamAdmin"),
                    "members": [attacker],
                }
            ],
        }
    )

    findings = analyze([project])

    finding = next(item for item in findings if item.rule_id == "GCP-IAM-007")

    assert finding.severity == "critical"
    assert finding.principal == attacker
    assert finding.resource == ("projects/payments-prod")
    assert finding.attack_path == (
        attacker,
        "resourcemanager.projects.setIamPolicy",
        "projects/payments-prod",
        "grant roles/owner",
        "Project compromise",
    )


def test_key_creation_reaches_privileged_service_account():
    attacker = "user:attacker@example.test"
    service_account = "serviceAccount:automation@payments-prod.iam.gserviceaccount.com"

    project = Resource.from_dict(
        {
            "name": "projects/payments-prod",
            "type": "project",
            "display_name": "payments-prod",
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [service_account],
                }
            ],
        }
    )

    automation_service_account = Resource.from_dict(
        {
            "name": (
                "projects/payments-prod/"
                "serviceAccounts/"
                "automation@payments-prod."
                "iam.gserviceaccount.com"
            ),
            "type": "service_account",
            "display_name": ("automation@payments-prod.iam.gserviceaccount.com"),
            "parent": "projects/payments-prod",
            "bindings": [
                {
                    "role": ("roles/iam.serviceAccountKeyAdmin"),
                    "members": [attacker],
                }
            ],
        }
    )

    findings = analyze(
        [
            project,
            automation_service_account,
        ]
    )

    finding = next(item for item in findings if item.rule_id == "GCP-IAM-008")

    assert finding.severity == "critical"
    assert finding.principal == attacker
    assert finding.resource == project.name
    assert finding.attack_path == (
        attacker,
        "iam.serviceAccountKeys.create",
        service_account,
        "create long-lived credential",
        "roles/owner",
        project.name,
        "Project compromise",
    )


def _project_iam_admin_environment():
    principal = "user:attacker@example.test"
    organization = Resource.from_dict(
        {"name": "organizations/987654", "type": "organization"}
    )
    project = Resource.from_dict(
        {
            "name": "projects/payments-prod",
            "type": "project",
            "parent": organization.name,
            "bindings": [
                {
                    "role": "roles/resourcemanager.projectIamAdmin",
                    "members": [principal],
                }
            ],
        }
    )
    return principal, organization, project


def _project_iam_deny_policy(principal, *, exception_principals=None, condition=None):
    return DenyPolicy.from_dict(
        {
            "name": "policies/deny-project-iam",
            "parent": "organizations/987654",
            "rules": [
                {
                    "denied_principals": [principal],
                    "denied_permissions": ["resourcemanager.projects.setIamPolicy"],
                    "exception_principals": exception_principals or [],
                    "condition": condition,
                }
            ],
        }
    )


def test_deny_policy_suppresses_confirmed_iam_escalation():
    principal, organization, project = _project_iam_admin_environment()
    policy = _project_iam_deny_policy(principal)
    findings = analyze([organization, project], deny_policies=[policy])
    assert not any(item.rule_id == "GCP-IAM-007" for item in findings)


def test_conditional_deny_does_not_create_confirmed_escalation():
    principal, organization, project = _project_iam_admin_environment()
    policy = _project_iam_deny_policy(
        principal,
        condition={
            "title": "Production resources",
            "expression": "resource.name.startsWith('projects/prod-')",
        },
    )
    findings = analyze([organization, project], deny_policies=[policy])
    assert not any(item.rule_id == "GCP-IAM-007" for item in findings)


def test_deny_principal_exception_preserves_escalation():
    principal, organization, project = _project_iam_admin_environment()
    policy = _project_iam_deny_policy(principal, exception_principals=[principal])
    findings = analyze([organization, project], deny_policies=[policy])
    assert any(item.rule_id == "GCP-IAM-007" for item in findings)


def _privileged_key_environment():
    attacker = "user:attacker@example.test"
    service_account = "serviceAccount:automation@payments-prod.iam.gserviceaccount.com"
    organization = Resource.from_dict(
        {"name": "organizations/987654", "type": "organization"}
    )
    project = Resource.from_dict(
        {
            "name": "projects/payments-prod",
            "type": "project",
            "parent": organization.name,
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [service_account],
                }
            ],
        }
    )
    service_account_resource = Resource.from_dict(
        {
            "name": (
                "projects/payments-prod/serviceAccounts/"
                "automation@payments-prod.iam.gserviceaccount.com"
            ),
            "type": "service_account",
            "display_name": ("automation@payments-prod.iam.gserviceaccount.com"),
            "parent": project.name,
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountKeyAdmin",
                    "members": [attacker],
                }
            ],
        }
    )
    return attacker, organization, project, service_account_resource


def _key_creation_deny_policy(attacker, *, exception_principals=None, condition=None):
    return DenyPolicy.from_dict(
        {
            "name": "policies/deny-key-creation",
            "parent": "organizations/987654",
            "rules": [
                {
                    "denied_principals": [attacker],
                    "denied_permissions": ["iam.serviceAccountKeys.create"],
                    "exception_principals": exception_principals or [],
                    "condition": condition,
                }
            ],
        }
    )


def test_deny_suppresses_direct_and_privileged_key_findings():
    attacker, organization, project, service_account = _privileged_key_environment()
    policy = _key_creation_deny_policy(attacker)
    findings = analyze([organization, project, service_account], deny_policies=[policy])
    rule_ids = {item.rule_id for item in findings}
    assert "GCP-IAM-004" not in rule_ids
    assert "GCP-IAM-008" not in rule_ids


def test_conditional_key_deny_suppresses_confirmed_paths():
    attacker, organization, project, service_account = _privileged_key_environment()
    policy = _key_creation_deny_policy(
        attacker,
        condition={
            "title": "Production only",
            "expression": ("resource.name.startsWith('projects/payments-prod')"),
        },
    )
    findings = analyze([organization, project, service_account], deny_policies=[policy])
    rule_ids = {item.rule_id for item in findings}
    assert "GCP-IAM-004" not in rule_ids
    assert "GCP-IAM-008" not in rule_ids


def test_key_deny_exception_preserves_confirmed_paths():
    attacker, organization, project, service_account = _privileged_key_environment()
    policy = _key_creation_deny_policy(attacker, exception_principals=[attacker])
    findings = analyze([organization, project, service_account], deny_policies=[policy])
    rule_ids = {item.rule_id for item in findings}
    assert "GCP-IAM-004" in rule_ids
    assert "GCP-IAM-008" in rule_ids


def _actas_environment():
    developer = "user:developer@example.test"
    service_account = "serviceAccount:runtime@payments-prod.iam.gserviceaccount.com"

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
                    "role": "roles/editor",
                    "members": [developer],
                },
                {
                    "role": "roles/owner",
                    "members": [service_account],
                },
            ],
        }
    )
    service_account_resource = Resource.from_dict(
        {
            "name": (
                "projects/payments-prod/"
                "serviceAccounts/"
                "runtime@payments-prod."
                "iam.gserviceaccount.com"
            ),
            "type": "service_account",
            "display_name": ("runtime@payments-prod.iam.gserviceaccount.com"),
            "parent": project.name,
            "bindings": [
                {
                    "role": ("roles/iam.serviceAccountUser"),
                    "members": [developer],
                }
            ],
        }
    )

    return (
        developer,
        organization,
        project,
        service_account_resource,
    )


def _actas_deny_policy(
    developer,
    permission,
    *,
    exception_permissions=None,
    condition=None,
):
    return DenyPolicy.from_dict(
        {
            "name": "policies/deny-actas-path",
            "parent": "organizations/987654",
            "rules": [
                {
                    "denied_principals": [developer],
                    "denied_permissions": [permission],
                    "exception_permissions": (exception_permissions or []),
                    "condition": condition,
                }
            ],
        }
    )


def test_actas_deny_suppresses_vm_escalation_path():
    (
        developer,
        organization,
        project,
        service_account,
    ) = _actas_environment()
    permission = "iam.serviceAccounts.actAs"
    policy = _actas_deny_policy(
        developer,
        permission,
    )

    findings = analyze(
        [
            organization,
            project,
            service_account,
        ],
        deny_policies=[policy],
    )

    assert not any(item.rule_id == "GCP-IAM-006" for item in findings)


def test_compute_create_deny_suppresses_vm_escalation_path():
    (
        developer,
        organization,
        project,
        service_account,
    ) = _actas_environment()
    permission = "compute.instances.create"
    policy = _actas_deny_policy(
        developer,
        permission,
    )

    findings = analyze(
        [
            organization,
            project,
            service_account,
        ],
        deny_policies=[policy],
    )

    assert not any(item.rule_id == "GCP-IAM-006" for item in findings)


def test_conditional_actas_deny_suppresses_confirmed_path():
    (
        developer,
        organization,
        project,
        service_account,
    ) = _actas_environment()
    policy = _actas_deny_policy(
        developer,
        "iam.serviceAccounts.actAs",
        condition={
            "title": "Production only",
            "expression": ("resource.name.startsWith('projects/payments-prod')"),
        },
    )

    findings = analyze(
        [
            organization,
            project,
            service_account,
        ],
        deny_policies=[policy],
    )

    assert not any(item.rule_id == "GCP-IAM-006" for item in findings)


def test_actas_permission_exception_preserves_vm_path():
    (
        developer,
        organization,
        project,
        service_account,
    ) = _actas_environment()
    permission = "iam.serviceAccounts.actAs"
    policy = _actas_deny_policy(
        developer,
        permission,
        exception_permissions=[permission],
    )

    findings = analyze(
        [
            organization,
            project,
            service_account,
        ],
        deny_policies=[policy],
    )

    finding = next(item for item in findings if item.rule_id == "GCP-IAM-006")

    assert finding.principal == developer
    assert any("compute.instances.create" in item for item in finding.evidence)
    assert any("iam.serviceAccounts.actAs" in item for item in finding.evidence)
