from gcp_iamgraph.detections import analyze
from gcp_iamgraph.models import (
    Binding,
    Resource,
    RoleDefinition,
)


def test_custom_role_with_iam_policy_permission_is_detected():
    custom_role = RoleDefinition.from_dict(
        {
            "name": ("projects/payments-prod/roles/deploymentOperator"),
            "title": "Deployment Operator",
            "permissions": [
                "compute.instances.create",
                ("resourcemanager.projects.setIamPolicy"),
            ],
        }
    )

    project = Resource(
        name="projects/payments-prod",
        resource_type="project",
        display_name="payments-prod",
        bindings=(
            Binding(
                role=custom_role.name,
                members=("user:developer@example.test",),
            ),
        ),
    )

    findings = analyze(
        [project],
        [custom_role],
    )

    matching_findings = [
        finding for finding in findings if finding.rule_id == "GCP-IAM-003"
    ]

    assert len(matching_findings) == 1
    assert matching_findings[0].principal == "user:developer@example.test"
    assert custom_role.name in matching_findings[0].evidence[0]
