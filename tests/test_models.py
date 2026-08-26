from gcp_iamgraph.models import RoleDefinition


def test_loads_custom_role_definition():
    role = RoleDefinition.from_dict(
        {
            "name": "projects/payments-prod/roles/deploymentOperator",
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
