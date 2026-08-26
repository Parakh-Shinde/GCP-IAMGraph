from gcp_iamgraph.models import RoleDefinition
from gcp_iamgraph.roles import RoleCatalog


def test_custom_role_permission_lookup():
    role = RoleDefinition.from_dict(
        {
            "name": ("projects/payments-prod/roles/deploymentOperator"),
            "title": "Deployment Operator",
            "permissions": [
                "iam.serviceAccounts.actAs",
                "compute.instances.create",
            ],
        }
    )

    catalog = RoleCatalog([role])

    assert catalog.has_permission(
        role.name,
        "iam.serviceAccounts.actAs",
    )
    assert catalog.has_permission(
        role.name,
        "compute.instances.create",
    )
    assert not catalog.has_permission(
        role.name,
        "resourcemanager.projects.setIamPolicy",
    )


def test_predefined_roles_remain_available():
    catalog = RoleCatalog()

    assert catalog.has_permission(
        "roles/iam.serviceAccountTokenCreator",
        "iam.serviceAccounts.getAccessToken",
    )


def test_unknown_role_has_no_permissions():
    catalog = RoleCatalog()

    assert not catalog.has_permission(
        "projects/test/roles/missingRole",
        "iam.serviceAccounts.actAs",
    )
