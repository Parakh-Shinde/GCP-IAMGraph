from __future__ import annotations

from collections.abc import Iterable

from .models import RoleDefinition

# Phase 1 contains a security-relevant subset of GCP
# predefined roles. Later, this catalog will be populated
# from Google Cloud IAM and Cloud Asset Inventory.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "roles/owner": frozenset({"*"}),
    "roles/editor": frozenset(
        {
            "compute.instances.create",
            "storage.objects.create",
        }
    ),
    "roles/resourcemanager.projectIamAdmin": (
        frozenset(
            {
                "resourcemanager.projects.getIamPolicy",
                "resourcemanager.projects.setIamPolicy",
            }
        )
    ),
    "roles/iam.securityAdmin": frozenset(
        {
            "resourcemanager.projects.setIamPolicy",
            "iam.roles.create",
            "iam.roles.update",
        }
    ),
    "roles/iam.serviceAccountAdmin": frozenset(
        {
            "iam.serviceAccounts.create",
            "iam.serviceAccounts.getIamPolicy",
            "iam.serviceAccounts.setIamPolicy",
        }
    ),
    "roles/iam.serviceAccountKeyAdmin": (
        frozenset(
            {
                "iam.serviceAccountKeys.create",
                "iam.serviceAccountKeys.delete",
            }
        )
    ),
    "roles/iam.serviceAccountTokenCreator": (
        frozenset(
            {
                "iam.serviceAccounts.getAccessToken",
                "iam.serviceAccounts.signBlob",
                "iam.serviceAccounts.signJwt",
                ("iam.serviceAccounts.implicitDelegation"),
            }
        )
    ),
    "roles/iam.serviceAccountUser": frozenset(
        {
            "iam.serviceAccounts.actAs",
        }
    ),
    "roles/viewer": frozenset(
        {
            "resourcemanager.projects.get",
            "resourcemanager.projects.getIamPolicy",
        }
    ),
    "roles/storage.objectViewer": frozenset(
        {
            "storage.objects.get",
            "storage.objects.list",
        }
    ),
    "roles/logging.viewer": frozenset(
        {
            "logging.logEntries.list",
            "logging.logs.list",
        }
    ),
}


class RoleCatalog:
    """Resolves predefined and custom GCP role permissions."""

    def __init__(
        self,
        role_definitions: Iterable[RoleDefinition] = (),
    ) -> None:
        self._permissions = dict(ROLE_PERMISSIONS)

        for role in role_definitions:
            self._permissions[role.name] = role.permissions

    def permissions_for(
        self,
        role_name: str,
    ) -> frozenset[str]:
        """Return permissions belonging to a role."""

        return self._permissions.get(
            role_name,
            frozenset(),
        )

    def has_permission(
        self,
        role_name: str,
        permission: str,
    ) -> bool:
        """Check whether a role grants a permission."""

        permissions = self.permissions_for(role_name)

        return "*" in permissions or permission in permissions


DEFAULT_ROLE_CATALOG = RoleCatalog()


def role_has_permission(
    role: str,
    permission: str,
    catalog: RoleCatalog | None = None,
) -> bool:
    """Backward-compatible permission lookup."""

    active_catalog = catalog if catalog is not None else DEFAULT_ROLE_CATALOG

    return active_catalog.has_permission(
        role,
        permission,
    )
