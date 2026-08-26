from __future__ import annotations


# Security-relevant subset used by Phase 1. Future releases will ingest the
# complete role catalog and custom-role definitions from Cloud Asset Inventory.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "roles/owner": frozenset({"*"}),
    "roles/editor": frozenset({"compute.instances.create", "storage.objects.create"}),
    "roles/resourcemanager.projectIamAdmin": frozenset({"resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"}),
    "roles/iam.securityAdmin": frozenset({"resourcemanager.projects.setIamPolicy", "iam.roles.create", "iam.roles.update"}),
    "roles/iam.serviceAccountAdmin": frozenset({"iam.serviceAccounts.create", "iam.serviceAccounts.getIamPolicy", "iam.serviceAccounts.setIamPolicy"}),
    "roles/iam.serviceAccountKeyAdmin": frozenset({"iam.serviceAccountKeys.create", "iam.serviceAccountKeys.delete"}),
    "roles/iam.serviceAccountTokenCreator": frozenset({"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation"}),
    "roles/iam.serviceAccountUser": frozenset({"iam.serviceAccounts.actAs"}),
    "roles/viewer": frozenset({"resourcemanager.projects.get", "resourcemanager.projects.getIamPolicy"}),
    "roles/storage.objectViewer": frozenset({"storage.objects.get", "storage.objects.list"}),
    "roles/logging.viewer": frozenset({"logging.logEntries.list", "logging.logs.list"}),
}


def role_has_permission(role: str, permission: str) -> bool:
    permissions = ROLE_PERMISSIONS.get(role, frozenset())
    return "*" in permissions or permission in permissions
