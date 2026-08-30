from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable

from .access import AccessIndex, Grant
from .authorization import (
    AuthorizationEngine,
    Decision,
)
from .hierarchy import Hierarchy
from .models import (
    DenyPolicy,
    Finding,
    Resource,
    RoleDefinition,
)
from .roles import RoleCatalog

PUBLIC_PRINCIPALS = {
    "allUsers",
    "allAuthenticatedUsers",
}

PRIVILEGED_ROLES = {
    "roles/owner": "critical",
    "roles/editor": "high",
}


def _finding_for_privileged_grant(
    grant: Grant,
) -> Finding:
    return Finding(
        rule_id="GCP-IAM-001",
        title=f"Broad primitive role: {grant.role}",
        severity=PRIVILEGED_ROLES[grant.role],
        principal=grant.principal,
        resource=grant.target.name,
        description=(
            "A principal has a broad primitive role "
            "that exceeds typical least-privilege "
            "requirements."
        ),
        attack_path=(
            grant.principal,
            grant.role,
            grant.target.name,
            "Broad resource control",
        ),
        evidence=(grant.evidence(),),
        remediation=(
            "Replace primitive roles with predefined "
            "or custom roles containing only required "
            "permissions."
        ),
        references=("CIS Google Cloud Foundations 1.0",),
    )


def _direct_findings(
    index: AccessIndex,
    authorization: AuthorizationEngine,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for resource in index.hierarchy.resources.values():
        for binding in resource.bindings:
            for principal in binding.members:
                grant = Grant(
                    principal,
                    binding.role,
                    resource,
                    resource,
                    binding.condition,
                )

                key = (
                    grant.principal,
                    grant.role,
                    grant.target.name,
                )

                if key in seen:
                    continue

                seen.add(key)

                if grant.role in PRIVILEGED_ROLES:
                    findings.append(_finding_for_privileged_grant(grant))

                if grant.principal in PUBLIC_PRINCIPALS:
                    severity = "critical" if grant.principal == "allUsers" else "high"

                    findings.append(
                        Finding(
                            rule_id="GCP-IAM-002",
                            title=("Public or globally authenticated access"),
                            severity=severity,
                            principal=grant.principal,
                            resource=grant.target.name,
                            description=(
                                "The IAM binding grants access to a public principal."
                            ),
                            attack_path=(
                                grant.principal,
                                grant.role,
                                grant.target.name,
                            ),
                            evidence=(grant.evidence(),),
                            remediation=(
                                "Remove the public member "
                                "and grant the minimum role "
                                "to explicitly identified "
                                "principals."
                            ),
                        )
                    )

                # Owner already represents unrestricted
                # privilege at this resource scope.
                if grant.role == "roles/owner":
                    continue

                permission_rules = (
                    (
                        ("resourcemanager.projects.setIamPolicy"),
                        "GCP-IAM-003",
                        "IAM policy modification",
                        "critical",
                        (
                            "A principal can change "
                            "project IAM bindings and "
                            "grant additional access."
                        ),
                    ),
                    (
                        ("iam.serviceAccountKeys.create"),
                        "GCP-IAM-004",
                        "Service-account key creation",
                        "high",
                        (
                            "A principal can create "
                            "long-lived credentials for "
                            "a service account."
                        ),
                    ),
                )

                for (
                    permission,
                    rule_id,
                    title,
                    severity,
                    description,
                ) in permission_rules:
                    if not index.catalog.has_permission(
                        grant.role,
                        permission,
                    ):
                        continue

                    authorization_result = authorization.evaluate(
                        grant.principal,
                        permission,
                        grant.target.name,
                    )

                    if authorization_result.decision is not Decision.ALLOW:
                        continue

                    dedupe = (
                        rule_id,
                        grant.principal,
                        grant.target.name,
                    )

                    if dedupe in seen:
                        continue

                    seen.add(dedupe)

                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=title,
                            severity=severity,
                            principal=grant.principal,
                            resource=grant.target.name,
                            description=description,
                            attack_path=(
                                grant.principal,
                                permission,
                                grant.target.name,
                                "Privilege expansion",
                            ),
                            evidence=(grant.evidence(),),
                            remediation=(
                                "Restrict this permission "
                                "to a controlled deployment "
                                "identity and require "
                                "short-lived credentials "
                                "and approval controls."
                            ),
                        )
                    )

    return findings


def _impersonation_edges(
    index: AccessIndex,
) -> dict[str, list[tuple[str, Grant]]]:
    edges: dict[
        str,
        list[tuple[str, Grant]],
    ] = defaultdict(list)

    for resource in index.hierarchy.resources.values():
        if resource.resource_type != "service_account":
            continue

        target_principal = f"serviceAccount:{resource.display_name}"

        for grant in index.grants_on(resource.name):
            if index.catalog.has_permission(
                grant.role,
                ("iam.serviceAccounts.getAccessToken"),
            ):
                edges[grant.principal].append(
                    (
                        target_principal,
                        grant,
                    )
                )

    return edges


def _privileged_targets(
    index: AccessIndex,
) -> dict[str, list[Grant]]:
    targets: dict[
        str,
        list[Grant],
    ] = defaultdict(list)

    for (
        resource_name,
        resource,
    ) in index.hierarchy.resources.items():
        if resource.resource_type not in {
            "organization",
            "folder",
            "project",
        }:
            continue

        for grant in index.grants_on(resource_name):
            if grant.role in PRIVILEGED_ROLES:
                targets[grant.principal].append(grant)

    return targets


def _impersonation_findings(
    index: AccessIndex,
) -> list[Finding]:
    edges = _impersonation_edges(index)
    privileged = _privileged_targets(index)
    findings: list[Finding] = []

    for start in sorted(edges):
        queue = deque(
            [
                (
                    start,
                    [start],
                    [],
                )
            ]
        )
        visited = {start}

        while queue:
            current, path, evidence = queue.popleft()

            if current != start and current in privileged:
                for target_grant in privileged[current]:
                    findings.append(
                        Finding(
                            rule_id="GCP-IAM-005",
                            title=(
                                "Service-account "
                                "impersonation reaches "
                                "a privileged role"
                            ),
                            severity="critical",
                            principal=start,
                            resource=(target_grant.target.name),
                            description=(
                                "The principal can obtain "
                                "short-lived credentials "
                                "for a service account "
                                "with broad access."
                            ),
                            attack_path=(
                                *path,
                                target_grant.role,
                                target_grant.target.name,
                            ),
                            evidence=(
                                *evidence,
                                target_grant.evidence(),
                            ),
                            remediation=(
                                "Remove unnecessary Token "
                                "Creator bindings and grant "
                                "impersonation only on "
                                "narrowly scoped service "
                                "accounts."
                            ),
                            references=("MITRE ATT&CK T1078.004",),
                        )
                    )

                continue

            for target, grant in edges.get(
                current,
                [],
            ):
                if target in visited:
                    continue

                visited.add(target)

                queue.append(
                    (
                        target,
                        [
                            *path,
                            "impersonates",
                            target,
                        ],
                        [
                            *evidence,
                            grant.evidence(),
                        ],
                    )
                )

    return findings


def _actas_compute_findings(
    index: AccessIndex,
    authorization: AuthorizationEngine,
) -> list[Finding]:
    """Detect confirmed VM creation using a privileged service account."""

    findings: list[Finding] = []
    privileged = _privileged_targets(index)
    seen: set[tuple[str, str, str]] = set()
    actas_permission = "iam.serviceAccounts.actAs"
    compute_permission = "compute.instances.create"

    for resource in index.hierarchy.resources.values():
        if resource.resource_type != "service_account":
            continue

        service_account_principal = f"serviceAccount:{resource.display_name}"
        privileged_grants = privileged.get(
            service_account_principal,
            [],
        )

        if not privileged_grants:
            continue

        actas_results = []

        for grant in index.grants_on(resource.name):
            if grant.principal == service_account_principal:
                continue

            if not index.catalog.has_permission(
                grant.role,
                actas_permission,
            ):
                continue

            actas_result = authorization.evaluate(
                grant.principal,
                actas_permission,
                resource.name,
            )

            if actas_result.decision is not Decision.ALLOW:
                continue

            actas_results.append((grant, actas_result))

        for actas_grant, actas_result in actas_results:
            for privileged_grant in privileged_grants:
                target_name = privileged_grant.target.name
                compute_result = authorization.evaluate(
                    actas_grant.principal,
                    compute_permission,
                    target_name,
                )

                if compute_result.decision is not Decision.ALLOW:
                    continue

                dedupe = (
                    actas_grant.principal,
                    resource.name,
                    target_name,
                )

                if dedupe in seen:
                    continue

                seen.add(dedupe)

                evidence = tuple(
                    dict.fromkeys(
                        [
                            *(
                                (f"{compute_permission}: {item.description}")
                                for item in compute_result.allow_evidence
                            ),
                            *(
                                (f"{actas_permission}: {item.description}")
                                for item in actas_result.allow_evidence
                            ),
                            privileged_grant.evidence(),
                        ]
                    )
                )

                findings.append(
                    Finding(
                        rule_id="GCP-IAM-006",
                        title=("VM creation can use a privileged service account"),
                        severity="critical",
                        principal=actas_grant.principal,
                        resource=target_name,
                        description=(
                            "The principal can create "
                            "a Compute Engine instance "
                            "and attach a privileged "
                            "service account, allowing "
                            "access to the service "
                            "account's permissions."
                        ),
                        attack_path=(
                            actas_grant.principal,
                            compute_permission,
                            target_name,
                            actas_permission,
                            service_account_principal,
                            privileged_grant.role,
                            target_name,
                        ),
                        evidence=evidence,
                        remediation=(
                            "Do not grant both Compute "
                            "instance creation and "
                            "service-account actAs to "
                            "the same principal. "
                            "Restrict actAs to "
                            "non-privileged service "
                            "accounts and enforce "
                            "approved service accounts "
                            "for VM deployments."
                        ),
                        references=("MITRE ATT&CK T1548",),
                    )
                )

    return findings


def _iam_policy_escalation_findings(
    index: AccessIndex,
    authorization: AuthorizationEngine,
) -> list[Finding]:
    """Detect confirmed IAM policy modification leading to Owner."""

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    permission = "resourcemanager.projects.setIamPolicy"

    for resource in index.hierarchy.resources.values():
        if resource.resource_type != "project":
            continue

        for grant in index.grants_on(resource.name):
            # Owner is already reported by GCP-IAM-001
            # and does not require a separate escalation finding.
            if grant.role == "roles/owner":
                continue

            if not index.catalog.has_permission(
                grant.role,
                permission,
            ):
                continue

            decision = authorization.evaluate(
                grant.principal,
                permission,
                resource.name,
            )

            # DENY and UNKNOWN must not create a confirmed
            # attack path.
            if decision.decision is not Decision.ALLOW:
                continue

            dedupe = (
                grant.principal,
                resource.name,
            )

            if dedupe in seen:
                continue

            seen.add(dedupe)

            authorization_evidence = tuple(
                item.description for item in decision.allow_evidence
            )

            findings.append(
                Finding(
                    rule_id="GCP-IAM-007",
                    title=("IAM policy modification can escalate to project Owner"),
                    severity="critical",
                    principal=grant.principal,
                    resource=resource.name,
                    description=(
                        "The principal can modify the "
                        "project IAM policy and grant "
                        "itself or another controlled "
                        "identity the Owner role."
                    ),
                    attack_path=(
                        grant.principal,
                        permission,
                        resource.name,
                        "grant roles/owner",
                        "Project compromise",
                    ),
                    evidence=authorization_evidence,
                    remediation=(
                        "Restrict project IAM policy "
                        "modification to a controlled "
                        "administrative identity. "
                        "Require approval, audit IAM "
                        "changes, and prevent direct "
                        "Owner grants."
                    ),
                    references=("MITRE ATT&CK T1098",),
                )
            )

    return findings


def _privileged_service_account_key_findings(
    index: AccessIndex,
    authorization: AuthorizationEngine,
) -> list[Finding]:
    """Detect confirmed key creation for a privileged service account."""

    findings: list[Finding] = []
    privileged = _privileged_targets(index)
    seen: set[tuple[str, str, str]] = set()
    permission = "iam.serviceAccountKeys.create"

    for resource in index.hierarchy.resources.values():
        if resource.resource_type != "service_account":
            continue

        service_account_principal = f"serviceAccount:{resource.display_name}"

        privileged_grants = privileged.get(
            service_account_principal,
            [],
        )

        if not privileged_grants:
            continue

        key_creation_grants: list[Grant] = []

        for grant in index.grants_on(resource.name):
            if grant.principal == service_account_principal:
                continue

            if not index.catalog.has_permission(
                grant.role,
                permission,
            ):
                continue

            authorization_result = authorization.evaluate(
                grant.principal,
                permission,
                resource.name,
            )

            if authorization_result.decision is not Decision.ALLOW:
                continue

            key_creation_grants.append(grant)

        for key_grant in key_creation_grants:
            for privileged_grant in privileged_grants:
                dedupe = (
                    key_grant.principal,
                    resource.name,
                    privileged_grant.target.name,
                )

                if dedupe in seen:
                    continue

                seen.add(dedupe)

                findings.append(
                    Finding(
                        rule_id="GCP-IAM-008",
                        title=("Key creation reaches a privileged service account"),
                        severity="critical",
                        principal=key_grant.principal,
                        resource=(privileged_grant.target.name),
                        description=(
                            "The principal can create a "
                            "long-lived key for a service "
                            "account that has a broad "
                            "primitive role."
                        ),
                        attack_path=(
                            key_grant.principal,
                            permission,
                            service_account_principal,
                            ("create long-lived credential"),
                            privileged_grant.role,
                            privileged_grant.target.name,
                            "Project compromise",
                        ),
                        evidence=(
                            key_grant.evidence(),
                            privileged_grant.evidence(),
                        ),
                        remediation=(
                            "Remove unnecessary service-"
                            "account key creation access. "
                            "Use short-lived credentials, "
                            "workload identity federation, "
                            "and organization policies "
                            "that disable service-account "
                            "key creation."
                        ),
                        references=("MITRE ATT&CK T1098.001",),
                    )
                )

    return findings


def analyze(
    resources: list[Resource],
    role_definitions: Iterable[RoleDefinition] = (),
    deny_policies: Iterable[DenyPolicy] = (),
) -> list[Finding]:
    role_definition_list = list(role_definitions)
    deny_policy_list = list(deny_policies)

    hierarchy = Hierarchy(resources)
    catalog = RoleCatalog(role_definition_list)
    index = AccessIndex(
        hierarchy,
        catalog,
    )
    authorization = AuthorizationEngine(
        resources,
        deny_policy_list,
        role_definition_list,
    )

    findings = [
        *_direct_findings(
            index,
            authorization,
        ),
        *_impersonation_findings(index),
        *_actas_compute_findings(
            index,
            authorization,
        ),
        *_iam_policy_escalation_findings(
            index,
            authorization,
        ),
        *_privileged_service_account_key_findings(
            index,
            authorization,
        ),
    ]

    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }

    unique = {
        (
            finding.rule_id,
            finding.principal,
            finding.resource,
            finding.attack_path,
        ): finding
        for finding in findings
    }

    return sorted(
        unique.values(),
        key=lambda finding: (
            severity_rank[finding.severity],
            finding.rule_id,
            finding.principal,
            finding.resource,
        ),
    )
