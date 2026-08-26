from __future__ import annotations

from collections import defaultdict, deque

from .access import AccessIndex, Grant
from .hierarchy import Hierarchy
from .models import Finding, Resource
from .roles import role_has_permission

PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}
PRIVILEGED_ROLES = {"roles/owner": "critical", "roles/editor": "high"}


def _finding_for_privileged_grant(grant: Grant) -> Finding:
    return Finding(
        rule_id="GCP-IAM-001",
        title=f"Broad primitive role: {grant.role}",
        severity=PRIVILEGED_ROLES[grant.role],
        principal=grant.principal,
        resource=grant.target.name,
        description="A principal has a broad primitive role that exceeds typical least-privilege requirements.",
        attack_path=(grant.principal, grant.role, grant.target.name, "Broad resource control"),
        evidence=(grant.evidence(),),
        remediation="Replace primitive roles with predefined or custom roles containing only required permissions.",
        references=("CIS Google Cloud Foundations 1.0",),
    )


def _direct_findings(index: AccessIndex) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for resource in index.hierarchy.resources.values():
        # Report risky grants at the policy where they are configured. Their
        # inherited impact remains available to the attack-path analysis.
        for binding in resource.bindings:
            for principal in binding.members:
                grant = Grant(principal, binding.role, resource, resource, binding.condition)
                key = (grant.principal, grant.role, grant.target.name)
                if key in seen:
                    continue
                seen.add(key)
                if grant.role in PRIVILEGED_ROLES:
                    findings.append(_finding_for_privileged_grant(grant))
                if grant.principal in PUBLIC_PRINCIPALS:
                    findings.append(Finding(
                    rule_id="GCP-IAM-002",
                    title="Public or globally authenticated access",
                    severity="critical" if grant.principal == "allUsers" else "high",
                    principal=grant.principal,
                    resource=grant.target.name,
                    description="The IAM binding grants access to a public principal.",
                    attack_path=(grant.principal, grant.role, grant.target.name),
                    evidence=(grant.evidence(),),
                    remediation="Remove the public member and grant the minimum role to explicitly identified principals.",
                    ))
                # Owner already explains unrestricted privilege at this scope;
                # narrower derivative findings would only add report noise.
                if grant.role == "roles/owner":
                    continue
                permission_rules = (
                    ("resourcemanager.projects.setIamPolicy", "GCP-IAM-003", "IAM policy modification", "critical", "A principal can change project IAM bindings and grant additional access."),
                    ("iam.serviceAccountKeys.create", "GCP-IAM-004", "Service-account key creation", "high", "A principal can create long-lived credentials for a service account."),
                )
                for permission, rule_id, title, severity, description in permission_rules:
                    if not role_has_permission(grant.role, permission):
                        continue
                    dedupe = (rule_id, grant.principal, grant.target.name)
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)
                    findings.append(Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    principal=grant.principal,
                    resource=grant.target.name,
                    description=description,
                    attack_path=(grant.principal, permission, grant.target.name, "Privilege expansion"),
                    evidence=(grant.evidence(),),
                    remediation="Restrict this permission to a controlled deployment identity and require short-lived credentials and approval controls.",
                    ))
    return findings


def _impersonation_edges(index: AccessIndex) -> dict[str, list[tuple[str, Grant]]]:
    edges: dict[str, list[tuple[str, Grant]]] = defaultdict(list)
    for resource in index.hierarchy.resources.values():
        if resource.resource_type != "service_account":
            continue
        target_principal = f"serviceAccount:{resource.display_name}"
        for grant in index.grants_on(resource.name):
            if grant.role == "roles/iam.serviceAccountTokenCreator":
                edges[grant.principal].append((target_principal, grant))
    return edges


def _privileged_targets(index: AccessIndex) -> dict[str, list[Grant]]:
    targets: dict[str, list[Grant]] = defaultdict(list)
    for resource_name, resource in index.hierarchy.resources.items():
        if resource.resource_type not in {"organization", "folder", "project"}:
            continue
        for grant in index.grants_on(resource_name):
            if grant.role in PRIVILEGED_ROLES:
                targets[grant.principal].append(grant)
    return targets


def _impersonation_findings(index: AccessIndex) -> list[Finding]:
    edges = _impersonation_edges(index)
    privileged = _privileged_targets(index)
    findings: list[Finding] = []
    for start in sorted(edges):
        queue = deque([(start, [start], [])])
        visited = {start}
        while queue:
            current, path, evidence = queue.popleft()
            if current != start and current in privileged:
                for target_grant in privileged[current]:
                    findings.append(Finding(
                        rule_id="GCP-IAM-005",
                        title="Service-account impersonation reaches a privileged role",
                        severity="critical",
                        principal=start,
                        resource=target_grant.target.name,
                        description="The principal can obtain short-lived credentials for a service account with broad access.",
                        attack_path=tuple([*path, target_grant.role, target_grant.target.name]),
                        evidence=tuple([*evidence, target_grant.evidence()]),
                        remediation="Remove unnecessary Token Creator bindings and grant impersonation only on narrowly scoped service accounts.",
                        references=("MITRE ATT&CK T1078.004",),
                    ))
                continue
            for target, grant in edges.get(current, []):
                if target not in visited:
                    visited.add(target)
                    queue.append((target, [*path, "impersonates", target], [*evidence, grant.evidence()]))
    return findings


def analyze(resources: list[Resource]) -> list[Finding]:
    hierarchy = Hierarchy(resources)
    index = AccessIndex(hierarchy)
    findings = [*_direct_findings(index), *_impersonation_findings(index)]
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique = {(f.rule_id, f.principal, f.resource, f.attack_path): f for f in findings}
    return sorted(unique.values(), key=lambda f: (severity_rank[f.severity], f.rule_id, f.principal, f.resource))
