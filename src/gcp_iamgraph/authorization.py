from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .access import AccessIndex, Grant
from .hierarchy import Hierarchy
from .models import (
    DenyPolicy,
    DenyRule,
    Resource,
    RoleDefinition,
)
from .roles import RoleCatalog


class Decision(str, Enum):
    """Possible authorization evaluation outcomes."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class DecisionEvidence:
    """Structured evidence contributing to a decision."""

    evidence_type: str
    source: str
    description: str
    inherited: bool
    conditioned: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.evidence_type,
            "source": self.source,
            "description": self.description,
            "inherited": self.inherited,
            "conditioned": self.conditioned,
        }


@dataclass(frozen=True)
class AuthorizationResult:
    """Explainable result of an authorization evaluation."""

    principal: str
    permission: str
    resource: str
    decision: Decision
    allow_evidence: tuple[DecisionEvidence, ...]
    deny_evidence: tuple[DecisionEvidence, ...]
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "permission": self.permission,
            "resource": self.resource,
            "decision": self.decision.value,
            "allow_evidence": [item.to_dict() for item in self.allow_evidence],
            "deny_evidence": [item.to_dict() for item in self.deny_evidence],
            "notes": list(self.notes),
        }


class AuthorizationEngine:
    """Evaluate explainable IAM allow and deny decisions."""

    def __init__(
        self,
        resources: list[Resource],
        deny_policies: list[DenyPolicy] | None = None,
        role_definitions: list[RoleDefinition] | None = None,
    ) -> None:
        self.hierarchy = Hierarchy(resources)
        self.catalog = RoleCatalog(role_definitions or [])
        self.access = AccessIndex(
            self.hierarchy,
            self.catalog,
        )
        self.deny_policies = tuple(
            sorted(
                deny_policies or [],
                key=lambda policy: policy.name,
            )
        )

        self._validate_policy_parents()

    def evaluate(
        self,
        principal: str,
        permission: str,
        resource_name: str,
    ) -> AuthorizationResult:
        """Evaluate one principal, permission, and resource tuple."""

        if resource_name not in self.hierarchy.resources:
            raise ValueError(f"Unknown resource: '{resource_name}'")

        grants = self.access.has_permission(
            principal,
            resource_name,
            permission,
        )

        allow_evidence = tuple(
            sorted(
                (self._allow_evidence(grant) for grant in grants),
                key=self._evidence_sort_key,
            )
        )

        deny_evidence = tuple(
            sorted(
                self._matching_deny_evidence(
                    principal,
                    permission,
                    resource_name,
                ),
                key=self._evidence_sort_key,
            )
        )

        unconditional_denies = tuple(
            item for item in deny_evidence if not item.conditioned
        )
        conditional_denies = tuple(item for item in deny_evidence if item.conditioned)
        unconditional_allows = tuple(
            item for item in allow_evidence if not item.conditioned
        )
        conditional_allows = tuple(item for item in allow_evidence if item.conditioned)

        if unconditional_denies:
            decision = Decision.DENY
            notes = (
                "An applicable unconditional deny rule overrides all allow grants.",
            )
        elif conditional_denies:
            decision = Decision.UNKNOWN
            notes = (
                "A matching deny rule contains an unevaluated condition.",
                "The permission cannot be confirmed as allowed or denied safely.",
            )
        elif unconditional_allows:
            decision = Decision.ALLOW
            notes = (
                (
                    "At least one unconditional effective allow grant "
                    "contains the requested permission."
                ),
                "No applicable deny rule blocks the permission.",
            )
        elif conditional_allows:
            decision = Decision.UNKNOWN
            notes = (
                "The matching allow grant contains an unevaluated condition.",
                "Conditional access is not assumed to be allowed.",
            )
        else:
            decision = Decision.UNKNOWN
            notes = (
                ("No effective allow grant or applicable deny rule was found."),
                (
                    "Absence of evidence is not treated as a confirmed "
                    "authorization decision."
                ),
            )

        return AuthorizationResult(
            principal=principal,
            permission=permission,
            resource=resource_name,
            decision=decision,
            allow_evidence=allow_evidence,
            deny_evidence=deny_evidence,
            notes=notes,
        )

    def _matching_deny_evidence(
        self,
        principal: str,
        permission: str,
        resource_name: str,
    ) -> list[DecisionEvidence]:
        evidence: list[DecisionEvidence] = []
        applicable_resources = self._applicable_resource_names(resource_name)

        for policy in self.deny_policies:
            if policy.parent not in applicable_resources:
                continue

            for rule_number, rule in enumerate(
                policy.rules,
                start=1,
            ):
                if not self._rule_matches(
                    rule,
                    principal,
                    permission,
                ):
                    continue

                inherited = policy.parent != resource_name
                origin = (
                    f"inherited from {policy.parent}"
                    if inherited
                    else f"attached to {policy.parent}"
                )
                condition_text = (
                    " with an unevaluated condition"
                    if rule.condition is not None
                    else ""
                )

                evidence.append(
                    DecisionEvidence(
                        evidence_type="deny",
                        source=(f"{policy.name}#rule-{rule_number}"),
                        description=(
                            f"{principal} is denied {permission} "
                            f"on {resource_name}; {origin}"
                            f"{condition_text}"
                        ),
                        inherited=inherited,
                        conditioned=rule.condition is not None,
                    )
                )

        return evidence

    def _applicable_resource_names(
        self,
        resource_name: str,
    ) -> set[str]:
        return {
            resource_name,
            *(ancestor.name for ancestor in self.hierarchy.ancestors(resource_name)),
        }

    @staticmethod
    def _rule_matches(
        rule: DenyRule,
        principal: str,
        permission: str,
    ) -> bool:
        principal_denied = (
            principal in rule.denied_principals or "*" in rule.denied_principals
        )
        permission_denied = (
            permission in rule.denied_permissions or "*" in rule.denied_permissions
        )

        principal_excepted = (
            principal in rule.exception_principals or "*" in rule.exception_principals
        )
        permission_excepted = (
            permission in rule.exception_permissions
            or "*" in rule.exception_permissions
        )

        return (
            principal_denied
            and permission_denied
            and not principal_excepted
            and not permission_excepted
        )

    @staticmethod
    def _allow_evidence(
        grant: Grant,
    ) -> DecisionEvidence:
        return DecisionEvidence(
            evidence_type="allow",
            source=grant.source.name,
            description=grant.evidence(),
            inherited=grant.inherited,
            conditioned=grant.condition is not None,
        )

    @staticmethod
    def _evidence_sort_key(
        evidence: DecisionEvidence,
    ) -> tuple[str, str, str]:
        return (
            evidence.evidence_type,
            evidence.source,
            evidence.description,
        )

    def _validate_policy_parents(self) -> None:
        resource_names = set(self.hierarchy.resources)

        for policy in self.deny_policies:
            if policy.parent not in resource_names:
                raise ValueError(
                    f"Unknown deny policy parent '{policy.parent}' for '{policy.name}'"
                )
