from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Binding:
    role: str
    members: tuple[str, ...]
    condition: dict[str, Any] | None = None

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> Binding:
        return cls(
            role=data["role"],
            members=tuple(data.get("members", [])),
            condition=data.get("condition"),
        )


@dataclass(frozen=True)
class RoleDefinition:
    """A predefined or custom GCP IAM role."""

    name: str
    title: str
    permissions: frozenset[str]
    stage: str = "GA"
    is_custom: bool = True

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> RoleDefinition:
        name = data["name"]

        return cls(
            name=name,
            title=data.get("title", name),
            permissions=frozenset(data.get("permissions", [])),
            stage=data.get("stage", "GA"),
            is_custom=not name.startswith("roles/"),
        )


@dataclass(frozen=True)
class Resource:
    name: str
    resource_type: str
    display_name: str
    parent: str | None = None
    bindings: tuple[Binding, ...] = ()

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> Resource:
        return cls(
            name=data["name"],
            resource_type=data["type"],
            display_name=data.get(
                "display_name",
                data["name"],
            ),
            parent=data.get("parent"),
            bindings=tuple(
                Binding.from_dict(item) for item in data.get("bindings", [])
            ),
        )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    principal: str
    resource: str
    description: str
    attack_path: tuple[str, ...]
    evidence: tuple[str, ...]
    remediation: str
    references: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "principal": self.principal,
            "resource": self.resource,
            "description": self.description,
            "attack_path": list(self.attack_path),
            "evidence": list(self.evidence),
            "remediation": self.remediation,
            "references": list(self.references),
        }
