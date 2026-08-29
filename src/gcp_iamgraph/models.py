from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _required_string(
    data: dict[str, Any],
    key: str,
) -> str:
    """Return a required, non-empty string field."""

    value = data[key]

    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"'{key}' must be a non-empty string")

    return value


def _string_tuple(
    data: dict[str, Any],
    key: str,
) -> tuple[str, ...]:
    """Convert an array of strings into an immutable tuple."""

    value = data.get(
        key,
        [],
    )

    if not isinstance(value, list):
        raise TypeError(f"'{key}' must be an array")

    if not all(isinstance(item, str) and item for item in value):
        raise TypeError(f"'{key}' must contain non-empty strings")

    return tuple(value)


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
            permissions=frozenset(
                data.get(
                    "permissions",
                    [],
                )
            ),
            stage=data.get("stage", "GA"),
            is_custom=not name.startswith("roles/"),
        )


@dataclass(frozen=True)
class DenyRule:
    """A rule that denies selected principals and permissions."""

    denied_principals: tuple[str, ...]
    exception_principals: tuple[str, ...]
    denied_permissions: tuple[str, ...]
    exception_permissions: tuple[str, ...]
    condition: dict[str, Any] | None = None

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> DenyRule:
        denied_principals = _string_tuple(
            data,
            "denied_principals",
        )
        denied_permissions = _string_tuple(
            data,
            "denied_permissions",
        )
        condition = data.get("condition")

        if not denied_principals:
            raise ValueError("A deny rule must contain at least one denied principal")

        if not denied_permissions:
            raise ValueError("A deny rule must contain at least one denied permission")

        if condition is not None and not isinstance(
            condition,
            dict,
        ):
            raise TypeError("'condition' must be an object")

        return cls(
            denied_principals=denied_principals,
            exception_principals=_string_tuple(
                data,
                "exception_principals",
            ),
            denied_permissions=denied_permissions,
            exception_permissions=_string_tuple(
                data,
                "exception_permissions",
            ),
            condition=condition,
        )


@dataclass(frozen=True)
class DenyPolicy:
    """A deny policy attached to a hierarchy resource."""

    name: str
    parent: str
    display_name: str
    rules: tuple[DenyRule, ...]

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> DenyPolicy:
        name = _required_string(
            data,
            "name",
        )
        parent = _required_string(
            data,
            "parent",
        )
        raw_rules = data.get(
            "rules",
            [],
        )

        if not isinstance(raw_rules, list):
            raise TypeError("'rules' must be an array")

        if not raw_rules:
            raise ValueError("A deny policy must contain at least one rule")

        display_name = data.get(
            "display_name",
            name,
        )

        if (
            not isinstance(
                display_name,
                str,
            )
            or not display_name.strip()
        ):
            raise TypeError("'display_name' must be a non-empty string")

        return cls(
            name=name,
            parent=parent,
            display_name=display_name,
            rules=tuple(DenyRule.from_dict(item) for item in raw_rules),
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
                Binding.from_dict(item)
                for item in data.get(
                    "bindings",
                    [],
                )
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
