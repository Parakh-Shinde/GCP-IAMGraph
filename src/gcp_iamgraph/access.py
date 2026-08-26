from __future__ import annotations

from dataclasses import dataclass

from .hierarchy import Hierarchy
from .models import Binding, Resource
from .roles import (
    DEFAULT_ROLE_CATALOG,
    RoleCatalog,
)


@dataclass(frozen=True)
class Grant:
    principal: str
    role: str
    target: Resource
    source: Resource
    condition: dict | None

    @property
    def inherited(self) -> bool:
        return self.target.name != self.source.name

    def evidence(self) -> str:
        origin = f" inherited from {self.source.name}" if self.inherited else ""
        condition = " with a condition" if self.condition else ""

        return (
            f"{self.principal} has {self.role} on {self.target.name}{origin}{condition}"
        )


class AccessIndex:
    """Indexes effective access across the GCP hierarchy."""

    def __init__(
        self,
        hierarchy: Hierarchy,
        catalog: RoleCatalog | None = None,
    ) -> None:
        self.hierarchy = hierarchy
        self.catalog = catalog if catalog is not None else DEFAULT_ROLE_CATALOG

    def grants_on(
        self,
        resource_name: str,
    ) -> list[Grant]:
        target = self.hierarchy.resources[resource_name]
        grants: list[Grant] = []

        for (
            source,
            binding,
        ) in self.hierarchy.effective_bindings(resource_name):
            grants.extend(
                self._binding_grants(
                    binding,
                    target,
                    source,
                )
            )

        return grants

    def grants_for(
        self,
        principal: str,
    ) -> list[Grant]:
        return [
            grant
            for name in self.hierarchy.resources
            for grant in self.grants_on(name)
            if grant.principal == principal
        ]

    def has_permission(
        self,
        principal: str,
        resource_name: str,
        permission: str,
    ) -> list[Grant]:
        return [
            grant
            for grant in self.grants_on(resource_name)
            if (
                grant.principal == principal
                and self.catalog.has_permission(
                    grant.role,
                    permission,
                )
            )
        ]

    @staticmethod
    def _binding_grants(
        binding: Binding,
        target: Resource,
        source: Resource,
    ) -> list[Grant]:
        return [
            Grant(
                member,
                binding.role,
                target,
                source,
                binding.condition,
            )
            for member in binding.members
        ]
