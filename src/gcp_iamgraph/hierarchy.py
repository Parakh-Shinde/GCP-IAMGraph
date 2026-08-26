from __future__ import annotations

from .models import Binding, Resource


class Hierarchy:
    def __init__(self, resources: list[Resource]):
        self.resources = {item.name: item for item in resources}
        self._assert_acyclic()

    def ancestors(self, resource_name: str) -> list[Resource]:
        chain: list[Resource] = []
        current = self.resources[resource_name]
        while current.parent:
            current = self.resources[current.parent]
            chain.append(current)
        return chain

    def effective_bindings(self, resource_name: str) -> list[tuple[Resource, Binding]]:
        target = self.resources[resource_name]
        sources = [target, *self.ancestors(resource_name)]
        return [(source, binding) for source in sources for binding in source.bindings]

    def descendants(self, resource_name: str) -> list[Resource]:
        return [
            item for item in self.resources.values()
            if resource_name in {ancestor.name for ancestor in self.ancestors(item.name)}
        ]

    def _assert_acyclic(self) -> None:
        for resource in self.resources.values():
            seen = {resource.name}
            current = resource
            while current.parent:
                if current.parent in seen:
                    raise ValueError(f"Resource hierarchy contains a cycle at '{current.parent}'")
                seen.add(current.parent)
                current = self.resources[current.parent]

