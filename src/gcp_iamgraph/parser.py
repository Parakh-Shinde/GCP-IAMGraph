from __future__ import annotations

import json
from pathlib import Path

from .models import Resource


class InputError(ValueError):
    """Raised when an input document is invalid."""


def load_environment(path: str | Path) -> list[Resource]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"Unable to read GCP IAM data: {exc}") from exc
    resources = data.get("resources") if isinstance(data, dict) else None
    if not isinstance(resources, list):
        raise InputError("Input must contain a 'resources' array")
    try:
        result = [Resource.from_dict(item) for item in resources]
    except (KeyError, TypeError, AttributeError) as exc:
        raise InputError(f"Invalid resource or binding structure: {exc}") from exc
    _validate(result)
    return result


def _validate(resources: list[Resource]) -> None:
    names = {item.name for item in resources}
    if len(names) != len(resources):
        raise InputError("Resource names must be unique")
    for resource in resources:
        if resource.parent and resource.parent not in names:
            raise InputError(f"Unknown parent '{resource.parent}' for '{resource.name}'")
        if resource.parent == resource.name:
            raise InputError(f"Resource '{resource.name}' cannot be its own parent")

