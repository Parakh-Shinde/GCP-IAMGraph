from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Resource, RoleDefinition


class InputError(ValueError):
    """Raised when an input document is invalid."""


def _load_document(
    path: str | Path,
) -> dict[str, Any]:
    """Read and validate a GCP IAMGraph JSON document."""

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"Unable to read GCP IAM data: {exc}") from exc

    if not isinstance(data, dict):
        raise InputError("Input document must be a JSON object")

    return data


def load_environment(
    path: str | Path,
) -> list[Resource]:
    """Load GCP resources and IAM bindings."""

    data = _load_document(path)
    resources = data.get("resources")

    if not isinstance(resources, list):
        raise InputError("Input must contain a 'resources' array")

    try:
        result = [Resource.from_dict(item) for item in resources]
    except (
        KeyError,
        TypeError,
        AttributeError,
    ) as exc:
        raise InputError(f"Invalid resource or binding structure: {exc}") from exc

    _validate_resources(result)
    return result


def load_role_definitions(
    path: str | Path,
) -> list[RoleDefinition]:
    """Load custom role definitions from IAMGraph JSON."""

    data = _load_document(path)
    role_definitions = data.get(
        "role_definitions",
        [],
    )

    if not isinstance(role_definitions, list):
        raise InputError("'role_definitions' must be an array")

    try:
        return [RoleDefinition.from_dict(item) for item in role_definitions]
    except (
        KeyError,
        TypeError,
        AttributeError,
    ) as exc:
        raise InputError(f"Invalid role definition: {exc}") from exc


def _validate_resources(
    resources: list[Resource],
) -> None:
    """Validate resource names and parent relationships."""

    names = {resource.name for resource in resources}

    if len(names) != len(resources):
        raise InputError("Resource names must be unique")

    for resource in resources:
        if resource.parent and resource.parent not in names:
            raise InputError(
                f"Unknown parent '{resource.parent}' for '{resource.name}'"
            )

        if resource.parent == resource.name:
            raise InputError(f"Resource '{resource.name}' cannot be its own parent")
