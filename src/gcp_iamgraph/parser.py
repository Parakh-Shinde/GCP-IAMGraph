from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    Binding,
    DenyPolicy,
    Resource,
    RoleDefinition,
)


class InputError(ValueError):
    """Raised when an input document is invalid."""


def _load_document(
    path: str | Path,
) -> dict[str, Any]:
    """Read and validate a GCP IAMGraph JSON document."""

    try:
        data = json.loads(
            Path(path).read_text(
                encoding="utf-8",
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
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


def load_deny_policies(
    path: str | Path,
) -> list[DenyPolicy]:
    """Load and validate deny policies from IAMGraph JSON."""

    data = _load_document(path)
    raw_policies = data.get(
        "deny_policies",
        [],
    )

    if not isinstance(raw_policies, list):
        raise InputError("'deny_policies' must be an array")

    raw_resources = data.get("resources")

    if not isinstance(raw_resources, list):
        raise InputError("Input must contain a 'resources' array")

    try:
        resources = [Resource.from_dict(item) for item in raw_resources]
    except (
        KeyError,
        TypeError,
        AttributeError,
    ) as exc:
        raise InputError(f"Invalid resource or binding structure: {exc}") from exc

    _validate_resources(resources)

    try:
        policies = [DenyPolicy.from_dict(item) for item in raw_policies]
    except (
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
    ) as exc:
        raise InputError(f"Invalid deny policy: {exc}") from exc

    _validate_deny_policies(
        policies,
        resources,
    )

    return policies


def _relative_asset_name(
    full_name: str,
) -> str:
    """Convert a full CAI asset name to a relative name."""

    if not full_name.startswith("//"):
        return full_name

    without_prefix = full_name[2:]
    separator = without_prefix.find("/")

    if separator == -1:
        raise InputError(f"Invalid Cloud Asset name: {full_name}")

    return without_prefix[separator + 1 :]


def _resource_type_from_name(
    name: str,
) -> str:
    """Infer an IAMGraph resource type from its name."""

    if name.startswith("organizations/"):
        return "organization"

    if name.startswith("folders/"):
        return "folder"

    if "/serviceAccounts/" in name:
        return "service_account"

    if name.startswith("projects/"):
        return "project"

    return "resource"


def _resource_type_from_asset(
    asset_type: str,
    name: str,
) -> str:
    """Map a CAI asset type to an IAMGraph type."""

    suffix = asset_type.rsplit(
        "/",
        maxsplit=1,
    )[-1]

    known_types = {
        "Organization": "organization",
        "Folder": "folder",
        "Project": "project",
        "ServiceAccount": "service_account",
    }

    return known_types.get(
        suffix,
        _resource_type_from_name(name),
    )


def _display_name(
    name: str,
) -> str:
    """Return a human-readable resource name."""

    return name.rsplit(
        "/",
        maxsplit=1,
    )[-1]


def _load_json_lines(
    path: str | Path,
) -> list[dict[str, Any]]:
    """Read a Cloud Asset Inventory JSONL export."""

    try:
        lines = (
            Path(path)
            .read_text(
                encoding="utf-8",
            )
            .splitlines()
        )
    except OSError as exc:
        raise InputError(f"Unable to read Cloud Asset Inventory data: {exc}") from exc

    assets: list[dict[str, Any]] = []

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        if not line.strip():
            continue

        try:
            asset = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(
                f"Invalid Cloud Asset Inventory JSON on line {line_number}: {exc}"
            ) from exc

        if not isinstance(asset, dict):
            raise InputError(
                f"Cloud Asset Inventory entry on line {line_number} must be an object"
            )

        assets.append(asset)

    if not assets:
        raise InputError("Cloud Asset Inventory export is empty")

    return assets


def load_cloud_asset_inventory(
    path: str | Path,
) -> list[Resource]:
    """Load a Cloud Asset Inventory IAM-policy export."""

    assets = _load_json_lines(path)
    resources: dict[str, Resource] = {}

    for asset in assets:
        try:
            full_name = asset["name"]
            asset_type = asset["assetType"]
        except KeyError as exc:
            raise InputError(
                f"Cloud Asset Inventory asset is missing a required field: {exc}"
            ) from exc

        if not isinstance(full_name, str):
            raise InputError("Cloud Asset Inventory asset name must be a string")

        if not isinstance(asset_type, str):
            raise InputError("Cloud Asset Inventory assetType must be a string")

        ancestors = asset.get(
            "ancestors",
            [],
        )

        if not isinstance(ancestors, list):
            raise InputError("Cloud Asset Inventory ancestors must be an array")

        if not all(isinstance(item, str) for item in ancestors):
            raise InputError("Cloud Asset Inventory ancestors must contain strings")

        # CAI orders ancestors from the closest
        # resource to the organization root.
        for position, ancestor in enumerate(ancestors):
            parent = ancestors[position + 1] if position + 1 < len(ancestors) else None

            existing = resources.get(ancestor)

            resources[ancestor] = Resource(
                name=ancestor,
                resource_type=(_resource_type_from_name(ancestor)),
                display_name=_display_name(ancestor),
                parent=parent,
                bindings=(existing.bindings if existing is not None else ()),
            )

        name = _relative_asset_name(full_name)
        parent = None

        if ancestors:
            if name == ancestors[0]:
                parent = ancestors[1] if len(ancestors) > 1 else None
            else:
                parent = ancestors[0]

        iam_policy = asset.get(
            "iamPolicy",
            {},
        )

        if not isinstance(iam_policy, dict):
            raise InputError("Cloud Asset Inventory iamPolicy must be an object")

        raw_bindings = iam_policy.get(
            "bindings",
            [],
        )

        if not isinstance(raw_bindings, list):
            raise InputError("Cloud Asset Inventory IAM bindings must be an array")

        try:
            bindings = tuple(Binding.from_dict(item) for item in raw_bindings)
        except (
            KeyError,
            TypeError,
            AttributeError,
        ) as exc:
            raise InputError(
                f"Invalid Cloud Asset Inventory IAM binding: {exc}"
            ) from exc

        existing = resources.get(name)
        existing_bindings = existing.bindings if existing is not None else ()

        resources[name] = Resource(
            name=name,
            resource_type=(
                _resource_type_from_asset(
                    asset_type,
                    name,
                )
            ),
            display_name=_display_name(name),
            parent=parent,
            bindings=(
                *existing_bindings,
                *bindings,
            ),
        )

    result = list(resources.values())
    _validate_resources(result)

    return result


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


def _validate_deny_policies(
    policies: list[DenyPolicy],
    resources: list[Resource],
) -> None:
    """Validate deny-policy names and attachment points."""

    policy_names = {policy.name for policy in policies}

    if len(policy_names) != len(policies):
        raise InputError("Deny policy names must be unique")

    resource_names = {resource.name for resource in resources}

    for policy in policies:
        if policy.parent not in resource_names:
            raise InputError(
                f"Unknown deny policy parent '{policy.parent}' for '{policy.name}'"
            )
