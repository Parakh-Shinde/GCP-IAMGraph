import json

from gcp_iamgraph.cli import main
from gcp_iamgraph.parser import (
    load_cloud_asset_inventory,
)


def test_loads_cloud_asset_inventory_iam_policy(
    tmp_path,
):
    export_path = tmp_path / "cloud-assets.jsonl"

    asset = {
        "name": ("//cloudresourcemanager.googleapis.com/projects/payments-prod"),
        "assetType": ("cloudresourcemanager.googleapis.com/Project"),
        "iamPolicy": {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["user:admin@example.test"],
                }
            ]
        },
        "ancestors": [
            "projects/payments-prod",
            "folders/123456",
            "organizations/987654",
        ],
    }

    export_path.write_text(
        json.dumps(asset) + "\n",
        encoding="utf-8",
    )

    resources = load_cloud_asset_inventory(export_path)

    assert len(resources) == 3

    organization = next(
        item for item in resources if item.name == "organizations/987654"
    )
    folder = next(item for item in resources if item.name == "folders/123456")
    project = next(item for item in resources if item.name == "projects/payments-prod")

    assert organization.resource_type == ("organization")
    assert organization.parent is None

    assert folder.resource_type == "folder"
    assert folder.parent == ("organizations/987654")

    assert project.resource_type == "project"
    assert project.parent == "folders/123456"

    assert len(project.bindings) == 1
    assert project.bindings[0].role == ("roles/owner")
    assert project.bindings[0].members == ("user:admin@example.test",)


def test_cli_analyzes_cloud_asset_inventory(
    tmp_path,
    capsys,
):
    export_path = tmp_path / "cloud-assets.jsonl"

    asset = {
        "name": ("//cloudresourcemanager.googleapis.com/projects/payments-prod"),
        "assetType": ("cloudresourcemanager.googleapis.com/Project"),
        "iamPolicy": {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["user:admin@example.test"],
                }
            ]
        },
        "ancestors": [
            "projects/payments-prod",
        ],
    }

    export_path.write_text(
        json.dumps(asset) + "\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            str(export_path),
            "--input-format",
            "cai",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["summary"]["resources_analyzed"] == 1
    assert output["summary"]["total_findings"] == 1
    assert output["findings"][0]["rule_id"] == "GCP-IAM-001"
