import json
from pathlib import Path

from gcp_iamgraph.detections import analyze
from gcp_iamgraph.models import Resource
from gcp_iamgraph.parser import load_environment


EXAMPLES = Path(__file__).parents[1] / "examples"


def test_vulnerable_environment_exposes_key_risks():
    findings = analyze(load_environment(EXAMPLES / "vulnerable-environment.json"))
    rule_ids = {item.rule_id for item in findings}
    assert {"GCP-IAM-001", "GCP-IAM-002", "GCP-IAM-003", "GCP-IAM-004", "GCP-IAM-005"} <= rule_ids
    impersonation = next(item for item in findings if item.rule_id == "GCP-IAM-005")
    assert impersonation.principal == "user:developer@example.test"
    assert "serviceAccount:deployment@payments-prod.iam.gserviceaccount.com" in impersonation.attack_path


def test_hardened_environment_has_no_findings():
    findings = analyze(load_environment(EXAMPLES / "hardened-environment.json"))
    assert findings == []


def test_public_authenticated_access_is_high_not_critical():
    resource = Resource.from_dict({
        "name": "projects/test",
        "type": "project",
        "bindings": [{"role": "roles/viewer", "members": ["allAuthenticatedUsers"]}],
    })
    finding = next(item for item in analyze([resource]) if item.rule_id == "GCP-IAM-002")
    assert finding.severity == "high"

