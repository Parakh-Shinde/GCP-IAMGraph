from gcp_iamgraph.hierarchy import Hierarchy
from gcp_iamgraph.models import Resource


def test_effective_bindings_include_ancestors():
    resources = [
        Resource.from_dict(
            {
                "name": "organizations/1",
                "type": "organization",
                "bindings": [{"role": "roles/viewer", "members": ["user:a@test"]}],
            }
        ),
        Resource.from_dict(
            {"name": "projects/p", "type": "project", "parent": "organizations/1"}
        ),
    ]
    bindings = Hierarchy(resources).effective_bindings("projects/p")
    assert bindings[0][0].name == "organizations/1"
    assert bindings[0][1].role == "roles/viewer"
