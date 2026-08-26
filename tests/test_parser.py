import json

import pytest

from gcp_iamgraph.parser import InputError, load_environment


def test_loads_valid_environment(tmp_path):
    path = tmp_path / "gcp.json"
    path.write_text(json.dumps({"resources": [{"name": "projects/test", "type": "project"}]}))
    assert load_environment(path)[0].name == "projects/test"


def test_rejects_unknown_parent(tmp_path):
    path = tmp_path / "gcp.json"
    path.write_text(json.dumps({"resources": [{"name": "projects/test", "type": "project", "parent": "folders/missing"}]}))
    with pytest.raises(InputError):
        load_environment(path)

