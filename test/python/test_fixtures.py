"""The committed Solidity test fixtures match what the generator produces."""
import json
import sys

from conftest import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import gen_kzg_fixtures  # noqa: E402


def test_fixture_file_is_up_to_date():
    committed = json.loads(gen_kzg_fixtures.FIXTURE_PATH.read_text())
    assert committed == gen_kzg_fixtures.build_fixtures(), (
        "run `python3 scripts/gen_kzg_fixtures.py` and commit the result"
    )


def test_fixture_openings_are_consistent():
    sets = gen_kzg_fixtures.build_fixtures()["sets"]
    for data in sets.values():
        for opening in data["openings"]:
            assert opening["offchain_verifies"]
            assert (opening["y"] == "0") == opening["revoked"]
