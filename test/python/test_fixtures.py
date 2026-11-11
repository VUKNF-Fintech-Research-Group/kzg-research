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


def test_gas_sweep_file_is_up_to_date():
    committed = json.loads(gen_kzg_fixtures.SWEEP_PATH.read_text())
    sweep = gen_kzg_fixtures.build_sweep()
    assert committed == sweep, "run `python3 scripts/gen_kzg_fixtures.py` and commit the result"
    for point in sweep["points"]:
        assert point["valid"]["offchain_verifies"] and point["valid"]["y"] != "0"
        assert point["revoked"]["offchain_verifies"] and point["revoked"]["y"] == "0"
        assert point["commitment"] != point["next_commitment"]


def test_batch_sweep_file_is_up_to_date():
    committed = json.loads(gen_kzg_fixtures.BATCH_PATH.read_text())
    batch = gen_kzg_fixtures.build_batch()
    assert committed == batch, "run `python3 scripts/gen_kzg_fixtures.py` and commit the result"
    commitments = batch["commitments"]
    assert len(commitments) == gen_kzg_fixtures.BATCH_MAX + 1
    assert len(set(commitments)) == len(commitments)
    # the empty set commits to f = 1, i.e. the G1 generator
    import eip2537
    assert commitments[0] == "0x" + eip2537.g1_generator_eip2537().hex()


def test_fixture_openings_are_consistent():
    sets = gen_kzg_fixtures.build_fixtures()["sets"]
    for data in sets.values():
        for opening in data["openings"]:
            assert opening["offchain_verifies"]
            assert (opening["y"] == "0") == opening["revoked"]
