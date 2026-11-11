"""Shared pytest setup: import path for the off-chain KZG code and the SRS."""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "bindings" / "python"))

TRUSTED_SETUP_PATH = REPO_ROOT / "src" / "trusted_setup.txt"


@pytest.fixture(scope="session")
def trusted_setup():
    import ckzg

    return ckzg.load_trusted_setup(str(TRUSTED_SETUP_PATH), 0)
