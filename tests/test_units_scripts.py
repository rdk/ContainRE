"""Unit checks for repository shell test runners."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script", [
    "scripts/test-unit.sh",
    "scripts/test-specimens-extended.sh",
])
def test_test_runner_scripts_are_executable_and_parse(script):
    path = ROOT / script
    assert path.exists()
    assert os.access(path, os.X_OK)
    subprocess.run(["sh", "-n", str(path)], check=True)
