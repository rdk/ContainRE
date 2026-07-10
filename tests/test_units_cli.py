"""Unit tests for CLI behavior that doesn't execute a specimen."""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from containre.cli.main import app

pytestmark = pytest.mark.unit


def test_run_rejects_an_invalid_effective_policy_before_executing():
    # --net bogus makes the effective policy fail validation; `run` must reject it
    # up front (mirroring POST /api/runs) rather than persisting/executing it.
    result = CliRunner().invoke(app, ["run", "/bin/true", "--net", "bogus"])

    assert result.exit_code != 0
    assert "invalid effective policy" in result.output
