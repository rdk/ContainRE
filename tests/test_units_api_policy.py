"""Unit tests for API request-to-policy translation."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from containre.api.app import RunRequest, _build_policy

pytestmark = pytest.mark.unit


def test_build_policy_supports_binary_with_policy_overrides():
    policy = _build_policy(RunRequest(
        binary="/bin/true",
        net="deny",
        decoys=["wallet.dat"],
        policy={"trace": {"l2": {"mode": "singlestep", "window": {"max_insns": 5}}}},
    ))

    assert policy["specimen"]["path"] == "/bin/true"
    assert policy["network"]["posture"] == "deny"
    assert policy["files"]["decoys"] == ["wallet.dat"]
    assert policy["trace"]["l2"]["mode"] == "singlestep"
    assert policy["trace"]["l2"]["window"]["max_insns"] == 5
    assert policy["trace"]["snapshot_on"] == ["connect", "mmap+x", "exec"]


def test_build_policy_still_accepts_complete_policy_without_binary():
    policy = _build_policy(RunRequest(policy={"specimen": {"path": "/bin/true"}}))
    assert policy["specimen"]["path"] == "/bin/true"
    assert policy["network"]["posture"] == "simulate"


def test_build_policy_rejects_missing_binary_and_policy():
    with pytest.raises(HTTPException) as exc:
        _build_policy(RunRequest())
    assert exc.value.status_code == 400
