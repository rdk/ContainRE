"""Every event the harness emits, and every meta.json, must validate against the
versioned JSON-Schema contracts."""
from __future__ import annotations

import pytest

from containre import contracts

pytestmark = pytest.mark.specimen


@pytest.mark.parametrize("name,overrides", [
    ("filewriter", {"files": {"decoys": ["wallet.dat"]}}),
    ("netbeacon", {}),
    ("spawner", {}),
    ("antidebug", {}),
    ("unpacker", {}),      # mem map/protect + snapshot events
    ("snooper", {}),       # sensitive-file detections
    ("udpbeacon", {}),     # net send events
])
def test_event_stream_conforms_to_schema(harness, name, overrides):
    if contracts.find_contracts_dir() is None:
        pytest.skip("contracts dir not found")
    r = harness(name, **overrides)
    assert r.events(), "expected a non-empty event stream"
    for event in r.events():
        errors = contracts.validate(event, "events.v1.schema.json")
        assert not errors, f"event seq={event['seq']} kind={event['kind']}: {errors}"


def test_meta_conforms_to_schema(harness):
    if contracts.find_contracts_dir() is None:
        pytest.skip("contracts dir not found")
    r = harness("filewriter", files={"decoys": ["wallet.dat"]})
    errors = contracts.validate(r.meta, "meta.v1.schema.json")
    assert not errors, f"meta.json: {errors}"
