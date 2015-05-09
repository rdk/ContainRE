#!/usr/bin/env python3
"""Validate the ContainRE contract examples against their JSON Schemas.

Keeps the contracts honest: run this in CI or locally after editing a schema or
example. Requires `jsonschema` (and `pyyaml` for the policy example).

    python3 contracts/validate.py
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_json(p: Path):
    return json.loads(p.read_text())


def main() -> int:
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        print("[FAIL] pip install jsonschema  (validation requires it)")
        return 2

    ev_schema = load_json(HERE / "events.v1.schema.json")
    pol_schema = load_json(HERE / "policy.v1.schema.json")
    meta_schema = load_json(HERE / "meta.v1.schema.json")

    ok = True
    for name, sch in (("events", ev_schema), ("policy", pol_schema), ("meta", meta_schema)):
        Draft202012Validator.check_schema(sch)
        print(f"[ok] schema valid (draft 2020-12): {name}")

    # events.example.jsonl
    ev_v = Draft202012Validator(ev_schema)
    events = [
        json.loads(line)
        for line in (HERE / "examples/events.example.jsonl").read_text().splitlines()
        if line.strip()
    ]
    for e in events:
        for err in ev_v.iter_errors(e):
            ok = False
            print(f"[FAIL] event seq={e.get('seq')} kind={e.get('kind')}: {err.message} at {list(err.path)}")
    print(f"[ok] {len(events)} events validate against events.v1")

    # meta.example.json
    for err in Draft202012Validator(meta_schema).iter_errors(load_json(HERE / "examples/meta.example.json")):
        ok = False
        print(f"[FAIL] meta example: {err.message} at {list(err.path)}")
    print("[ok] meta example validates against meta.v1")

    # policy.example.yaml (needs pyyaml)
    try:
        import yaml
        pol_ex = yaml.safe_load((HERE / "examples/policy.example.yaml").read_text())
        assert pol_ex["trace"]["l2"]["mode"] == "off", "quote 'off' in YAML - it parsed as a bool"
        for err in Draft202012Validator(pol_schema).iter_errors(pol_ex):
            ok = False
            print(f"[FAIL] policy example: {err.message} at {list(err.path)}")
        print("[ok] policy example validates against policy.v1")
    except ImportError:
        print("[skip] policy example (pip install pyyaml to validate it)")

    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
