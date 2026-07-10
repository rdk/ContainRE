"""Locate and apply the versioned JSON-Schema contracts at runtime.

Single source of truth is the repo ``contracts/`` directory. We discover it by
walking up from this file (works when running from a source checkout) or via the
``CONTAINRE_CONTRACTS_DIR`` override. Validation is *soft* when no schema dir is
found, so the harness still runs if installed without the contracts alongside.
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path


@functools.lru_cache(maxsize=1)
def find_contracts_dir() -> Path | None:
    override = os.environ.get("CONTAINRE_CONTRACTS_DIR")
    if override:
        p = Path(override)
        if (p / "events.v1.schema.json").exists():
            return p
    here = Path(__file__).resolve()
    # Packaged location first (shipped inside the wheel), then the source tree.
    candidates = [here.parent / "_contracts"]
    candidates += [parent / "contracts" for parent in [here.parent, *here.parents]]
    for candidate in candidates:
        if (candidate / "events.v1.schema.json").exists():
            return candidate
    return None


_warned_no_schema = False


def _warn_no_schema() -> None:
    global _warned_no_schema
    if not _warned_no_schema:
        _warned_no_schema = True
        import warnings
        warnings.warn(
            "ContainRE JSON-Schema contracts not found; policy/event validation is "
            "DISABLED (malformed policies are accepted silently). Set "
            "CONTAINRE_CONTRACTS_DIR or install a build that bundles contracts/.",
            RuntimeWarning, stacklevel=3)


@functools.lru_cache(maxsize=None)
def load_schema(name: str) -> dict | None:
    d = find_contracts_dir()
    if d is None:
        return None
    path = d / name
    if not path.exists():
        return None
    return json.loads(path.read_text())


def validate(instance, schema_name: str) -> list[str]:
    """Return a list of human-readable validation errors (empty = valid or no schema)."""
    schema = load_schema(schema_name)
    if schema is None:
        _warn_no_schema()
        return []
    from jsonschema import Draft202012Validator

    errors = sorted(Draft202012Validator(schema).iter_errors(instance), key=lambda e: list(e.path))
    return [f"{list(e.path)}: {e.message}" for e in errors]
