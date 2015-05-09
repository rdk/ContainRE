"""Run-policy loading, defaulting, and validation (contracts/policy.v1.schema.json)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import yaml

from . import contracts

DEFAULTS: dict = {
    "schema_version": 1,
    "specimen": {"args": [], "stdin": None, "env": {}, "cwd": "/work", "container_path": None},
    "limits": {"cpu": 1, "mem_mb": 512, "pids": 128, "wallclock_s": 120, "disk_mb": 256},
    "network": {
        "posture": "simulate",
        "simulate": True,
        "mitm": False,
        "allow": [],
        "extra_hosts": [],
        "docker_network": "auto",
        "sink": {"type": "builtin"},
    },
    "files": {"work_mount": None, "decoys": [], "read_only_mounts": []},
    "trace": {
        "tracer": "ptrace",
        "l1": ["net", "file", "proc", "mmap", "signal"],
        "snapshot_on": ["connect", "mmap+x", "exec"],
        "snapshot_every_ms": 0,
        "l2": {"mode": "off", "window": {}},
    },
    "detect": {"yara": True, "iocs": True, "heuristics": True, "attack_tags": False, "yara_rules": []},
    "instrumentation": {
        "tls_plaintext": {
            "enabled": False,
            "provider": "openssl-preload",
            "mode": "observe",
            "output": None,
            "max_bytes_per_record": 4096,
            "replay_file": None,
            "fake_handshake": False,
            "libssl": None,
        },
    },
    "runtime": {
        "setup_commands": [],
        "teardown_commands": [],
        "command_shell": "/bin/sh",
        "command_timeout_s": 30,
        "docker_reuse_container": False,
        "docker_reuse_key": "default",
        "docker_user": None,
    },
    "report": {"assertions": []},
    "kill_on": ["egress_violation", "oom", "timeout"],
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def apply_defaults(policy: dict) -> dict:
    return _deep_merge(DEFAULTS, policy or {})


def validate(policy: dict) -> list[str]:
    return contracts.validate(policy, "policy.v1.schema.json")


def load_policy(path: str | Path) -> dict:
    """Load a policy from YAML/JSON, validate the *raw* document, then apply defaults."""
    path = Path(path)
    raw = path.read_text()
    doc = json.loads(raw) if path.suffix == ".json" else yaml.safe_load(raw)
    if not isinstance(doc, dict):
        raise ValueError(f"policy must be a mapping, got {type(doc).__name__}")
    errors = validate(doc)
    if errors:
        raise ValueError("invalid policy:\n  " + "\n  ".join(errors))
    return apply_defaults(doc)


def policy_for_binary(binary: str | Path, **overrides) -> dict:
    """Build a minimal valid policy that just runs ``binary`` (used by the CLI's
    'run a bare binary' path and by tests)."""
    policy = apply_defaults({"specimen": {"path": str(binary)}})
    return _deep_merge(policy, overrides)
