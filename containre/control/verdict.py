"""Verdict accumulator - folds detections into meta.json's `verdict`.

Keeps the highest severity seen, the union of ATT&CK tags, and a set of concise
human-facing flags mapped from detection ids.
"""
from __future__ import annotations

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# detection id -> concise verdict flag
_FLAG_MAP = {
    "decoy-access": "decoy-hit",
    "network-egress": "egress-attempt",
    "http-request": "http-c2",
    "sensitive-file-access": "credential-access",
    "anti-debug": "anti-debug",
    "rwx-memory": "executable-memory",
}


class Verdict:
    def __init__(self) -> None:
        self.max_severity = "info"
        self.attack: set[str] = set()
        self.flags: set[str] = set()

    def absorb(self, detection: dict) -> None:
        severity = detection.get("severity", "info")
        if _SEVERITY.get(severity, 0) > _SEVERITY[self.max_severity]:
            self.max_severity = severity
        self.attack.update(detection.get("attack", []))
        did = detection.get("id", "")
        self.flags.add(_FLAG_MAP.get(did, did))

    def to_dict(self) -> dict:
        return {"max_severity": self.max_severity,
                "attack": sorted(self.attack),
                "flags": sorted(self.flags)}
