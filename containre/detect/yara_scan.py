"""YARA scanning of memory snapshots and captured files (SPEC §13).

Unlike the event-stream Detectors, YARA operates on *bytes* (snapshot blobs and
dropped-file contents), so it is driven directly by the runner rather than the
Detector.feed() pipeline. Built-in rules ship in rules/builtin.yar; users add more
via policy.detect.yara_rules.
"""
from __future__ import annotations

from pathlib import Path

try:
    import yara
    _HAVE_YARA = True
except ImportError:  # pragma: no cover
    _HAVE_YARA = False

_BUILTIN = Path(__file__).parent / "rules" / "builtin.yar"
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def have_yara() -> bool:
    return _HAVE_YARA


class YaraScanner:
    def __init__(self, extra_rule_paths: list[str] | None = None, use_builtin: bool = True):
        self.rules = None
        if not _HAVE_YARA:
            return
        filepaths: dict[str, str] = {}
        if use_builtin and _BUILTIN.exists():
            filepaths["builtin"] = str(_BUILTIN)
        for i, p in enumerate(extra_rule_paths or []):
            if Path(p).exists():
                filepaths[f"custom{i}"] = str(p)
        if not filepaths:
            return
        try:
            self.rules = yara.compile(filepaths=filepaths)
        except Exception:
            self.rules = None

    def enabled(self) -> bool:
        return self.rules is not None

    def scan(self, data: bytes, refs: dict) -> list[dict]:
        """Scan ``data`` and return detection payload dicts (refs identify the source)."""
        if self.rules is None or not data:
            return []
        try:
            matches = self.rules.match(data=data, timeout=10)
        except Exception:
            return []
        out = []
        clean_refs = {k: v for k, v in refs.items() if v is not None}
        for m in matches:
            meta = getattr(m, "meta", {}) or {}
            sev = meta.get("severity", "medium")
            attack = meta.get("attack", "")
            attack = ([t.strip() for t in attack.split(",") if t.strip()]
                      if isinstance(attack, str) else [])
            try:
                ids = sorted({s.identifier for s in m.strings})
            except Exception:
                ids = []
            out.append({
                "detector": "yara",
                "id": f"yara:{m.rule}",
                "severity": sev if sev in _SEVERITIES else "medium",
                "title": f"YARA rule matched: {m.rule}"
                         + (f" ({', '.join(ids)})" if ids else ""),
                "description": meta.get("description", f"Content matched YARA rule {m.rule}."),
                "refs": clean_refs,
                "attack": attack,
            })
        return out
