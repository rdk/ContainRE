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
        # Compile each ruleset independently so one malformed custom rule doesn't
        # silently disable ALL scanning (including the builtin PE/UPX/shell rules);
        # failures are collected in .warnings instead of vanishing.
        self._rulesets: list = []
        self.warnings: list[str] = []
        if not _HAVE_YARA:
            return
        sources: list[tuple[str, str]] = []
        if use_builtin and _BUILTIN.exists():
            sources.append(("builtin", str(_BUILTIN)))
        for i, p in enumerate(extra_rule_paths or []):
            if Path(p).exists():
                sources.append((f"custom{i}", str(p)))
            else:
                self.warnings.append(f"yara rule file not found: {p}")
        for name, path in sources:
            try:
                self._rulesets.append(yara.compile(filepath=path))
            except Exception as exc:
                self.warnings.append(f"yara ruleset '{name}' ({path}) failed to compile: {exc}")

    def enabled(self) -> bool:
        return bool(self._rulesets)

    def scan(self, data: bytes, refs: dict) -> list[dict]:
        """Scan ``data`` and return detection payload dicts (refs identify the source)."""
        if not self._rulesets or not data:
            return []
        matches = []
        for rules in self._rulesets:
            try:
                matches.extend(rules.match(data=data, timeout=10))
            except Exception:
                continue
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
