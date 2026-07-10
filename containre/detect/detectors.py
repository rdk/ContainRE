"""Behavioral detectors (SPEC §13). Each consumes the event stream and emits
`detection` payload dicts (contracts/events.v1.schema.json §detection).

These are event-stream heuristics. Byte-oriented scanners such as YARA run from
RunSession over memory snapshots and captured dropped-file artifacts.
"""
from __future__ import annotations


def _refs(**kw) -> dict:
    """Build a detection.refs dict, omitting keys whose value is absent (the schema
    requires strings, not nulls, for optional refs)."""
    return {k: v for k, v in kw.items() if v is not None}


class _Base:
    name = "base"

    def feed(self, event: dict) -> list[dict]:
        return []

    def close(self) -> list[dict]:
        return []


class DecoyDetector(_Base):
    """A specimen touching a planted canary file is high-signal (ransomware/stealer)."""
    name = "decoy"

    _TAMPER_OPS = ("write", "unlink", "rename", "chmod")
    _ACCESS_OPS = ("open", "read")

    def __init__(self) -> None:
        self._seen: set[tuple[str, bool]] = set()

    def feed(self, event: dict) -> list[dict]:
        if event.get("kind") != "file":
            return []
        d = event["data"]
        op = d.get("op")
        # Any decoy access is high-signal (SPEC §8/§13): reading a canary is a
        # stealer tell (high), tampering with it is a ransomware tell (critical).
        if not d.get("decoy") or op not in self._TAMPER_OPS + self._ACCESS_OPS:
            return []
        tampering = op in self._TAMPER_OPS
        path = d.get("path", "")
        key = (path, tampering)
        if key in self._seen:
            return []
        self._seen.add(key)
        return [{
            "detector": "heuristic",
            "id": "decoy-access",
            "severity": "critical" if tampering else "high",
            "title": f"Decoy file {op}: {path}",
            "description": "Specimen accessed a planted canary file - strong ransomware/stealer signal.",
            "refs": _refs(seq=event["seq"], artifact_id=d.get("artifact_id")),
            "iocs": [{"type": "path", "value": path}],
            "attack": ["T1657"],
        }]


class EgressDetector(_Base):
    """Any outbound network attempt (allowed, blocked, or simulated) is worth flagging."""
    name = "egress"

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def feed(self, event: dict) -> list[dict]:
        if event.get("kind") != "net":
            return []
        d = event["data"]
        op = d.get("op")
        if op in ("connect", "send") and d.get("raddr"):
            raddr = d["raddr"]
            if raddr in self._seen:
                return []
            self._seen.add(raddr)
            handled = d.get("decision") in ("block", "simulated")
            ip = raddr.rsplit(":", 1)[0].strip("[]")
            return [{
                "detector": "ioc",
                "id": "network-egress",
                "severity": "medium",
                "title": f"Network egress attempt to {raddr} ({d.get('decision')})",
                "description": "Specimen attempted an outbound connection."
                               + (" Contained by policy." if handled else " Allowed by policy."),
                "refs": _refs(seq=event["seq"], flow_id=d.get("flow_id")),
                "iocs": [{"type": "ip", "value": ip}],
                "attack": ["T1071"],
            }]
        if op == "http" and d.get("http"):
            h = d["http"]
            host, path = h.get("host", ""), h.get("path", "")
            key = f"http:{host}{path}"
            if key in self._seen:
                return []
            self._seen.add(key)
            iocs = []
            if host:
                iocs.append({"type": "domain", "value": host})
                iocs.append({"type": "url", "value": f"http://{host}{path}"})
            return [{
                "detector": "ioc",
                "id": "http-request",
                "severity": "medium",
                "title": f"HTTP {h.get('method')} {host}{path}",
                "description": "Specimen issued an HTTP request (captured by the simulated-internet sink).",
                "refs": _refs(seq=event["seq"]),
                "iocs": iocs,
                "attack": ["T1071.001"],
            }]
        return []


class AntiDebugDetector(_Base):
    """Specimen calling ptrace()/process_vm_* itself is a classic anti-analysis tell."""
    name = "anti-debug"

    def __init__(self) -> None:
        self._fired = False

    def feed(self, event: dict) -> list[dict]:
        if self._fired or event.get("kind") != "syscall":
            return []
        if event["data"].get("name") not in ("ptrace", "process_vm_writev", "process_vm_readv"):
            return []
        self._fired = True
        return [{
            "detector": "heuristic",
            "id": "anti-debug",
            "severity": "medium",
            "title": "Anti-analysis syscall used",
            "description": f"Specimen invoked {event['data'].get('name')} - anti-debug or injection.",
            "refs": _refs(seq=event["seq"]),
            "attack": ["T1622", "T1055"],
        }]


class InjectionDetector(_Base):
    """Mapping/mprotecting memory as executable can indicate unpacking or injection."""
    name = "injection"

    def __init__(self) -> None:
        self._count = 0

    def feed(self, event: dict) -> list[dict]:
        if event.get("kind") != "mem":
            return []
        d = event["data"]
        perms = d.get("region", {}).get("perms", "")
        # mmap(PROT_EXEC) emits op='map' and mprotect emits op='protect'; the
        # allocate-RWX-directly-via-mmap pattern (common shellcode/JIT loader) must
        # count too, not just mprotect.
        if "x" not in perms or d.get("op") not in ("map", "protect"):
            return []
        self._count += 1
        if self._count != 1:
            return []
        return [{
            "detector": "heuristic",
            "id": "rwx-memory",
            "severity": "low",
            "title": "Executable memory created at runtime",
            "description": "Specimen made memory executable via mmap/mprotect - unpacking/JIT/injection.",
            "refs": _refs(seq=event["seq"], addr=d.get("addr")),
            "attack": ["T1055", "T1027"],
        }]


class SensitiveFileDetector(_Base):
    """Reading credential/secret files is a stealer/priv-esc signal. We deliberately
    do NOT flag world-readable /etc/passwd (too common); only high-value secrets."""
    name = "sensitive-file"

    EXACT = {"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}
    SUBSTR = ("id_rsa", "id_ed25519", "/.ssh/", ".aws/credentials", "/.gnupg/",
              ".docker/config.json", "/proc/self/mem")

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def feed(self, event: dict) -> list[dict]:
        if event.get("kind") != "file":
            return []
        d = event["data"]
        if d.get("op") not in ("open", "read"):
            return []
        path = d.get("path", "")
        if path in self._seen:
            return []
        if not (path in self.EXACT or any(s in path for s in self.SUBSTR)):
            return []
        self._seen.add(path)
        return [{
            "detector": "heuristic",
            "id": "sensitive-file-access",
            "severity": "high",
            "title": f"Access to sensitive file: {path}",
            "description": "Specimen opened a credential/secret file.",
            "refs": _refs(seq=event["seq"]),
            "iocs": [{"type": "path", "value": path}],
            "attack": ["T1552", "T1005"],
        }]


def default_detectors(detect: dict | None = None) -> list[_Base]:
    """Build the enabled detector set from the policy detect config.

    detect.heuristics gates the behavioral heuristics (decoy/anti-debug/rwx/
    sensitive-file); detect.iocs gates the network-egress IOC detector. Both
    default on. (detect.attack_tags is applied downstream in RunSession, which
    strips ATT&CK tags from recorded detections when disabled.)
    """
    detect = detect or {}
    heuristics = detect.get("heuristics", True)
    iocs = detect.get("iocs", True)
    dets: list[_Base] = []
    if heuristics:
        dets.append(DecoyDetector())
    if iocs:
        dets.append(EgressDetector())
    if heuristics:
        dets += [AntiDebugDetector(), InjectionDetector(), SensitiveFileDetector()]
    return dets
