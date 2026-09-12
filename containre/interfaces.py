"""Typed seams between the harness subsystems (SPEC §4).

These Protocols let the runtime (Docker vs Local), the tracer, and the detectors
evolve independently. The same runtime seam can host stronger isolation backends
such as gVisor or Firecracker without changing the control plane.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass
class Job:
    """A fully-resolved unit of work handed to a Runtime."""
    run_dir: Path
    specimen_path: str          # path as seen by the tracer (host path, or in-container path)
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str = "/work"
    stdin_path: str | None = None
    policy: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "run_dir": str(self.run_dir),
            "specimen_path": self.specimen_path,
            "args": self.args,
            "env": self.env,
            "cwd": self.cwd,
            "stdin_path": self.stdin_path,
            "policy": self.policy,
        }

    @classmethod
    def from_json(cls, d: dict) -> "Job":
        return cls(
            run_dir=Path(d["run_dir"]),
            specimen_path=d["specimen_path"],
            args=list(d.get("args", [])),
            env=dict(d.get("env", {})),
            cwd=d.get("cwd", "/work"),
            stdin_path=d.get("stdin_path"),
            policy=d.get("policy", {}),
        )


@dataclass
class RunHandle:
    run_dir: Path
    runtime: str
    pid: int | None = None
    container: str | None = None
    # Container ownership is a property of the run, independent of its live
    # marker. It must survive wait()/stop() and cleanup by an external reaper.
    reuse_exec: bool = False


@runtime_checkable
class Runtime(Protocol):
    name: str

    def start(self, job: Job) -> RunHandle:
        """Launch the tracer+specimen for ``job`` and return a handle immediately."""
        ...

    def wait(self, handle: RunHandle, timeout: float | None = None) -> int | None:
        """Block until the run finishes; return the specimen exit code (or None on timeout)."""
        ...

    def stop(self, handle: RunHandle) -> None:
        """Terminate a running specimen."""
        ...


class Detector(Protocol):
    """Consumes the event stream and emits ``detection`` payload dicts
    (see contracts/events.v1.schema.json §detection)."""
    name: str

    def feed(self, event: dict) -> list[dict]:
        ...

    def close(self) -> list[dict]:
        ...
