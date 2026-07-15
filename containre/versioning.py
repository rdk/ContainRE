"""Version, dependency, and environment reporting.

Public API (re-exported from the ``containre`` package):

- :func:`version_info` -> ``dict`` - structured version / dependency / system
  data. Backs the ``GET /api/version`` endpoint and the web-UI About page.
- :func:`version_report` -> ``str`` - the documented plain-text report emitted by
  ``containre --version``.

The text report format ("containre version report v1") is specified in
``documentation/version-report.md`` and is intended to be machine-parsable.
"""
from __future__ import annotations

import platform
import shutil
import ssl
import subprocess
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

# Direct runtime dependencies, by distribution name as declared in pyproject.
# ``zstandard`` is the optional ``snapshots`` extra and is reported as absent
# (None / "not installed") when it is not present.
_DEP_DISTRIBUTIONS: tuple[str, ...] = (
    "python-ptrace",
    "pyyaml",
    "jsonschema",
    "typer",
    "fastapi",
    "uvicorn",
    "capstone",
    "unicorn",
    "yara-python",
    "cryptography",
    "zstandard",
)

# Rendered in place of a None value in the text report.
_ABSENT = "not installed"


def _dep_version(dist: str) -> str | None:
    try:
        return _dist_version(dist)
    except PackageNotFoundError:
        return None


def _tool_first_line(cmd: str, args: list[str]) -> str | None:
    """First non-empty line of ``cmd args`` output, or None if the tool is
    absent, errors, or hangs. Never raises."""
    path = shutil.which(cmd)
    if not path:
        return None
    try:
        out = subprocess.check_output(
            [path, *args], text=True, stderr=subprocess.STDOUT, timeout=5
        )
    except Exception:
        return None
    for line in out.splitlines():
        if line.strip():
            return line.strip()
    return None


def _docker_version() -> str | None:
    # Prefer the daemon's server version; fall back to "present" if the binary
    # exists but the daemon is unreachable (mirrors control.orchestrator).
    ver = _tool_first_line("docker", ["version", "-f", "{{.Server.Version}}"])
    if ver:
        return ver
    return "present" if shutil.which("docker") else None


def _criu_version() -> str | None:
    # `criu --version` prints e.g. "Version: 3.19"; keep the first line as-is.
    return _tool_first_line("criu", ["--version"])


def _system_info() -> dict:
    uname = platform.uname()
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "system": uname.system,
        "release": uname.release,
        "machine": uname.machine,
        "openssl": ssl.OPENSSL_VERSION,
        "docker": _docker_version(),
        "criu": _criu_version(),
    }


def version_info() -> dict:
    """Structured version, dependency, and system information.

    Shape::

        {
          "containre": "<version>",
          "dependencies": {"<distribution>": "<version>" | None, ...},
          "system": {"python": ..., "platform": ..., "docker": ... | None, ...},
        }

    A None value means the item is not installed / not available. This dict is
    the payload returned by ``GET /api/version`` and consumed by the web UI.
    """
    from . import __version__  # late import: avoids an __init__ import cycle

    return {
        "containre": __version__,
        "dependencies": {d: _dep_version(d) for d in _DEP_DISTRIBUTIONS},
        "system": _system_info(),
    }


def _section(header: str, items: dict) -> list[str]:
    lines = [f"[{header}]"]
    for key, value in items.items():
        lines.append(f"{key}={value if value is not None else _ABSENT}")
    return lines


def version_report(info: dict | None = None) -> str:
    """Render the documented plain-text ``--version`` report.

    Three blank-line-separated sections: the containre version on the first
    line, then ``[dependencies]``, then ``[system]``; within a section each item
    is a ``key=value`` line (absent items use ``not installed``). See
    ``documentation/version-report.md`` for the parsing contract.
    """
    if info is None:
        info = version_info()
    lines = [f"containre {info['containre']}", ""]
    lines += _section("dependencies", info["dependencies"])
    lines.append("")
    lines += _section("system", info["system"])
    return "\n".join(lines)
