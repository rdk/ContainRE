"""Shared fixtures: compile the example specimens and run them under the harness."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from containre import policy as P
from containre.control import execute

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "specimens" / "src"


@pytest.fixture(scope="session")
def cc() -> str:
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        pytest.skip("no C compiler available to build specimens")
    return compiler


# Some specimens need non-default compile flags (kept in sync with specimens/Makefile).
_EXTRA_FLAGS = {
    # freestanding/static/no-PIE so the ELF entry point is the specimen's own code
    "l2demo": ["-no-pie", "-static", "-nostdlib", "-ffreestanding", "-fno-stack-protector"],
}
# Link libraries (appended after the source, where the linker wants them).
_EXTRA_LIBS = {
    "httpsbeacon": ["-lssl", "-lcrypto"],
    "forkwall": ["-lpthread"],
}


@pytest.fixture(scope="session")
def build_specimen(cc, tmp_path_factory):
    outdir = tmp_path_factory.mktemp("specimen-bin")
    cache: dict[str, Path] = {}

    def build(name: str) -> Path:
        if name in cache:
            return cache[name]
        src = SRC / f"{name}.c"
        if not src.exists():
            pytest.skip(f"specimen source missing: {src}")
        out = outdir / name
        flags = _EXTRA_FLAGS.get(name, ["-g"])
        libs = _EXTRA_LIBS.get(name, [])
        proc = subprocess.run([cc, "-O0", *flags, "-o", str(out), str(src), *libs],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            pytest.skip(f"could not build {name}: {proc.stderr.strip()[:200]}")
        cache[name] = out
        return out

    return build


@pytest.fixture
def runs_root(tmp_path) -> Path:
    return tmp_path / "runs"


@pytest.fixture
def harness(build_specimen, runs_root):
    """Run a named specimen under the harness (deny network by default) and return
    the RunResult."""
    def run(name: str, *, args=None, network=None, **overrides):
        net = {"posture": "deny"}
        if network:
            net.update(network)
        pol = P.policy_for_binary(build_specimen(name), network=net, **overrides)
        if args:
            pol["specimen"]["args"] = list(args)
        return execute(pol, runs_root=runs_root, timeout=60)

    return run
