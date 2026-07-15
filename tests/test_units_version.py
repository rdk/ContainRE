"""Unit tests for the --version / version_info reporting surface (CLI, Python
API, HTTP endpoint) and the documented plain-text report format."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import containre
from containre import version_info, version_report
from containre.api import create_app
from containre.cli.main import app
from containre.versioning import _ABSENT, _DEP_DISTRIBUTIONS

pytestmark = pytest.mark.unit

_REQUIRED_SYSTEM_KEYS = {
    "python", "python_implementation", "platform",
    "system", "release", "machine", "openssl", "docker", "criu",
}


def _parse_report(text: str):
    """Reference parser for the documented "containre version report v1" format
    (see documentation/version-report.md)."""
    lines = text.split("\n")
    assert lines[0].startswith("containre ")
    version = lines[0].split(" ", 1)[1].strip()
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in lines[1:]:
        if not line.strip():
            continue
        if line.startswith("[") and line.endswith("]"):
            current = {}
            sections[line[1:-1]] = current
        else:
            assert current is not None, "key=value line before any [section]"
            key, sep, value = line.partition("=")
            assert sep == "=", f"non key=value line: {line!r}"
            current[key] = value
    return version, sections


def test_version_info_structure():
    info = version_info()
    assert info["containre"] == containre.__version__
    # every declared direct dependency is reported, value is a version or None
    assert set(info["dependencies"]) == set(_DEP_DISTRIBUTIONS)
    for name, ver in info["dependencies"].items():
        assert ver is None or isinstance(ver, str)
    # core deps are actually installed in the test env
    assert info["dependencies"]["fastapi"]
    assert info["dependencies"]["typer"]
    # system block has all keys; always-present probes are non-empty strings
    assert set(info["system"]) == _REQUIRED_SYSTEM_KEYS
    for key in ("python", "python_implementation", "platform", "system", "release",
                "machine", "openssl"):
        assert isinstance(info["system"][key], str) and info["system"][key]
    # docker/criu are str-or-None (absent tool -> None)
    for key in ("docker", "criu"):
        assert info["system"][key] is None or isinstance(info["system"][key], str)


def test_version_report_is_parsable_and_matches_info():
    info = version_info()
    version, sections = _parse_report(version_report(info))

    assert version == info["containre"]
    assert list(sections) == ["dependencies", "system"]

    # dependencies round-trip; None renders as the documented sentinel
    assert set(sections["dependencies"]) == set(info["dependencies"])
    for name, ver in info["dependencies"].items():
        expected = ver if ver is not None else _ABSENT
        assert sections["dependencies"][name] == expected

    # system round-trips too, incl. values that contain spaces (openssl)
    assert set(sections["system"]) == set(info["system"])
    assert sections["system"]["openssl"] == info["system"]["openssl"]


def test_version_report_first_line_and_sections():
    report = version_report()
    lines = report.split("\n")
    assert lines[0] == f"containre {containre.__version__}"
    assert lines[1] == ""                      # blank line after the version
    assert "[dependencies]" in lines
    assert "[system]" in lines
    # the version stands alone on line 1 (a bare "--version" reader can trust it)
    assert "=" not in lines[0]


def test_api_version_endpoint(tmp_path):
    client = TestClient(create_app(runs_root=tmp_path / "runs", runtime_name="local"))
    resp = client.get("/api/version")
    assert resp.status_code == 200
    body = resp.json()
    assert body["containre"] == containre.__version__
    assert set(body["dependencies"]) == set(_DEP_DISTRIBUTIONS)
    assert _REQUIRED_SYSTEM_KEYS <= set(body["system"])


def test_cli_version_flag_exits_zero_with_report():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith(f"containre {containre.__version__}")
    assert "[dependencies]" in result.output
    assert "[system]" in result.output
