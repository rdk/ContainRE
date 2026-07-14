"""Fast unit tests for the store, policy, and network-decision logic (no ptrace)."""
from __future__ import annotations

import json
import os

import pytest

from containre import policy as P
from containre.model import Event, Kind
from containre.runtime.docker import DockerError, DockerRuntime, HostNetworkingWarning
from containre.store import RunStore
from containre.tracer import ptrace_tracer as ptrace_mod
from containre.tracer import syscalls as sc
from containre.tracer.ptrace_tracer import PtraceTracer

pytestmark = pytest.mark.unit


# -- store -----------------------------------------------------------------
def test_store_seq_and_index_match_jsonl(tmp_path):
    with RunStore(tmp_path) as st:
        st.write_meta({"schema_version": 1, "run_id": "t", "status": "running",
                       "specimen": {"sha256": "0" * 64}, "created_wall": 1})
        seqs = [st.write_event(Event(Kind.FILE, {"op": "write", "path": f"/f{i}"}))
                for i in range(5)]
    assert seqs == [0, 1, 2, 3, 4]
    lines = (tmp_path / "events.jsonl").read_text().splitlines()
    assert len(lines) == 5
    # reopening continues the seq counter from the index
    with RunStore(tmp_path) as st:
        assert st.write_event(Event(Kind.NET, {"op": "socket"})) == 5
        rows = st.query(kind="file")
    assert len(rows) == 5
    assert [json.loads(ln)["seq"] for ln in lines] == [0, 1, 2, 3, 4]


def test_store_artifact_roundtrip(tmp_path):
    with RunStore(tmp_path) as st:
        aid = st.add_artifact("wallet.dat", b"stolen")
    assert aid.startswith("a-")
    hits = list((tmp_path / "files").glob(f"{aid}_*"))
    assert hits and hits[0].read_bytes() == b"stolen"


# -- policy ----------------------------------------------------------------
def test_policy_defaults_are_valid():
    pol = P.policy_for_binary("/bin/true")
    assert P.validate(pol) == []
    assert pol["network"]["posture"] == "simulate"
    assert pol["network"]["sink"]["type"] == "builtin"
    assert pol["limits"]["wallclock_s"] == 120
    assert pol["trace"]["tracer"] == "ptrace"
    assert pol["instrumentation"]["tls_plaintext"]["enabled"] is False
    assert pol["runtime"]["setup_commands"] == []
    assert pol["runtime"]["teardown_commands"] == []
    assert pol["runtime"]["docker_reuse_container"] is False
    assert pol["runtime"]["docker_user"] is None


def test_policy_accepts_h2_grpc_replay_sink():
    pol = {
        "specimen": {"path": "/bin/true"},
        "network": {
            "posture": "simulate",
            "mitm": True,
            "sink": {
                "type": "h2-grpc-replay",
                "listen_port": 53000,
                "unary_methods": ["UnaryProbe"],
                "streaming_methods": ["StreamProbe"],
                "unary_response_hex": "",
                "stream_initial_response_hex": "2200",
                "stream_response_hex": "1200",
                "idle_timeout_s": 5,
                "record_payloads": True,
                "payload_preview_bytes": 256,
                "payload_record_limit": 8,
                "negative_feature_substrings": ["FEAT_ALPHA"],
                "negative_grpc_status": "5",
                "negative_grpc_message": "feature {feature} is not expected to exist in the server",
            },
        },
        "trace": {"tracer": "none"},
    }
    assert P.validate(pol) == []


def test_policy_accepts_runtime_helper_commands():
    pol = {
        "specimen": {"path": "/bin/true"},
        "runtime": {
            "setup_commands": ["printf setup"],
            "teardown_commands": ["printf teardown"],
            "command_shell": "/bin/sh",
            "command_timeout_s": 5,
            "docker_reuse_container": True,
            "docker_reuse_key": "batch-smoke",
            "docker_user": "1000:1000",
        },
    }
    assert P.validate(pol) == []


def test_runtime_shell_command_logs_output(tmp_path):
    from containre.tracer.runner import _run_shell_command

    rc, reason = _run_shell_command(
        command="printf hook-output",
        shell="/bin/sh",
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
        log_path=tmp_path / "setup.log",
    )

    assert rc == 0
    assert reason is None
    assert "hook-output" in (tmp_path / "setup.log").read_text()


def test_policy_rejects_bad_posture(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("specimen: {path: /bin/true}\nnetwork: {posture: bogus}\n")
    with pytest.raises(ValueError):
        P.load_policy(bad)


def test_policy_load_yaml_off_is_string(tmp_path):
    # the 'off' YAML footgun: must remain a string, not boolean False
    p = tmp_path / "p.yaml"
    p.write_text('specimen: {path: /bin/true}\ntrace: {l2: {mode: "off"}}\n')
    pol = P.load_policy(p)
    assert pol["trace"]["l2"]["mode"] == "off"


# -- network decision ------------------------------------------------------
def _tracer(posture, allow=()):
    return PtraceTracer(specimen="/bin/true", args=[], env={},
                        policy={"network": {"posture": posture, "allow": list(allow)}},
                        decoy_paths=[], sink=lambda e: None)


def test_net_decision_deny_blocks():
    assert _tracer("deny")._net_decision(sc.AF_INET, "1.2.3.4", "1.2.3.4:80") == "block"


def test_net_decision_simulate_simulated():
    assert _tracer("simulate")._net_decision(sc.AF_INET, "1.2.3.4", "1.2.3.4:80") == "simulated"


def test_net_decision_allow_posture_allows():
    assert _tracer("allow")._net_decision(sc.AF_INET, "1.2.3.4", "1.2.3.4:80") == "allow"


def test_net_decision_allowlist_allows():
    t = _tracer("deny", allow=["1.2.3.4"])
    assert t._net_decision(sc.AF_INET, "1.2.3.4", "1.2.3.4:80") == "allow"


def test_net_decision_allowlist_accepts_ip_port():
    t = _tracer("deny", allow=["1.2.3.4:443"])
    assert t._net_decision(sc.AF_INET, "1.2.3.4", "1.2.3.4:443") == "allow"
    assert t._net_decision(sc.AF_INET, "1.2.3.4", "1.2.3.4:80") == "block"


def test_net_decision_unix_socket_is_local():
    assert _tracer("deny")._net_decision(sc.AF_UNIX, "/run/x", "unix:/run/x") == "allow"


def test_docker_network_args_attach_bridge_for_allowlist():
    rt = DockerRuntime()
    assert rt._network_args({"network": {"posture": "deny", "allow": []}}) == ["--network", "none"]
    assert rt._network_args({"network": {"posture": "deny", "allow": ["192.0.2.10:443"]}}) == []
    assert rt._network_args({
        "network": {
            "posture": "deny",
            "allow": ["192.0.2.10:443"],
            "docker_network": "bridge",
        },
    }) == []


def test_docker_network_args_host_requires_narrow_allowlist():
    rt = DockerRuntime()
    with pytest.warns(HostNetworkingWarning):
        assert rt._network_args({
            "network": {
                "posture": "deny",
                "allow": ["192.0.2.10:443"],
                "docker_network": "host",
            },
        }) == ["--network", "host"]
    with pytest.raises(DockerError):
        rt._network_args({"network": {"posture": "deny", "allow": [], "docker_network": "host"}})
    with pytest.raises(DockerError):
        rt._network_args({
            "network": {
                "posture": "allow",
                "allow": ["192.0.2.10:443"],
                "docker_network": "host",
            },
        })


def test_docker_extra_host_args():
    rt = DockerRuntime()
    policy = {"network": {"extra_hosts": [{"host": "service.example.test", "ip": "192.0.2.10"}]}}
    assert rt._extra_host_args(policy) == ["--add-host", "service.example.test:192.0.2.10"]


def test_docker_user_args():
    rt = DockerRuntime()
    assert rt._docker_user_args({"runtime": {"docker_user": None}}) == []
    assert rt._docker_user_args({"runtime": {"docker_user": "1000:1000"}}) == ["--user", "1000:1000"]
    assert rt._docker_user_args({"runtime": {"docker_user": "containre"}}) == ["--user", "containre"]
    with pytest.raises(DockerError):
        rt._docker_user_args({"runtime": {"docker_user": "bad user"}})


def test_docker_no_trace_mode_drops_ptrace_capability(tmp_path):
    rt = DockerRuntime()
    policy = {
        "trace": {"tracer": "none"},
        "network": {"posture": "simulate", "docker_network": "none"},
    }
    assert rt._network_args(policy) == ["--network", "none"]
    assert rt._trace_security_args(policy) == []
    assert rt._trace_security_args({"trace": {"tracer": "ptrace"}}) == [
        "--cap-add", "SYS_PTRACE",
        "--security-opt", "seccomp=unconfined",
    ]


def test_docker_reuse_container_name_and_key_validation():
    rt = DockerRuntime()
    policy = {"runtime": {"docker_reuse_key": "batch_1"}}
    assert rt._reuse_container_name(policy) == "containre-reuse-batch_1"
    with pytest.raises(DockerError):
        rt._reuse_container_name({"runtime": {"docker_reuse_key": "bad/key"}})


def test_create_child_fast_skips_python_ptrace_fd_close_loop(monkeypatch):
    calls = []

    def fake_create_child(argv, no_stdout, env=None, close_fds=True, pass_fds=()):
        calls.append({
            "argv": argv,
            "no_stdout": no_stdout,
            "env": env,
            "close_fds": close_fds,
            "pass_fds": pass_fds,
        })
        return 123

    monkeypatch.setattr(ptrace_mod, "createChild", fake_create_child)

    assert ptrace_mod._create_child_fast(["/bin/true"], {"LANG": "C"}) == 123
    assert calls == [{
        "argv": ["/bin/true"],
        "no_stdout": False,
        "env": {"LANG": "C"},
        "close_fds": False,
        "pass_fds": (),
    }]
