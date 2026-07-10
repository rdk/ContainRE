"""Tracer runner - the entrypoint a Runtime launches to actually record a run.

Under LocalRuntime this runs as a host subprocess; under DockerRuntime it runs as
the in-container probe-agent. It wires a RunSession (recording) to the PtraceTracer
(observation) and finalizes the run.

    python -m containre.tracer.runner <job.json>
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import traceback
from pathlib import Path

from ..interfaces import Job
from ..model import Event, Kind, wall_ns
from ..net import BuiltinSink, MitmCA
from .ptrace_tracer import PtraceTracer
from .session import RunSession


def _start_sink(job: Job, session: RunSession) -> tuple[BuiltinSink | None, tuple[str, int] | None]:
    net_sink = None
    sink_addr = None
    net_cfg = job.policy.get("network", {})
    if net_cfg.get("posture") == "simulate":
        ca = None
        if net_cfg.get("mitm"):
            # trust our CA inside the sandbox so TLS to the sink can be decrypted
            ca = MitmCA()
            ca.write_ca(job.run_dir / "ca.pem")
            job.env["SSL_CERT_FILE"] = str(job.run_dir / "ca.pem")
            job.env["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"] = str(job.run_dir / "ca.pem")
        net_sink = BuiltinSink(on_interaction=lambda info: session.emit(Event(Kind.NET, info)),
                               mitm=bool(net_cfg.get("mitm")), ca=ca,
                               sink_config=net_cfg.get("sink"))
        try:
            net_sink.start()
            sink_addr = ("127.0.0.1", net_sink.port)
        except OSError:
            net_sink = None
    return net_sink, sink_addr


def _run_shell_command(
    *,
    command: str,
    shell: str,
    cwd: str,
    env: dict[str, str],
    timeout: float,
    log_path: Path,
) -> tuple[int, str | None]:
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"\n$ {command}\n")
        log.flush()
        try:
            proc = subprocess.Popen(
                [shell, "-c", command],
                cwd=cwd,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            log.write(f"failed to start command: {exc}\n")
            return 127, str(exc)
        try:
            return proc.wait(timeout=timeout), None
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.wait()
            log.write(f"command timed out after {timeout:g}s\n")
            return proc.returncode if proc.returncode is not None else -signal.SIGKILL, "timeout"


def _run_runtime_commands(job: Job, session: RunSession, phase: str) -> tuple[int | None, str | None]:
    runtime_cfg = job.policy.get("runtime", {})
    commands = [str(c) for c in runtime_cfg.get(f"{phase}_commands", []) if str(c).strip()]
    if not commands:
        return None, None
    shell = str(runtime_cfg.get("command_shell") or "/bin/sh")
    timeout = float(runtime_cfg.get("command_timeout_s") or 30)
    log_path = job.run_dir / f"{phase}.log"
    for idx, command in enumerate(commands, start=1):
        rc, reason = _run_shell_command(
            command=command,
            shell=shell,
            cwd=job.cwd,
            env=job.env,
            timeout=timeout,
            log_path=log_path,
        )
        event = {
            "op": "exec",
            "path": shell,
            "argv": [shell, "-c", command],
            "phase": phase,
            "index": idx,
            "exit_code": int(rc),
        }
        if reason:
            event["reason"] = reason
        session.emit(Event(Kind.PROC, event))
        if phase == "setup" and rc != 0:
            # Stable kill_reason token (meta.v1 enum); the failing command index
            # is carried in the exec event emitted just above.
            return rc, "setup_failed"
    return None, None


def _run_without_tracer(job: Job, console_path: str) -> tuple[int | None, str | None]:
    stdin_fh = open(job.stdin_path, "rb") if job.stdin_path else None
    timeout = float(job.policy.get("limits", {}).get("wallclock_s", 120))
    try:
        with open(console_path, "wb") as console:
            proc = subprocess.Popen(
                [job.specimen_path, *job.args],
                cwd=job.cwd,
                env=job.env,
                stdin=stdin_fh,
                stdout=console,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                return proc.wait(timeout=timeout), None
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait()
                return proc.returncode, "timeout"
    finally:
        if stdin_fh is not None:
            stdin_fh.close()


def execute(job: Job) -> int:
    cwd = job.cwd
    if cwd and os.path.isdir(cwd):
        os.chdir(cwd)
    workdir = os.getcwd()

    session = RunSession(job.run_dir, job.policy, workdir)
    decoy_names = job.policy.get("files", {}).get("decoys", [])
    decoy_paths = [os.path.join(workdir, d) for d in decoy_names]

    # Bring up the simulated-internet sink for simulate posture. In normal ptrace
    # mode the tracer redirects connects to it; in trace.tracer=none benchmark
    # mode policies should map the target hostname to loopback and configure the
    # sink's original service listen_port.
    net_sink, sink_addr = _start_sink(job, session)

    session.store.update_meta(status="running", started_wall=wall_ns())

    tracer_mode = job.policy.get("trace", {}).get("tracer", "ptrace")
    kill_reason = None
    flows = {}
    exit_code = None
    try:
        setup_exit, setup_reason = _run_runtime_commands(job, session, "setup")
        if setup_reason:
            exit_code, kill_reason = setup_exit, setup_reason
        elif tracer_mode == "none":
            exit_code, kill_reason = _run_without_tracer(job, str(job.run_dir / "console.log"))
        else:
            tracer = PtraceTracer(
                specimen=job.specimen_path, args=job.args, env=job.env, policy=job.policy,
                decoy_paths=decoy_paths, sink=session.emit,
                stdin_path=job.stdin_path, console_path=str(job.run_dir / "console.log"),
                snapshot_cb=session.snapshot, sink_addr=sink_addr,
            )
            exit_code = tracer.run()
            kill_reason = tracer.kill_reason
            flows = tracer.flows
    finally:
        teardown_exit, teardown_reason = _run_runtime_commands(job, session, "teardown")
        if teardown_reason and kill_reason is None:
            kill_reason = teardown_reason
        if teardown_exit is not None and exit_code is None:
            exit_code = teardown_exit
        if net_sink is not None:
            net_sink.stop()

    if tracer_mode != "none":
        # A failure in any post-processing step must not prevent finalize() from
        # writing the terminal meta.json (else the run is stuck 'running' with an
        # unflushed store). Surface failures to runner.log for diagnosis.
        for step in (session.close_detectors, lambda: session.write_pcap(flows),
                     session.capture_artifacts):
            try:
                step()
            except Exception:
                traceback.print_exc(file=sys.stderr)
    session.finalize("killed" if kill_reason else "finished", exit_code, kill_reason)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m containre.tracer.runner <job.json>", file=sys.stderr)
        return 2
    job = Job.from_json(json.loads(Path(argv[0]).read_text()))
    return execute(job)


if __name__ == "__main__":
    raise SystemExit(main())
