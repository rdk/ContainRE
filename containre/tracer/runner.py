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
import time
import traceback
from pathlib import Path

from ..interfaces import Job
from ..model import Event, Kind, wall_ns
from ..net import BuiltinSink, MitmCA
from ..runtime import execution
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


def _run_without_tracer(job: Job, console_path: str, on_start=None) -> tuple[int | None, str | None]:
    if job.policy.get("runtime", {}).get("docker_reuse_container"):
        return _run_reused_workload(job, console_path, on_start)
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
            # start_new_session makes the child a session/pgroup leader, so its
            # pid IS its pgid — the handle the host reconciler kills (S1/C2).
            if on_start is not None:
                on_start(proc.pid)
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


def _run_reused_workload(job: Job, console_path: str, on_start=None):
    run_dir = Path(job.run_dir)
    with open(console_path, "wb") as console:
        with execution.locked(run_dir):
            record = execution.read(run_dir)
            if record["phase"] == "stopped":
                return -signal.SIGTERM, "manual"
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            if (record["phase"] != "pending" or record["boot_id"] != boot_id
                    or record["init_start"] != execution.start_token(1)):
                raise RuntimeError("reuse execution generation changed before launch")
            ready_generation = f"{boot_id}:{record['init_start']}"
            if _workload_only(job) and Path("/work/.containre-ready").read_text().strip() != ready_generation:
                raise RuntimeError("supervised services are not ready for this generation")
            try:
                execution.require_group_signals()
            except (OSError, AttributeError) as exc:
                raise RuntimeError("shared execution requires pidfd process-group signals (Linux 6.9+)") from exc
            record["phase"] = "launching"
            execution.write(run_dir, record)
            proc = subprocess.Popen(
                [job.specimen_path, *job.args], cwd=job.cwd, env=job.env,
                stdout=console, stderr=subprocess.STDOUT, start_new_session=True,
            )
            try:
                record.update(phase="running", pgid=proc.pid,
                              leader_start=execution.start_token(proc.pid))
                execution.write(run_dir, record)
                if on_start is not None:
                    on_start(proc.pid)
            except BaseException:
                # Our direct child has not been waited on: its group number
                # cannot be reused while this parent kills the failed launch.
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise
        timeout = float(job.policy.get("limits", {}).get("wallclock_s", 120))
        deadline = time.monotonic() + timeout
        timed_out = False
        while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.05)
        # Keep the exited leader unreaped until its children are drained. Its
        # pidfd then still identifies the original group, even after leader exit.
        gone = execution.control(record, stop=True) == "gone"
        if not gone:
            raise RuntimeError("reuse workload cleanup remains unconfirmed")
        rc = proc.wait(timeout=5)
        with execution.locked(run_dir):
            current = execution.read(run_dir)
            current["phase"] = "stopped"
            execution.write(run_dir, current)
        return rc, "timeout" if timed_out else None


def _workload_only(job: Job) -> bool:
    return bool(job.policy.get("runtime", {}).get("workload_only"))


def _pgid_writer(job: Job):
    """Return a callback that records the workload's leader pgid at
    <run_dir>/leader.pgid — the generic handle ContainRE (and any external
    orchestrator) uses to tell whether this exec is still alive and to stop just
    this exec's process group. The run dir is host-visible via the /runs mount.

    Note what the pgid does and does not cover: it is the process group of the
    specimen ContainRE launched. A specimen that hands work to a pre-existing
    daemon (a job server, say) has descendants outside that group, and stopping
    those is the specimen's own responsibility — ContainRE delivers the signal,
    the workload defines what stopping means."""
    pgid_path = Path(job.run_dir) / "leader.pgid"

    def _write(pgid: int) -> None:
        try:
            pgid_path.parent.mkdir(parents=True, exist_ok=True)
            pgid_path.write_text(str(pgid))
        except OSError:
            pass  # the reaper falls back to the marker window; never crash the run

    return _write


def execute(job: Job) -> int:
    cwd = job.cwd
    if cwd and os.path.isdir(cwd):
        os.chdir(cwd)
    workdir = os.getcwd()

    session = RunSession(job.run_dir, job.policy, workdir)
    decoy_names = job.policy.get("files", {}).get("decoys", [])
    decoy_paths = [os.path.join(workdir, d) for d in decoy_names]

    workload_only = _workload_only(job)
    if workload_only:
        # Supervised reuse container: the sink + setup services are already hosted
        # by the container's supervisor. Fail CLOSED if it is not healthy —
        # running a workload with no services is a silent-failure trap.
        runtime_cfg = job.policy.get("runtime", {})
        if not Path("/work/.containre-ready").exists():
            session.store.update_meta(status="running", started_wall=wall_ns())
            session.finalize("killed", None, "services_unavailable")
            return 3
        # Trust the supervisor's fixed CA so TLS to the shared sink verifies.
        ca_path = runtime_cfg.get("ca_path") or "/work/.containre-ca.pem"
        if os.path.exists(ca_path):
            job.env["SSL_CERT_FILE"] = ca_path
            job.env["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"] = ca_path
        net_sink, sink_addr = None, None
    else:
        # Bring up the simulated-internet sink for simulate posture. In normal
        # ptrace mode the tracer redirects connects to it; in trace.tracer=none
        # benchmark mode policies map the target hostname to loopback and
        # configure the sink's original service listen_port.
        net_sink, sink_addr = _start_sink(job, session)

    session.store.update_meta(status="running", started_wall=wall_ns())

    tracer_mode = job.policy.get("trace", {}).get("tracer", "ptrace")
    kill_reason = None
    flows = {}
    exit_code = None
    try:
        # In workload_only mode the singleton services are hosted by the
        # supervisor, so per-exec setup/teardown are skipped entirely.
        setup_exit, setup_reason = (None, None) if workload_only \
            else _run_runtime_commands(job, session, "setup")
        if setup_reason:
            exit_code, kill_reason = setup_exit, setup_reason
        elif tracer_mode == "none":
            # Record the leader pgid for EVERY untraced run, not just
            # workload_only ones. stop() / `reuse kill` / `reuse reap` all address
            # a run by that pgid, and with no file recorded they silently do
            # nothing at all — a reuse-container run could not be stopped, only
            # abandoned. Writing it is free for a non-reuse run (one small file in
            # the run dir) and is what makes the reuse verbs work everywhere.
            exit_code, kill_reason = _run_without_tracer(
                job, str(job.run_dir / "console.log"), on_start=_pgid_writer(job))
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
        if not workload_only:
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
