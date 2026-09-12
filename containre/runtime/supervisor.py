"""PID-1 supervisor entrypoint for a *supervised reuse container* (generic).

It replaces the bare ``sleep infinity`` of a plain reuse container: it hosts the
built-in sink and any operator-supplied ``setup_commands`` as long-lived
SINGLETONS, so ``workload_only`` execs run only their workload and skip per-exec
service setup. It publishes the MITM CA at a fixed path every workload trusts,
gates readiness on REAL probes (not a ``|| true`` marker), and — while healthy —
keeps a readiness marker present so the in-container runner fails closed if the
services are down.

This module is domain-agnostic: the hosted services are whatever the policy's
``network.sink`` + ``runtime.setup_commands`` describe. A caller can start a
worker service there without adding application-specific behavior to ContainRE.
Everything is driven by environment variables passed at ``docker run`` by
``DockerRuntime._supervised_spec``:

  CONTAINRE_SINK_CONFIG     JSON of the policy network.sink block (has listen_port)
  CONTAINRE_SINK_MITM       "1" to serve TLS with a generated CA
  CONTAINRE_CA_PATH         fixed in-container path to publish the CA at
  CONTAINRE_SETUP_COMMANDS  JSON list of shell commands to run once as singletons
  CONTAINRE_COMMAND_SHELL   shell for the setup commands
  CONTAINRE_READY_PROBE     optional shell command that must exit 0 for readiness
  CONTAINRE_READY_MARKER    file written when healthy / removed when not
  plus any specimen env the setup commands need (forwarded verbatim by the caller).

The sink half needs nothing external (exercised by the docker tests); any
setup-command services are exercised where their tooling exists.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from ..net import BuiltinSink, MitmCA

POLL_S = 5.0
MAX_RESTARTS = 3


def _log(msg: str) -> None:
    print(f"[reuse-supervisor] {msg}", file=sys.stderr, flush=True)


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class Supervisor:
    def __init__(self) -> None:
        self.sink_config = json.loads(os.environ.get("CONTAINRE_SINK_CONFIG") or "{}")
        self.mitm = os.environ.get("CONTAINRE_SINK_MITM") == "1"
        self.ca_path = Path(os.environ.get("CONTAINRE_CA_PATH") or "/work/.containre-ca.pem")
        self.setup_commands = json.loads(os.environ.get("CONTAINRE_SETUP_COMMANDS") or "[]")
        self.shell = os.environ.get("CONTAINRE_COMMAND_SHELL") or "/bin/sh"
        self.ready_probe = os.environ.get("CONTAINRE_READY_PROBE") or ""
        # Bound each setup command / ready probe: a hung one (a job server that
        # never returns, a wedged probe) must not block bring-up OR the mid-life
        # recovery loop forever — that would leave the shared container running but
        # permanently unready, silently failing every later exec closed.
        self.command_timeout_s = float(os.environ.get("CONTAINRE_COMMAND_TIMEOUT_S") or 600.0)
        self.marker = Path(os.environ.get("CONTAINRE_READY_MARKER") or "/work/.containre-ready")
        self._ca: MitmCA | None = None
        self._sink: BuiltinSink | None = None
        self._stop = False

    # -- CA + sink ----------------------------------------------------------
    def _publish_ca(self) -> None:
        """Create the MITM CA once and publish it atomically at the fixed path so
        every workload's SSL_CERT_FILE resolves to the same trust root (C3)."""
        if not self.mitm:
            return
        if self._ca is None:
            self._ca = MitmCA()
        tmp = self.ca_path.with_suffix(".pem.tmp")
        self._ca.write_ca(tmp)
        os.replace(tmp, self.ca_path)

    def _start_sink(self) -> None:
        self._publish_ca()
        sink = BuiltinSink(on_interaction=lambda info: None, mitm=self.mitm,
                           ca=self._ca, sink_config=self.sink_config)
        sink.start()
        self._sink = sink
        _log(f"sink up on 127.0.0.1:{sink.port} (mitm={self.mitm})")

    def _sink_alive(self) -> bool:
        if self._sink is None or not self._sink.port:
            return False
        try:
            with socket.create_connection(("127.0.0.1", self._sink.port), timeout=2.0):
                return True
        except OSError:
            return False

    # -- job server (setup commands) ---------------------------------------
    def _run_setup(self) -> bool:
        """Run each setup command once; ALL must exit 0 (no `|| true`) — this is
        the real job-server readiness signal (C3/C4)."""
        for cmd in self.setup_commands:
            try:
                rc = subprocess.run([self.shell, "-c", str(cmd)], env=os.environ.copy(),
                                    timeout=self.command_timeout_s).returncode
            except subprocess.TimeoutExpired:
                _log(f"setup command timed out after {self.command_timeout_s:g}s: {cmd}")
                return False
            if rc != 0:
                _log(f"setup command failed (rc={rc}): {cmd}")
                return False
        return True

    def _probe_ok(self) -> bool:
        if not self.ready_probe:
            return True
        try:
            return subprocess.run([self.shell, "-c", self.ready_probe], env=os.environ.copy(),
                                  timeout=self.command_timeout_s).returncode == 0
        except subprocess.TimeoutExpired:
            _log(f"ready probe timed out after {self.command_timeout_s:g}s")
            return False

    # -- readiness ----------------------------------------------------------
    def _mark_ready(self) -> None:
        _atomic_write(self.marker, str(int(time.time())).encode())

    def _mark_unready(self) -> None:
        self.marker.unlink(missing_ok=True)

    def _healthy(self) -> bool:
        return self._sink_alive() and self._probe_ok()

    # -- lifecycle ----------------------------------------------------------
    def bring_up(self) -> bool:
        self._mark_unready()  # clear any stale marker from a prior incarnation
        self._start_sink()
        if not self._run_setup():
            return False
        if not self._sink_alive() or not self._probe_ok():
            return False
        self._mark_ready()
        _log("ready")
        return True

    def supervise(self) -> int:
        restarts = 0
        while not self._stop:
            time.sleep(POLL_S)
            if self._stop:
                break
            if self._healthy():
                if not self.marker.exists():
                    self._mark_ready()
                continue
            # A service died: mark unhealthy so in-flight/new workloads fail
            # closed (C4), then try to recover.
            self._mark_unready()
            restarts += 1
            if restarts > MAX_RESTARTS:
                _log("unrecoverable: exhausted restarts, exiting (container will be replaced)")
                return 1
            _log(f"unhealthy — recovery attempt {restarts}/{MAX_RESTARTS}")
            self._recover()
        return 0

    def _recover(self) -> None:
        if not self._sink_alive():
            try:
                if self._sink is not None:
                    self._sink.stop()
            except Exception:
                pass
            self._start_sink()  # same CA re-published atomically
        if not self._probe_ok():
            self._run_setup()
        if self._healthy():
            self._mark_ready()

    def shutdown(self, *_a) -> None:
        self._stop = True
        self._mark_unready()
        try:
            if self._sink is not None:
                self._sink.stop()
        except Exception:
            pass


def main() -> int:
    sup = Supervisor()
    signal.signal(signal.SIGTERM, sup.shutdown)
    signal.signal(signal.SIGINT, sup.shutdown)
    if not sup.bring_up():
        sup.shutdown()
        _log("bring-up failed; exiting non-zero (container will be replaced)")
        return 1
    return sup.supervise()


if __name__ == "__main__":
    raise SystemExit(main())
