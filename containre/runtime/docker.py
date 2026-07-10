"""DockerRuntime - the isolated backend for untrusted specimens (SPEC §4, §15).

The specimen runs inside a container with no network egress by default, cgroup
resource limits, dropped capabilities, and the in-container probe-agent
(containre.tracer.runner) driving the trace. The host run directory is bind-mounted
so events land on disk exactly as with LocalRuntime.

Posture deny/simulate use `--network none` unless a policy allowlist is present.
With an allowlist, Docker bridge networking is attached and the in-container
ptrace tracer remains responsible for allowing only matching destinations. A
policy may request host networking for environments where bridge/NAT breaks a
specific allowlisted service; this is rejected unless the allowlist is non-empty.
Simulate redirects non-allowlisted egress to the in-container built-in sink. CRIU
checkpoint/restore remains best-effort and depends on host Docker support.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from ..control.instrumentation import configure_tls_plaintext
from ..interfaces import Job, RunHandle

_IMAGE = "containre/runner:0.1"
_REPO = Path(__file__).resolve().parents[2]
_SAFE_REUSE_KEY = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SAFE_DOCKER_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?$")


class DockerError(RuntimeError):
    pass


def docker_available() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    return subprocess.run([docker, "info"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


class DockerRuntime:
    name = "docker"

    def __init__(self, image: str = _IMAGE, build_context: Path = _REPO):
        self.image = image
        self.build_context = build_context
        self._procs: dict[str, subprocess.Popen] = {}

    # -- image --------------------------------------------------------------
    def image_present(self) -> bool:
        return subprocess.run(["docker", "image", "inspect", self.image],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    def ensure_image(self, timeout: int = 900) -> None:
        if self.image_present():
            return
        dockerfile = self.build_context / "images" / "Dockerfile.runner"
        proc = subprocess.run(
            ["docker", "build", "-t", self.image, "-f", str(dockerfile), str(self.build_context)],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            raise DockerError(f"docker build failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")

    # -- run ----------------------------------------------------------------
    def _network_args(self, policy: dict) -> list[str]:
        network = policy.get("network", {})
        posture = network.get("posture", "simulate")
        docker_network = network.get("docker_network", "auto")
        tracer = policy.get("trace", {}).get("tracer", "ptrace")
        if docker_network == "none":
            return ["--network", "none"]
        if docker_network == "host":
            if posture == "allow" or not network.get("allow"):
                raise DockerError("network.docker_network=host requires a non-empty "
                                  "network.allow and posture other than allow")
            self._require_tracer_for_networking(tracer, "network.docker_network=host")
            return ["--network", "host"]
        if docker_network not in ("auto", "bridge"):
            raise DockerError(f"invalid network.docker_network: {docker_network!r}")
        # A non-empty allowlist means "attach networking, then let ptrace enforce
        # the narrow destination policy". Without it, deny/simulate stay fully
        # detached at the Docker layer.
        if posture == "allow" or network.get("allow"):
            self._require_tracer_for_networking(
                tracer, "attaching container networking (posture=allow or a non-empty network.allow)")
            return []
        return ["--network", "none"]

    @staticmethod
    def _require_tracer_for_networking(tracer: str, what: str) -> None:
        # With trace.tracer=none the runner runs the specimen untraced (raw
        # subprocess), so there is NO egress enforcement. Attaching real container
        # networking would then give the specimen unrestricted egress while the
        # operator believes it is limited to the allowlist. Refuse the
        # combination; untraced runs must use --network none + a loopback sink.
        if tracer == "none":
            raise DockerError(
                f"{what} requires an active tracer (trace.tracer != none) to enforce "
                "the destination policy; an untraced run would have unrestricted egress. "
                "Use network.docker_network=none (with a loopback sink) for untraced runs.")

    def _extra_host_args(self, policy: dict) -> list[str]:
        args: list[str] = []
        for entry in policy.get("network", {}).get("extra_hosts", []):
            host = str(entry.get("host", ""))
            ip = str(entry.get("ip", ""))
            if not host or ":" in host or not ip or any(ch.isspace() for ch in host + ip):
                raise DockerError(f"invalid network.extra_hosts entry: {entry!r}")
            args += ["--add-host", f"{host}:{ip}"]
        return args

    def _read_only_mount_args(self, policy: dict) -> list[str]:
        args: list[str] = []
        for mount in policy.get("files", {}).get("read_only_mounts", []):
            source = Path(str(mount.get("source", ""))).resolve()
            target = str(mount.get("target", ""))
            if not source.exists():
                raise DockerError(f"read-only mount source does not exist: {source}")
            if not target.startswith("/") or ":" in target:
                raise DockerError(f"read-only mount target must be an absolute container path: {target}")
            args += ["-v", f"{source}:{target}:ro"]
        return args

    def _container_specimen_path(self, policy: dict) -> str:
        target = str(policy.get("specimen", {}).get("container_path") or "/specimen")
        if not target.startswith("/") or ":" in target:
            raise DockerError(f"specimen container_path must be an absolute container path: {target}")
        return target

    def _trace_security_args(self, policy: dict) -> list[str]:
        if policy.get("trace", {}).get("tracer", "ptrace") == "none":
            return []
        return [
            "--cap-add", "SYS_PTRACE",
            "--security-opt", "seccomp=unconfined",  # ptrace + traced syscalls
        ]

    def _docker_user_args(self, policy: dict) -> list[str]:
        user = policy.get("runtime", {}).get("docker_user")
        if user is None:
            return []
        user = str(user).strip()
        if not user:
            return []
        if not _SAFE_DOCKER_USER.fullmatch(user):
            raise DockerError(f"invalid runtime.docker_user: {user!r}")
        return ["--user", user]

    def _reuse_requested(self, policy: dict) -> bool:
        return bool(policy.get("runtime", {}).get("docker_reuse_container", False))

    def _reuse_key(self, policy: dict) -> str:
        key = str(policy.get("runtime", {}).get("docker_reuse_key") or "default")
        if not _SAFE_REUSE_KEY.fullmatch(key):
            raise DockerError(f"invalid runtime.docker_reuse_key: {key!r}")
        return key

    def _reuse_container_name(self, policy: dict) -> str:
        return f"containre-reuse-{self._reuse_key(policy)}"

    def _reuse_config_hash(self, job: Job, specimen_parent: Path, workdir: Path) -> str:
        payload = {
            "image": self.image,
            "network_args": self._network_args(job.policy),
            "extra_host_args": self._extra_host_args(job.policy),
            "read_only_mount_args": self._read_only_mount_args(job.policy),
            "docker_user_args": self._docker_user_args(job.policy),
            "runs_root": str(job.run_dir.resolve().parent),
            "workdir": str(workdir),
            "specimen_parent": str(specimen_parent),
            "limits": job.policy.get("limits", {}),
            "trace": job.policy.get("trace", {}).get("tracer", "ptrace"),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()[:24]

    def _inspect_reuse_container(self, name: str) -> tuple[bool, bool, str | None]:
        proc = subprocess.run(
            [
                "docker", "inspect",
                "--format", "{{.State.Running}} {{index .Config.Labels \"containre.config\"}}",
                name,
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return False, False, None
        parts = proc.stdout.strip().split(maxsplit=1)
        running = bool(parts and parts[0].lower() == "true")
        config = parts[1] if len(parts) > 1 and parts[1] != "<no value>" else None
        return True, running, config

    def _ensure_reuse_container(self, job: Job, specimen_parent: Path, workdir: Path,
                                name: str, config_hash: str) -> None:
        exists, running, current_hash = self._inspect_reuse_container(name)
        if exists and current_hash != config_hash:
            subprocess.run(["docker", "rm", "-f", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            exists = running = False
        if exists and running:
            return
        if exists:
            proc = subprocess.run(["docker", "start", name], capture_output=True, text=True)
            if proc.returncode != 0:
                raise DockerError(f"docker start {name} failed: {proc.stderr.strip() or proc.stdout.strip()}")
            return

        limits = job.policy.get("limits", {})
        runs_root = job.run_dir.resolve().parent
        cmd = [
            "docker", "run", "-d", "--name", name,
            "--label", "containre.reuse=1",
            "--label", f"containre.config={config_hash}",
            "--cap-drop", "ALL",
            "--cap-add", "DAC_OVERRIDE",
            "--security-opt", "no-new-privileges",
            "--ulimit", "nofile=1024:4096",
            *self._docker_user_args(job.policy),
            *self._network_args(job.policy),
            *self._extra_host_args(job.policy),
            "--pids-limit", str(int(limits.get("pids", 128))),
            "--memory", f"{int(limits.get('mem_mb', 512))}m",
            "--cpus", str(limits.get("cpu", 1)),
            *self._read_only_mount_args(job.policy),
            "-v", f"{runs_root}:/runs",
            "-v", f"{workdir}:/work",
            "-v", f"{specimen_parent}:/specimen-src:ro",
            "-v", f"{self.build_context / 'containre'}:/opt/containre/containre:ro",
            "-v", f"{self.build_context / 'contracts'}:/opt/containre/contracts:ro",
            "-w", "/work",
            self.image,
            "sleep", "infinity",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise DockerError(f"docker reusable container start failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")

    def _start_reused(self, job: Job) -> RunHandle:
        if job.policy.get("trace", {}).get("tracer", "ptrace") != "none":
            raise DockerError("runtime.docker_reuse_container requires trace.tracer=none")
        if job.stdin_path:
            raise DockerError("runtime.docker_reuse_container does not support stdin yet")

        run_dir = job.run_dir.resolve()
        workdir = Path(job.cwd).resolve()

        specimen = Path(job.specimen_path).resolve()
        specimen_parent = specimen.parent
        container_specimen = job.policy.get("specimen", {}).get("container_path")
        if container_specimen:
            container_specimen = self._container_specimen_path(job.policy)
        else:
            container_specimen = f"/specimen-src/{specimen.name}"

        container_run_dir = f"/runs/{run_dir.name}"
        container_workdir = "/work"
        configure_tls_plaintext(job, visible_workdir=container_workdir)

        cjob = Job(run_dir=Path(container_run_dir), specimen_path=container_specimen, args=job.args,
                   env=job.env, cwd=container_workdir, stdin_path=None, policy=job.policy)
        (run_dir / "cjob.json").write_text(json.dumps(cjob.to_json()))

        name = self._reuse_container_name(job.policy)
        config_hash = self._reuse_config_hash(job, specimen_parent, workdir)
        self._ensure_reuse_container(job, specimen_parent, workdir, name, config_hash)

        cmd = [
            "docker", "exec", *self._docker_user_args(job.policy), "-w", container_workdir, name,
            "python3", "-m", "containre.tracer.runner", f"{container_run_dir}/cjob.json",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=open(run_dir / "runner.log", "wb"))
        self._procs[str(run_dir)] = proc
        return RunHandle(run_dir=run_dir, runtime=self.name, container=name, pid=proc.pid)

    def start(self, job: Job) -> RunHandle:
        self.ensure_image()
        if self._reuse_requested(job.policy):
            return self._start_reused(job)
        limits = job.policy.get("limits", {})
        run_dir = job.run_dir.resolve()
        workdir = Path(job.cwd).resolve()
        specimen = Path(job.specimen_path).resolve()
        container_specimen = self._container_specimen_path(job.policy)
        configure_tls_plaintext(job, visible_workdir="/work")

        # Container-side job: fixed in-container mount points.
        cjob = Job(run_dir=Path("/out"), specimen_path=container_specimen, args=job.args,
                   env=job.env, cwd="/work", stdin_path="/stdin" if job.stdin_path else None,
                   policy=job.policy)
        (run_dir / "cjob.json").write_text(json.dumps(cjob.to_json()))

        name = f"containre-{run_dir.name}"
        cmd = [
            "docker", "run", "--rm", "--name", name,
            # Minimal capability set: DAC_OVERRIDE lets the container write into
            # the bind-mounted (host-owned) run dir. SYS_PTRACE and unconfined
            # seccomp are added only when the ptrace tracer is enabled.
            # Everything else is dropped. Isolation is raised further behind the
            # Runtime interface (gVisor/Firecracker) later.
            "--cap-drop", "ALL",
            *self._trace_security_args(job.policy),
            "--cap-add", "DAC_OVERRIDE",
            "--security-opt", "no-new-privileges",
            # Keep the in-container limit modest for tools that inspect fd ranges.
            "--ulimit", "nofile=1024:4096",
            *self._docker_user_args(job.policy),
            *self._network_args(job.policy),
            *self._extra_host_args(job.policy),
            "--pids-limit", str(int(limits.get("pids", 128))),
            "--memory", f"{int(limits.get('mem_mb', 512))}m",
            "--cpus", str(limits.get("cpu", 1)),
            *self._read_only_mount_args(job.policy),
            "-v", f"{specimen}:{container_specimen}:ro",
            "-v", f"{workdir}:/work",
            "-v", f"{run_dir}:/out",
            # Overlay the live package + contracts over the image's baked copy so
            # code changes take effect without rebuilding the image.
            "-v", f"{self.build_context / 'containre'}:/opt/containre/containre:ro",
            "-v", f"{self.build_context / 'contracts'}:/opt/containre/contracts:ro",
        ]
        if job.stdin_path:
            cmd += ["-v", f"{Path(job.stdin_path).resolve()}:/stdin:ro"]
        cmd += ["-w", "/work", self.image,
                "python3", "-m", "containre.tracer.runner", "/out/cjob.json"]

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=open(run_dir / "runner.log", "wb"))
        self._procs[str(run_dir)] = proc
        return RunHandle(run_dir=run_dir, runtime=self.name, container=name, pid=proc.pid)

    def wait(self, handle: RunHandle, timeout: float | None = None) -> int | None:
        proc = self._procs.get(str(handle.run_dir))
        if proc is None:
            return None
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.stop(handle)
            return None

    def stop(self, handle: RunHandle) -> None:
        if handle.container:
            subprocess.run(["docker", "kill", handle.container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # -- CRIU checkpoint/restore (best-effort) ------------------------------
    def _experimental(self) -> bool:
        try:
            out = subprocess.check_output(
                ["docker", "info", "--format", "{{.ExperimentalBuild}}"],
                text=True, stderr=subprocess.DEVNULL).strip().lower()
            return out == "true"
        except Exception:
            return False

    def checkpoint(self, handle: RunHandle, name: str = "checkpoint") -> dict:
        """CRIU-dump the whole container tree (probe-agent + specimen, ptrace
        relationship and all) via `docker checkpoint`. Best-effort: returns a
        structured result, never raises."""
        if not handle.container:
            return {"ok": False, "name": name, "reason": "run has no container"}
        if not self._experimental():
            return {"ok": False, "name": name,
                    "reason": "docker daemon experimental features are disabled "
                              "(required for CRIU checkpoint)"}
        proc = subprocess.run(
            ["docker", "checkpoint", "create", "--leave-running", handle.container, name],
            capture_output=True, text=True)
        ok = proc.returncode == 0
        return {"ok": ok, "name": name,
                "reason": "" if ok else (proc.stderr.strip() or proc.stdout.strip())[:400]}

    def restore(self, handle: RunHandle, name: str = "checkpoint") -> dict:
        if not handle.container:
            return {"ok": False, "name": name, "reason": "run has no container"}
        proc = subprocess.run(
            ["docker", "start", "--checkpoint", name, handle.container],
            capture_output=True, text=True)
        ok = proc.returncode == 0
        return {"ok": ok, "name": name,
                "reason": "" if ok else (proc.stderr.strip() or proc.stdout.strip())[:400]}
