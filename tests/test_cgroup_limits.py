"""A breached resource ceiling must fail the run, not quietly shape its results.

The regression these guard: a container was given ``--pids-limit 1024``, hit it
118 times, and every process that could not fork was recorded by the workload as
an ordinary failure. The run reported success. Nothing read the counter that the
kernel had already incremented.

The unit tests below need no Docker and are the ones that must never be allowed
to rot - they pin the decision logic. The Docker test proves the whole path end
to end on hosts that can run it.
"""
from __future__ import annotations

import shutil
import time
import tempfile
from pathlib import Path

import pytest

from containre import policy as P
from containre.control import execute
from containre.runtime import DockerRuntime, docker_available
from containre.runtime.cgroup import ResourceSampler, cgroup_path, evaluate
from containre.runtime.docker import DockerError


# --------------------------------------------------------------------------
# decision logic - no Docker, no kernel, always runs
# --------------------------------------------------------------------------
pytestmark_unit = pytest.mark.unit


@pytest.mark.unit
def test_clean_run_reports_no_breach():
    assert evaluate({"pids_peak": 300, "pids_max": 18432, "pids_events_max": 0}) == []


@pytest.mark.unit
def test_no_counters_is_not_a_breach():
    """A host where the cgroup could not be read must not fail every run."""
    assert evaluate({}) == []


@pytest.mark.unit
def test_single_denied_fork_is_a_breach():
    """One refused fork is enough: some process asked for a thread and lost."""
    breaches = evaluate({"pids_max": 1024, "pids_peak": 1024, "pids_events_max": 1})
    assert [b["trigger"] for b in breaches] == ["pids_exceeded"]
    assert breaches[0]["hits"] == 1


@pytest.mark.unit
def test_pids_breach_carries_actionable_detail():
    detail = evaluate({"pids_max": 1024, "pids_peak": 1024, "pids_events_max": 118})[0]["detail"]
    assert "1024" in detail and "118" in detail
    assert "not trustworthy" in detail


@pytest.mark.unit
def test_memory_pressure_alone_is_not_a_breach():
    """Reclaim pressure is survivable; only an actual kill invalidates results."""
    assert evaluate({"memory_max": 1 << 30, "memory_events_max": 42, "memory_oom_kill": 0}) == []


@pytest.mark.unit
def test_oom_kill_is_a_breach():
    breaches = evaluate({"memory_max": 1 << 30, "memory_peak": 1 << 30, "memory_oom_kill": 2})
    assert [b["trigger"] for b in breaches] == ["oom"]


@pytest.mark.unit
def test_both_ceilings_can_breach_together():
    triggers = {b["trigger"] for b in evaluate({"pids_events_max": 3, "memory_oom_kill": 1})}
    assert triggers == {"pids_exceeded", "oom"}


@pytest.mark.unit
def test_both_triggers_are_in_the_default_policy():
    """The defaults promised these guards long before they existed. Keep them honest."""
    kill_on = set(P.DEFAULTS["kill_on"]) if hasattr(P, "DEFAULTS") else set(
        P.apply_defaults({"specimen": {"path": "/bin/true"}})["kill_on"])
    assert {"oom", "pids_exceeded"} <= kill_on


@pytest.mark.unit
def test_sampler_without_a_container_is_inert():
    """The local runtime has no container; the sampler must be a no-op, not a crash."""
    assert ResourceSampler(None).start().stop() == {}


@pytest.mark.unit
def test_sampler_survives_an_unknown_container():
    assert ResourceSampler("containre-no-such-container-xyz").start().stop() == {}


@pytest.mark.unit
def test_cgroup_path_returns_none_for_nonsense():
    assert cgroup_path("0" * 64) is None


# --------------------------------------------------------------------------
# end to end - needs Docker
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def docker_runtime():
    if not docker_available():
        pytest.skip("docker daemon not available")
    rt = DockerRuntime()
    try:
        rt.ensure_image()
    except (DockerError, Exception) as exc:  # noqa: BLE001
        pytest.skip(f"could not prepare runner image: {exc}")
    return rt


@pytest.fixture
def docker_runs():
    d = Path(tempfile.mkdtemp(prefix="containre-cgroup-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.docker
@pytest.mark.specimen
def test_pids_ceiling_fails_the_run(docker_runtime, docker_runs, build_specimen):
    """The whole regression, reproduced: the specimen exits 0 after being refused
    a thread, and the run must still be reported as failed."""
    pol = P.policy_for_binary(
        build_specimen("forkwall"),
        limits={"wallclock_s": 60, "pids": 16, "mem_mb": 512},
        network={"posture": "deny"},
    )
    r = execute(pol, runs_root=docker_runs, runtime=docker_runtime, timeout=120)

    assert r.meta.get("resources"), "resource counters were not recorded at all"
    assert r.meta["resources"]["pids_events_max"] > 0, "the ceiling was not actually reached"
    assert r.status == "error", "a throttled run was reported as a clean one"
    assert r.meta.get("kill_reason") == "pids_exceeded"
    assert "not trustworthy" in (r.meta.get("error") or "")


@pytest.mark.docker
@pytest.mark.specimen
def test_headroom_run_is_not_failed(docker_runtime, docker_runs, build_specimen):
    """The guard must not fire on a run that stayed inside its ceiling."""
    pol = P.policy_for_binary(
        build_specimen("hello"),
        limits={"wallclock_s": 30, "pids": 4096, "mem_mb": 512},
        network={"posture": "deny"},
    )
    r = execute(pol, runs_root=docker_runs, runtime=docker_runtime, timeout=90)

    assert r.status == "finished"
    assert r.exit_code == 0
    assert r.meta.get("resource_breaches") == []
    assert r.meta["resources"]["pids_peak"] < 4096


# --------------------------------------------------------------------------
# shared containers: the counters outlive the job
# --------------------------------------------------------------------------
@pytest.mark.unit
def test_shared_container_does_not_inherit_an_earlier_breach():
    """A container reused across jobs carries the previous job's counters.

    Charging them to this job would fail every later job in that container, and
    the counter never resets - so the container would be condemned for good.
    """
    assert evaluate({
        "pids_max": 4096, "pids_peak": 900,
        "pids_events_max": 118,        # accumulated by an earlier job
        "pids_events_max_delta": 0,    # this job breached nothing
    }) == []


@pytest.mark.unit
def test_shared_container_reports_only_this_jobs_breach():
    breaches = evaluate({
        "pids_max": 4096, "pids_peak": 4096,
        "pids_events_max": 130,        # 118 inherited + 12 ours
        "pids_events_max_delta": 12,
    })
    assert [b["trigger"] for b in breaches] == ["pids_exceeded"]
    assert breaches[0]["hits"] == 12, "must charge the job only for its own breaches"


@pytest.mark.unit
def test_oom_delta_is_preferred_over_absolute():
    assert evaluate({"memory_max": 1 << 30, "memory_oom_kill": 3,
                     "memory_oom_kill_delta": 0}) == []


@pytest.mark.unit
def test_absolute_counter_used_when_no_delta_available():
    """A fresh --rm container has no earlier history; absolute is correct there."""
    assert len(evaluate({"pids_max": 1024, "pids_events_max": 4})) == 1


@pytest.mark.unit
def test_memory_breach_detail_is_human_readable():
    detail = evaluate({"memory_max": 536870912, "memory_peak": 536870912,
                       "memory_oom_kill": 1})[0]["detail"]
    assert "512 MiB" in detail, "raw byte counts are not readable in an error"
    assert "536870912" not in detail


@pytest.mark.unit
def test_sampler_emits_deltas_for_cumulative_counters(monkeypatch, tmp_path):
    """Shared observations report the window change, without per-job attribution."""
    from containre.runtime import cgroup as cg

    readings = iter([
        {"pids_events_max": 7, "pids_peak": 10},   # baseline: inherited
        {"pids_events_max": 9, "pids_peak": 12},   # after our work
    ])
    monkeypatch.setattr(cg, "container_id", lambda name: "deadbeef")
    monkeypatch.setattr(cg, "cgroup_path", lambda cid: tmp_path)
    monkeypatch.setattr(cg, "sample", lambda p: next(readings, {"pids_events_max": 9,
                                                                "pids_peak": 12}))
    s = cg.ResourceSampler("anything", sample_s=0.01, reuse_exec=True)
    s.start()
    time.sleep(0.15)
    out = s.stop()

    assert out["pids_events_max"] == 9, "absolute counter is still reported"
    assert out["pids_events_max_delta"] == 2, "delta must describe the observed window"
