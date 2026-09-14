"""Resource evidence must survive sampling and reach the final run outcome."""
import threading

import pytest

from containre import policy as P
from containre.control import orchestrator
from containre.interfaces import RunHandle
from containre.runtime import cgroup as cg
from containre.store import RunStore

pytestmark = pytest.mark.unit


def test_early_events_and_partial_final_read(monkeypatch, tmp_path):
    observed = threading.Event()
    sampler = cg.ResourceSampler('test')
    monkeypatch.setattr(cg, 'container_id', lambda _: 'id')
    monkeypatch.setattr(cg, 'cgroup_path', lambda _: tmp_path)
    reads = iter([{'pids_events_max': 1, 'memory_oom_kill': 1}, {'memory_current': 42}])
    merge = sampler._merge
    def record(got):
        merge(got)
        observed.set()
    monkeypatch.setattr(sampler, '_merge', record)
    monkeypatch.setattr(cg, 'sample', lambda _: next(reads))
    sampler.start()
    assert observed.wait(2)
    out = sampler.stop()
    assert {b['trigger'] for b in cg.evaluate(out)} == {'oom', 'pids_exceeded'}
    assert 'pids_events_max_delta' not in out
    assert sampler.stop() == out


@pytest.mark.parametrize('baseline,final', [({'pids_peak': 10}, 118),
                                         ({'pids_events_max': 118}, 1)])
def test_shared_missing_baseline_or_reset_is_not_a_breach(monkeypatch, tmp_path, baseline, final):
    sampler = cg.ResourceSampler('test', reuse_exec=True)
    sampler._cg = tmp_path
    sampler._merge(baseline)
    monkeypatch.setattr(cg, 'sample', lambda _: {'pids_events_max': final})
    assert cg.evaluate(sampler.stop()) == []


def test_stop_discards_late_discovery(monkeypatch, tmp_path):
    entered, release = threading.Event(), threading.Event()
    def resolve(_):
        entered.set()
        assert release.wait(5)
        return 'id'
    monkeypatch.setattr(cg, 'container_id', resolve)
    monkeypatch.setattr(cg, 'cgroup_path', lambda _: tmp_path)
    monkeypatch.setattr(cg, 'sample', lambda _: {'pids_events_max': 1})
    sampler = cg.ResourceSampler('test', poll_s=0.01).start()
    try:
        assert entered.wait(2)
        out = sampler.stop()
    finally:
        release.set()
        sampler._thread.join(2)
    assert out == sampler.stop() == {}
    assert sampler._cg is None


class Runtime:
    name = 'fake'
    def __init__(self, reuse=False, timeout=False):
        self.reuse, self.timeout, self.stopped = reuse, timeout, False
    def start(self, job):
        self.job = job
        return RunHandle(job.run_dir, self.name, container='test', reuse_exec=self.reuse)
    def wait(self, handle, timeout=None):
        if self.timeout:
            return None
        with RunStore(handle.run_dir) as store:
            store.update_meta(status='finished', exit_code=0)
        return 0
    def stop(self, handle):
        self.stopped = True


def run(tmp_path, monkeypatch, runtime):
    monkeypatch.setattr(orchestrator, '_host_facts', lambda: {})
    specimen = tmp_path / 'specimen'
    specimen.write_bytes(b'test')
    return orchestrator.execute(P.policy_for_binary(specimen), runs_root=tmp_path / 'runs',
                                runtime=runtime, timeout=1)


@pytest.mark.parametrize('reuse,timeout', [(False, False), (False, True), (True, False)])
def test_resource_rejection_preserves_outcome(monkeypatch, tmp_path, reuse, timeout):
    monkeypatch.setattr(cg.ResourceSampler, 'start', lambda self: self)
    monkeypatch.setattr(cg.ResourceSampler, 'stop', lambda self: {'pids_events_max': 1})
    runtime = Runtime(reuse, timeout)
    result = run(tmp_path, monkeypatch, runtime)
    if reuse:
        assert result.status == 'finished'
        assert result.meta['fatal_resource_breaches'] == []
    else:
        assert result.status == 'error'
        assert result.meta['fatal_resource_breaches'][0]['trigger'] == 'pids_exceeded'
        if timeout:
            assert runtime.stopped
            assert 'runtime did not finish within 1s' in result.meta['error']
        else:
            assert result.exit_code == 0


def test_sampler_start_failure_still_waits_and_cleans_up(monkeypatch, tmp_path):
    def fail(_):
        raise RuntimeError("can't start new thread")
    monkeypatch.setattr(threading.Thread, 'start', fail)
    runtime = Runtime(timeout=True)
    result = run(tmp_path, monkeypatch, runtime)
    assert runtime.stopped
    assert 'runtime did not finish' in result.meta['error']
