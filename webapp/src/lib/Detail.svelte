<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, stream, pcapExists, type Ev, type Stream } from './api';
  import MemoryView from './MemoryView.svelte';
  import StaticView from './StaticView.svelte';

  let { id } = $props<{ id: string }>();

  let meta = $state<any>(null);
  let events = $state<Ev[]>([]);
  let status = $state('running');
  let active = $state(true);
  let tab = $state(new URLSearchParams(location.search).get('tab') ?? 'events');
  let kindFilter = $state('');
  let artifacts = $state<{ name: string; size: number }[]>([]);
  let hasPcap = $state(false);
  let checkpoints = $state<any[]>([]);
  let cpMsg = $state('');
  let streamErr = $state('');
  let ws: Stream | null = null;

  // Maintained incrementally (not $derived over the whole events array, which was
  // O(n) per message => O(n^2) and froze the tab on a chatty/L2-singlestep run).
  let detections = $state<Ev[]>([]);
  let snapshots = $state<Ev[]>([]);
  let instrs = $state<Ev[]>([]);
  let kindCounts = $state<Record<string, number>>({});
  const EVENT_CAP = 4000;   // bound the retained timeline buffer
  const INSTR_CAP = 20000;

  const kinds = $derived(Object.entries(kindCounts).sort((a, b) => b[1] - a[1]));
  const shown = $derived((kindFilter ? events.filter((e) => e.kind === kindFilter) : events).slice(-800));

  let pending: Ev[] = [];
  let flushScheduled = false;
  function ingest(e: Ev) {
    kindCounts[e.kind] = (kindCounts[e.kind] ?? 0) + 1;
    if (e.kind === 'detection') detections.push(e);
    else if (e.kind === 'mem' && e.data?.op === 'snapshot') snapshots.push(e);
    else if (e.kind === 'instr') {
      instrs.push(e);
      if (instrs.length > INSTR_CAP) instrs.splice(0, instrs.length - INSTR_CAP);
    }
    pending.push(e);
    if (!flushScheduled) {
      flushScheduled = true;
      requestAnimationFrame(flushEvents);
    }
  }
  function flushEvents() {
    flushScheduled = false;
    if (!pending.length) return;
    let next = events.concat(pending);   // one array copy per frame, not per event
    pending = [];
    if (next.length > EVENT_CAP) next = next.slice(next.length - EVENT_CAP);
    events = next;
  }

  async function loadFiles() {
    try { artifacts = (await api.artifacts(id)).artifacts; } catch {}
    hasPcap = await pcapExists(id);
    try { checkpoints = (await api.checkpoints(id)).checkpoints; } catch {}
  }

  async function doCheckpoint() {
    cpMsg = 'checkpointing…';
    try {
      const r = await api.checkpoint(id, `cp-${Date.now()}`);
      cpMsg = r.ok ? `checkpoint ${r.name} created` : `checkpoint unavailable: ${r.reason}`;
      await loadFiles();
    } catch (e) {
      cpMsg = 'error: ' + (e as Error).message;
    }
  }

  onMount(() => {
    api.run(id).then((m) => (meta = m)).catch(() => {});
    ws = stream(id, 0,
      (e) => ingest(e),
      (s, a) => {
        status = s; active = a; streamErr = '';
        if (['finished', 'killed', 'error'].includes(s) && !a) {
          api.run(id).then((m) => (meta = m)).catch(() => {});
          loadFiles();
        }
      },
      (msg) => { streamErr = msg; });
    loadFiles();
  });
  onDestroy(() => ws?.close());

  const KCOLOR: Record<string, string> = {
    net: '#79c0ff', file: '#a5d6ff', proc: '#d2a8ff', mem: '#f0883e',
    detection: '#ff6a69', instr: '#7ee787', signal: '#8b98a9', syscall: '#8b98a9', gate: '#e3b341',
  };
  function fmt(e: Ev): string {
    const d = e.data;
    if (e.kind === 'net') return [d.op, d.raddr || d.laddr || '', d.decision ? `[${d.decision}]` : '',
      d.redirected_to ? `→ ${d.redirected_to}` : '', d.http ? `${d.http.method} ${d.http.path}` : '',
      d.preview ? JSON.stringify(d.preview) : ''].filter(Boolean).join(' ');
    if (e.kind === 'file') return `${d.op} ${d.path || ''}${d.decoy ? ' [DECOY]' : ''}`;
    if (e.kind === 'proc') return `${d.op} ${d.path || d.child_pid || (d.exit_code ?? '')} ${d.argv ? d.argv.join(' ') : ''}`;
    if (e.kind === 'mem') return `${d.op} ${d.reason || d.region?.perms || ''} ${d.snapshot_id || d.region?.base || ''}`;
    if (e.kind === 'detection') return `[${d.severity}] ${d.id}: ${d.title}`;
    if (e.kind === 'signal') return `${d.name} (${d.signo})`;
    if (e.kind === 'instr') return `${d.ip}  ${d.disasm}`;
    return JSON.stringify(d);
  }
</script>

<div class="detail">
  <div class="head">
    <h2 class="rid">{id}</h2>
    <span class="st-{status}">{status}{active ? ' ●' : ''}{meta?.kill_reason ? ` (${meta.kill_reason})` : ''}</span>
    {#if meta}<span class="dim">exit={meta.exit_code ?? '-'}</span>{/if}
    <span class="spacer"></span>
    <button class="cp" onclick={doCheckpoint} title="CRIU checkpoint - docker runtime, best-effort">⚑ checkpoint</button>
  </div>
  {#if cpMsg}<div class="dim cpmsg">{cpMsg}</div>{/if}
  {#if streamErr}<div class="dim cpmsg">stream: {streamErr}</div>{/if}

  {#if meta?.verdict}
    <div class="verdict">
      severity <span class="sev-{meta.verdict.max_severity}">{meta.verdict.max_severity}</span>
      · flags [{(meta.verdict.flags ?? []).join(', ')}]
      · ATT&CK [{(meta.verdict.attack ?? []).join(', ')}]
    </div>
  {/if}

  <div class="bar">
    {#each kinds as [k, n]}
      <div class="seg" style="flex:{n};background:{KCOLOR[k] ?? 'var(--line)'}" title="{k}: {n}"></div>
    {/each}
  </div>
  <div class="counts dim">
    {#each kinds as [k, n]}<span><i style="background:{KCOLOR[k] ?? 'var(--line)'}"></i>{k} {n}</span>{/each}
  </div>

  <nav class="tabs">
    {#each [['events', `Events`], ['detections', `Detections (${detections.length})`], ['memory', `Memory (${snapshots.length})`], ['instructions', `L2 trace (${instrs.length})`], ['static', `Static`], ['artifacts', `Artifacts`]] as [t, label]}
      <button class:on={tab === t} onclick={() => (tab = t)}>{label}</button>
    {/each}
  </nav>

  {#if tab === 'events'}
    <div class="toolbar">
      <select bind:value={kindFilter}>
        <option value="">all kinds</option>
        {#each kinds as [k]}<option value={k}>{k}</option>{/each}
      </select>
      <span class="dim">{shown.length} shown / {events.length}</span>
    </div>
    <div class="stream">
      {#each shown as e (e.seq)}
        <div class="ev"><span class="seq dim">#{e.seq}</span><span class="k" style="color:{KCOLOR[e.kind] ?? 'var(--fg)'}">{e.kind}</span><span class="txt">{fmt(e)}</span></div>
      {/each}
    </div>
  {:else if tab === 'detections'}
    {#if detections.length}
      <table>
        <thead><tr><th>sev</th><th>id</th><th>title</th><th>IOCs</th><th>ATT&CK</th></tr></thead>
        <tbody>
          {#each detections as e (e.seq)}
            <tr>
              <td class="sev-{e.data.severity}">{e.data.severity}</td>
              <td>{e.data.id}</td>
              <td>{e.data.title}</td>
              <td class="dim">{(e.data.iocs ?? []).map((i: any) => i.value).join(', ')}</td>
              <td class="dim">{(e.data.attack ?? []).join(', ')}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}<div class="pad dim">no detections</div>{/if}
  {:else if tab === 'memory'}
    <MemoryView {id} {snapshots} />
  {:else if tab === 'instructions'}
    {#if instrs.length}
      <div class="stream">
        {#each instrs.slice(-600) as e (e.seq)}
          <div class="ev instr">
            <span class="seq dim">{e.data.ip}</span>
            <span class="disasm">{e.data.disasm}</span>
            {#if e.data.reg_deltas}<span class="dim">Δ {Object.keys(e.data.reg_deltas).join(',')}</span>{/if}
            {#if e.data.mem_writes}<span class="w">✎ {e.data.mem_writes.map((w: any) => `${w.addr}=${w.new}`).join(' ')}</span>{/if}
          </div>
        {/each}
      </div>
    {:else}<div class="pad dim">no instruction trace - run with L2 singlestep/unicorn</div>{/if}
  {:else if tab === 'static'}
    <StaticView {id} />
  {:else if tab === 'artifacts'}
    <div class="files">
      {#each artifacts as a}
        <div><a href="/api/runs/{id}/artifacts/{encodeURIComponent(a.name)}">{a.name}</a> <span class="dim">{a.size} B</span></div>
      {:else}<div class="dim">no dropped-file artifacts</div>{/each}
      {#if hasPcap}<div><a href="/api/runs/{id}/pcap">capture.pcap</a> <span class="dim">tcpdump</span></div>{/if}
      {#if checkpoints.length}
        <div class="cps">Checkpoints:
          {#each checkpoints as c}
            <div class="dim">⚑ {c.name} - {c.ok ? 'ok' : `unavailable (${c.reason})`}</div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .detail { padding: 12px 16px; }
  .head { display: flex; align-items: baseline; gap: 12px; }
  .head .spacer { flex: 1; }
  .cp { font-size: 12px; padding: 3px 9px; }
  .cpmsg { margin-top: 2px; font-size: 12px; }
  .cps { margin-top: 8px; }
  .rid { font-size: 15px; }
  .verdict { margin-top: 4px; color: var(--dim); }
  .bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 12px 0 6px; background: var(--line); }
  .seg { min-width: 2px; }
  .counts { display: flex; flex-wrap: wrap; gap: 12px; font-size: 12px; }
  .counts i { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 4px; vertical-align: middle; }
  .tabs { display: flex; gap: 4px; margin: 14px 0 8px; border-bottom: 1px solid var(--line); }
  .tabs button { background: transparent; border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 6px 10px; color: var(--dim); }
  .tabs button.on { color: var(--fg); border-bottom-color: var(--acc); }
  .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 6px; }
  .stream { background: var(--panel2); border: 1px solid var(--line); border-radius: 8px; height: 56vh; overflow: auto; padding: 6px 8px; }
  .ev { display: flex; gap: 8px; white-space: pre-wrap; word-break: break-word; padding: 1px 0; }
  .ev .seq { flex: 0 0 auto; }
  .ev .k { flex: 0 0 70px; }
  .ev .txt { flex: 1; }
  .ev.instr .disasm { flex: 1; color: #7ee787; }
  .ev.instr .w { color: var(--high); }
  .pad, .files { padding: 12px 2px; }
  .files > div { padding: 2px 0; }
</style>
