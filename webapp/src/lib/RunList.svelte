<script lang="ts">
  let { runs, selected, onselect, launch } = $props<{
    runs: any[]; selected: string | null;
    onselect: (id: string) => void; launch: (b: any) => Promise<void>;
  }>();

  let binary = $state('');
  let net = $state('deny');
  let decoys = $state('');
  let l2 = $state('off');
  let mitm = $state(false);
  let policyText = $state('');
  let busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    try {
      const trimmedBinary = binary.trim();
      const trimmedPolicy = policyText.trim();
      if (!trimmedBinary && !trimmedPolicy) throw new Error('provide a binary or policy JSON');
      const body: any = {};
      if (trimmedPolicy) body.policy = JSON.parse(trimmedPolicy);
      if (trimmedBinary) {
        body.binary = trimmedBinary;
        body.net = net;
        body.mitm = net === 'simulate' && mitm;
        body.decoys = decoys.split(',').map((s) => s.trim()).filter(Boolean);
        if (l2 !== 'off') {
          body.policy = { ...(body.policy ?? {}), trace: { ...((body.policy ?? {}).trace ?? {}), l2: { mode: l2 } } };
        }
      }
      await launch(body);
    } catch (err) {
      alert('launch failed: ' + (err as Error).message);
    }
    busy = false;
  }
</script>

<form onsubmit={submit}>
  <input bind:value={binary} placeholder="/path/to/specimen" required={policyText.trim() === ''} />
  <div class="row">
    <select bind:value={net} title="network posture">
      <option value="deny">deny</option>
      <option value="simulate">simulate</option>
      <option value="allow">allow</option>
    </select>
    <select bind:value={l2} title="L2 tracing">
      <option value="off">L2 off</option>
      <option value="singlestep">singlestep</option>
    </select>
    <button class="primary" disabled={busy}>{busy ? '…' : 'Run'}</button>
  </div>
  <input bind:value={decoys} placeholder="decoys (comma separated)" />
  {#if net === 'simulate'}
    <label class="mitm"><input type="checkbox" bind:checked={mitm} /> TLS-MITM (decrypt HTTPS)</label>
  {/if}
  <textarea bind:value={policyText} placeholder='policy JSON, full policy or binary override'></textarea>
</form>

<h3 class="hd">Runs <span class="dim">({runs.length})</span></h3>
<div class="runs">
  {#each runs as m (m.run_id)}
    {@const v = m.verdict ?? {}}
    <button class="card" class:sel={m.run_id === selected} onclick={() => onselect(m.run_id)}>
      <div class="top">
        <span class="rid">{m.run_id}</span>
        <span class="st-{m.status}">{m.status}{m.active ? ' ●' : ''}</span>
      </div>
      <div class="bot dim">
        <span class="sev-{v.max_severity ?? 'info'}">{v.max_severity ?? 'info'}</span>
        <span>{(v.flags ?? []).join(', ') || '-'}</span>
      </div>
    </button>
  {:else}
    <div class="dim empty">no runs yet</div>
  {/each}
</div>

<style>
  form { display: flex; flex-direction: column; gap: 6px; padding: 10px; border-bottom: 1px solid var(--line); }
  form .row { display: flex; gap: 6px; }
  form .row select { flex: 1; }
  textarea { min-height: 96px; resize: vertical; font-family: var(--mono); font-size: 12px; }
  .mitm { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--dim); }
  .mitm input { width: auto; }
  .hd { padding: 10px 10px 4px; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--dim); }
  .runs { display: flex; flex-direction: column; gap: 6px; padding: 6px 10px 16px; }
  .card { text-align: left; background: var(--panel); padding: 7px 9px; display: flex; flex-direction: column; gap: 2px; }
  .card.sel { border-color: var(--acc); box-shadow: 0 0 0 1px var(--acc); }
  .top, .bot { display: flex; justify-content: space-between; gap: 8px; }
  .rid { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bot { font-size: 12px; }
  .empty { padding: 12px; }
</style>
