<script lang="ts">
  import { api, type Ev } from './api';

  let { id, snapshots } = $props<{ id: string; snapshots: Ev[] }>();
  let current = $state<any>(null);
  let loading = $state(false);

  async function view(snapshotId: string, base?: string) {
    loading = true;
    try { current = await api.memory(id, snapshotId, base); } catch {}
    loading = false;
  }
</script>

<div class="mem">
  <div class="snaps">
    {#each snapshots as s (s.seq)}
      <button class="snap" class:on={current?.snapshot_id === s.data.snapshot_id}
              onclick={() => view(s.data.snapshot_id)}>
        {s.data.reason ?? 'snap'} · {s.data.snapshot_id.slice(5, 13)}
      </button>
    {:else}<span class="dim">no snapshots - configure trace.snapshot_on</span>{/each}
  </div>

  {#if loading}<div class="dim pad">loading…</div>{/if}
  {#if current}
    <div class="cols">
      <div class="regions">
        <table>
          <thead><tr><th>base</th><th>size</th><th>perms</th><th>path</th></tr></thead>
          <tbody>
            {#each current.regions as r}
              <tr class:on={current.region?.base === r.base} onclick={() => view(current.snapshot_id, r.base)}>
                <td class="mono">{r.base}</td>
                <td class="dim">{r.size}</td>
                <td class="mono">{r.perms}</td>
                <td class="dim">{r.path || ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <pre class="hex">{current.hexdump || '(no bytes captured for this region)'}</pre>
    </div>
  {/if}
</div>

<style>
  .snaps { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
  .snap { background: var(--panel2); }
  .snap.on { border-color: var(--acc); }
  .cols { display: grid; grid-template-columns: minmax(240px, 340px) 1fr; gap: 12px; }
  .regions { max-height: 52vh; overflow: auto; border: 1px solid var(--line); border-radius: 8px; }
  .regions tr { cursor: pointer; }
  .regions tr.on { background: color-mix(in srgb, var(--acc) 18%, transparent); }
  .hex { margin: 0; background: var(--panel2); border: 1px solid var(--line); border-radius: 8px; padding: 10px; overflow: auto; max-height: 52vh; font-size: 12px; white-space: pre; }
  .pad { padding: 10px; }
</style>
