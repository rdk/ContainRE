<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './api';

  let { id } = $props<{ id: string }>();

  let data = $state<any>(null);
  let result = $state<any>(null);
  let query = $state(new URLSearchParams(location.search).get('symbol') ?? '');
  let busy = $state(false);
  let message = $state('');

  const symbols = $derived((data?.symbols ?? []).slice(0, 240));
  const imports = $derived((data?.imports ?? []).slice(0, 120));
  const edges = $derived((data?.call_edges ?? []).slice(0, 160));
  function shortLabel(value: unknown, max = 42) {
    const text = String(value ?? '');
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
  }
  const graph = $derived.by(() => {
    const q = query.trim() || result?.query || 'query';
    const callers = Array.from(new Set((result?.callers ?? []).map((e: any) => e.from_normalized || e.from))).slice(0, 8);
    const callees = Array.from(new Set((result?.callees ?? []).map((e: any) => e.to_normalized || e.to))).slice(0, 8);
    const nodes: any[] = [{ id: q, label: shortLabel(q), title: q, role: 'query', x: 390, y: 170 }];
    callers.forEach((name, i) => nodes.push({ id: `caller:${name}`, label: shortLabel(name), title: name, role: 'caller', x: 120, y: 45 + i * 36 }));
    callees.forEach((name, i) => nodes.push({ id: `callee:${name}`, label: shortLabel(name), title: name, role: 'callee', x: 660, y: 45 + i * 36 }));
    const links = [
      ...callers.map((name) => ({ from: `caller:${name}`, to: q })),
      ...callees.map((name) => ({ from: q, to: `callee:${name}` })),
    ];
    return { nodes, links };
  });

  async function load(refresh = false) {
    busy = true;
    message = refresh ? 'refreshing static evidence...' : 'loading static evidence...';
    try {
      data = await api.staticAnalysis(id, refresh, query.trim());
      message = '';
    } catch (e) {
      message = 'static analysis failed: ' + (e as Error).message;
    }
    busy = false;
  }

  async function search(refresh = false) {
    const symbol = query.trim();
    if (!symbol) return;
    busy = true;
    message = 'querying call graph...';
    try {
      result = await api.staticQuery(id, symbol, 'both', refresh, 120);
      if (!data || refresh) data = await api.staticAnalysis(id, false, symbol);
      message = '';
    } catch (e) {
      message = 'query failed: ' + (e as Error).message;
    }
    busy = false;
  }

  function node(id: string) {
    return graph.nodes.find((n: any) => n.id === id);
  }

  onMount(async () => {
    await load(false);
    if (query.trim()) await search(false);
  });
</script>

<section class="static">
  <div class="panel">
    <div class="static-head">
      <div>
        <h3>Static Evidence</h3>
        <div class="dim">{data?.target ?? 'Analyze the run specimen to extract symbols and call sites.'}</div>
      </div>
      <button onclick={() => load(true)} disabled={busy}>Refresh</button>
    </div>

    {#if message}<div class="dim msg">{message}</div>{/if}

    <div class="metrics">
      <div><b>{data?.summary?.files_total ?? 0}</b><span>files</span></div>
      <div><b>{data?.summary?.symbols ?? 0}</b><span>symbols</span></div>
      <div><b>{data?.summary?.functions ?? 0}</b><span>functions</span></div>
      <div><b>{data?.summary?.call_edges ?? 0}</b><span>direct calls</span></div>
      <div><b>{data?.summary?.imports ?? 0}</b><span>imports</span></div>
      <div><b>{data?.summary?.warnings ?? 0}</b><span>warnings</span></div>
    </div>

    <form class="query" onsubmit={(e) => { e.preventDefault(); search(false); }}>
      <input bind:value={query} placeholder="symbol or function name, e.g. main, connect, LicenseManager" />
      <button class="primary" disabled={busy || !query.trim()}>Search</button>
      <button type="button" onclick={() => search(true)} disabled={busy || !query.trim()}>Search + refresh</button>
    </form>
  </div>

  {#if result}
    <div class="grid">
      <div class="panel graph-panel">
        <h3>Call Graph</h3>
        <svg viewBox="0 0 780 340" role="img" aria-label="call graph">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z"></path>
            </marker>
          </defs>
          {#each graph.links as link}
            {@const a = node(link.from)}
            {@const b = node(link.to)}
            {#if a && b}
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} marker-end="url(#arrow)"></line>
            {/if}
          {/each}
          {#each graph.nodes as n}
            <g transform="translate({n.x},{n.y})" class:nq={n.role === 'query'}>
              <title>{n.title}</title>
              <circle r={n.role === 'query' ? 19 : 13}></circle>
              <text x="0" y={n.role === 'query' ? -27 : -19}>{n.label}</text>
            </g>
          {/each}
        </svg>
        <div class="dim">Confirmed direct calls only. Imports, strings, and source references are listed separately.</div>
      </div>

      <div class="panel">
        <h3>Query Results</h3>
        <div class="cols">
          <div>
            <h4>Callers ({result.callers.length})</h4>
            {#each result.callers as e}
              <div class="edge">{e.from} <span class="dim">at {e.callsite}</span></div>
            {:else}<div class="dim">none found</div>{/each}
          </div>
          <div>
            <h4>Callees ({result.callees.length})</h4>
            {#each result.callees as e}
              <div class="edge">{e.to} <span class="dim">at {e.callsite}</span></div>
            {:else}<div class="dim">none found</div>{/each}
          </div>
        </div>
        {#if result.string_refs?.length}
          <h4>String References</h4>
          {#each result.string_refs.slice(0, 12) as s}
            <div class="ref"><span class="dim">{s.file}:{s.offset}</span> {s.value}</div>
          {/each}
        {/if}
      </div>
    </div>
  {/if}

  <div class="grid">
    <div class="panel">
      <h3>Symbols</h3>
      <div class="list">
        {#each symbols as s}
          <button type="button" onclick={() => { query = s.name; search(false); }}>
            <span>{s.name}</span><span class="dim">{s.type} {s.address ?? ''}</span>
          </button>
        {:else}<div class="dim">no symbols extracted</div>{/each}
      </div>
    </div>
    <div class="panel">
      <h3>Imports</h3>
      <div class="list">
        {#each imports as s}
          <button type="button" onclick={() => { query = s.name; search(false); }}>
            <span>{s.name}</span><span class="dim">{s.type}</span>
          </button>
        {:else}<div class="dim">no imports extracted</div>{/each}
      </div>
    </div>
  </div>

  <div class="panel">
    <h3>Recent Direct Calls</h3>
    <div class="stream">
      {#each edges as e}
        <div class="call"><span class="dim">{e.file} {e.callsite}</span> {e.from} <span class="dim">→</span> {e.to}</div>
      {:else}<div class="dim">no direct call edges extracted</div>{/each}
    </div>
  </div>
</section>

<style>
  .static { display: flex; flex-direction: column; gap: 12px; }
  .panel { background: var(--panel2); border: 1px solid var(--line); border-radius: 8px; padding: 10px; }
  .static-head { display: flex; align-items: flex-start; gap: 10px; }
  .static-head > div { flex: 1; min-width: 0; }
  .msg { margin-top: 6px; }
  .metrics { display: grid; grid-template-columns: repeat(6, minmax(80px, 1fr)); gap: 8px; margin-top: 10px; }
  .metrics div { border: 1px solid var(--line); padding: 7px 8px; background: var(--panel); }
  .metrics b { display: block; font-size: 16px; }
  .metrics span { color: var(--dim); font-size: 11px; }
  .query { display: flex; gap: 6px; margin-top: 10px; }
  .query input { flex: 1; min-width: 160px; }
  .grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; }
  h3 { font-size: 13px; margin-bottom: 6px; }
  h4 { color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; margin: 8px 0 4px; }
  svg { width: 100%; height: 330px; background: var(--panel); border: 1px solid var(--line); }
  line { stroke: var(--dim); stroke-width: 1.2; }
  marker path { fill: var(--dim); }
  circle { fill: var(--panel2); stroke: var(--acc); stroke-width: 1.4; }
  .nq circle { fill: var(--acc); stroke: var(--acc); }
  text { fill: var(--fg); font-size: 11px; text-anchor: middle; paint-order: stroke; stroke: var(--panel); stroke-width: 3px; stroke-linejoin: round; }
  .nq text { font-weight: 700; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .edge, .ref, .call { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding: 2px 0; }
  .list { max-height: 260px; overflow: auto; display: flex; flex-direction: column; gap: 3px; }
  .list button { display: flex; justify-content: space-between; gap: 8px; text-align: left; border-radius: 4px; padding: 3px 6px; }
  .list button span:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .stream { max-height: 240px; overflow: auto; }
  @media (max-width: 980px) {
    .grid, .cols { grid-template-columns: 1fr; }
    .metrics { grid-template-columns: repeat(2, minmax(80px, 1fr)); }
    .query { flex-wrap: wrap; }
  }
</style>
