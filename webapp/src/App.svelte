<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './lib/api';
  import RunList from './lib/RunList.svelte';
  import Detail from './lib/Detail.svelte';
  import Version from './lib/Version.svelte';

  let health = $state<any>(null);
  let runs = $state<any[]>([]);
  let selected = $state<string | null>(null);
  let view = $state<'runs' | 'about'>('runs');
  let theme = $state<'dark' | 'light'>('dark');

  function initialRun() {
    try {
      return new URLSearchParams(location.search).get('run');
    } catch {
      return null;
    }
  }

  async function refresh() {
    try { runs = (await api.runs()).runs; } catch {}
  }
  onMount(() => {
    selected = initialRun();
    api.health().then((h) => (health = h)).catch(() => {});
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  });

  function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
  }
  async function launch(body: any) {
    const res = await api.launch(body);
    await refresh();
    selected = res.run_id;
  }

  function selectRun(id: string) {
    selected = id;
    const url = new URL(location.href);
    url.searchParams.set('run', id);
    history.replaceState(null, '', url);
  }
</script>

<header>
  <span class="brand">Contain<span class="re">RE</span></span>
  <span class="dim tag">sandbox · tracer · flight recorder</span>
  <span class="spacer"></span>
  <nav class="nav">
    <button class:active={view === 'runs'} onclick={() => (view = 'runs')}>Runs</button>
    <button class:active={view === 'about'} onclick={() => (view = 'about')}>About</button>
  </nav>
  {#if health}<span class="dim">runtime={health.runtime} · cap={health.max_concurrent}</span>{/if}
  <button class="theme" onclick={toggleTheme} title="toggle theme">◑</button>
</header>

{#if view === 'about'}
  <main class="full"><Version /></main>
{:else}
  <div class="layout">
    <aside>
      <RunList {runs} {selected} onselect={selectRun} {launch} />
    </aside>
    <main>
      {#if selected}
        {#key selected}<Detail id={selected} />{/key}
      {:else}
        <div class="empty dim">Select a run on the left, or launch one to begin.</div>
      {/if}
    </main>
  </div>
{/if}

<style>
  header {
    display: flex; align-items: center; gap: 12px;
    padding: 9px 16px; border-bottom: 1px solid var(--line); background: var(--panel);
  }
  .brand { font-size: 16px; font-weight: 700; letter-spacing: -0.02em; }
  .re { color: var(--acc); }
  .tag { font-size: 12px; }
  .spacer { flex: 1; }
  .theme { padding: 2px 8px; }
  .nav { display: flex; gap: 4px; }
  .nav button { padding: 2px 10px; }
  .nav button.active { color: var(--acc); font-weight: 600; }
  .layout { display: grid; grid-template-columns: 340px 1fr; height: calc(100vh - 45px); }
  aside { border-right: 1px solid var(--line); overflow: auto; }
  main { overflow: auto; }
  main.full { height: calc(100vh - 45px); }
  .empty { padding: 40px; text-align: center; }
</style>
