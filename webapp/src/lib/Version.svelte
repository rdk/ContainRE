<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type VersionInfo } from './api';

  let info = $state<VersionInfo | null>(null);
  let err = $state('');

  onMount(() => {
    api.version().then((v) => (info = v)).catch((e) => (err = String(e)));
  });

  // null (absent dependency / unavailable probe) renders as this.
  const shown = (v: string | null) => (v == null ? 'not installed' : v);
</script>

<div class="about">
  <h2>Version &amp; environment</h2>
  <p class="dim">
    The same data is available from the CLI (<code>containre --version</code>) and
    the <code>GET /api/version</code> endpoint.
  </p>

  {#if err}
    <div class="err">Could not load version info: {err}</div>
  {:else if !info}
    <div class="dim">loading…</div>
  {:else}
    <section>
      <h3>Package</h3>
      <div class="pkg">containre <span class="ver">{info.containre}</span></div>
    </section>

    <section>
      <h3>Dependencies</h3>
      <table>
        <tbody>
          {#each Object.entries(info.dependencies) as [name, ver]}
            <tr>
              <td class="k">{name}</td>
              <td class="v" class:absent={ver == null}>{shown(ver)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>

    <section>
      <h3>System</h3>
      <table>
        <tbody>
          {#each Object.entries(info.system) as [key, val]}
            <tr>
              <td class="k">{key}</td>
              <td class="v" class:absent={val == null}>{shown(val)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}
</div>

<style>
  .about { padding: 16px 20px; max-width: 720px; }
  h2 { margin: 0 0 4px; font-size: 16px; }
  h3 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--dim); }
  p { margin: 0 0 8px; font-size: 12px; }
  code { font-family: var(--mono); }
  section { margin-top: 18px; }
  .pkg { font-size: 15px; font-weight: 600; }
  .ver { color: var(--acc); }
  table { border-collapse: collapse; width: 100%; font-family: var(--mono); font-size: 12px; }
  td { padding: 3px 10px 3px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
  td.k { color: var(--dim); white-space: nowrap; width: 1%; }
  td.v { word-break: break-all; }
  td.absent { color: var(--dim); font-style: italic; }
  .err { color: var(--acc); font-size: 13px; }
</style>
