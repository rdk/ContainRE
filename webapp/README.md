# ContainRE webapp

Vite + **Svelte 5** single-page dashboard for the ContainRE control plane. It is a
pure client of the REST + WebSocket API (`/api/...`) served by `containre serve`.

## Panels
- **Overview** - launch form (binary, network posture, L2 mode, decoys) + a live
  list of all runs with status, severity, and flags (drive many at once).
- **Run detail** - verdict + an activity distribution bar, and tabs:
  - **Events** - live WebSocket stream, color-coded, with a per-kind filter.
  - **Detections** - heuristic + YARA findings with IOCs and ATT&CK ids.
  - **Memory** - online viewer: snapshot picker → clickable region map → hexdump.
  - **L2 trace** - per-instruction disassembly with register deltas and memory writes.
  - **Artifacts** - dropped-file downloads + `capture.pcap`.
- Dark/light theme toggle.

## Build

```bash
npm install
npm run build      # -> webapp/build/  (committed; served by `containre serve`)
npm run dev        # vite dev server on :5173, proxies /api to :8787
```

`containre serve` serves `webapp/build/` at `/` when present, and falls back to the
minimal inline dashboard (`containre/api/static/index.html`) otherwise.
