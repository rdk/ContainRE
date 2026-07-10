export type Ev = { schema_version: number; seq: number; ts_mono: number; pid?: number; kind: string; data: any };
export type Meta = Record<string, any>;

async function J(url: string, opts?: RequestInit) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export const api = {
  health: () => J('/api/health'),
  runs: (): Promise<{ runs: Meta[] }> => J('/api/runs'),
  run: (id: string): Promise<Meta> => J(`/api/runs/${id}`),
  events: (id: string, since = 0, limit = 2000, kind?: string) =>
    J(`/api/runs/${id}/events?since=${since}&limit=${limit}${kind ? `&kind=${kind}` : ''}`),
  detections: (id: string) => J(`/api/runs/${id}/detections`),
  snapshots: (id: string) => J(`/api/runs/${id}/snapshots`),
  memory: (id: string, snap: string, base?: string) =>
    J(`/api/runs/${id}/memory?snapshot=${snap}${base ? `&base=${base}` : ''}`),
  artifacts: (id: string): Promise<{ artifacts: { name: string; size: number }[] }> =>
    J(`/api/runs/${id}/artifacts`),
  launch: (body: any) =>
    J('/api/runs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
  stop: (id: string) => J(`/api/runs/${id}/stop`, { method: 'POST' }),
  checkpoint: (id: string, name = 'checkpoint') =>
    J(`/api/runs/${id}/checkpoint?name=${encodeURIComponent(name)}`, { method: 'POST' }),
  checkpoints: (id: string): Promise<{ checkpoints: any[] }> => J(`/api/runs/${id}/checkpoints`),
  staticAnalysis: (id: string, refresh = false, query = '') =>
    J(`/api/runs/${id}/static?refresh=${refresh}${query ? `&query=${encodeURIComponent(query)}` : ''}`),
  staticQuery: (id: string, symbol: string, direction = 'both', refresh = false, limit = 120) =>
    J(`/api/runs/${id}/static/query?symbol=${encodeURIComponent(symbol)}&direction=${direction}&refresh=${refresh}&limit=${limit}`),
};

export type Stream = { close: () => void };

const TERMINAL = ['finished', 'killed', 'error'];

// Resilient live stream: reconnects (resuming from the last seq via ?since=) if
// the socket drops mid-run, guards JSON.parse, and surfaces {type:'error'}
// frames. Stops reconnecting once the run reaches a terminal, inactive status so
// a finished run doesn't loop.
export function stream(
  id: string, since: number,
  onEvent: (e: Ev) => void, onStatus: (s: string, active: boolean) => void,
  onError?: (msg: string) => void,
): Stream {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  let lastSeq = since - 1;
  let closed = false;
  let done = false;
  let retry = 0;
  let ws: WebSocket | null = null;

  function connect() {
    if (closed || done) return;
    ws = new WebSocket(`${proto}://${location.host}/api/runs/${id}/stream?since=${lastSeq + 1}`);
    ws.onmessage = (m) => {
      let msg: any;
      try { msg = JSON.parse(m.data); } catch { return; }
      if (msg.type === 'event') {
        if (typeof msg.event?.seq === 'number') lastSeq = msg.event.seq;
        onEvent(msg.event);
      } else if (msg.type === 'status') {
        retry = 0;
        if (TERMINAL.includes(msg.status) && !msg.active) done = true;
        onStatus(msg.status, msg.active);
      } else if (msg.type === 'error') {
        // The backend sends an error frame then closes (no such run / bad since);
        // treat it as terminal so onclose does not reconnect in a tight loop.
        done = true;
        onError?.(msg.message ?? 'stream error');
      }
    };
    ws.onclose = () => {
      if (closed || done) return;
      const delay = Math.min(1000 * 2 ** retry, 15000);
      retry += 1;
      setTimeout(connect, delay);
    };
    ws.onerror = () => { try { ws?.close(); } catch { /* ignore */ } };
  }

  connect();
  return { close() { closed = true; try { ws?.close(); } catch { /* ignore */ } } };
}

export async function pcapExists(id: string): Promise<boolean> {
  try {
    return (await fetch(`/api/runs/${id}/pcap`, { method: 'HEAD' })).ok;
  } catch {
    return false;
  }
}
