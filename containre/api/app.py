"""FastAPI control plane: REST + live WebSocket, plus the embedded dashboard.

Both the CLI and the webapp are clients of this API. Runs are started non-blocking
so many specimens can be observed at once; live and post-hoc reads share one path.
"""
from __future__ import annotations

import asyncio
import copy
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import policy as P
from .manager import CapacityError, RunManager

_STATIC = Path(__file__).parent / "static"
_WEBAPP_BUILD = Path(__file__).resolve().parents[2] / "webapp" / "build"
_TERMINAL = {"finished", "killed", "error"}


class RunRequest(BaseModel):
    binary: str | None = None
    policy: dict | None = None
    args: list[str] | None = None
    net: str | None = None                 # deny | simulate | allow
    mitm: bool = False                     # TLS interception (simulate posture)
    decoys: list[str] | None = None
    timeout: int | None = None


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _build_policy(req: RunRequest) -> dict:
    if req.binary:
        policy = P.policy_for_binary(req.binary)
        if req.policy:
            policy = _deep_merge(policy, req.policy)
    elif req.policy:
        policy = P.apply_defaults(req.policy)
    else:
        raise HTTPException(400, "provide either 'binary' or 'policy'")
    if req.args is not None:
        policy["specimen"]["args"] = req.args
    if req.net:
        policy["network"]["posture"] = req.net
        policy["network"]["simulate"] = req.net == "simulate"
    if req.mitm:
        policy["network"]["mitm"] = True
    if req.decoys is not None:
        policy["files"]["decoys"] = req.decoys
    if req.timeout:
        policy["limits"]["wallclock_s"] = req.timeout
    errors = P.validate(policy)
    if errors:
        raise HTTPException(400, f"invalid policy: {errors}")
    return policy


def create_app(runs_root: Path | None = None, runtime_name: str | None = None,
               max_concurrent: int | None = None) -> FastAPI:
    manager = RunManager(
        runs_root=runs_root or os.environ.get("CONTAINRE_RUNS_ROOT"),
        runtime_name=runtime_name or os.environ.get("CONTAINRE_RUNTIME", "local"),
        max_concurrent=max_concurrent
        or (int(os.environ["CONTAINRE_MAX_CONCURRENT"]) if os.environ.get("CONTAINRE_MAX_CONCURRENT") else None),
    )
    app = FastAPI(title="ContainRE", version="0.1.0")
    app.state.manager = manager

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "runtime": manager.runtime_name,
                "max_concurrent": manager.max_concurrent}

    @app.post("/api/runs")
    def create_run_ep(req: RunRequest) -> JSONResponse:
        policy = _build_policy(req)
        try:
            return JSONResponse(manager.start(policy), status_code=201)
        except CapacityError as exc:
            raise HTTPException(429, str(exc))
        except FileNotFoundError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/runs")
    def list_runs_ep() -> dict:
        return {"runs": manager.list()}

    @app.get("/api/runs/{run_id}")
    def get_run_ep(run_id: str) -> dict:
        meta = manager.get(run_id)
        if meta is None:
            raise HTTPException(404, "no such run")
        return meta

    @app.post("/api/runs/{run_id}/stop")
    def stop_run_ep(run_id: str) -> dict:
        return {"stopped": manager.stop(run_id)}

    @app.get("/api/runs/{run_id}/events")
    def events_ep(run_id: str, since: int = 0, limit: int = 1000, kind: str | None = None) -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        return manager.events(run_id, since=since, limit=limit, kind=kind)

    @app.get("/api/runs/{run_id}/snapshots")
    def snapshots_ep(run_id: str) -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        return {"snapshots": manager.snapshots(run_id)}

    @app.get("/api/runs/{run_id}/detections")
    def detections_ep(run_id: str) -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        return {"detections": manager.detections(run_id)}

    @app.get("/api/runs/{run_id}/summary")
    def summary_ep(run_id: str, retry_threshold: int = 3) -> dict:
        summary = manager.summary(run_id, retry_threshold=retry_threshold)
        if summary is None:
            raise HTTPException(404, "no such run")
        return summary

    @app.get("/api/runs/{run_id}/static")
    def static_ep(run_id: str, refresh: bool = False, query: str | None = None) -> dict:
        result = manager.static_analysis(run_id, refresh=refresh, query=query)
        if result is None:
            raise HTTPException(404, "no such run")
        return result

    @app.get("/api/runs/{run_id}/static/query")
    def static_query_ep(
        run_id: str,
        symbol: str,
        direction: str = "both",
        refresh: bool = False,
        limit: int = 120,
    ) -> dict:
        if direction not in {"both", "callers", "callees"}:
            raise HTTPException(400, "direction must be both, callers, or callees")
        result = manager.static_query(
            run_id,
            symbol,
            direction=direction,
            refresh=refresh,
            limit=limit,
        )
        if result is None:
            raise HTTPException(404, "no such run")
        return result

    @app.get("/api/runs/{run_id}/artifacts")
    def artifacts_ep(run_id: str) -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        return {"artifacts": manager.artifacts(run_id)}

    @app.get("/api/runs/{run_id}/artifacts/{name}")
    def artifact_download_ep(run_id: str, name: str) -> FileResponse:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        p = manager.artifact_path(run_id, name)
        if p is None:
            raise HTTPException(404, "no such artifact")
        return FileResponse(p, filename=name, media_type="application/octet-stream")

    @app.post("/api/runs/{run_id}/checkpoint")
    def checkpoint_ep(run_id: str, name: str = "checkpoint") -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        return manager.checkpoint(run_id, name)

    @app.post("/api/runs/{run_id}/restore")
    def restore_ep(run_id: str, name: str = "checkpoint") -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        return manager.restore(run_id, name)

    @app.get("/api/runs/{run_id}/checkpoints")
    def checkpoints_ep(run_id: str) -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        return {"checkpoints": manager.checkpoints(run_id)}

    @app.get("/api/runs/{run_id}/pcap")
    def pcap_download_ep(run_id: str) -> FileResponse:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        p = manager.pcap_path(run_id)
        if p is None:
            raise HTTPException(404, "no pcap for this run")
        return FileResponse(p, filename=f"{run_id}.pcap",
                            media_type="application/vnd.tcpdump.pcap")

    @app.get("/api/runs/{run_id}/memory")
    def memory_ep(run_id: str, snapshot: str, base: str | None = None) -> dict:
        if manager.get(run_id) is None:
            raise HTTPException(404, "no such run")
        result = manager.memory(run_id, snapshot, base=base)
        if result is None:
            raise HTTPException(404, "no such snapshot")
        return result

    @app.websocket("/api/runs/{run_id}/stream")
    async def stream_ep(ws: WebSocket, run_id: str) -> None:
        await ws.accept()
        since = int(ws.query_params.get("since", 0))
        if manager.get(run_id) is None:
            await ws.send_json({"type": "error", "message": "no such run"})
            await ws.close()
            return
        try:
            while True:
                res = manager.events(run_id, since=since, limit=500)
                for event in res["events"]:
                    await ws.send_json({"type": "event", "event": event})
                since = res["next_seq"]
                meta = manager.get(run_id)
                status = meta["status"] if meta else "error"
                await ws.send_json({"type": "status", "status": status,
                                    "active": bool(meta and meta.get("active"))})
                if status in _TERMINAL and not (meta and meta.get("active")):
                    break
                await asyncio.sleep(0.2)
        except WebSocketDisconnect:
            return
        await ws.close()

    # Serve the built Svelte SPA at "/" if present; otherwise the inline dashboard.
    # Mounted last so all /api routes take precedence.
    if _WEBAPP_BUILD.is_dir():
        app.mount("/", StaticFiles(directory=_WEBAPP_BUILD, html=True), name="webapp")
    else:
        @app.get("/", response_class=HTMLResponse)
        def index() -> str:
            return (_STATIC / "index.html").read_text()

    return app


app = create_app()
