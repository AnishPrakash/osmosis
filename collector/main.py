"""
OSmosis - FastAPI Collector Backend v2
Spawns all 5 eBPF probes, aggregates events via EventAggregator,
stores to SQLite asynchronously, and fans out to WebSocket clients.
"""

import asyncio, json, time
from collections import deque
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from collector.aggregator import EventAggregator
from collector.db import init_db, insert_event, insert_anomaly, upsert_cgroup, \
    get_recent_events, get_timeline
from ml.inference import AnomalyScorer

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="OSmosis Collector", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ── Global state ──────────────────────────────────────────────────────────────
DB_PATH: Optional[Path]  = None
connected_ws: list[WebSocket] = []
event_buffer: deque       = deque(maxlen=5000)
aggregator                = EventAggregator()
scorer                    = AnomalyScorer()

# ── Probe subprocess commands ─────────────────────────────────────────────────
PROBES = [
    ["sudo", "python3", "probes/syscall_tracer.py"],
    ["sudo", "python3", "probes/scheduler_tracer.py"],
    ["sudo", "python3", "probes/memory_tracer.py"],
    ["sudo", "python3", "probes/io_tracer.py"],
    ["sudo", "python3", "probes/container_tracker.py"],
]

async def run_probe(cmd: list[str]):
    """Launch a probe subprocess and consume its stdout JSON stream."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        try:
            event = json.loads(line.decode().strip())
            # container_tracker sends map updates, not standard events
            if event.get("event") == "cgroup_map":
                aggregator.update_cgroup_map(event.get("map", {}))
                for k, v in event.get("map", {}).items():
                    await upsert_cgroup(DB_PATH, int(k), v)
            else:
                await process_event(event)
        except Exception:
            pass

async def process_event(event: dict):
    """Core event processing: aggregate → score → store → broadcast."""
    # Aggregate into per-process state
    ps = aggregator.update(event)
    event["container_id"] = ps.get("container_id", "host")

    # Score every 50 syscalls per process
    if ps["syscall_count"] % 50 == 0 and ps["syscall_count"] > 0:
        score = scorer.score(ps)
        ps["risk_score"] = score
        event["risk_score"] = score
        if scorer.is_anomaly(ps):
            await insert_anomaly(
                DB_PATH, ps["pid"], ps["comm"],
                ps["container_id"], score, True
            )

    # Buffer and persist
    event_buffer.appendleft(event)
    await insert_event(DB_PATH, event)

    # Broadcast to all WebSocket clients
    msg = json.dumps(event)
    dead = []
    for ws in connected_ws:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for d in dead:
        connected_ws.remove(d)

# ── Startup ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global DB_PATH
    DB_PATH = await init_db()
    for cmd in PROBES:
        asyncio.create_task(run_probe(cmd))
    print("[OSmosis] Collector v2 started. All probes launching...")

# ── REST Endpoints ─────────────────────────────────────────────────────────────
@app.get("/api/events")
async def api_events(limit: int = 100, event_type: str = None):
    return JSONResponse(await get_recent_events(DB_PATH, limit=limit, event_type=event_type))

@app.get("/api/processes")
async def api_processes():
    return JSONResponse(aggregator.get_top_processes(30))

@app.get("/api/containers")
async def api_containers():
    """Aggregate stats grouped by container_id."""
    from collections import defaultdict
    by_cid = defaultdict(lambda: {
        "container_id": "", "syscall_count": 0, "page_faults": 0,
        "vfs_writes": 0, "vfs_renames": 0,
        "max_risk_score": 0.0, "process_count": 0
    })
    for ps in aggregator.get_all_processes():
        cid = ps.get("container_id", "host")
        c   = by_cid[cid]
        c["container_id"]   = cid
        c["syscall_count"] += ps["syscall_count"]
        c["page_faults"]   += ps["page_faults"]
        c["vfs_writes"]    += ps["vfs_writes"]
        c["vfs_renames"]   += ps["vfs_renames"]
        c["max_risk_score"] = max(c["max_risk_score"], ps["risk_score"])
        c["process_count"] += 1
    return JSONResponse(list(by_cid.values()))

@app.get("/api/timeline")
async def api_timeline(seconds: int = 10):
    """
    Returns scheduler context-switch events for the last N seconds.
    Powers the SchedulerTimeline Gantt chart in the dashboard.
    """
    return JSONResponse(await get_timeline(DB_PATH, seconds=seconds))

@app.get("/api/stats")
async def api_stats():
    return {
        "total_events_buffered": len(event_buffer),
        "active_processes":      len(aggregator.get_all_processes()),
        "connected_clients":     len(connected_ws),
    }

# ── WebSocket Endpoint ─────────────────────────────────────────────────────────
@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    connected_ws.append(websocket)
    try:
        # Send last 100 events as backlog on connect
        for evt in reversed(list(event_buffer)[:100]):
            await websocket.send_text(json.dumps(evt))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_ws:
            connected_ws.remove(websocket)
