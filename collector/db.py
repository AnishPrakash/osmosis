"""
OSmosis - Async SQLite Interface
Non-blocking time-series event store via aiosqlite.
Dual-table schema: events (raw) + anomaly_scores (ML results) + cgroup_map.
"""

import aiosqlite, json, time
from pathlib import Path
from typing import Optional

DB_PATH = Path("osmosis.db")

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_s         REAL NOT NULL,
    ts_ns        INTEGER,
    type         TEXT NOT NULL,
    pid          INTEGER,
    cgroup_id    INTEGER,
    container_id TEXT DEFAULT 'host',
    comm         TEXT,
    latency_ns   INTEGER,
    payload      TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts_s);
CREATE INDEX IF NOT EXISTS idx_events_pid       ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_container ON events(container_id);

CREATE TABLE IF NOT EXISTS anomaly_scores (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_s         REAL NOT NULL,
    pid          INTEGER,
    container_id TEXT,
    comm         TEXT,
    score        REAL,
    is_anomaly   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sched_timeline (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_s         REAL NOT NULL,
    cpu          INTEGER,
    prev_pid     INTEGER,
    prev_comm    TEXT,
    next_pid     INTEGER,
    next_comm    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sched_ts ON sched_timeline(ts_s);

CREATE TABLE IF NOT EXISTS cgroup_map (
    cgroup_id    INTEGER PRIMARY KEY,
    container_id TEXT,
    updated_at   REAL
);
"""

async def init_db(path: Path = DB_PATH) -> Path:
    async with aiosqlite.connect(path) as db:
        await db.executescript(CREATE_SQL)
        await db.commit()
    return path

async def insert_event(db_path: Path, event: dict):
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO events "
            "(ts_s, ts_ns, type, pid, cgroup_id, container_id, comm, latency_ns, payload) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                event.get("ts_s", time.time()),
                event.get("ts_ns"),
                event.get("type", "unknown"),
                event.get("pid"),
                event.get("cgroup_id"),
                event.get("container_id", "host"),
                event.get("comm"),
                event.get("latency_ns"),
                json.dumps(event),
            )
        )
        # Also write scheduler events to timeline table for /api/timeline
        if event.get("type") == "sched_switch":
            await db.execute(
                "INSERT INTO sched_timeline (ts_s, cpu, prev_pid, prev_comm, next_pid, next_comm) "
                "VALUES (?,?,?,?,?,?)",
                (
                    event.get("ts_s", time.time()),
                    event.get("cpu", 0),
                    event.get("prev_pid"),
                    event.get("prev_comm"),
                    event.get("next_pid"),
                    event.get("next_comm"),
                )
            )
        await db.commit()

async def insert_anomaly(db_path: Path, pid: int, comm: str, container_id: str,
                          score: float, is_anomaly: bool):
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO anomaly_scores (ts_s, pid, container_id, comm, score, is_anomaly) "
            "VALUES (?,?,?,?,?,?)",
            (time.time(), pid, container_id, comm, score, int(is_anomaly))
        )
        await db.commit()

async def upsert_cgroup(db_path: Path, cgroup_id: int, container_id: str):
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT OR REPLACE INTO cgroup_map (cgroup_id, container_id, updated_at) "
            "VALUES (?,?,?)",
            (cgroup_id, container_id, time.time())
        )
        await db.commit()

async def get_recent_events(db_path: Path, limit: int = 200,
                             event_type: Optional[str] = None) -> list:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        if event_type:
            rows = await db.execute_fetchall(
                "SELECT payload FROM events WHERE type=? ORDER BY ts_s DESC LIMIT ?",
                (event_type, limit)
            )
        else:
            rows = await db.execute_fetchall(
                "SELECT payload FROM events ORDER BY ts_s DESC LIMIT ?", (limit,)
            )
        return [json.loads(r["payload"]) for r in rows]

async def get_timeline(db_path: Path, seconds: int = 10) -> list:
    """Get scheduler timeline for the last N seconds — powers the Gantt chart."""
    cutoff = time.time() - seconds
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        rows = await db.execute_fetchall(
            "SELECT ts_s, cpu, prev_pid, prev_comm, next_pid, next_comm "
            "FROM sched_timeline WHERE ts_s >= ? ORDER BY ts_s ASC LIMIT 500",
            (cutoff,)
        )
        return [dict(r) for r in rows]
