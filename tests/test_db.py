"""
Tests for collector/db.py — async SQLite interface.
Uses a temporary in-memory-like DB path.
"""
import pytest
import asyncio
import tempfile
from pathlib import Path
from collector.db import init_db, insert_event, get_recent_events, get_timeline


@pytest.fixture
def tmp_db(tmp_path):
    return tmp_path / "test_osmosis.db"


@pytest.mark.asyncio
async def test_init_creates_tables(tmp_db):
    db_path = await init_db(tmp_db)
    assert db_path.exists()


@pytest.mark.asyncio
async def test_insert_and_retrieve_event(tmp_db):
    await init_db(tmp_db)
    event = {
        "type": "syscall", "pid": 1234, "comm": "bash",
        "cgroup_id": 0, "container_id": "host",
        "syscall": "read", "ts_s": 1720000000.0, "ts_ns": 0,
    }
    await insert_event(tmp_db, event)
    events = await get_recent_events(tmp_db, limit=10)
    assert len(events) == 1
    assert events[0]["pid"] == 1234
    assert events[0]["comm"] == "bash"


@pytest.mark.asyncio
async def test_filter_by_event_type(tmp_db):
    await init_db(tmp_db)
    await insert_event(tmp_db, {"type": "syscall",  "pid": 1, "ts_s": 1.0, "comm": "a"})
    await insert_event(tmp_db, {"type": "memory",   "pid": 2, "ts_s": 2.0, "comm": "b"})
    await insert_event(tmp_db, {"type": "syscall",  "pid": 3, "ts_s": 3.0, "comm": "c"})

    syscalls = await get_recent_events(tmp_db, limit=10, event_type="syscall")
    assert len(syscalls) == 2
    assert all(e["type"] == "syscall" for e in syscalls)


@pytest.mark.asyncio
async def test_sched_timeline_stored(tmp_db):
    await init_db(tmp_db)
    import time
    sched_event = {
        "type": "sched_switch",
        "pid": 0, "ts_s": time.time(),
        "cpu": 0, "prev_pid": 100, "prev_comm": "bash",
        "next_pid": 200, "next_comm": "python3",
    }
    await insert_event(tmp_db, sched_event)
    timeline = await get_timeline(tmp_db, seconds=60)
    assert len(timeline) == 1
    assert timeline[0]["next_comm"] == "python3"


@pytest.mark.asyncio
async def test_empty_db_returns_empty_list(tmp_db):
    await init_db(tmp_db)
    events = await get_recent_events(tmp_db, limit=10)
    assert events == []
