"""
OSmosis - Event Aggregator
Converts raw probe JSON events into per-process ProcessSummary state.
This is the stateful core that feeds both the ML scorer and the dashboard.
"""

from collections import defaultdict
from typing import Dict

def make_empty_process(pid: int, comm: str = "", cgroup_id: int = 0) -> dict:
    return {
        "pid": pid, "comm": comm, "cgroup_id": cgroup_id,
        "container_id": "host",
        "syscall_count": 0, "page_faults": 0, "major_faults": 0,
        "sched_preemptions": 0, "vfs_reads": 0, "vfs_writes": 0,
        "vfs_renames": 0, "page_allocs": 0, "page_frees": 0,
        "write_count": 0, "open_count": 0, "fork_count": 0,
        "mmap_count": 0, "syscall_types": set(), "syscall_diversity": 0,
        "risk_score": 0.0,
    }

class EventAggregator:
    """
    Maintains a dict of pid → ProcessSummary.
    update() accepts a raw parsed JSON event dict and updates state.
    Returns the mutated process summary for the caller to score and broadcast.
    """

    def __init__(self):
        self._procs: Dict[int, dict] = defaultdict(lambda: make_empty_process(0))
        self._cgroup_map: Dict[int, str] = {}

    def update_cgroup_map(self, cgroup_map: dict):
        """Ingest a cgroup_id → container_name mapping from container_tracker."""
        for k, v in cgroup_map.items():
            self._cgroup_map[int(k)] = v

    def resolve_container(self, cgroup_id: int) -> str:
        return self._cgroup_map.get(cgroup_id, "host")

    def update(self, event: dict) -> dict:
        """
        Apply one raw event to per-process state.
        Returns the updated ProcessSummary dict.
        """
        pid       = event.get("pid", 0)
        comm      = event.get("comm", "?")
        cgroup_id = event.get("cgroup_id", 0)
        etype     = event.get("type", "unknown")

        ps = self._procs[pid]
        ps["pid"]          = pid
        ps["comm"]         = comm or ps["comm"]
        ps["cgroup_id"]    = cgroup_id
        ps["container_id"] = self.resolve_container(cgroup_id)

        if etype == "syscall":
            ps["syscall_count"] += 1
            sc = event.get("syscall", "")
            ps["syscall_types"].add(sc)
            if "write"  in sc:                        ps["write_count"] += 1
            if "open"   in sc:                        ps["open_count"]  += 1
            if "fork"   in sc or "clone" in sc:       ps["fork_count"]  += 1
            if "mmap"   in sc:                        ps["mmap_count"]  += 1

        elif etype == "memory":
            me = event.get("mem_event", "")
            if me == "page_fault":
                ps["page_faults"] += 1
                if event.get("is_major"): ps["major_faults"] += 1
            elif me == "page_alloc": ps["page_allocs"] += 1
            elif me == "page_free":  ps["page_frees"]  += 1

        elif etype == "sched_switch":
            ps["sched_preemptions"] += 1

        elif etype == "io":
            op = event.get("io_op", "")
            if op == "vfs_read":   ps["vfs_reads"]   += 1
            if op == "vfs_write":  ps["vfs_writes"]  += 1
            if op == "vfs_rename": ps["vfs_renames"] += 1

        # Always refresh diversity count
        ps["syscall_diversity"] = len(ps.get("syscall_types", set()))

        return ps

    def get_all_processes(self) -> list:
        """Return all process summaries (without the internal set)."""
        result = []
        for ps in self._procs.values():
            d = {k: v for k, v in ps.items() if k != "syscall_types"}
            result.append(d)
        return result

    def get_process(self, pid: int) -> dict:
        ps = self._procs.get(pid, {})
        return {k: v for k, v in ps.items() if k != "syscall_types"}

    def get_top_processes(self, n: int = 30) -> list:
        all_procs = self.get_all_processes()
        return sorted(all_procs, key=lambda x: x["syscall_count"], reverse=True)[:n]
