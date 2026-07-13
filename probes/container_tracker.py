#!/usr/bin/env python3
"""
OSmosis - Container Tracker
Reads /sys/fs/cgroup hierarchy to build cgroup_id → container_name map.
Streams the map as JSON on startup and every 30s (or on SIGHUP refresh).

Run: sudo python3 probes/container_tracker.py
"""

import os, json, re, signal, time

CGROUP_BASE = "/sys/fs/cgroup"

def build_cgroup_map():
    """Walk cgroup tree, map numeric IDs to container names."""
    cgroup_map = {}
    for root, dirs, files in os.walk(CGROUP_BASE):
        if "cgroup.id" in files:
            try:
                with open(os.path.join(root, "cgroup.id")) as f:
                    cgroup_id = int(f.read().strip())
                # Docker containers show as: docker-<64-char-hash>.scope
                match = re.search(r'docker[-/]([a-f0-9]{12})', root)
                container_id = match.group(1) if match else os.path.basename(root)
                cgroup_map[cgroup_id] = container_id
            except (PermissionError, ValueError, FileNotFoundError):
                pass
    return cgroup_map

def stream_map():
    cgroup_map = build_cgroup_map()

    def refresh(signum, frame):
        nonlocal cgroup_map
        cgroup_map = build_cgroup_map()
        print(json.dumps({"event": "refresh", "entries": len(cgroup_map)}), flush=True)

    signal.signal(signal.SIGHUP, refresh)

    # Emit initial full map
    print(json.dumps({
        "event": "cgroup_map",
        "map": {str(k): v for k, v in cgroup_map.items()}
    }), flush=True)

    while True:
        time.sleep(30)
        cgroup_map = build_cgroup_map()
        print(json.dumps({
            "event": "cgroup_map",
            "map": {str(k): v for k, v in cgroup_map.items()}
        }), flush=True)

if __name__ == "__main__":
    stream_map()
