"""
OSmosis Attack Simulation — Controlled Fork Bomb
Spawns 2^MAX_DEPTH child processes, then waits for all to exit cleanly.
Watch sys_clone syscall count burst and scheduler context switches explode.

Usage: python3 attacks/fork_bomb_safe.py [depth]
       python3 attacks/fork_bomb_safe.py 5    (spawns 32 children)
WARNING: Keep depth ≤ 7 (128 processes). Higher values can stress WSL2.
"""

import os, sys, time

MAX_DEPTH = int(sys.argv[1]) if len(sys.argv) > 1 else 5
SPAWNED = []

def fork_limited(depth):
    if depth <= 0: return
    pid = os.fork()
    if pid == 0:     # child
        fork_limited(depth - 1)
        time.sleep(0.5)
        sys.exit(0)
    else:
        SPAWNED.append(pid)

print(f"[Attack] Fork bomb (safe): depth={MAX_DEPTH}, will spawn ~{2**MAX_DEPTH} processes.")
print("[Attack] Watch sys_clone burst in Syscall Heatmap and sched_preemptions spike.")
fork_limited(MAX_DEPTH)
for pid in SPAWNED:
    try: os.waitpid(pid, 0)
    except: pass
print(f"[Attack] All {2**MAX_DEPTH} children reaped cleanly.")
