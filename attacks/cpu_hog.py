"""
OSmosis Attack Simulation — CPU Starvation
Pegs one CPU core at 100% for a specified duration.
Watch sched_preemptions count spike in the Process Monitor.

Usage: python3 attacks/cpu_hog.py [duration_seconds]
       python3 attacks/cpu_hog.py 15
"""

import time, sys

duration = int(sys.argv[1]) if len(sys.argv) > 1 else 10
print(f"[Attack] CPU hog running for {duration}s. PID={os.getpid()}")
print("[Attack] Watch sched_preemptions spike for this PID in OSmosis.")
import os

end = time.time() + duration
ops = 0
while time.time() < end:
    _ = sum(i * i for i in range(10000))
    ops += 1

print(f"[Attack] Done. Completed {ops} computation cycles.")
