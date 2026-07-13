"""
OSmosis Attack Simulation — Memory Leak
Forces kmem:mm_page_alloc events WITHOUT corresponding mm_page_free.
The growing alloc - free delta is the leak signal OSmosis catches.
Invisible to CPU and I/O metrics — only visible at the memory tracepoint layer.

Run: python3 attacks/memory_leak.py
     Ctrl+C to stop and release all memory.
"""

import time

allocations = []
print("[Attack] Memory leak simulation starting. Ctrl+C to stop.")
print("[Attack] Watch page_alloc - page_free diverge in the Memory tab.")

total_mb = 0
try:
    while True:
        chunk = bytearray(10 * 1024 * 1024)
        for i in range(0, len(chunk), 4096):
            chunk[i] = 1   # Touch each page to force kmem:mm_page_alloc events
        allocations.append(chunk)
        total_mb += 10
        print(f"[Attack] Total allocated: {total_mb} MB | "
              f"alloc/free delta rising...", end="\r")
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\n[Attack] Stopped. Releasing {total_mb} MB...")
    allocations.clear()
    print("[Attack] Memory released. alloc/free delta should normalize.")
