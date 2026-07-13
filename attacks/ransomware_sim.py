"""
OSmosis Attack Simulation — Ransomware Pattern
Generates the exact VFS fingerprint ransomware produces:
  vfs_open → vfs_read → vfs_write (encrypted data) → vfs_rename (.locked extension)

Run WHILE the OSmosis backend is active:
  python3 attacks/ransomware_sim.py
  Watch the dashboard: vfs_rename count should spike, triggering an alert.
SAFE: only touches /tmp/osmosis_test/
"""

import os, time

TEST_DIR = "/tmp/osmosis_test"
os.makedirs(TEST_DIR, exist_ok=True)

print("[Attack] Creating 100 test files in /tmp/osmosis_test/ ...")
for i in range(100):
    path = os.path.join(TEST_DIR, f"document_{i}.txt")
    with open(path, "w") as f:
        f.write("Sensitive corporate data " * 100)

print("[Attack] Simulating ransomware VFS chain (open → read → write → rename)...")
for i in range(100):
    src = os.path.join(TEST_DIR, f"document_{i}.txt")
    dst = os.path.join(TEST_DIR, f"document_{i}.enc.locked")
    with open(src, "rb") as f:
        data = f.read()
    encrypted = bytes(b ^ 0xAA for b in data)   # Toy XOR "encryption"
    with open(dst, "wb") as f:
        f.write(encrypted)
    os.rename(src, dst)
    time.sleep(0.01)  # 100 files/sec burst
    if i % 10 == 0:
        print(f"[Attack] {i+1}/100 files processed. Watch OSmosis vfs_rename spike.")

print("[Attack] Done. Check AlertPanel — anomaly score should have spiked.")
print("[Attack] Cleanup: rm -rf /tmp/osmosis_test")
