#!/bin/bash
# OSmosis Live Demo Script
# Runs all attacks in sequence with pauses for the audience to watch the dashboard.
# Usage: bash scripts/demo.sh

echo "╔══════════════════════════════════════════════════════╗"
echo "║            OSmosis Live Demo                         ║"
echo "║  Make sure the backend and dashboard are running:    ║"
echo "║    Terminal 1: make backend                          ║"
echo "║    Terminal 2: make dashboard                        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

echo ">>> Waiting 3s before starting attacks..."
sleep 3

echo ""
echo "=== [1/4] CPU Hog (10s) — Watch sched_preemptions spike ==="
python3 attacks/cpu_hog.py 10

echo ""
echo "=== Pausing 5s for dashboard to update ==="
sleep 5

echo ""
echo "=== [2/4] Ransomware Simulation — Watch vfs_rename burst ==="
python3 attacks/ransomware_sim.py

echo ""
echo "=== Pausing 5s for anomaly alert to appear ==="
sleep 5

echo ""
echo "=== [3/4] Fork Bomb (safe, depth=5) — Watch sys_clone spike ==="
python3 attacks/fork_bomb_safe.py 5

echo ""
echo "=== Pausing 5s ==="
sleep 5

echo ""
echo "=== [4/4] Memory Leak (30s) — Watch alloc/free diverge ==="
timeout 30 python3 attacks/memory_leak.py || true

echo ""
echo "=== Demo complete. Check the Alerts tab on the dashboard. ==="
