# OSmosis 🔬
> Real-Time Linux Kernel Behavioral Fingerprinting & ML Anomaly Detection

[![CI](https://github.com/YOUR_USERNAME/osmosis/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/osmosis/actions)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![eBPF](https://img.shields.io/badge/eBPF-kernel--native-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## What is OSmosis?

OSmosis attaches eBPF probes to the Linux kernel at runtime — with **zero kernel
modification** — and streams every syscall, scheduling decision, memory event, and
VFS I/O operation to a live dashboard. An Isolation Forest ML model (with optional
VAE+IF hybrid) continuously flags processes whose behavioral fingerprint deviates
from the established baseline.

**Production systems using the same stack:** Falco · Tetragon · Datadog Cloud Workload Security · Pixie

---

## Architecture

```
Linux Kernel
│
├── raw_syscalls:sys_enter  ──→ syscall_tracer.py    ─┐
├── sched:sched_switch      ──→ scheduler_tracer.py   │
├── handle_mm_fault kprobe  ──→ memory_tracer.py      ├──→ FastAPI Collector
├── vfs_read/write kprobes  ──→ io_tracer.py          │        │
├── kmem:mm_page_alloc/free ──→ memory_tracer.py      │        ├──→ SQLite DB
└── /sys/fs/cgroup          ──→ container_tracker.py  ┘        ├──→ ML Scorer
                                                                └──→ WebSocket → React Dashboard
```

## Quick Start

```bash
# 1. Setup
make setup

# 2. Start backend (requires Linux root for eBPF)
make backend

# 3. Start dashboard
make dashboard

# 4. Train ML model (after ~10 min baseline)
make train

# 5. Run attack simulations
make attack-ransom   # VFS rename burst
make attack-mem      # Memory leak
make attack-cpu      # CPU starvation
make attack-fork     # Fork bomb (safe)
```

## Modules

| Module | Lines | Description |
|--------|-------|-------------|
| `probes/` | ~300 | 5 eBPF kernel probes: syscall, scheduler, memory+latency, VFS/IO, container |
| `collector/` | ~350 | FastAPI v2 — async event aggregation, WebSocket fan-out, `/api/timeline` |
| `ml/` | ~280 | Isolation Forest + dynamic σ-thresholds + VAE+IF hybrid |
| `dashboard/` | ~600 | React tabs: Scheduler Gantt, Memory Pressure, Container View, Alert Panel |
| `attacks/` | ~120 | 4 simulation scripts covering all detection categories |
| `tests/` | ~150 | pytest suite — 14 tests, CI-ready |

## Docker (Least-Privilege — No `--privileged`)

```bash
docker compose up --build
# Uses CAP_BPF + CAP_PERFMON only — not SYS_ADMIN
```

## ML Approach

- **Isolation Forest** on 13-feature process-behavior vectors
- **Dynamic σ-thresholds** (2σ = suspicious, 3σ = high-risk) calibrated from baseline
  distribution — avoids the 64% failure rate of fixed `contamination` parameters
- **VAE+IF Hybrid** (optional): VAE encodes syscall behavior → latent z →
  IF scores latent space. Comparable to FedMon (94% precision, 91% recall on CVE detection).
- **Sliding window aggregation**: 5s windows capture temporal drift (a single
  write event is noise; 100 writes in 5s is ransomware).

## Resources

| Topic | Resource |
|---|---|
| eBPF fundamentals | [ebpf.io/what-is-ebpf](https://ebpf.io/what-is-ebpf/) |
| BCC Python docs | [github.com/iovisor/bcc](https://github.com/iovisor/bcc/tree/master/docs) |
| Memory leak tracing | Brendan Gregg — [brendangregg.com/BPF](https://brendangregg.com/BPF.html) |
| Reference product | [falco.org](https://falco.org) |
| BTF + CO-RE | [nakryiko.com](https://nakryiko.com/posts/bpf-core-reference-guide/) |

---
*Built at VIT Chennai — goes far beyond the BACSE106 OS curriculum.*
