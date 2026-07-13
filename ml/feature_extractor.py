"""
OSmosis - Sliding Window Feature Extractor

WHY SLIDING WINDOWS (not raw events):
- Ransomware doesn't appear in one vfs_write. It appears in 100 vfs_writes in 5s.
- Memory leaks are invisible in a single page_alloc. Visible as a rising delta.
- Sequential temporal patterns require windowed aggregation to be detectable.

The 13-feature vector here maps directly to what the Isolation Forest and VAE
encoder expect as input. Order matters — do not change it without retraining.
"""

import numpy as np
from typing import Dict

# Feature vector index reference (do not reorder without retraining)
FEATURE_NAMES = [
    "log_syscall_count",  # 0  Total syscall volume (log-scaled)
    "log_page_faults",  # 1  Minor fault rate
    "log_major_faults",  # 2  Major fault rate (disk-backed)
    "log_sched_preemptions",  # 3  Scheduler preemption intensity
    "write_ratio",  # 4  vfs_write / total_syscalls
    "open_ratio",  # 5  open/openat / total
    "fork_ratio",  # 6  clone/fork / total
    "mmap_ratio",  # 7  mmap / total
    "syscall_diversity",  # 8  Unique syscall types (normalized 0..1)
    "rename_ratio",  # 9  vfs_rename / total (ransomware indicator)
    "memory_leak_pressure",  # 10 (page_allocs - page_frees) / total
    "major_fault_ratio",  # 11 major_faults / total_page_faults
    "vfs_write_intensity",  # 12 vfs_writes / total
]

INPUT_DIM = len(FEATURE_NAMES)  # 13


def extract_features(process_stats: Dict) -> np.ndarray:
    """
    Convert a ProcessSummary dict to a 13-dimensional float32 feature vector.
    All divisions are guarded against zero. Log-scaling reduces the effect
    of extreme outliers in syscall counts.
    """
    total = max(process_stats.get("syscall_count", 1), 1)
    faults = max(process_stats.get("page_faults", 0), 1)
    allocs = process_stats.get("page_allocs", 0)
    frees = process_stats.get("page_frees", 0)

    vec = np.array(
        [
            np.log1p(total),
            np.log1p(process_stats.get("page_faults", 0)),
            np.log1p(process_stats.get("major_faults", 0)),
            np.log1p(process_stats.get("sched_preemptions", 0)),
            process_stats.get("write_count", 0) / total,
            process_stats.get("open_count", 0) / total,
            process_stats.get("fork_count", 0) / total,
            process_stats.get("mmap_count", 0) / total,
            min(process_stats.get("syscall_diversity", 1) / 50.0, 1.0),
            process_stats.get("vfs_renames", 0) / total,  # rename ratio
            max(allocs - frees, 0) / total,  # leak pressure
            process_stats.get("major_faults", 0) / faults,  # major fault ratio
            process_stats.get("vfs_writes", 0) / total,  # write intensity
        ],
        dtype=np.float32,
    )

    return vec
