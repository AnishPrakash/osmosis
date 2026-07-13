"""
Tests for ml/feature_extractor.py
Verifies the feature vector is the correct shape and handles edge cases.
"""
import pytest
import numpy as np
from ml.feature_extractor import extract_features, INPUT_DIM, FEATURE_NAMES

def make_process(
    syscall_count=100, page_faults=10, major_faults=2,
    sched_preemptions=5, write_count=20, open_count=8,
    fork_count=1, mmap_count=3, syscall_diversity=15,
    vfs_renames=0, page_allocs=50, page_frees=45,
    vfs_writes=18,
):
    return {
        "syscall_count": syscall_count, "page_faults": page_faults,
        "major_faults": major_faults, "sched_preemptions": sched_preemptions,
        "write_count": write_count, "open_count": open_count,
        "fork_count": fork_count, "mmap_count": mmap_count,
        "syscall_diversity": syscall_diversity, "vfs_renames": vfs_renames,
        "page_allocs": page_allocs, "page_frees": page_frees,
        "vfs_writes": vfs_writes,
    }


class TestExtractFeatures:

    def test_output_shape(self):
        ps  = make_process()
        vec = extract_features(ps)
        assert vec.shape == (INPUT_DIM,), f"Expected ({INPUT_DIM},), got {vec.shape}"

    def test_output_dtype(self):
        vec = extract_features(make_process())
        assert vec.dtype == np.float32

    def test_all_finite(self):
        vec = extract_features(make_process())
        assert np.all(np.isfinite(vec)), "Feature vector contains NaN or Inf"

    def test_zero_process_no_crash(self):
        """Zero-syscall process should not raise."""
        ps  = make_process(syscall_count=0, page_faults=0, page_allocs=0, page_frees=0)
        vec = extract_features(ps)
        assert vec.shape == (INPUT_DIM,)
        assert np.all(np.isfinite(vec))

    def test_rename_ratio_for_ransomware(self):
        """High vfs_renames should produce a high rename_ratio feature."""
        normal = extract_features(make_process(vfs_renames=0))
        ransom = extract_features(make_process(vfs_renames=80, syscall_count=100))
        rename_idx = FEATURE_NAMES.index("rename_ratio")
        assert ransom[rename_idx] > normal[rename_idx], \
            "Ransomware pattern (high renames) should produce higher rename_ratio"

    def test_leak_pressure_positive_for_growing_allocs(self):
        """More allocs than frees should produce positive leak pressure."""
        ps     = make_process(page_allocs=100, page_frees=10, syscall_count=100)
        vec    = extract_features(ps)
        leak_idx = FEATURE_NAMES.index("memory_leak_pressure")
        assert vec[leak_idx] > 0.0, "Leak pressure should be positive when allocs > frees"

    def test_syscall_diversity_clamped(self):
        """Diversity must be in [0, 1]."""
        ps  = make_process(syscall_diversity=500, syscall_count=1000)
        vec = extract_features(ps)
        div_idx = FEATURE_NAMES.index("syscall_diversity")
        assert 0.0 <= vec[div_idx] <= 1.0

    def test_feature_name_count_matches_dim(self):
        assert len(FEATURE_NAMES) == INPUT_DIM
