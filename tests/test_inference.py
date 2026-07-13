"""
Tests for ml/inference.py
Uses a mock model so no real ml/models/*.pkl files are required.
"""
import pytest
import numpy as np
from unittest.mock import MagicMock, patch
from ml.inference import AnomalyScorer

def make_process(risk=False):
    base = {
        "syscall_count": 1000, "page_faults": 10, "major_faults": 1,
        "sched_preemptions": 5, "write_count": 50, "open_count": 20,
        "fork_count": 2, "mmap_count": 5, "syscall_diversity": 20,
        "vfs_renames": 0, "page_allocs": 100, "page_frees": 95,
        "vfs_writes": 45,
    }
    if risk:
        base["vfs_renames"] = 200   # ransomware-like
        base["vfs_writes"]  = 900
    return base


class TestAnomalyScorer:

    def test_score_returns_zero_when_no_model(self):
        """AnomalyScorer with no model files returns 0.0."""
        scorer = AnomalyScorer()
        # If no model loaded, score returns 0
        if scorer.model is None:
            assert scorer.score(make_process()) == 0.0

    def test_score_range_with_mock_model(self):
        """Score must always be in [0, 1]."""
        scorer = AnomalyScorer()
        scorer.model  = MagicMock()
        scorer.scaler = MagicMock()
        scorer.scaler.transform.return_value = np.zeros((1, 13))

        # Mock: normal process gets a benign IF score
        scorer.model.score_samples.return_value = np.array([-0.05])  # near normal
        scorer.thresholds = {"threshold_med": -0.2, "threshold_high": -0.4}
        result = scorer.score(make_process())
        assert 0.0 <= result <= 1.0, f"Score {result} out of [0,1]"

    def test_anomalous_process_higher_score(self):
        """A process with ransomware-like behavior should score higher than a normal one."""
        scorer = AnomalyScorer()
        scorer.thresholds = {"threshold_med": -0.2, "threshold_high": -0.4}

        if scorer.model is None:
            pytest.skip("No trained model available — skipping comparative test")

        normal_score = scorer.score(make_process(risk=False))
        ransom_score = scorer.score(make_process(risk=True))
        assert ransom_score >= normal_score, \
            "Ransomware-like process should score >= normal process"

    def test_is_anomaly_threshold(self):
        """is_anomaly() should return True above 0.6."""
        scorer = AnomalyScorer()
        scorer.model  = MagicMock()
        scorer.scaler = MagicMock()
        scorer.scaler.transform.return_value = np.zeros((1, 13))
        # Simulate a very anomalous IF score
        scorer.model.score_samples.return_value = np.array([-1.0])
        scorer.thresholds = {"threshold_med": -0.2, "threshold_high": -0.4}
        assert scorer.is_anomaly(make_process()) is True
