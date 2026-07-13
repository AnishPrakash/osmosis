"""
OSmosis - Real-Time Anomaly Scorer
Uses dynamically calibrated σ-based thresholds, NOT fixed contamination percentiles.
"""

import pickle
import json
import numpy as np
from pathlib import Path
from ml.feature_extractor import extract_features

MODEL_DIR = Path("ml/models")


class AnomalyScorer:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.thresholds = {"threshold_med": -0.3, "threshold_high": -0.5}
        self._load()

    def _load(self):
        iso_path = MODEL_DIR / "iso_forest.pkl"
        scaler_path = MODEL_DIR / "scaler.pkl"
        thresh_path = MODEL_DIR / "thresholds.json"

        if iso_path.exists() and scaler_path.exists():
            with open(iso_path, "rb") as f:
                self.model = pickle.load(f)
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)
            if thresh_path.exists():
                with open(thresh_path) as f:
                    self.thresholds = json.load(f)
            print("[OSmosis] ✅ Anomaly model + dynamic thresholds loaded.")
        else:
            print(
                "[OSmosis] ⚠ No model found — run 'make train' after ~10 min baseline. Scoring disabled."
            )

    def raw_score(self, process_stats: dict) -> float:
        """Raw IF score (more negative = more anomalous)."""
        if self.model is None:
            return 0.0
        feat = extract_features(process_stats).reshape(1, -1)
        return float(self.model.score_samples(self.scaler.transform(feat))[0])

    def score(self, process_stats: dict) -> float:
        """Normalized risk score [0, 1]. >0.6 suspicious, >0.8 high risk."""
        raw = self.raw_score(process_stats)
        t_med = self.thresholds.get("threshold_med", -0.3)
        t_high = self.thresholds.get("threshold_high", -0.5)

        if raw >= t_med:
            return 0.1  # Normal
        if raw >= t_high:
            return 0.65  # Suspicious
        return float(np.clip(0.8 + (t_high - raw) * 0.5, 0.0, 1.0))  # High-risk

    def is_anomaly(self, process_stats: dict) -> bool:
        return self.score(process_stats) >= 0.6
