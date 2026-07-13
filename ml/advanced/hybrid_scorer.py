"""
OSmosis Advanced ML - VAE + Isolation Forest Hybrid Scorer
Combines reconstruction error (VAE) + isolation score (IF on latent space).
"""

import torch, pickle
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from ml.feature_extractor import extract_features
from ml.advanced.vae_encoder import OSmosisVAE

MODEL_DIR = Path("ml/models")

class HybridScorer:
    def __init__(self):
        self.vae    = None
        self.iso    = None
        self.scaler = None
        self._load()

    def _load(self):
        paths = {
            "vae":    MODEL_DIR / "vae.pt",
            "iso":    MODEL_DIR / "iso_latent.pkl",
            "scaler": MODEL_DIR / "scaler.pkl",
        }
        if all(p.exists() for p in paths.values()):
            self.vae = OSmosisVAE()
            self.vae.load_state_dict(torch.load(paths["vae"], map_location="cpu"))
            self.vae.eval()
            with open(paths["iso"],    "rb") as f: self.iso    = pickle.load(f)
            with open(paths["scaler"], "rb") as f: self.scaler = pickle.load(f)
            print("[OSmosis] ✅ Hybrid VAE+IF scorer loaded.")
        else:
            print("[OSmosis] ⚠ Hybrid model not found — run 'python3 -m ml.advanced.train_hybrid'")

    def score(self, process_stats: dict) -> float:
        if not all([self.vae, self.iso, self.scaler]):
            return 0.0

        raw  = extract_features(process_stats).reshape(1, -1).astype(np.float32)
        xsc  = self.scaler.transform(raw)
        feat = torch.tensor(xsc)

        with torch.no_grad():
            recon, mu, _ = self.vae(feat)
            z           = mu.numpy()
            recon_err   = float(torch.nn.functional.mse_loss(recon, feat).item())

        if_score         = float(self.iso.score_samples(z)[0])
        normalized_if    = float(np.clip(1.0 - (if_score + 0.5) / 0.6, 0.0, 1.0))
        normalized_err   = float(np.clip(recon_err / 2.0, 0.0, 1.0))
        combined         = 0.6 * normalized_if + 0.4 * normalized_err

        return float(np.clip(combined, 0.0, 1.0))
