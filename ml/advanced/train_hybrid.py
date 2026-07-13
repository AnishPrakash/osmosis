"""
OSmosis Advanced ML - VAE + Isolation Forest Hybrid Training

Step 1: Train the VAE on clean baseline feature vectors
Step 2: Encode all baseline vectors → latent space z
Step 3: Train a separate Isolation Forest on the latent z vectors
Step 4: At inference — encode → IF score + reconstruction error

Run after collecting ~30 min of baseline data and having run ml/train.py first:
    python3 -m ml.advanced.train_hybrid
"""

import json, pickle, sqlite3
import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from pathlib import Path

from ml.feature_extractor import extract_features
from ml.advanced.vae_encoder import OSmosisVAE
from ml.train import rebuild_process_stats

MODEL_DIR = Path("ml/models")

def train_hybrid(epochs: int = 100, batch_size: int = 32, lr: float = 1e-3):
    print("[OSmosis] Rebuilding process stats from DB...")
    all_stats = rebuild_process_stats()

    counts = np.array([ps["syscall_count"] for ps in all_stats])
    all_stats = [ps for ps, c in zip(all_stats, counts) if c >= 20]

    if len(all_stats) < 20:
        print("[OSmosis] ⚠ Need ≥20 processes for hybrid training. Collect more data.")
        return

    X = np.stack([extract_features(ps) for ps in all_stats]).astype(np.float32)

    # Normalize using the existing scaler from Phase 3 base training
    with open(MODEL_DIR / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    X_scaled = scaler.transform(X).astype(np.float32)

    dataset = TensorDataset(torch.tensor(X_scaled))
    loader  = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    # ── Step 1: Train VAE ────────────────────────────────────────────────────
    print(f"[OSmosis] Training VAE for {epochs} epochs...")
    vae       = OSmosisVAE()
    optimizer = torch.optim.Adam(vae.parameters(), lr=lr)

    vae.train()
    for epoch in range(epochs):
        total_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            recon, mu, logv = vae(batch)
            loss = OSmosisVAE.loss_fn(recon, batch, mu, logv, beta=0.5)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        if (epoch + 1) % 20 == 0:
            print(f"  Epoch [{epoch+1}/{epochs}] loss={total_loss/len(loader):.4f}")

    # ── Step 2: Encode all baseline vectors → latent z ───────────────────────
    print("[OSmosis] Encoding baseline into latent space...")
    vae.eval()
    with torch.no_grad():
        X_t  = torch.tensor(X_scaled)
        mu, _ = vae.encoder(X_t)
        Z = mu.numpy()

    # ── Step 3: Train IF on latent z ─────────────────────────────────────────
    print("[OSmosis] Training Isolation Forest on latent space...")
    iso_latent = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    iso_latent.fit(Z)

    # ── Save all artifacts ────────────────────────────────────────────────────
    torch.save(vae.state_dict(), MODEL_DIR / "vae.pt")
    with open(MODEL_DIR / "iso_latent.pkl", "wb") as f:
        pickle.dump(iso_latent, f)

    print(f"[OSmosis] ✅ Hybrid VAE+IF model saved.")
    print(f"           vae.pt         → {MODEL_DIR / 'vae.pt'}")
    print(f"           iso_latent.pkl → {MODEL_DIR / 'iso_latent.pkl'}")

if __name__ == "__main__":
    train_hybrid()
