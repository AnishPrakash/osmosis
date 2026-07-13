"""
OSmosis Advanced ML - Variational Autoencoder for Syscall Sequence Embedding

Architecture:
    Input: 13-dim feature vector from feature_extractor
    Encoder: FC(13→64) → FC(64→32) → (μ, logσ²) both 16-dim
    Reparameterize: z = μ + ε·σ  (differentiable sampling)
    Decoder: FC(16→32) → FC(32→64) → FC(64→13)
    Loss: MSE reconstruction + KL divergence β·KL(q||p)

When trained on normal processes, the VAE learns the normal behavioral manifold.
Anomalous processes produce high reconstruction error AND get short IF paths
in the latent space — double confirmation.
"""

import torch
import torch.nn as nn
from ml.feature_extractor import INPUT_DIM

LATENT_DIM  = 16
HIDDEN_DIM  = 64

class VAEEncoder(nn.Module):
    def __init__(self, input_dim=INPUT_DIM, hidden_dim=HIDDEN_DIM, latent_dim=LATENT_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
        )
        self.fc_mu  = nn.Linear(hidden_dim // 2, latent_dim)
        self.fc_var = nn.Linear(hidden_dim // 2, latent_dim)

    def forward(self, x):
        h    = self.net(x)
        mu   = self.fc_mu(h)
        logv = self.fc_var(h)
        return mu, logv

    def sample(self, x):
        mu, logv = self.forward(x)
        std = torch.exp(0.5 * logv)
        return mu + torch.randn_like(std) * std   # reparameterization trick


class VAEDecoder(nn.Module):
    def __init__(self, latent_dim=LATENT_DIM, hidden_dim=HIDDEN_DIM, output_dim=INPUT_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, output_dim),
        )

    def forward(self, z):
        return self.net(z)


class OSmosisVAE(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = VAEEncoder()
        self.decoder = VAEDecoder()

    def forward(self, x):
        mu, logv = self.encoder(x)
        std      = torch.exp(0.5 * logv)
        z        = mu + torch.randn_like(std) * std
        recon    = self.decoder(z)
        return recon, mu, logv

    @staticmethod
    def loss_fn(recon, x, mu, logv, beta: float = 1.0):
        mse = nn.functional.mse_loss(recon, x, reduction="sum")
        kld = -0.5 * torch.sum(1 + logv - mu.pow(2) - logv.exp())
        return mse + beta * kld
