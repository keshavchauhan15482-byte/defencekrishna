"""
NTRO SIH26153: PyTorch Deep Learning Cyber Garuda AIs
Implements:
1. CyberLSTMWorldModel: 2-Layer Gated LSTM with dropout, autoregressive rollout, and risk head.
2. TransformerCyberWorldModel: Multi-Head Self-Attention Temporal Transformer with native attention explainability.
"""

import torch
import torch.nn as nn
import math

class CyberLSTMWorldModel(nn.Module):
    def __init__(self, input_dim=12, hidden_dim=64, num_layers=2, dropout=0.2):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )

        # Multi-Step Autoregressive State Transition Decoder S_{t+1}
        self.forecast_head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
            nn.Sigmoid()
        )

        # Infiltration / Breach Risk Classification Head P(Breach)
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x, k_steps=8):
        """
        Forward rollout:
        x: (batch_size, seq_len, input_dim)
        Returns:
            risk: (batch_size, 1) probability of attack
            forecasts: (batch_size, k_steps, input_dim) autoregressive future states
        """
        out, (h, c) = self.lstm(x)
        last_hidden = out[:, -1, :]
        risk = self.risk_head(last_hidden)

        # Autoregressive K-step rollout
        forecasts = []
        h_t, c_t = h, c
        curr_in = x[:, -1:, :]

        for _ in range(k_steps):
            out_step, (h_t, c_t) = self.lstm(curr_in, (h_t, c_t))
            pred_s = self.forecast_head(out_step[:, -1, :])
            forecasts.append(pred_s)
            curr_in = pred_s.unsqueeze(1)

        forecast_tensor = torch.stack(forecasts, dim=1)
        return risk, forecast_tensor

class PositionalEncoding(nn.Module):
    def __init__(self, d_model=64, max_len=100):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x):
        return x + self.pe[:, :x.size(1), :]

class TransformerCyberWorldModel(nn.Module):
    def __init__(self, input_dim=12, d_model=64, nhead=4, num_layers=2, dim_feedforward=128, dropout=0.1):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model=d_model)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        self.risk_head = nn.Sequential(
            nn.Linear(d_model, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
        self.forecast_head = nn.Sequential(
            nn.Linear(d_model, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x, k_steps=8):
        h = self.input_proj(x)
        h = self.pos_encoder(h)
        out = self.transformer(h)
        risk = self.risk_head(out[:, -1, :])

        # Autoregressive forward projection
        forecasts = []
        curr_seq = x
        for _ in range(k_steps):
            h_seq = self.input_proj(curr_seq)
            h_seq = self.pos_encoder(h_seq)
            out_seq = self.transformer(h_seq)
            pred_next = self.forecast_head(out_seq[:, -1, :])
            forecasts.append(pred_next)
            curr_seq = torch.cat([curr_seq, pred_next.unsqueeze(1)], dim=1)

        forecast_tensor = torch.stack(forecasts, dim=1)
        return risk, forecast_tensor

    def forward_with_attention(self, x):
        """
        Returns risk score AND per-head attention weights for explainability.
        Attention weights show which time windows the model focuses on most.

        Returns:
            risk: (batch, 1) infiltration probability
            attn_weights: list of (batch, nhead, seq_len, seq_len) per layer
        """
        h = self.input_proj(x)
        h = self.pos_encoder(h)

        attn_weights_all_layers = []
        curr = h
        for layer in self.transformer.layers:
            # Extract self-attention weights (need_weights=True)
            attn_out, attn_w = layer.self_attn(
                curr, curr, curr,
                need_weights=True,
                average_attn_weights=False  # get per-head weights
            )
            attn_weights_all_layers.append(attn_w.detach())  # (batch, nhead, seq, seq)

            # Apply the rest of the encoder layer manually
            curr = layer.norm1(curr + layer.dropout1(attn_out))
            ff_out = layer.linear2(layer.dropout(layer.activation(layer.linear1(curr))))
            curr = layer.norm2(curr + layer.dropout2(ff_out))

        risk = self.risk_head(curr[:, -1, :])
        return risk, attn_weights_all_layers
