"""Fixed, compact neural architectures for continuous tabular features."""

from __future__ import annotations

from typing import Any

import torch
from torch import nn


class MLPBinaryClassifier(nn.Module):
    """A fixed 38-input MLP with a single binary logit output."""

    def __init__(self, input_features: int, hidden_features: list[int], dropout: list[float]) -> None:
        super().__init__()
        if len(hidden_features) != 3 or len(dropout) != 3:
            raise ValueError("The fixed MLP requires exactly three hidden layers and three dropout values")
        first, second, third = hidden_features
        self.network = nn.Sequential(
            nn.Linear(input_features, first),
            nn.ReLU(),
            nn.LayerNorm(first),
            nn.Dropout(dropout[0]),
            nn.Linear(first, second),
            nn.ReLU(),
            nn.Dropout(dropout[1]),
            nn.Linear(second, third),
            nn.ReLU(),
            nn.Dropout(dropout[2]),
            nn.Linear(third, 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.network(features)


class NumericalFeatureTokenizer(nn.Module):
    """Feature-specific affine embeddings used by FT-Transformer-style models."""

    def __init__(self, n_features: int, d_token: int) -> None:
        super().__init__()
        self.weight = nn.Parameter(torch.empty(n_features, d_token))
        self.bias = nn.Parameter(torch.empty(n_features, d_token))
        nn.init.normal_(self.weight, mean=0.0, std=0.02)
        nn.init.normal_(self.bias, mean=0.0, std=0.02)

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        if features.ndim != 2 or features.shape[1] != self.weight.shape[0]:
            raise ValueError("Numerical tokenizer received an unexpected feature matrix shape")
        return features.unsqueeze(-1) * self.weight.unsqueeze(0) + self.bias.unsqueeze(0)


class FTTransformerBinaryClassifier(nn.Module):
    """Compact FT-Transformer-style classifier for continuous tabular inputs.

    Each numeric feature receives its own learned affine token; a learned CLS
    token is processed by two standard self-attention blocks and read by a
    small binary-logit head. This is intentionally a fixed baseline, not an
    architecture-search framework.
    """

    def __init__(
        self,
        input_features: int,
        d_token: int,
        n_blocks: int,
        n_heads: int,
        d_ffn: int,
        attention_dropout: float,
        ffn_dropout: float,
    ) -> None:
        super().__init__()
        if d_token % n_heads != 0:
            raise ValueError("d_token must be divisible by n_heads")
        self.tokenizer = NumericalFeatureTokenizer(input_features, d_token)
        self.cls_token = nn.Parameter(torch.empty(1, 1, d_token))
        nn.init.normal_(self.cls_token, mean=0.0, std=0.02)
        block = nn.TransformerEncoderLayer(
            d_model=d_token,
            nhead=n_heads,
            dim_feedforward=d_ffn,
            dropout=max(attention_dropout, ffn_dropout),
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.transformer = nn.TransformerEncoder(block, num_layers=n_blocks, enable_nested_tensor=False)
        self.head = nn.Sequential(nn.LayerNorm(d_token), nn.Linear(d_token, 1))

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        tokens = self.tokenizer(features)
        cls = self.cls_token.expand(features.shape[0], -1, -1)
        encoded = self.transformer(torch.cat((cls, tokens), dim=1))
        return self.head(encoded[:, 0, :])


def build_tabular_model(model_name: str, configuration: dict[str, Any]) -> nn.Module:
    """Instantiate only one of the two committed baseline architectures."""
    if model_name == "mlp":
        return MLPBinaryClassifier(
            input_features=int(configuration["input_features"]),
            hidden_features=[int(value) for value in configuration["hidden_features"]],
            dropout=[float(value) for value in configuration["dropout"]],
        )
    if model_name == "ft_transformer":
        return FTTransformerBinaryClassifier(
            input_features=int(configuration["input_features"]),
            d_token=int(configuration["d_token"]),
            n_blocks=int(configuration["n_blocks"]),
            n_heads=int(configuration["n_heads"]),
            d_ffn=int(configuration["d_ffn"]),
            attention_dropout=float(configuration["attention_dropout"]),
            ffn_dropout=float(configuration["ffn_dropout"]),
        )
    raise ValueError("Expected one of the fixed models: 'mlp' or 'ft_transformer'")


def count_trainable_parameters(model: nn.Module) -> int:
    """Count trainable scalars; this is not directly comparable to tree count."""
    return sum(parameter.numel() for parameter in model.parameters() if parameter.requires_grad)
