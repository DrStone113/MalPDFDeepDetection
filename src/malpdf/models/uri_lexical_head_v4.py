"""Residual MLP architecture and allow_pickle=False NPZ serialization for the v4 URI lexical head."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

URI_LEXICAL_MODEL_VERSION = "PDFURILexicalHead v4"


@dataclass(frozen=True)
class URILexicalHeadV4Config:
    in_dim: int = 36
    hidden_dim: int = 128
    bottleneck_dim: int = 64
    dropout: float = 0.15

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PDFURILexicalHeadV4(nn.Module):
    """Branchless residual MLP mapping 28D standardized pure-string lexical URL vectors to logit scores."""

    def __init__(self, config: URILexicalHeadV4Config | None = None) -> None:
        super().__init__()
        self.config = config or URILexicalHeadV4Config()
        d_in = self.config.in_dim
        h = self.config.hidden_dim
        b = self.config.bottleneck_dim
        drop = self.config.dropout

        self.in_proj = nn.Linear(d_in, h)
        self.in_norm = nn.LayerNorm(h)
        self.res_fc1 = nn.Linear(h, h)
        self.res_norm1 = nn.LayerNorm(h)
        self.res_drop = nn.Dropout(drop)
        self.res_fc2 = nn.Linear(h, h)
        self.res_norm2 = nn.LayerNorm(h)
        self.neck_proj = nn.Linear(h, b)
        self.neck_norm = nn.LayerNorm(b)
        self.neck_drop = nn.Dropout(drop)
        self.head = nn.Linear(b, 1)

    def forward(self, uri_features: torch.Tensor) -> torch.Tensor:
        x = F.silu(self.in_norm(self.in_proj(uri_features)))
        r = F.silu(self.res_norm1(self.res_fc1(x)))
        r = self.res_drop(r)
        r = self.res_norm2(self.res_fc2(r))
        x = x + r
        z = self.neck_drop(F.silu(self.neck_norm(self.neck_proj(x))))
        return self.head(z).squeeze(-1)


def save_uri_head_v4_npz(model: PDFURILexicalHeadV4, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    arrays: dict[str, np.ndarray] = {}
    for name, tensor in model.state_dict().items():
        arrays[f"sd::{name}"] = tensor.detach().cpu().numpy()
    np.savez(path, **arrays)


def load_uri_head_v4_npz(
    model: PDFURILexicalHeadV4,
    path: Path,
    map_location: str | torch.device = "cpu",
) -> PDFURILexicalHeadV4:
    with np.load(path, allow_pickle=False) as archive:
        state_dict = {
            key[4:]: torch.from_numpy(np.array(archive[key], copy=True)).to(map_location)
            for key in archive.files
            if key.startswith("sd::")
        }
    model.load_state_dict(state_dict, strict=True)
    return model
