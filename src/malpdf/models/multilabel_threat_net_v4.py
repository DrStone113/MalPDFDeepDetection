"""PDFMultiLabelThreatNet v4: DAG Graphormer + ActionSubgraphIR + Regime-B + Bounded Aux Telemetry."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any

import numpy as np
import torch
import torch.nn as nn

from malpdf.models.multilabel_threat_net import MULTILABEL_THREAT_DEFINITIONS
from malpdf.models.pdf_transgraph_v3 import (
    NUM_BASE_RELATIONS,
    NUM_NODE_TYPES,
    MaskedGatedCrossModalFusionV3,
    TabularEncoderV3,
)
from malpdf.models.pdf_transgraph_v4 import ActionSubgraphIREncoderV4, ShortestPathGraphEncoderV4
from malpdf.models.v4_graph_numpy import ACTION_IR_DIM, AUX_TELEMETRY_V4_DIM, AUX_TELEMETRY_V4_NAMES

MULTILABEL_V4_CONTRACT_VERSION = "pdf-multilabel-v4-regime-b"
EXPECTED_HEAD_IDS_V4: tuple[str, ...] = tuple(str(d["id"]) for d in MULTILABEL_THREAT_DEFINITIONS)


@dataclass(frozen=True)
class MultiLabelV4Config:
    tab_dim: int = 29
    action_ir_dim: int = ACTION_IR_DIM
    aux_dim: int = AUX_TELEMETRY_V4_DIM
    node_dim: int = 23
    hidden_dim: int = 128
    num_graph_layers: int = 3
    num_heads: int = 4
    num_node_types: int = NUM_NODE_TYPES
    num_base_relations: int = NUM_BASE_RELATIONS
    num_freq_bins: int = 4
    num_labels: int = 8
    dropout: float = 0.15
    modality_drop_prob: float = 0.10
    enable_spd_bias: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuxTelemetryEncoderV4(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, dropout: float) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class PDFMultiLabelThreatNetV4(nn.Module):
    def __init__(self, config: MultiLabelV4Config) -> None:
        super().__init__()
        self.config = config
        h = config.hidden_dim
        self.tab_encoder = TabularEncoderV3(
            config.tab_dim,
            hidden_dim=h,
            num_freq_bins=config.num_freq_bins,
            dropout=config.dropout,
            use_missing_mask=False,
        )
        self.graph_encoder = ShortestPathGraphEncoderV4(
            node_dim=config.node_dim,
            hidden_dim=h,
            num_layers=config.num_graph_layers,
            num_heads=config.num_heads,
            num_node_types=config.num_node_types,
            dropout=config.dropout,
            enable_spd_bias=config.enable_spd_bias,
        )
        self.action_ir_encoder = ActionSubgraphIREncoderV4(
            in_dim=config.action_ir_dim,
            hidden_dim=h,
            dropout=config.dropout,
        )
        self.aux_encoder = AuxTelemetryEncoderV4(
            in_dim=config.aux_dim,
            hidden_dim=h,
            dropout=config.dropout,
        )
        self.fusion = MaskedGatedCrossModalFusionV3(
            hidden_dim=h,
            dropout=config.dropout,
            modality_drop_prob=config.modality_drop_prob,
        )
        self.trunk_proj = nn.Sequential(
            nn.Linear(h * 5, h * 2),
            nn.LayerNorm(h * 2),
            nn.GELU(),
            nn.Dropout(config.dropout),
        )
        self.trunk_res = nn.Sequential(
            nn.Linear(h * 2, h * 2),
            nn.LayerNorm(h * 2),
            nn.GELU(),
            nn.Dropout(config.dropout),
        )
        self.label_queries = nn.Parameter(torch.randn(config.num_labels, h * 2) * 0.02)
        self.label_scale = nn.Parameter(torch.ones(config.num_labels))
        self.label_bias = nn.Parameter(torch.zeros(config.num_labels))
        self.label_linear = nn.Linear(h * 2, config.num_labels)
        self.aux_mal_head = nn.Linear(h * 2, 1)

    def forward(
        self,
        tab_x: torch.Tensor,
        action_ir_x: torch.Tensor,
        action_ir_active: torch.Tensor,
        node_x_pad: torch.Tensor,
        node_type_pad: torch.Tensor,
        deg_pad: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd_pad: torch.Tensor,
        rel_pad: torch.Tensor,
        root_depth_pad: torch.Tensor,
        sink_dist_pad: torch.Tensor,
        summary_12: torch.Tensor,
        aux_x: torch.Tensor,
    ) -> dict[str, torch.Tensor]:
        bsz = tab_x.shape[0]
        device = tab_x.device
        e_tab = self.tab_encoder(tab_x, None)
        has_tab = torch.ones((bsz,), device=device, dtype=torch.bool)
        e_graph, graph_present = self.graph_encoder(
            node_x_pad,
            node_type_pad,
            deg_pad,
            node_pad_mask,
            spd_pad,
            rel_pad,
            root_depth_pad,
            sink_dist_pad,
            summary_12,
        )
        e_ir = self.action_ir_encoder(action_ir_x)
        ir_present = action_ir_active.to(device=device, dtype=torch.bool) & graph_present
        e_aux = self.aux_encoder(aux_x)

        mod_mask = torch.stack((has_tab, graph_present, ir_present), dim=-1)
        fused, weights = self.fusion((e_tab, e_graph, e_ir), mod_mask)
        ir_masked = torch.where(ir_present.unsqueeze(-1), e_ir, torch.zeros_like(e_ir))
        graph_masked = torch.where(graph_present.unsqueeze(-1), e_graph, torch.zeros_like(e_graph))
        combined = torch.cat((fused, e_tab, graph_masked, ir_masked, e_aux), dim=-1)
        h = self.trunk_proj(combined)
        h = h + self.trunk_res(h)
        query_scores = torch.matmul(h, self.label_queries.t()) * self.label_scale + self.label_bias
        label_logits = self.label_linear(h) + query_scores
        mal_logit = self.aux_mal_head(h).squeeze(-1)
        return {
            "label_logits": label_logits,
            "mal_logit": mal_logit,
            "weights": weights,
        }


def save_multilabel_v4_npz(model: PDFMultiLabelThreatNetV4, path: Any) -> None:
    arrays = {f"param::{name}": tensor.detach().cpu().numpy() for name, tensor in model.state_dict().items()}
    np.savez_compressed(path, **arrays)


def load_multilabel_v4_npz(
    model: PDFMultiLabelThreatNetV4, path: Any, *, map_location: str | torch.device = "cpu"
) -> None:
    state = {}
    with np.load(path, allow_pickle=False) as archive:
        for key in archive.files:
            if key.startswith("param::"):
                state[key[len("param::") :]] = torch.from_numpy(np.array(archive[key], copy=True)).to(map_location)
    model.load_state_dict(state, strict=True)


def validate_multilabel_v4_contract(contract: dict[str, Any], expected_tab_names: tuple[str, ...]) -> None:
    if contract.get("contract_version") != MULTILABEL_V4_CONTRACT_VERSION:
        raise ValueError("invalid_multilabel_v4_contract_version")
    if tuple(contract.get("tab_feature_names") or ()) != expected_tab_names:
        raise ValueError("invalid_multilabel_v4_tab_feature_names")
    if tuple(contract.get("aux_feature_names") or ()) != AUX_TELEMETRY_V4_NAMES:
        raise ValueError("invalid_multilabel_v4_aux_feature_names")
    labels = contract.get("labels") or []
    if tuple(str(item.get("id", "")) for item in labels) != EXPECTED_HEAD_IDS_V4:
        raise ValueError("invalid_multilabel_v4_head_order")
    temps = contract.get("label_temperatures") or []
    if len(temps) != len(EXPECTED_HEAD_IDS_V4) or not all(
        isinstance(t, (int, float)) and math.isfinite(float(t)) and float(t) > 0.0 for t in temps
    ):
        raise ValueError("invalid_multilabel_v4_label_temperatures")
    mal_t = contract.get("mal_temperature")
    if not isinstance(mal_t, (int, float)) or not math.isfinite(float(mal_t)) or float(mal_t) <= 0.0:
        raise ValueError("invalid_multilabel_v4_mal_temperature")
    center = np.asarray(contract.get("tab29_center") or (), dtype=np.float64)
    scale = np.asarray(contract.get("tab29_scale") or (), dtype=np.float64)
    if (
        center.shape != (len(expected_tab_names),)
        or scale.shape != (len(expected_tab_names),)
        or not np.isfinite(center).all()
        or not np.isfinite(scale).all()
        or np.any(scale == 0.0)
    ):
        raise ValueError("invalid_multilabel_v4_scaler")
    for item in labels:
        thr = item.get("threshold")
        enabled = item.get("model_flag_enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("invalid_multilabel_v4_model_flag_enabled")
        if not isinstance(thr, (int, float)) or not math.isfinite(float(thr)) or float(thr) <= 0.0:
            raise ValueError("invalid_multilabel_v4_head_threshold")
        if enabled and float(thr) > 1.0:
            raise ValueError("invalid_multilabel_v4_enabled_threshold_range")
