from __future__ import annotations

import hashlib
import json
from pathlib import Path
import statistics
import sys
from tempfile import TemporaryDirectory
import time

import numpy as np
import onnx
import onnxruntime as ort
import torch
import torch.nn as nn
import torch.nn.functional as F

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.features.contract_v3 import FEATURES, log_matrix
from malpdf.models.ast_transformer import RotaryPositionalEmbedding, apply_rotary_pos_emb
from malpdf.models.cross_attention_fusion import CrossModalAttentionFusion
from malpdf.models.multilabel_threat_net import PDFMultiLabelThreatNet
from malpdf.models.pdf_transgraph_v3 import PDFTransGraphV3, TransGraphV3Config, load_v3_weights_npz
from malpdf.models.pdf_transgraph_v4 import (
    NUM_BASE_RELATIONS,
    SPD_UNREACHABLE,
    PDFTransGraphV4,
    TransGraphV4Config,
    load_v4_weights_npz,
)
from malpdf.models.tabular_resnet import TabularResNet
from malpdf.models.v4_graph_numpy import collate_v4_numpy_feed, single_graph_tuple
from malpdf.scanner.ingestion import REGIME_B_INDICES, InstantPDFIngestion
from malpdf.static.obfuscation import count_escaped_pdf_names
from malpdf.static.raw_scan import scan_raw_pdf_tokens

PROD_DIR = REPO_ROOT / "production"
PROD_MODELS_DIR = PROD_DIR / "models"
PROD_CONFIGS_DIR = PROD_DIR / "configs"

PT_V4_BINARY_PATH = REPO_ROOT / "artifacts/models/pdf_transgraph_v4/pdf_transgraph_v4_regime_b_seed42.npz"
V4_CONTRACT_PATH = REPO_ROOT / "configs/transgraph_v4_contract.json"
V4_CONFORMAL_PATH = REPO_ROOT / "configs/conformal_calibration_v4.json"

PT_V3_BINARY_PATH = REPO_ROOT / "artifacts/models/pdf_transgraph_v3/pdf_transgraph_v32b_regime_b_seed42.npz"
V3_CONTRACT_PATH = REPO_ROOT / "configs/transgraph_v3_contract.json"

OFFLINE_DIR = REPO_ROOT / "data/processed/pooled_bulk"
CONTROL_PATH = OFFLINE_DIR / "offline_provenance/reviewed_controls_v3.json"
STRESS_PATH = OFFLINE_DIR / "byte_level_stress_v3/offline_byte_stress_export.json"
STRESS_ARCHIVE = OFFLINE_DIR / "offline_provenance/byte_level_stress_v3.json"
STRESS_SHA256 = "1e13f4f5cff5c9eeeefc884e80a6ee28df83a9fb7c693208f347c9a4a48fd90f"
PT_MULTILABEL_PATH = REPO_ROOT / "artifacts" / "models" / "multilabel_threat_v2" / "multilabel_threat_net_v2_best.pt"
SCALER_PATH = REPO_ROOT / "configs" / "tabular_scaler.json"
ML_CONTRACT_PATH = REPO_ROOT / "configs" / "multilabel_threat_contract.json"


class ONNXRelationAwareMessagePassing(nn.Module):
    def __init__(self, in_dim: int, out_dim: int, num_relations: int = 8, num_heads: int = 4) -> None:
        super().__init__()
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.num_relations = num_relations
        self.num_heads = num_heads
        self.head_dim = out_dim // num_heads
        self.q_proj = nn.Linear(in_dim, out_dim)
        self.k_proj = nn.Linear(in_dim, out_dim)
        self.v_proj = nn.Linear(in_dim, out_dim)
        self.rel_emb = nn.Embedding(num_relations, out_dim)
        self.out_proj = nn.Linear(out_dim, out_dim)
        self.norm = nn.LayerNorm(out_dim)

    def forward(
        self,
        x: torch.Tensor,
        edge_src: torch.Tensor,
        edge_dst: torch.Tensor,
        edge_rel: torch.Tensor,
        edge_mask: torch.Tensor,
        has_edges: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        q = self.q_proj(x).view(-1, self.num_heads, self.head_dim)
        k = self.k_proj(x).view(-1, self.num_heads, self.head_dim)
        v = self.v_proj(x).view(-1, self.num_heads, self.head_dim)
        r = self.rel_emb(edge_rel).view(-1, self.num_heads, self.head_dim)
        k_msg = k[edge_src] + r
        v_msg = v[edge_src] + r
        score = (q[edge_dst] * k_msg).sum(dim=-1) / (self.head_dim**0.5)
        score = torch.clamp(score, -10.0, 10.0)
        attn = torch.exp(score) * edge_mask
        dst_h = edge_dst.unsqueeze(-1).expand(-1, self.num_heads)
        norm_factor = torch.zeros_like(q[:, :, 0]).scatter_add(0, dst_h, attn) + 1e-6
        alpha = attn / norm_factor[edge_dst]
        weighted_v = (v_msg * alpha.unsqueeze(-1)).reshape(-1, self.out_dim)
        dst_d = edge_dst.unsqueeze(-1).expand(-1, self.out_dim)
        aggr_flat = torch.zeros_like(x).scatter_add(0, dst_d, weighted_v)
        out = self.out_proj(aggr_flat)
        updated = self.norm(x + F.silu(out) * has_edges)
        return updated, alpha.mean(dim=-1)


class ONNXHeteroGraphTransformer(nn.Module):
    def __init__(
        self,
        node_in_dim: int = 23,
        hidden_dim: int = 128,
        num_node_types: int = 9,
        num_relations: int = 8,
    ) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.node_type_emb = nn.Embedding(num_node_types, hidden_dim)
        self.node_feat_proj = nn.Linear(node_in_dim, hidden_dim)
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.layer1 = ONNXRelationAwareMessagePassing(hidden_dim, hidden_dim, num_relations=num_relations)
        self.layer2 = ONNXRelationAwareMessagePassing(hidden_dim, hidden_dim, num_relations=num_relations)
        self.pool_proj = nn.Linear(hidden_dim * 2, hidden_dim)
        self.out_norm = nn.LayerNorm(hidden_dim)

    def forward(
        self,
        node_features: torch.Tensor,
        node_types: torch.Tensor,
        edge_src: torch.Tensor,
        edge_dst: torch.Tensor,
        edge_rel: torch.Tensor,
        edge_mask: torch.Tensor,
        has_edges: torch.Tensor,
        batch: torch.Tensor,
        batch_ref: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        feat_emb = self.node_feat_proj(node_features)
        type_emb = self.node_type_emb(node_types)
        x = self.input_norm(feat_emb + type_emb)
        x, _ = self.layer1(x, edge_src, edge_dst, edge_rel, edge_mask, has_edges)
        x, edge_alpha2 = self.layer2(x, edge_src, edge_dst, edge_rel, edge_mask, has_edges)

        graph_ids = torch.arange(batch_ref.size(0), device=x.device, dtype=batch.dtype).unsqueeze(1)
        mask_bn = graph_ids == batch.unsqueeze(0)
        mask_f = mask_bn.to(x.dtype)
        denom = mask_f.sum(dim=1, keepdim=True).clamp(min=1.0)
        mean_p = torch.matmul(mask_f, x) / denom

        neg_inf_fill = torch.full((1, 1, 1), -1e9, device=x.device, dtype=x.dtype)
        masked_x = torch.where(mask_bn.unsqueeze(-1), x.unsqueeze(0), neg_inf_fill)
        max_p = masked_x.max(dim=1).values

        pooled = torch.cat([mean_p, max_p], dim=-1)
        out = self.pool_proj(pooled)
        return self.out_norm(F.silu(out)), edge_alpha2


class ONNXASTSequenceTransformer(nn.Module):
    def __init__(self, vocab_size: int = 64, hidden_dim: int = 128, num_layers: int = 2, max_len: int = 256) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.token_emb = nn.Embedding(vocab_size, hidden_dim)
        self.rope = RotaryPositionalEmbedding(hidden_dim, max_len)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=4,
            dim_feedforward=hidden_dim * 2,
            dropout=0.1,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers,
            enable_nested_tensor=False,
        )
        self.pool_attn = nn.Linear(hidden_dim, 1)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, tokens: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        h = self.token_emb(tokens)
        cos, sin = self.rope(h)
        h_rope = apply_rotary_pos_emb(h, cos, sin)
        encoded = self.encoder(h_rope)
        attn_weights = F.softmax(self.pool_attn(encoded), dim=1)
        pooled = (encoded * attn_weights).sum(dim=1)
        return self.norm(pooled), attn_weights.squeeze(-1)


class ONNXPDFTransGraphV4(nn.Module):
    """100% branchless opset-17 ONNX wrapper for PDFTransGraphV4 (requires N >= 1 padded input)."""

    def __init__(self, model: PDFTransGraphV4) -> None:
        super().__init__()
        self.model = model

    def forward(
        self,
        tabular_features: torch.Tensor,
        action_ir_features: torch.Tensor,
        action_ir_active: torch.Tensor,
        node_features: torch.Tensor,
        node_types: torch.Tensor,
        deg_features: torch.Tensor,
        node_pad_mask: torch.Tensor,
        spd: torch.Tensor,
        direct_rel: torch.Tensor,
        root_depth: torch.Tensor,
        sink_dist: torch.Tensor,
        summary_12: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        enc = self.model.graph_encoder
        mask_bool = node_pad_mask > 0.5
        mask_f = mask_bool.unsqueeze(-1).to(node_features.dtype)
        present = node_pad_mask.sum(dim=1) > 0.5

        safe_types = node_types.clamp(0, enc.num_node_types - 1)
        h = enc.input_proj(torch.cat((node_features, deg_features), dim=-1)) + enc.type_emb(safe_types)
        if enc.enable_spd_bias:
            safe_rd = root_depth.clamp(0, SPD_UNREACHABLE)
            safe_sd = sink_dist.clamp(0, SPD_UNREACHABLE)
            h = h + enc.root_depth_emb(safe_rd) + enc.sink_dist_emb(safe_sd)
        h = enc.input_norm(h) * mask_f

        pair_attn = torch.zeros(
            (node_features.size(0), node_features.size(1), node_features.size(1)),
            device=node_features.device,
            dtype=node_features.dtype,
        )
        safe_spd = spd.clamp(0, SPD_UNREACHABLE)
        safe_rel = direct_rel.clamp(0, NUM_BASE_RELATIONS)
        key_mask = mask_bool.unsqueeze(1).unsqueeze(2)
        query_mask = mask_bool.unsqueeze(1).unsqueeze(-1).to(node_features.dtype)
        bsz, n_max, hdim = h.shape
        for layer in enc.layers:
            x = layer.norm1(h)
            qkv = layer.qkv(x).view(bsz, n_max, 3, layer.num_heads, layer.head_dim)
            q = qkv[:, :, 0].transpose(1, 2)
            k = qkv[:, :, 1].transpose(1, 2)
            v = qkv[:, :, 2].transpose(1, 2)
            scores = torch.matmul(q, k.transpose(-2, -1)) / (layer.head_dim**0.5)
            if layer.enable_spd_bias:
                bias = (
                    layer.spd_fwd_bias(safe_spd).permute(0, 3, 1, 2)
                    + layer.spd_rev_bias(safe_spd.transpose(1, 2)).permute(0, 3, 1, 2)
                    + layer.rel_bias(safe_rel).permute(0, 3, 1, 2)
                )
                scores = scores + bias
            scores = torch.where(key_mask, scores, torch.full_like(scores, -1e9))
            attn_clean = F.softmax(scores, dim=-1) * query_mask
            pair_attn = attn_clean.mean(dim=1)
            out_h = torch.matmul(attn_clean, v).transpose(1, 2).contiguous().view(bsz, n_max, hdim)
            h = h + layer.out_proj(out_h)
            h = h + layer.ffn(layer.norm2(h))

        h = enc.final_norm(h) * mask_f
        gate_raw = enc.attn_gate(h).squeeze(-1)
        gate_logits = torch.where(mask_bool, gate_raw, torch.full_like(gate_raw, -1e9))
        gate_w = F.softmax(gate_logits, dim=-1) * mask_bool.to(h.dtype)
        attn_pool = (h * gate_w.unsqueeze(-1)).sum(dim=1)

        max_pool = torch.where(mask_bool.unsqueeze(-1), h, torch.full_like(h, -1e9)).max(dim=1).values
        max_pool = torch.where(present.unsqueeze(-1), max_pool, torch.zeros_like(max_pool))

        e_graph = enc.pool_proj(torch.cat((attn_pool, max_pool, summary_12), dim=-1))
        e_graph = torch.where(present.unsqueeze(-1), e_graph, torch.zeros_like(e_graph))

        e_tab = self.model.tab_encoder(tabular_features, None)
        e_ir = self.model.action_ir_encoder(action_ir_features)
        has_tab = tabular_features[:, 0] > -1e30
        ir_present = (action_ir_active.squeeze(-1) > 0.5) & present
        mod_mask = torch.stack((has_tab, present, ir_present), dim=-1)
        fused, weights = self.model.fusion((e_tab, e_graph, e_ir), mod_mask)
        logits = self.model.classifier(fused).squeeze(-1)
        return logits, weights, pair_attn, gate_w


class ONNXPDFTransGraphV3(nn.Module):
    def __init__(self, model: PDFTransGraphV3) -> None:
        super().__init__()
        self.model = model

    def forward(
        self,
        node_features: torch.Tensor,
        node_types: torch.Tensor,
        edge_src: torch.Tensor,
        edge_dst: torch.Tensor,
        edge_rel: torch.Tensor,
        edge_mask: torch.Tensor,
        has_edges: torch.Tensor,
        use_graph_flag: torch.Tensor,
        batch: torch.Tensor,
        tabular_features: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        encoder = self.model.graph_encoder
        edge_valid = edge_mask.squeeze(-1) * has_edges
        zeros = torch.zeros_like(node_features[:, 0])
        out_degree = zeros.scatter_add(0, edge_src, edge_valid)
        in_degree = zeros.scatter_add(0, edge_dst, edge_valid)
        degree = torch.stack((torch.log1p(out_degree), torch.log1p(in_degree)), dim=-1)
        node_types = node_types.clamp(0, encoder.num_node_types - 1)
        h = encoder.input_norm(
            encoder.input_proj(torch.cat((node_features, degree), dim=-1)) + encoder.type_emb(node_types)
        )

        src = torch.cat((edge_src, edge_dst))
        dst = torch.cat((edge_dst, edge_src))
        rel = edge_rel.clamp(0, encoder.num_base_relations - 1)
        rel = torch.cat((rel, rel + encoder.num_base_relations))
        valid = torch.cat((edge_valid, edge_valid)) > 0
        for layer in encoder.layers:
            h_norm = layer.norm1(h)
            h_src, h_dst = h_norm[src], h_norm[dst]
            r = layer.rel_emb(rel)
            score = layer.attn_proj(torch.cat((h_dst, h_src, r), dim=-1)).squeeze(-1)
            score = torch.where(valid, score, torch.full_like(score, -1e9)).to(torch.float64)
            exp_score = torch.exp(score - score.max()) * valid
            denom = torch.zeros_like(zeros, dtype=torch.float64).scatter_add(0, dst, exp_score)[dst]
            alpha = (exp_score / torch.where(denom > 0, denom, torch.ones_like(denom))).to(h.dtype)
            messages = alpha.unsqueeze(-1) * (layer.msg_proj(h_src) + r)
            agg = torch.zeros_like(h).scatter_add(0, dst.unsqueeze(-1).expand_as(messages), messages)
            h = h + layer.out_proj(agg)
            h = h + layer.ffn(layer.norm2(h))
        h = encoder.final_norm(h)

        graph_ids = torch.arange(tabular_features.shape[0], device=batch.device, dtype=batch.dtype).unsqueeze(-1)
        membership = graph_ids == batch.unsqueeze(0)
        member_values = membership.to(h.dtype)
        node_counts = member_values.sum(dim=-1, keepdim=True)
        present = (node_counts > 0) & (use_graph_flag > 0.5)
        pool_scores = encoder.attn_gate(h).squeeze(-1).unsqueeze(0)
        node_weights = torch.softmax(torch.where(membership, pool_scores, -1e9), dim=-1) * member_values * present
        attn_pool = node_weights @ h
        max_pool = torch.where(membership.unsqueeze(-1), h.unsqueeze(0), -1e9).max(dim=1).values
        max_pool = torch.where(present, max_pool, torch.zeros_like(max_pool))

        type_counts = member_values @ F.one_hot(node_types, encoder.num_node_types).to(h.dtype)
        edge_counts = (member_values[:, edge_src] * edge_valid).sum(dim=-1, keepdim=True)
        orphan_counts = (member_values * ((out_degree + in_degree) == 0)).sum(dim=-1, keepdim=True)
        summary = torch.log1p(torch.cat((type_counts, node_counts, edge_counts, orphan_counts), dim=-1))
        graph = encoder.pool_proj(torch.cat((attn_pool, max_pool, summary), dim=-1))
        graph = torch.where(present, graph, torch.zeros_like(graph))

        tab = self.model.tab_encoder(tabular_features)
        mask = torch.cat((torch.ones_like(present), present, torch.zeros_like(present)), dim=-1)
        fused, weights = self.model.fusion((tab, graph, torch.zeros_like(tab)), mask)
        logits = self.model.classifier(fused).squeeze(-1)
        return logits, weights, alpha[: edge_src.shape[0]], node_weights.sum(dim=0)


class ONNXMultiLabelThreatNet(nn.Module):
    def __init__(
        self,
        node_in_dim: int = 23,
        tabular_in_features: int = 52,
        hidden_dim: int = 128,
        num_labels: int = 8,
    ) -> None:
        super().__init__()
        self.graph_encoder = ONNXHeteroGraphTransformer(node_in_dim=node_in_dim, hidden_dim=hidden_dim)
        self.ast_encoder = ONNXASTSequenceTransformer(vocab_size=64, hidden_dim=hidden_dim)
        self.tabular_encoder = TabularResNet(in_features=tabular_in_features, hidden_dim=hidden_dim)
        self.fusion = CrossModalAttentionFusion(hidden_dim=hidden_dim)
        self.no_graph_embedding = nn.Parameter(torch.zeros(1, hidden_dim))
        combined_dim = hidden_dim * 4
        self.trunk_proj = nn.Sequential(
            nn.Linear(combined_dim, hidden_dim * 2),
            nn.LayerNorm(hidden_dim * 2),
            nn.SiLU(),
            nn.Dropout(0.25),
        )
        self.trunk_res = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim * 2),
            nn.LayerNorm(hidden_dim * 2),
            nn.SiLU(),
            nn.Dropout(0.20),
        )
        self.label_queries = nn.Parameter(torch.zeros(num_labels, hidden_dim * 2))
        self.label_scale = nn.Parameter(torch.ones(num_labels))
        self.label_bias = nn.Parameter(torch.zeros(num_labels))
        self.label_linear = nn.Linear(hidden_dim * 2, num_labels)
        self.aux_mal_head = nn.Linear(hidden_dim * 2, 1)

    def forward(
        self,
        node_features: torch.Tensor,
        node_types: torch.Tensor,
        edge_src: torch.Tensor,
        edge_dst: torch.Tensor,
        edge_rel: torch.Tensor,
        edge_mask: torch.Tensor,
        has_edges: torch.Tensor,
        use_graph_flag: torch.Tensor,
        batch: torch.Tensor,
        ast_tokens: torch.Tensor,
        tabular_features: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        h_graph_raw, _ = self.graph_encoder(
            node_features,
            node_types,
            edge_src,
            edge_dst,
            edge_rel,
            edge_mask,
            has_edges,
            batch,
            tabular_features,
        )
        no_g = self.no_graph_embedding.expand(tabular_features.size(0), -1)
        h_graph = h_graph_raw * use_graph_flag + no_g * (1.0 - use_graph_flag)
        h_seq, _ = self.ast_encoder(ast_tokens)
        h_tab = self.tabular_encoder(tabular_features)
        z_fused, _ = self.fusion(h_graph, h_seq, h_tab)
        z_cat = torch.cat([z_fused, h_tab, h_seq], dim=-1)
        h = self.trunk_proj(z_cat)
        h = h + self.trunk_res(h)
        query_scores = torch.matmul(h, self.label_queries.t()) * self.label_scale + self.label_bias
        label_logits = self.label_linear(h) + query_scores
        mal_logit = self.aux_mal_head(h).squeeze(-1)
        return label_logits, mal_logit


def _prepare_edge_tensors(
    ei: torch.Tensor, er: torch.Tensor
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    if ei.numel() > 0 and ei.size(1) > 0:
        return (
            ei[0].long(),
            ei[1].long(),
            er.long(),
            torch.ones((ei.size(1), 1), dtype=torch.float32),
            torch.tensor([1.0], dtype=torch.float32),
        )
    return (
        torch.zeros((1,), dtype=torch.long),
        torch.zeros((1,), dtype=torch.long),
        torch.zeros((1,), dtype=torch.long),
        torch.zeros((1, 1), dtype=torch.float32),
        torch.tensor([0.0], dtype=torch.float32),
    )


def _offline_binary_rows(path: Path, key: str, expected_count: int) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload[key]
    if payload["features"] != list(FEATURES) or len(rows) != expected_count:
        raise ValueError(f"Unexpected offline evidence contract: {path}")
    return list(rows.values()) if isinstance(rows, dict) else rows


def _v4_pytorch_forward(model: PDFTransGraphV4, feed: dict[str, np.ndarray]) -> dict[str, torch.Tensor]:
    return model(
        torch.from_numpy(feed["tabular_features"]),
        torch.from_numpy(feed["action_ir_features"]),
        torch.from_numpy(feed["action_ir_active"].squeeze(-1) > 0.5),
        torch.from_numpy(feed["node_features"]),
        torch.from_numpy(feed["node_types"]),
        torch.from_numpy(feed["deg_features"]),
        torch.from_numpy(feed["node_pad_mask"] > 0.5),
        torch.from_numpy(feed["spd"]),
        torch.from_numpy(feed["direct_rel"]),
        torch.from_numpy(feed["root_depth"]),
        torch.from_numpy(feed["sink_dist"]),
        torch.from_numpy(feed["summary_12"]),
        return_graph_details=True,
    )


@torch.inference_mode()
def _v4_parity(model: PDFTransGraphV4, session: ort.InferenceSession, feed: dict[str, np.ndarray]) -> float:
    expected = _v4_pytorch_forward(model, feed)
    logits, weights, _pair_attn, node_attn = session.run(None, feed)
    np.testing.assert_allclose(weights, expected["weights"].numpy(), rtol=0.0, atol=1e-6)
    if float(feed["node_pad_mask"].sum()) == 0.0:
        np.testing.assert_array_equal(node_attn, 0.0)
    error = float(np.max(np.abs(expected["logits"].numpy() - logits)))
    if not np.isfinite(error):
        raise ValueError("non_finite_v4_logit_parity")
    return error


def _v4_offline_feed(row: dict, center: np.ndarray, scale: np.ndarray) -> dict[str, np.ndarray]:
    vector = np.asarray(row["vector_v3"], dtype=np.float32)
    raw = vector[list(REGIME_B_INDICES)]
    if not np.isfinite(raw).all():
        raise ValueError("non_finite_regime_b_features")
    tab = ((log_matrix(raw[None, :]) - center) / scale).astype(np.float32)
    nf, nt, es, ed, er = row["graph"]
    graph_tup = (
        (
            np.asarray(nf, dtype=np.float32),
            np.asarray(nt, dtype=np.int64),
            np.asarray(es, dtype=np.int64),
            np.asarray(ed, dtype=np.int64),
            np.asarray(er, dtype=np.int64),
        )
        if nf
        else None
    )
    return collate_v4_numpy_feed(tab, [graph_tup])


def _fixture_binary_inputs(ingested: dict[str, object]) -> dict[str, np.ndarray]:
    v4_tab = ingested.get("v4_tab_features")
    if v4_tab is None or not isinstance(v4_tab, torch.Tensor):
        raise ValueError("Expected v4_tab_features tensor in ingested payload")
    g_tup = single_graph_tuple(
        ingested["node_features"],  # type: ignore[arg-type]
        ingested["node_types"],  # type: ignore[arg-type]
        ingested["edge_index"],  # type: ignore[arg-type]
        ingested["edge_rel"],  # type: ignore[arg-type]
        bool(ingested["graph_present"]),
    )
    return collate_v4_numpy_feed(v4_tab.numpy(), [g_tup])


def _binary_parity(
    model: PDFTransGraphV4,
    session: ort.InferenceSession,
    feed: dict[str, np.ndarray],
) -> float:
    return _v4_parity(model, session, feed)


def verify_stress_parity(
    pt_model: nn.Module,
    ort_sess: ort.InferenceSession,
    ingestion: InstantPDFIngestion,
) -> float:
    if not isinstance(pt_model, PDFTransGraphV4):
        raise TypeError(f"Expected PDFTransGraphV4 for stress parity check, got {type(pt_model).__name__}")
    contract = json.loads(V4_CONTRACT_PATH.read_text(encoding="utf-8"))
    center = np.asarray(contract["center"], dtype=np.float64)
    scale = np.asarray(contract["scale"], dtype=np.float64)
    tb = load_real_threat_bytes()
    bb = load_real_benign_bytes()
    db, _ = PDFDisarmer().sanitize_bytes(tb, file_name="threat.pdf")
    live_diff = max(
        _binary_parity(pt_model, ort_sess, _fixture_binary_inputs(ingestion.ingest(sample_bytes)))
        for sample_bytes in (tb, bb, db)
    )

    controls = _offline_binary_rows(CONTROL_PATH, "controls", expected_count=4)
    controls_diff = max(_v4_parity(pt_model, ort_sess, _v4_offline_feed(row, center, scale)) for row in controls)

    stress_file = STRESS_PATH if STRESS_PATH.is_file() else STRESS_ARCHIVE
    if hashlib.sha256(stress_file.read_bytes()).hexdigest() != STRESS_SHA256:
        raise ValueError("phase_2_export_sha256_mismatch")
    stress_rows = _offline_binary_rows(stress_file, "variants", expected_count=20)
    empty = next(row for row in stress_rows if row["id"] == "benign_repaired_xref_padding")
    if empty["node_count"] != 0 or empty["graph"][0]:
        raise ValueError("phase_2_expected_empty_graph")
    stress_diff = max(_v4_parity(pt_model, ort_sess, _v4_offline_feed(row, center, scale)) for row in stress_rows)
    return max(live_diff, controls_diff, stress_diff)


def export_and_verify() -> dict[str, object]:
    PROD_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    PROD_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    use_v4 = PT_V4_BINARY_PATH.is_file() and V4_CONTRACT_PATH.is_file()
    with TemporaryDirectory(prefix=".onnx-", dir=PROD_MODELS_DIR) as models:
        with TemporaryDirectory(prefix=".onnx-", dir=PROD_CONFIGS_DIR) as configs:
            model_stage, config_stage = Path(models), Path(configs)
            manifest = (
                _export_and_verify_v4(model_stage, config_stage)
                if use_v4
                else _export_and_verify_v3(model_stage, config_stage)
            )
            for model in model_stage.iterdir():
                model.replace(PROD_MODELS_DIR / model.name)
            if use_v4:
                stale_v3 = PROD_MODELS_DIR / "pdf_transgraph_v3.onnx"
                if stale_v3.exists():
                    stale_v3.unlink()
            for config in config_stage.iterdir():
                if config.name != "onnx_manifest.json":
                    config.replace(PROD_CONFIGS_DIR / config.name)
            (config_stage / "onnx_manifest.json").replace(PROD_CONFIGS_DIR / "onnx_manifest.json")
    return manifest


def _export_multilabel_onnx(models_dir: Path) -> tuple[PDFMultiLabelThreatNet, Path]:
    ml_sd = torch.load(PT_MULTILABEL_PATH, map_location="cpu", weights_only=True)
    pt_ml = PDFMultiLabelThreatNet(node_in_dim=23, tabular_in_features=52, hidden_dim=128, num_labels=8)
    pt_ml.load_state_dict(ml_sd, strict=True)
    pt_ml.eval()

    onnx_ml = ONNXMultiLabelThreatNet(node_in_dim=23, tabular_in_features=52, hidden_dim=128, num_labels=8)
    onnx_ml.load_state_dict(ml_sd, strict=True)
    onnx_ml.eval()

    dummy_nf = torch.randn(12, 23, dtype=torch.float32)
    dummy_nt = torch.zeros(12, dtype=torch.long)
    dummy_es = torch.tensor([0, 1, 2, 6, 7], dtype=torch.long)
    dummy_ed = torch.tensor([1, 2, 3, 7, 8], dtype=torch.long)
    dummy_er = torch.tensor([0, 1, 2, 0, 1], dtype=torch.long)
    dummy_em = torch.ones((5, 1), dtype=torch.float32)
    dummy_he = torch.tensor([1.0], dtype=torch.float32)
    dummy_ug = torch.tensor([1.0], dtype=torch.float32)
    dummy_b = torch.tensor([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1], dtype=torch.long)
    dummy_tok = torch.zeros((2, 32), dtype=torch.long)
    dummy_tab52 = torch.randn(2, 52, dtype=torch.float32)

    ml_onnx_path = models_dir / "multilabel_threat_net_v2.onnx"
    torch.onnx.export(
        onnx_ml,
        (
            dummy_nf,
            dummy_nt,
            dummy_es,
            dummy_ed,
            dummy_er,
            dummy_em,
            dummy_he,
            dummy_ug,
            dummy_b,
            dummy_tok,
            dummy_tab52,
        ),
        str(ml_onnx_path),
        input_names=[
            "node_features",
            "node_types",
            "edge_src",
            "edge_dst",
            "edge_rel",
            "edge_mask",
            "has_edges",
            "use_graph_flag",
            "batch",
            "ast_tokens",
            "tabular_features",
        ],
        output_names=["label_logits", "mal_logit"],
        dynamic_axes={
            "node_features": {0: "num_nodes"},
            "node_types": {0: "num_nodes"},
            "edge_src": {0: "num_edges"},
            "edge_dst": {0: "num_edges"},
            "edge_rel": {0: "num_edges"},
            "edge_mask": {0: "num_edges"},
            "batch": {0: "num_nodes"},
            "ast_tokens": {0: "batch_size"},
            "tabular_features": {0: "batch_size"},
            "label_logits": {0: "batch_size"},
            "mal_logit": {0: "batch_size"},
        },
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )
    onnx.checker.check_model(str(ml_onnx_path))
    return pt_ml, ml_onnx_path


def _export_and_verify_v4(models_dir: Path, configs_dir: Path) -> dict[str, object]:
    torch.set_num_threads(2)
    contract = json.loads(V4_CONTRACT_PATH.read_text(encoding="utf-8"))
    if hashlib.sha256(PT_V4_BINARY_PATH.read_bytes()).hexdigest() != contract["weights_npz_sha256"]:
        raise ValueError("binary_v4_npz_sha256_mismatch")
    if not V4_CONFORMAL_PATH.is_file():
        raise FileNotFoundError(f"Missing v4 conformal calibration: {V4_CONFORMAL_PATH}")
    conf_lf_sha = hashlib.sha256(V4_CONFORMAL_PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if contract.get("conformal_calibration_sha256") != conf_lf_sha:
        raise ValueError("v4_conformal_calibration_sha256_mismatch")

    pt_bin = PDFTransGraphV4(TransGraphV4Config(**contract["model_config"])).eval()
    load_v4_weights_npz(pt_bin, PT_V4_BINARY_PATH)
    onnx_bin = ONNXPDFTransGraphV4(pt_bin).eval()

    dummy_feed = collate_v4_numpy_feed(
        np.zeros((2, 29), dtype=np.float32),
        [
            (
                np.zeros((6, 23), dtype=np.float32),
                np.array([0, 1, 2, 3, 5, 6], dtype=np.int64),
                np.array([0, 1, 0, 3], dtype=np.int64),
                np.array([1, 2, 3, 4], dtype=np.int64),
                np.array([0, 1, 2, 4], dtype=np.int64),
            ),
            None,
        ],
    )
    input_names = [
        "tabular_features",
        "action_ir_features",
        "action_ir_active",
        "node_features",
        "node_types",
        "deg_features",
        "node_pad_mask",
        "spd",
        "direct_rel",
        "root_depth",
        "sink_dist",
        "summary_12",
    ]
    dummy_args = tuple(torch.from_numpy(dummy_feed[k]) for k in input_names)
    bin_onnx_path = models_dir / "pdf_transgraph_v4.onnx"
    torch.onnx.export(
        onnx_bin,
        dummy_args,
        str(bin_onnx_path),
        input_names=input_names,
        output_names=["logits", "attn_weights", "pair_attn", "node_attn"],
        dynamic_axes={
            "tabular_features": {0: "batch_size"},
            "action_ir_features": {0: "batch_size"},
            "action_ir_active": {0: "batch_size"},
            "node_features": {0: "batch_size", 1: "num_nodes"},
            "node_types": {0: "batch_size", 1: "num_nodes"},
            "deg_features": {0: "batch_size", 1: "num_nodes"},
            "node_pad_mask": {0: "batch_size", 1: "num_nodes"},
            "spd": {0: "batch_size", 1: "num_nodes", 2: "num_nodes"},
            "direct_rel": {0: "batch_size", 1: "num_nodes", 2: "num_nodes"},
            "root_depth": {0: "batch_size", 1: "num_nodes"},
            "sink_dist": {0: "batch_size", 1: "num_nodes"},
            "summary_12": {0: "batch_size"},
            "logits": {0: "batch_size"},
            "attn_weights": {0: "batch_size"},
            "pair_attn": {0: "batch_size", 1: "num_nodes", 2: "num_nodes"},
            "node_attn": {0: "batch_size", 1: "num_nodes"},
        },
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )
    binary_onnx = onnx.load(str(bin_onnx_path))
    onnx.checker.check_model(binary_onnx)
    if any(node.op_type in {"If", "Loop", "Scan"} for node in binary_onnx.graph.node):
        raise ValueError("unexpected_binary_onnx_control_flow")

    pt_ml, ml_onnx_path = _export_multilabel_onnx(models_dir)

    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = 2
    sess_opts.inter_op_num_threads = 1
    sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
    bin_sess = ort.InferenceSession(str(bin_onnx_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])
    ml_sess = ort.InferenceSession(str(ml_onnx_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])

    ing = InstantPDFIngestion(v4_contract_path=V4_CONTRACT_PATH)
    tb = load_real_threat_bytes()
    bb = load_real_benign_bytes()
    db, _ = PDFDisarmer().sanitize_bytes(tb, file_name="threat.pdf")
    ml_contract = json.loads(ML_CONTRACT_PATH.read_text(encoding="utf-8"))
    mean52 = np.array(ml_contract["scaler_mean"], dtype=np.float32)
    scale52 = np.array(ml_contract["scaler_scale"], dtype=np.float32)

    max_bin_diff = 0.0
    max_ml_diff = 0.0
    for sample_bytes in (tb, bb, db):
        d = ing.ingest(sample_bytes)
        nf, nt, ei, er, b, tok = (
            d["node_features"],
            d["node_types"],
            d["edge_index"],
            d["edge_rel"],
            d["batch"],
            d["ast_tokens"],
        )
        g_tup = single_graph_tuple(nf, nt, ei, er, d["graph_present"])
        v4_feed = collate_v4_numpy_feed(d["v4_tab_features"].numpy(), [g_tup])
        max_bin_diff = max(max_bin_diff, _v4_parity(pt_bin, bin_sess, v4_feed))

        es, ed, er_p, em, he = _prepare_edge_tensors(ei, er)
        rt = scan_raw_pdf_tokens(sample_bytes)
        esc = float(count_escaped_pdf_names(sample_bytes))
        loops = 1.0 if d["ast_stats"]["loops"] > 0 else 0.0
        js_txt = "\n".join(s["code"] for s in d["extracted_scripts"])
        deobf = 1.0 if any(k in js_txt for k in ("unescape", "fromCharCode", "eval")) else 0.0
        uri_eff = float(rt.get("URI", 0))
        emb_eff = float(rt.get("EmbeddedFile", 0) + rt.get("Launch", 0))
        extra = [
            float(rt.get("AA", 0)),
            float(rt.get("Acroform", 0)),
            float(rt.get("Launch", 0)),
            float(rt.get("EmbeddedFile", 0)),
            float(rt.get("URI", 0)),
            float(rt.get("ObjStm", 0)),
            float(rt.get("Encrypt", 0)),
            float(rt.get("JBIG2Decode", 0)),
            float(rt.get("RichMedia", 0)),
            esc,
            loops,
            deobf,
            uri_eff,
            emb_eff,
        ]
        vec52 = np.array([float(x or 0.0) for x in d["raw_feature_vec"]] + extra, dtype=np.float32)
        tab52 = torch.tensor((vec52 - mean52) / scale52, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            pt_ml_logits, _, _ = pt_ml(nf, nt, ei, er, b, tok, tab52)
        ort_ml_out = ml_sess.run(
            None,
            {
                "node_features": nf.numpy(),
                "node_types": nt.numpy(),
                "edge_src": es.numpy(),
                "edge_dst": ed.numpy(),
                "edge_rel": er_p.numpy(),
                "edge_mask": em.numpy(),
                "has_edges": he.numpy(),
                "use_graph_flag": np.array([1.0], dtype=np.float32),
                "batch": b.numpy(),
                "ast_tokens": tok.numpy(),
                "tabular_features": tab52.numpy(),
            },
        )
        diff_m = float(np.max(np.abs(pt_ml_logits.numpy() - np.asarray(ort_ml_out[0]))))
        max_ml_diff = max(max_ml_diff, diff_m)

    center = np.asarray(contract["center"], dtype=np.float64)
    scale = np.asarray(contract["scale"], dtype=np.float64)
    controls = _offline_binary_rows(CONTROL_PATH, "controls", expected_count=4)
    controls_diff = max(_v4_parity(pt_bin, bin_sess, _v4_offline_feed(row, center, scale)) for row in controls)

    stress_file = STRESS_PATH if STRESS_PATH.is_file() else STRESS_ARCHIVE
    if hashlib.sha256(stress_file.read_bytes()).hexdigest() != STRESS_SHA256:
        raise ValueError("phase_2_export_sha256_mismatch")
    stress_rows = _offline_binary_rows(stress_file, "variants", expected_count=20)
    empty = next(row for row in stress_rows if row["id"] == "benign_repaired_xref_padding")
    if empty["node_count"] != 0 or empty["graph"][0]:
        raise ValueError("phase_2_expected_empty_graph")
    stress_diff = max(_v4_parity(pt_bin, bin_sess, _v4_offline_feed(row, center, scale)) for row in stress_rows)

    max_bin_diff = max(max_bin_diff, controls_diff, stress_diff)
    assert max_bin_diff < 1e-5, f"Binary v4 ONNX parity drift too high: {max_bin_diff}"
    assert max_ml_diff < 1e-4, f"MultiLabel ONNX parity drift too high: {max_ml_diff}"

    for config_path in (V4_CONTRACT_PATH, V4_CONFORMAL_PATH, SCALER_PATH, ML_CONTRACT_PATH):
        (configs_dir / config_path.name).write_bytes(config_path.read_bytes())

    d_bench = ing.ingest(tb)
    nf_b, nt_b, ei_b, er_b, b_b, tok_b = (
        d_bench["node_features"],
        d_bench["node_types"],
        d_bench["edge_index"],
        d_bench["edge_rel"],
        d_bench["batch"],
        d_bench["ast_tokens"],
    )
    ort_bin_feed = collate_v4_numpy_feed(
        d_bench["v4_tab_features"].numpy(),
        [single_graph_tuple(nf_b, nt_b, ei_b, er_b, d_bench["graph_present"])],
    )
    es_b, ed_b, er_pb, em_b, he_b = _prepare_edge_tensors(ei_b, er_b)
    tab52_b = torch.zeros((1, 52), dtype=torch.float32)
    ort_ml_feed = {
        "node_features": nf_b.numpy(),
        "node_types": nt_b.numpy(),
        "edge_src": es_b.numpy(),
        "edge_dst": ed_b.numpy(),
        "edge_rel": er_pb.numpy(),
        "edge_mask": em_b.numpy(),
        "has_edges": he_b.numpy(),
        "use_graph_flag": np.array([1.0], dtype=np.float32),
        "batch": b_b.numpy(),
        "ast_tokens": tok_b.numpy(),
        "tabular_features": tab52_b.numpy(),
    }

    for _ in range(3):
        with torch.no_grad():
            _v4_pytorch_forward(pt_bin, ort_bin_feed)
            pt_ml(nf_b, nt_b, ei_b, er_b, b_b, tok_b, tab52_b)
        bin_sess.run(None, ort_bin_feed)
        ml_sess.run(None, ort_ml_feed)

    pt_neural_ms: list[float] = []
    ort_neural_ms: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        with torch.no_grad():
            _v4_pytorch_forward(pt_bin, ort_bin_feed)
            pt_ml(nf_b, nt_b, ei_b, er_b, b_b, tok_b, tab52_b)
        pt_neural_ms.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        bin_sess.run(None, ort_bin_feed)
        ml_sess.run(None, ort_ml_feed)
        ort_neural_ms.append((time.perf_counter() - t1) * 1000.0)

    pt_med = statistics.median(pt_neural_ms)
    ort_med = statistics.median(ort_neural_ms)
    bin_param_count = int(sum(p.numel() for p in onnx_bin.parameters()))
    ml_param_count = int(sum(p.numel() for p in pt_ml.parameters()))

    manifest = {
        "onnx_opset": 17,
        "binary_model": {
            "filename": bin_onnx_path.name,
            "model_version": "PDF-TransGraph v4",
            "regime": contract["regime"],
            "source_run": contract["source_run"],
            "conformal_run": contract.get("conformal_run"),
            "temperature": contract["temperature"],
            "decision_threshold": contract["decision_threshold"],
            "tabular_in_features": pt_bin.config.tab_dim,
            "action_ir_in_features": pt_bin.config.action_ir_dim,
            "node_in_dim": pt_bin.config.node_dim,
            "sha256": hashlib.sha256(bin_onnx_path.read_bytes()).hexdigest(),
            "contract_sha256": hashlib.sha256(V4_CONTRACT_PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
            "conformal_sha256": conf_lf_sha,
            "size_bytes": bin_onnx_path.stat().st_size,
            "parameter_count": bin_param_count,
            "max_logit_abs_diff_vs_pytorch": max_bin_diff,
            "reviewed_controls_max_logit_abs_diff": controls_diff,
            "phase_2_max_logit_abs_diff": stress_diff,
        },
        "multilabel_model": {
            "filename": "multilabel_threat_net_v2.onnx",
            "sha256": hashlib.sha256(ml_onnx_path.read_bytes()).hexdigest(),
            "size_bytes": ml_onnx_path.stat().st_size,
            "parameter_count": ml_param_count,
            "max_logit_abs_diff_vs_pytorch": round(max_ml_diff, 8),
        },
        "neural_forward_benchmark_cpu": {
            "pytorch_median_ms": round(pt_med, 3),
            "onnxruntime_median_ms": round(ort_med, 3),
            "speedup_factor": round(pt_med / max(ort_med, 1e-6), 2),
        },
    }
    (configs_dir / "onnx_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def _export_and_verify_v3(models_dir: Path, configs_dir: Path) -> dict[str, object]:
    torch.set_num_threads(2)
    contract = json.loads(V3_CONTRACT_PATH.read_text(encoding="utf-8"))
    if hashlib.sha256(PT_V3_BINARY_PATH.read_bytes()).hexdigest() != contract["weights_npz_sha256"]:
        raise ValueError("binary_npz_sha256_mismatch")
    pt_bin = PDFTransGraphV3(TransGraphV3Config(**contract["model_config"])).eval()
    load_v3_weights_npz(pt_bin, PT_V3_BINARY_PATH)
    onnx_bin = ONNXPDFTransGraphV3(pt_bin).eval()
    pt_ml, ml_onnx_path = _export_multilabel_onnx(models_dir)

    dummy_nf = torch.randn(12, 23, dtype=torch.float32)
    dummy_nt = torch.zeros(12, dtype=torch.long)
    dummy_es = torch.tensor([0, 1, 2, 6, 7], dtype=torch.long)
    dummy_ed = torch.tensor([1, 2, 3, 7, 8], dtype=torch.long)
    dummy_er = torch.tensor([0, 1, 2, 0, 1], dtype=torch.long)
    dummy_em = torch.ones((5, 1), dtype=torch.float32)
    dummy_he = torch.tensor([1.0], dtype=torch.float32)
    dummy_b = torch.tensor([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1], dtype=torch.long)
    dummy_tab29 = torch.randn(2, 29, dtype=torch.float32)

    bin_onnx_path = models_dir / "pdf_transgraph_v3.onnx"
    torch.onnx.export(
        onnx_bin,
        (
            dummy_nf,
            dummy_nt,
            dummy_es,
            dummy_ed,
            dummy_er,
            dummy_em,
            dummy_he,
            torch.tensor([[1.0], [0.0]]),
            dummy_b,
            dummy_tab29,
        ),
        str(bin_onnx_path),
        input_names=[
            "node_features",
            "node_types",
            "edge_src",
            "edge_dst",
            "edge_rel",
            "edge_mask",
            "has_edges",
            "use_graph_flag",
            "batch",
            "tabular_features",
        ],
        output_names=["logits", "attn_weights", "edge_alpha", "node_attn"],
        dynamic_axes={
            "node_features": {0: "num_nodes"},
            "node_types": {0: "num_nodes"},
            "edge_src": {0: "num_edges"},
            "edge_dst": {0: "num_edges"},
            "edge_rel": {0: "num_edges"},
            "edge_mask": {0: "num_edges"},
            "batch": {0: "num_nodes"},
            "use_graph_flag": {0: "batch_size"},
            "tabular_features": {0: "batch_size"},
            "logits": {0: "batch_size"},
            "attn_weights": {0: "batch_size"},
            "edge_alpha": {0: "num_edges"},
            "node_attn": {0: "num_nodes"},
        },
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )
    binary_onnx = onnx.load(str(bin_onnx_path))
    onnx.checker.check_model(binary_onnx)
    if any(node.op_type in {"If", "Loop", "Scan"} for node in binary_onnx.graph.node):
        raise ValueError("unexpected_binary_onnx_control_flow")

    for config_path in (V3_CONTRACT_PATH, SCALER_PATH, ML_CONTRACT_PATH):
        (configs_dir / config_path.name).write_bytes(config_path.read_bytes())

    manifest = {
        "onnx_opset": 17,
        "binary_model": {
            "filename": bin_onnx_path.name,
            "model_version": "PDF-TransGraph v3.2b",
            "regime": contract["regime"],
            "source_run": contract["source_run"],
            "temperature": contract["temperature"],
            "decision_threshold": contract["decision_threshold"],
            "tabular_in_features": pt_bin.config.tab_dim,
            "node_in_dim": pt_bin.config.node_dim,
            "sha256": hashlib.sha256(bin_onnx_path.read_bytes()).hexdigest(),
            "contract_sha256": hashlib.sha256(V3_CONTRACT_PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
            "size_bytes": bin_onnx_path.stat().st_size,
            "parameter_count": int(sum(p.numel() for p in pt_bin.parameters())),
        },
        "multilabel_model": {
            "filename": "multilabel_threat_net_v2.onnx",
            "sha256": hashlib.sha256(ml_onnx_path.read_bytes()).hexdigest(),
            "size_bytes": ml_onnx_path.stat().st_size,
            "parameter_count": int(sum(p.numel() for p in pt_ml.parameters())),
        },
    }
    (configs_dir / "onnx_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


if __name__ == "__main__":
    res = export_and_verify()
    print(json.dumps(res, indent=2, ensure_ascii=False))
