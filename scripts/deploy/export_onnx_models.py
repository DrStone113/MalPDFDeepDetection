from __future__ import annotations

import hashlib
import json
from pathlib import Path
import statistics
import sys
import time
import warnings

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
from malpdf.models.ast_transformer import RotaryPositionalEmbedding, apply_rotary_pos_emb
from malpdf.models.cross_attention_fusion import CrossModalAttentionFusion
from malpdf.models.multilabel_threat_net import PDFMultiLabelThreatNet
from malpdf.models.pdf_transgraph import PDFTransGraph
from malpdf.models.tabular_resnet import TabularResNet
from malpdf.scanner.ingestion import InstantPDFIngestion
from malpdf.static.obfuscation import count_escaped_pdf_names
from malpdf.static.raw_scan import scan_raw_pdf_tokens

PROD_DIR = REPO_ROOT / "production"
PROD_MODELS_DIR = PROD_DIR / "models"
PROD_CONFIGS_DIR = PROD_DIR / "configs"

PT_BINARY_PATH = REPO_ROOT / "artifacts" / "models" / "pdf_transgraph_v2" / "pdf_transgraph_v2_23d_best.pt"
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


class ONNXPDFTransGraph(nn.Module):
    def __init__(self, node_in_dim: int = 23, tabular_in_features: int = 38, hidden_dim: int = 128) -> None:
        super().__init__()
        self.graph_encoder = ONNXHeteroGraphTransformer(node_in_dim=node_in_dim, hidden_dim=hidden_dim)
        self.ast_encoder = ONNXASTSequenceTransformer(vocab_size=64, hidden_dim=hidden_dim)
        self.tabular_encoder = TabularResNet(in_features=tabular_in_features, hidden_dim=hidden_dim)
        self.fusion = CrossModalAttentionFusion(hidden_dim=hidden_dim)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 1),
        )
        self.single_branch_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim // 2, 1),
        )

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
        ast_tokens: torch.Tensor,
        tabular_features: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        h_graph, edge_alpha = self.graph_encoder(
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
        h_seq, ast_token_attn = self.ast_encoder(ast_tokens)
        h_tab = self.tabular_encoder(tabular_features)
        z_final, attn_weights = self.fusion(h_graph, h_seq, h_tab)
        logits = self.classifier(z_final).squeeze(-1)
        return logits, attn_weights, edge_alpha, ast_token_attn


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


def _prepare_edge_tensors(ei: torch.Tensor, er: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
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


def export_and_verify() -> dict[str, object]:
    warnings.filterwarnings("ignore")
    PROD_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    PROD_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

    bin_sd = torch.load(PT_BINARY_PATH, map_location="cpu", weights_only=True)
    pt_bin = PDFTransGraph(node_in_dim=23, tabular_in_features=38, hidden_dim=128)
    pt_bin.load_state_dict(bin_sd, strict=True)
    pt_bin.eval()

    onnx_bin = ONNXPDFTransGraph(node_in_dim=23, tabular_in_features=38, hidden_dim=128)
    onnx_bin.load_state_dict(bin_sd, strict=True)
    onnx_bin.eval()

    ml_contract = json.loads(ML_CONTRACT_PATH.read_text(encoding="utf-8"))
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
    dummy_tab38 = torch.randn(2, 38, dtype=torch.float32)
    dummy_tab52 = torch.randn(2, 52, dtype=torch.float32)

    bin_onnx_path = PROD_MODELS_DIR / "pdf_transgraph_v2.onnx"
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
            dummy_b,
            dummy_tok,
            dummy_tab38,
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
            "batch",
            "ast_tokens",
            "tabular_features",
        ],
        output_names=["logits", "attn_weights", "edge_alpha", "ast_token_attn"],
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
            "logits": {0: "batch_size"},
            "attn_weights": {0: "batch_size"},
            "edge_alpha": {0: "num_edges"},
            "ast_token_attn": {0: "batch_size"},
        },
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )
    onnx.checker.check_model(str(bin_onnx_path))

    ml_onnx_path = PROD_MODELS_DIR / "multilabel_threat_net_v2.onnx"
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

    sess_opts = ort.SessionOptions()
    sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    bin_sess = ort.InferenceSession(str(bin_onnx_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])
    ml_sess = ort.InferenceSession(str(ml_onnx_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])

    ing = InstantPDFIngestion()
    tb = load_real_threat_bytes()
    bb = load_real_benign_bytes()
    db, _ = PDFDisarmer().sanitize_bytes(tb, file_name="threat.pdf")
    mean52 = np.array(ml_contract["scaler_mean"], dtype=np.float32)
    scale52 = np.array(ml_contract["scaler_scale"], dtype=np.float32)

    max_bin_diff = 0.0
    max_ml_diff = 0.0
    for sample_bytes in (tb, bb, db):
        d = ing.ingest(sample_bytes)
        nf, nt, ei, er, b, tok, tab38 = (
            d["node_features"],
            d["node_types"],
            d["edge_index"],
            d["edge_rel"],
            d["batch"],
            d["ast_tokens"],
            d["tab_features"],
        )
        es, ed, er_p, em, he = _prepare_edge_tensors(ei, er)
        with torch.no_grad():
            pt_logit, _ = pt_bin(nf, nt, ei, er, b, tok, tab38)
        ort_out = bin_sess.run(
            None,
            {
                "node_features": nf.numpy(),
                "node_types": nt.numpy(),
                "edge_src": es.numpy(),
                "edge_dst": ed.numpy(),
                "edge_rel": er_p.numpy(),
                "edge_mask": em.numpy(),
                "has_edges": he.numpy(),
                "batch": b.numpy(),
                "ast_tokens": tok.numpy(),
                "tabular_features": tab38.numpy(),
            },
        )
        diff_b = float(np.max(np.abs(pt_logit.numpy().reshape(-1) - np.asarray(ort_out[0]).reshape(-1))))
        max_bin_diff = max(max_bin_diff, diff_b)

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
            pt_ml_logits, pt_mal_l, _ = pt_ml(nf, nt, ei, er, b, tok, tab52)
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

    assert max_bin_diff < 1e-4, f"Binary ONNX parity drift too high: {max_bin_diff}"
    assert max_ml_diff < 1e-4, f"MultiLabel ONNX parity drift too high: {max_ml_diff}"

    (PROD_CONFIGS_DIR / "tabular_scaler.json").write_bytes(SCALER_PATH.read_bytes())
    (PROD_CONFIGS_DIR / "multilabel_threat_contract.json").write_bytes(ML_CONTRACT_PATH.read_bytes())

    d_bench = ing.ingest(tb)
    nf_b = d_bench["node_features"]
    nt_b = d_bench["node_types"]
    ei_b = d_bench["edge_index"]
    er_b = d_bench["edge_rel"]
    b_b = d_bench["batch"]
    tok_b = d_bench["ast_tokens"]
    tab38_b = d_bench["tab_features"]
    es_b, ed_b, er_pb, em_b, he_b = _prepare_edge_tensors(ei_b, er_b)
    ort_bin_feed = {
        "node_features": np.ascontiguousarray(nf_b.numpy(), dtype=np.float32),
        "node_types": np.ascontiguousarray(nt_b.numpy(), dtype=np.int64),
        "edge_src": np.ascontiguousarray(es_b.numpy(), dtype=np.int64),
        "edge_dst": np.ascontiguousarray(ed_b.numpy(), dtype=np.int64),
        "edge_rel": np.ascontiguousarray(er_pb.numpy(), dtype=np.int64),
        "edge_mask": np.ascontiguousarray(em_b.numpy(), dtype=np.float32),
        "has_edges": np.ascontiguousarray(he_b.numpy(), dtype=np.float32),
        "batch": np.ascontiguousarray(b_b.numpy(), dtype=np.int64),
        "ast_tokens": np.ascontiguousarray(tok_b.numpy(), dtype=np.int64),
        "tabular_features": np.ascontiguousarray(tab38_b.numpy(), dtype=np.float32),
    }
    tab52_b = torch.zeros((1, 52), dtype=torch.float32)
    ort_ml_feed = dict(ort_bin_feed)
    ort_ml_feed["use_graph_flag"] = np.array([1.0], dtype=np.float32)
    ort_ml_feed["tabular_features"] = np.zeros((1, 52), dtype=np.float32)

    for _ in range(3):
        with torch.no_grad():
            pt_bin(nf_b, nt_b, ei_b, er_b, b_b, tok_b, tab38_b)
            pt_ml(nf_b, nt_b, ei_b, er_b, b_b, tok_b, tab52_b)
        bin_sess.run(None, ort_bin_feed)
        ml_sess.run(None, ort_ml_feed)

    pt_neural_ms: list[float] = []
    ort_neural_ms: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        with torch.no_grad():
            pt_bin(nf_b, nt_b, ei_b, er_b, b_b, tok_b, tab38_b)
            pt_ml(nf_b, nt_b, ei_b, er_b, b_b, tok_b, tab52_b)
        pt_neural_ms.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        bin_sess.run(None, ort_bin_feed)
        ml_sess.run(None, ort_ml_feed)
        ort_neural_ms.append((time.perf_counter() - t1) * 1000.0)

    pt_med = statistics.median(pt_neural_ms)
    ort_med = statistics.median(ort_neural_ms)

    bin_param_count = int(sum(p.numel() for p in pt_bin.parameters()))
    ml_param_count = int(sum(p.numel() for p in pt_ml.parameters()))

    manifest = {
        "onnx_opset": 17,
        "binary_model": {
            "filename": "pdf_transgraph_v2.onnx",
            "sha256": hashlib.sha256(bin_onnx_path.read_bytes()).hexdigest(),
            "size_bytes": bin_onnx_path.stat().st_size,
            "parameter_count": bin_param_count,
            "max_logit_abs_diff_vs_pytorch": round(max_bin_diff, 8),
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
    (PROD_CONFIGS_DIR / "onnx_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return manifest


if __name__ == "__main__":
    res = export_and_verify()
    print(json.dumps(res, indent=2, ensure_ascii=False))
