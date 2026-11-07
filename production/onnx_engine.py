from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import io
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any

import numpy as np
import onnxruntime as ort
import pikepdf

PROD_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROD_ROOT.parent
for candidate_src in (PROD_ROOT / "src", REPO_ROOT / "src"):
    if candidate_src.is_dir() and str(candidate_src) not in sys.path:
        sys.path.insert(0, str(candidate_src))
if str(PROD_ROOT) not in sys.path:
    sys.path.insert(0, str(PROD_ROOT))

from malpdf.scanner.forensic import ForensicAttributionEngine
from malpdf.scanner.ingestion import InstantPDFIngestion
from onnx_taxonomy import ONNXThreatTaxonomyClassifier

DEFAULT_ONNX_MODEL_PATH = (
    Path(os.environ["MALPDF_ONNX_MODEL_PATH"])
    if "MALPDF_ONNX_MODEL_PATH" in os.environ
    else PROD_ROOT / "models" / "pdf_transgraph_v2.onnx"
)
DEFAULT_SCALER_PATH = PROD_ROOT / "configs" / "tabular_scaler.json"
DEFAULT_MANIFEST_PATH = PROD_ROOT / "configs" / "onnx_manifest.json"


def _sigmoid_scalar(x: float) -> float:
    clipped = max(-40.0, min(40.0, float(x)))
    return 1.0 / (1.0 + math.exp(-clipped))


def _sigmoid_array(x: np.ndarray) -> np.ndarray:
    clipped = np.clip(x, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


@dataclass
class ScanResult:
    sha256: str
    file_name: str
    file_size_bytes: int
    verdict: str
    malware_probability: float | None
    confidence: str
    ood_score: float | None
    is_ood: bool | None
    ood_warning: str | None
    latency_ms: float
    forensic_dossier: dict[str, Any]
    graph_nodes: list[dict[str, Any]] = field(default_factory=list)
    graph_edges: list[dict[str, Any]] = field(default_factory=list)
    pdf_version: str = "1.7"
    pages_count: int = 1
    raw_entropy: float = 0.0
    ood_threshold: float = -0.85
    prediction_available: bool = True
    prediction_blockers: list[str] = field(default_factory=list)
    threat_taxonomy: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ONNXMalPDFScannerEngine:
    def __init__(
        self,
        model_path: Path | str | None = None,
        scaler_path: Path | str | None = None,
        manifest_path: Path | str | None = None,
        temperature: float = 1.0,
        ood_threshold: float = -0.85,
        intra_op_threads: int = 2,
    ) -> None:
        if not math.isfinite(temperature) or temperature <= 0:
            raise ValueError("temperature_must_be_positive_and_finite")

        self.temperature = temperature
        self.ood_threshold = ood_threshold
        self.device = "onnxruntime-cpu"
        self.node_in_dim = 23
        self.tabular_in_features = 38

        resolved_model = Path(model_path) if model_path is not None else DEFAULT_ONNX_MODEL_PATH
        if not resolved_model.is_file():
            raise FileNotFoundError(f"ONNX model checkpoint unavailable: {resolved_model}")

        resolved_manifest = Path(manifest_path) if manifest_path is not None else DEFAULT_MANIFEST_PATH
        manifest_data: dict[str, Any] = {}
        if resolved_manifest.is_file():
            manifest_data = json.loads(resolved_manifest.read_text(encoding="utf-8"))
            if model_path is None and "MALPDF_ONNX_MODEL_PATH" not in os.environ:
                expected_sha = (manifest_data.get("binary_model") or {}).get("sha256")
                if expected_sha:
                    actual_sha = hashlib.sha256(resolved_model.read_bytes()).hexdigest()
                    if actual_sha != expected_sha:
                        raise ValueError("binary_onnx_sha256_mismatch")

        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = max(1, int(intra_op_threads))
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL

        self.bin_session = ort.InferenceSession(
            str(resolved_model),
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )
        self.model_path: Path | None = resolved_model
        self.weights_loaded: bool = True
        self.parameter_count: int = int(
            (manifest_data.get("binary_model") or {}).get("parameter_count", 828674)
        )

        resolved_scaler = Path(scaler_path) if scaler_path is not None else DEFAULT_SCALER_PATH
        if not resolved_scaler.is_file():
            fallback_scaler = REPO_ROOT / "configs" / "tabular_scaler.json"
            if fallback_scaler.is_file():
                resolved_scaler = fallback_scaler

        self.ingestion = InstantPDFIngestion(
            scaler_path=resolved_scaler,
            node_in_dim=self.node_in_dim,
            as_numpy=True,
        )
        if len(self.ingestion.feature_names) != self.tabular_in_features:
            raise ValueError("checkpoint_scaler_feature_count_mismatch")

        self.forensic = ForensicAttributionEngine()
        self.taxonomy = ONNXThreatTaxonomyClassifier(manifest_path=resolved_manifest)

    def calculate_energy_ood(self, logit: float) -> tuple[float, bool]:
        t = self.temperature
        scaled = logit / (2.0 * t)
        if abs(scaled) > 40.0:
            energy = -abs(scaled) * t
        else:
            energy = -t * math.log(math.exp(-scaled) + math.exp(scaled))
        is_ood = energy >= self.ood_threshold
        return round(energy, 4), is_ood

    @staticmethod
    def _prepare_single_edges(
        ei_np: np.ndarray,
        er_np: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, bool]:
        if ei_np.ndim == 2 and ei_np.shape[1] > 0:
            n_edges = ei_np.shape[1]
            return (
                np.ascontiguousarray(ei_np[0], dtype=np.int64),
                np.ascontiguousarray(ei_np[1], dtype=np.int64),
                np.ascontiguousarray(er_np, dtype=np.int64),
                np.ones((n_edges, 1), dtype=np.float32),
                np.array([1.0], dtype=np.float32),
                True,
            )
        return (
            np.zeros((1,), dtype=np.int64),
            np.zeros((1,), dtype=np.int64),
            np.zeros((1,), dtype=np.int64),
            np.zeros((1, 1), dtype=np.float32),
            np.array([0.0], dtype=np.float32),
            False,
        )

    def _batched_ort_logits(
        self,
        variants: list[tuple[np.ndarray, np.ndarray, np.ndarray]],
        nt_np: np.ndarray,
        ei_np: np.ndarray,
        er_np: np.ndarray,
    ) -> np.ndarray:
        batch_size = len(variants)
        n_nodes = variants[0][0].shape[0]
        nf_cat = np.ascontiguousarray(np.concatenate([v[0] for v in variants], axis=0), dtype=np.float32)
        nt_cat = np.ascontiguousarray(np.tile(nt_np, batch_size), dtype=np.int64)
        if ei_np.ndim == 2 and ei_np.shape[1] > 0:
            e_count = ei_np.shape[1]
            offsets = (np.arange(batch_size, dtype=np.int64) * n_nodes)[:, None]
            es_cat = np.ascontiguousarray((ei_np[0][None, :] + offsets).reshape(-1), dtype=np.int64)
            ed_cat = np.ascontiguousarray((ei_np[1][None, :] + offsets).reshape(-1), dtype=np.int64)
            er_cat = np.ascontiguousarray(np.tile(er_np, batch_size), dtype=np.int64)
            em_cat = np.ones((e_count * batch_size, 1), dtype=np.float32)
            he_val = np.array([1.0], dtype=np.float32)
        else:
            es_cat = np.zeros((1,), dtype=np.int64)
            ed_cat = np.zeros((1,), dtype=np.int64)
            er_cat = np.zeros((1,), dtype=np.int64)
            em_cat = np.zeros((1, 1), dtype=np.float32)
            he_val = np.array([0.0], dtype=np.float32)
        b_cat = np.ascontiguousarray(np.repeat(np.arange(batch_size, dtype=np.int64), n_nodes), dtype=np.int64)
        tok_cat = np.ascontiguousarray(np.concatenate([v[1] for v in variants], axis=0), dtype=np.int64)
        tab_cat = np.ascontiguousarray(np.concatenate([v[2] for v in variants], axis=0), dtype=np.float32)

        logits_out = self.bin_session.run(
            ["logits"],
            {
                "node_features": nf_cat,
                "node_types": nt_cat,
                "edge_src": es_cat,
                "edge_dst": ed_cat,
                "edge_rel": er_cat,
                "edge_mask": em_cat,
                "has_edges": he_val,
                "batch": b_cat,
                "ast_tokens": tok_cat,
                "tabular_features": tab_cat,
            },
        )[0]
        return np.asarray(logits_out, dtype=np.float32).reshape(-1)

    def _compute_xai_signals_ort(
        self,
        nf_np: np.ndarray,
        nt_np: np.ndarray,
        ei_np: np.ndarray,
        er_np: np.ndarray,
        tok_np: np.ndarray,
        tab_np: np.ndarray,
        raw_recs: list[dict[str, Any]],
        base_logit: float,
        base_prob: float,
        attn_weights: np.ndarray,
        edge_alpha: np.ndarray,
        ast_token_attn: np.ndarray,
        real_edges: bool,
    ) -> tuple[list[float], list[float], list[float], list[float], dict[str, float]]:
        n_nodes = nf_np.shape[0]
        priority_nodes: list[int] = []
        other_nodes: list[int] = []
        for idx_n in range(n_nodes):
            rec = raw_recs[idx_n] if idx_n < len(raw_recs) else {}
            if rec.get("is_threat_trigger") or rec.get("kind") in ("action", "script", "filespec"):
                priority_nodes.append(idx_n)
            else:
                other_nodes.append(idx_n)
        other_nodes.sort(key=lambda idx_n: float(np.linalg.norm(nf_np[idx_n])), reverse=True)
        cand_nodes = (priority_nodes + other_nodes)[: min(n_nodes, 24)]

        abs_z = np.abs(tab_np[0])
        active_tab_indices = [int(i) for i in np.argsort(abs_z)[::-1] if float(abs_z[i]) > 0.03][:16]
        if not active_tab_indices:
            active_tab_indices = [int(i) for i in np.argsort(abs_z)[::-1][:8]]

        variants: list[tuple[np.ndarray, np.ndarray, np.ndarray]] = []
        for idx_n in cand_nodes:
            nf_occ = nf_np.copy()
            nf_occ[idx_n] = 0.0
            variants.append((nf_occ, tok_np, tab_np))

        tab_offset = len(variants)
        for idx_t in active_tab_indices:
            tab_occ = tab_np.copy()
            tab_occ[0, idx_t] = 0.0
            variants.append((nf_np, tok_np, tab_occ))

        mod_offset = len(variants)
        variants.append((np.zeros_like(nf_np), tok_np, tab_np))
        variants.append((nf_np, np.zeros_like(tok_np), tab_np))
        variants.append((nf_np, tok_np, np.zeros_like(tab_np)))

        noise_offset = len(variants)
        rng = np.random.default_rng(42)
        noise_norms: list[float] = []
        for _ in range(3):
            noise_nf = rng.standard_normal(nf_np.shape, dtype=np.float32) * 0.05
            noise_tab = rng.standard_normal(tab_np.shape, dtype=np.float32) * 0.05
            variants.append((nf_np + noise_nf, tok_np, tab_np + noise_tab))
            noise_norms.append(
                math.sqrt(float(np.sum(noise_nf * noise_nf)) + float(np.sum(noise_tab * noise_tab)))
            )

        batch_logits = self._batched_ort_logits(variants, nt_np, ei_np, er_np)
        batch_probs = _sigmoid_array(batch_logits)

        raw_node_imp = np.zeros((n_nodes,), dtype=np.float64)
        for pos, idx_n in enumerate(cand_nodes):
            raw_node_imp[idx_n] = abs(base_logit - float(batch_logits[pos]))
        node_imp_sum = float(np.sum(raw_node_imp))
        if node_imp_sum > 1e-9:
            node_saliency = [round(float(v / node_imp_sum), 4) for v in raw_node_imp.tolist()]
        else:
            uniform = round(1.0 / max(n_nodes, 1), 4)
            node_saliency = [uniform for _ in range(n_nodes)]

        tabular_grad_importance = [0.0 for _ in range(tab_np.shape[1])]
        for pos, idx_t in enumerate(active_tab_indices):
            delta_logit = base_logit - float(batch_logits[tab_offset + pos])
            tabular_grad_importance[idx_t] = round(float(delta_logit), 5)

        edge_attention: list[float] = []
        if real_edges and edge_alpha.size > 0:
            edge_attention = [round(float(x), 4) for x in edge_alpha.reshape(-1).tolist()]

        ast_token_attention: list[float] = []
        if ast_token_attn.size > 0:
            ast_token_attention = [round(float(x), 4) for x in ast_token_attn.reshape(-1).tolist()]

        kept_nf = nf_np.copy()
        if len(node_saliency) > 2:
            mean_sal = float(np.mean(node_saliency))
            for idx_n, s_val in enumerate(node_saliency):
                if s_val < mean_sal * 0.5:
                    kept_nf[idx_n] = 0.0
        kept_tab = tab_np.copy()
        if len(tabular_grad_importance) > 4:
            abs_tab = [abs(x) for x in tabular_grad_importance]
            nonzero_abs = [x for x in abs_tab if x > 0.0]
            med_tab = float(np.median(nonzero_abs)) if nonzero_abs else 0.0
            for idx_t, t_val in enumerate(abs_tab):
                if t_val < med_tab * 0.5:
                    kept_tab[0, idx_t] = 0.0

        masked_nf = nf_np.copy()
        if len(node_saliency) > 1:
            top_n_indices = np.argsort(node_saliency)[-max(1, len(node_saliency) // 4) :]
            for idx_n in top_n_indices:
                masked_nf[int(idx_n)] = 0.0
        masked_tok = np.zeros_like(tok_np)
        masked_tab = tab_np.copy()
        if tabular_grad_importance:
            top_t_indices = np.argsort([abs(x) for x in tabular_grad_importance])[-4:]
            for idx_t in top_t_indices:
                masked_tab[0, int(idx_t)] = 0.0

        fid_logits = self._batched_ort_logits(
            [(kept_nf, tok_np, kept_tab), (masked_nf, masked_tok, masked_tab)],
            nt_np,
            ei_np,
            er_np,
        )
        fid_probs = _sigmoid_array(fid_logits)
        suff_prob = float(fid_probs[0])
        occ_prob = float(fid_probs[1])
        fidelity_score = max(0.0, 1.0 - abs(base_prob - suff_prob))
        comprehensiveness_drop = abs(base_prob - occ_prob)

        lip_ratios = [
            abs(base_prob - float(batch_probs[noise_offset + i])) / max(noise_norms[i], 1e-6)
            for i in range(len(noise_norms))
        ]
        lipschitz_val = float(sum(lip_ratios) / max(len(lip_ratios), 1))

        all_abs_attr = [abs(x) for x in tabular_grad_importance] + node_saliency
        n_dim = len(all_abs_attr)
        if n_dim > 1:
            l1_norm = sum(all_abs_attr)
            l2_norm = math.sqrt(sum(x * x for x in all_abs_attr))
            if l2_norm > 1e-12:
                sqrt_n = math.sqrt(float(n_dim))
                hoyer = (sqrt_n - (l1_norm / l2_norm)) / (sqrt_n - 1.0)
                sparsity_index = max(0.0, min(100.0, hoyer * 100.0))
            else:
                sparsity_index = 0.0
        else:
            sparsity_index = 0.0

        gw = 0.5
        aw = 0.5
        flat_attn = attn_weights.reshape(-1)
        if flat_attn.size >= 2:
            gw = float(flat_attn[0])
            aw = float(flat_attn[1])

        g_latent = abs(base_logit - float(batch_logits[mod_offset])) * (0.5 + gw)
        a_latent = abs(base_logit - float(batch_logits[mod_offset + 1])) * (0.5 + aw)
        t_latent = abs(base_logit - float(batch_logits[mod_offset + 2]))
        total_latent = g_latent + a_latent + t_latent
        if total_latent > 1e-9:
            graph_branch_pct = round((g_latent / total_latent) * 100.0, 1)
            ast_branch_pct = round((a_latent / total_latent) * 100.0, 1)
            tabular_branch_pct = round(max(0.0, 100.0 - graph_branch_pct - ast_branch_pct), 1)
        else:
            graph_branch_pct = round(gw * 100.0, 1)
            ast_branch_pct = round(aw * 100.0, 1)
            tabular_branch_pct = 0.0

        proof_metrics = {
            "fidelity_score": round(fidelity_score, 4),
            "comprehensiveness_drop": round(comprehensiveness_drop, 4),
            "sparsity_index": round(sparsity_index, 1),
            "lipschitz_stability": round(lipschitz_val, 4),
            "graph_branch_pct": graph_branch_pct,
            "ast_branch_pct": ast_branch_pct,
            "tabular_branch_pct": tabular_branch_pct,
        }
        return node_saliency, edge_attention, ast_token_attention, tabular_grad_importance, proof_metrics

    def scan_bytes(
        self,
        data: bytes,
        file_name: str = "in_memory_sample.pdf",
        explain: bool = True,
    ) -> ScanResult:
        if not self.weights_loaded:
            raise RuntimeError("ONNX model weights unavailable")
        start_time = time.perf_counter()

        ingest_data = self.ingestion.ingest(data)
        sha256 = ingest_data["sha256"]
        file_size = ingest_data["size_bytes"]
        pdf_version = ingest_data.get("pdf_version", "1.7")
        pages_count = int(ingest_data.get("pages_count", 1))
        raw_entropy = float(ingest_data.get("raw_entropy", 0.0))

        if ingest_data.get("prediction_blockers"):
            dossier = self.forensic.explain(ingest_data, malware_prob=None) if explain else {}
            taxonomy_info = self.taxonomy.classify(
                raw_pdf_bytes=data,
                ingest_data=ingest_data,
                forensic_dossier=dossier,
                verdict="UNAVAILABLE",
                malware_prob=None,
            )
            if explain:
                dossier["threat_taxonomy"] = taxonomy_info
            records = ingest_data["raw_records"]
            nodes = [
                {
                    "id": record["evidence_id"],
                    "label": record["kind"].capitalize(),
                    "kind": record["kind"],
                    "obj_ref": record.get("obj_ref_str"),
                    "invoker": record.get("invoker"),
                    "filter": record.get("filter"),
                    "size_bytes": record.get("size_bytes"),
                    "has_stream": record.get("has_stream"),
                    "entropy": record.get("entropy"),
                    "offset_hex": record.get("offset_hex"),
                    "hex_dump": record.get("hex_dump", []),
                    "content_preview": record.get("content_preview", ""),
                    "is_threat_trigger": record.get("is_threat_trigger", False),
                    "xai_saliency": None,
                }
                for record in records
            ]
            edges = [
                {
                    "from": edge["source"],
                    "to": edge["target"],
                    "arrows": "to",
                    "relation": "->".join(edge.get("relation", ())),
                    "hgt_attention": None,
                }
                for edge in ingest_data["raw_edges"]
            ]
            return ScanResult(
                sha256=sha256,
                file_name=file_name,
                file_size_bytes=file_size,
                verdict="UNAVAILABLE",
                malware_probability=None,
                confidence="UNAVAILABLE",
                ood_score=None,
                is_ood=None,
                ood_warning="feature_contract_unverified",
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                forensic_dossier=dossier,
                graph_nodes=nodes,
                graph_edges=edges,
                pdf_version=pdf_version,
                pages_count=pages_count,
                raw_entropy=raw_entropy,
                ood_threshold=self.ood_threshold,
                prediction_available=False,
                prediction_blockers=ingest_data["prediction_blockers"],
                threat_taxonomy=taxonomy_info,
            )

        nf_np = np.ascontiguousarray(ingest_data["node_features"], dtype=np.float32)
        nt_np = np.ascontiguousarray(ingest_data["node_types"], dtype=np.int64)
        ei_np = np.asarray(ingest_data["edge_index"], dtype=np.int64)
        er_np = np.asarray(ingest_data["edge_rel"], dtype=np.int64)
        b_np = np.ascontiguousarray(ingest_data["batch"], dtype=np.int64)
        tok_np = np.ascontiguousarray(ingest_data["ast_tokens"], dtype=np.int64)
        tab_np = np.ascontiguousarray(ingest_data["tab_features"], dtype=np.float32)

        es_np, ed_np, er_feed, em_np, he_np, real_edges = self._prepare_single_edges(ei_np, er_np)
        logits_arr, attn_weights_arr, edge_alpha_arr, ast_token_attn_arr = self.bin_session.run(
            None,
            {
                "node_features": nf_np,
                "node_types": nt_np,
                "edge_src": es_np,
                "edge_dst": ed_np,
                "edge_rel": er_feed,
                "edge_mask": em_np,
                "has_edges": he_np,
                "batch": b_np,
                "ast_tokens": tok_np,
                "tabular_features": tab_np,
            },
        )
        logit_val = float(np.asarray(logits_arr).reshape(-1)[0])
        prob = _sigmoid_scalar(logit_val)

        raw_recs = ingest_data.get("raw_records", [])
        verdict = "MALICIOUS" if prob >= 0.50 else "BENIGN"
        energy_score, is_ood = self.calculate_energy_ood(logit_val)

        ood_warning = None
        if is_ood:
            ood_warning = "OOD_ANOMALY_DETECTED"
            confidence = "LOW"
        elif prob >= 0.85 or prob <= 0.15:
            confidence = "HIGH"
        elif prob >= 0.70 or prob <= 0.30:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        node_saliency: list[float] = []
        edge_attention: list[float] = []
        forensic_dossier: dict[str, Any] = {}
        if explain:
            (
                node_saliency,
                edge_attention,
                ast_token_attention,
                tabular_grad_importance,
                proof_metrics,
            ) = self._compute_xai_signals_ort(
                nf_np=nf_np,
                nt_np=nt_np,
                ei_np=ei_np,
                er_np=er_np,
                tok_np=tok_np,
                tab_np=tab_np,
                raw_recs=raw_recs,
                base_logit=logit_val,
                base_prob=prob,
                attn_weights=np.asarray(attn_weights_arr),
                edge_alpha=np.asarray(edge_alpha_arr),
                ast_token_attn=np.asarray(ast_token_attn_arr),
                real_edges=real_edges,
            )
            forensic_dossier = self.forensic.explain(
                ingest_data,
                cross_modal_attn=np.asarray(attn_weights_arr),
                malware_prob=prob,
                node_saliency=node_saliency,
                edge_attention=edge_attention,
                ast_token_attention=ast_token_attention,
                tabular_grad_importance=tabular_grad_importance,
                xai_proof_metrics=proof_metrics,
            )

        graph_nodes: list[dict[str, Any]] = []
        for idx, r in enumerate(raw_recs):
            k = r.get("kind", "pdf_object")
            eid = r.get("evidence_id", "")
            is_threat = r.get("is_threat_trigger", False)
            sal_val = node_saliency[idx] if idx < len(node_saliency) else None
            if is_threat or k == "script":
                color = "#FF3B30"
                shape = "star" if k == "action" else "hexagon"
            elif k == "catalog":
                color = "#0071E3"
                shape = "dot"
            elif k in ("pages", "page"):
                color = "#5856D6"
                shape = "dot"
            elif k == "stream":
                color = "#FF9500"
                shape = "dot"
            else:
                color = "#94A3B8"
                shape = "dot"
            base_sz = 26 if k == "catalog" else 22 if is_threat else 20 if k == "pages" else 16
            sal_rounded = round(float(sal_val), 4) if sal_val is not None else None
            preview_text = r.get("content_preview", "")
            graph_nodes.append(
                {
                    "id": eid,
                    "label": f"{k.capitalize()}\n({eid.split(':')[-1]})",
                    "obj_ref": r.get("obj_ref_str"),
                    "color": color,
                    "shape": shape,
                    "size": base_sz,
                    "kind": k,
                    "invoker": r.get("invoker", "/Root"),
                    "filter": r.get("filter", "Dictionary"),
                    "size_bytes": round(float(r.get("size_bytes", 0.0)), 1),
                    "has_stream": bool(r.get("has_stream", False)),
                    "is_threat": bool(is_threat),
                    "is_threat_trigger": bool(is_threat),
                    "entropy": round(float(r.get("entropy", 0.0)), 4),
                    "offset_hex": r.get("offset_hex"),
                    "hex_dump": r.get("hex_dump", []),
                    "snippet": preview_text,
                    "content_preview": preview_text,
                    "saliency": sal_rounded,
                    "xai_saliency": sal_rounded,
                }
            )

        graph_edges: list[dict[str, Any]] = []
        raw_eds = ingest_data.get("raw_edges", [])
        threat_node_ids = {
            r["evidence_id"]
            for r in raw_recs
            if r.get("is_threat_trigger", False) or r.get("kind") == "script"
        }
        for e_idx, e in enumerate(raw_eds):
            s = e.get("source", "")
            t = e.get("target", "")
            rel_pair = e.get("relation", ("pdf_object", "pdf_object"))
            rel_label = (
                f"{rel_pair[0]}->{rel_pair[1]}"
                if isinstance(rel_pair, tuple) and len(rel_pair) == 2
                else "ref"
            )
            is_threat_edge = s in threat_node_ids or t in threat_node_ids
            edge_alpha_val = edge_attention[e_idx] if e_idx < len(edge_attention) else None
            graph_edges.append(
                {
                    "from": s,
                    "to": t,
                    "arrows": "to",
                    "relation": rel_label,
                    "is_threat_edge": is_threat_edge,
                    "hgt_attention": round(float(edge_alpha_val), 4) if edge_alpha_val is not None else None,
                    "color": {"color": "#FF3B30" if is_threat_edge else "#CBD5E1"},
                    "width": 3.2 if is_threat_edge else 1.6,
                }
            )

        taxonomy_info = self.taxonomy.classify(
            raw_pdf_bytes=data,
            ingest_data=ingest_data,
            forensic_dossier=forensic_dossier,
            verdict=verdict,
            malware_prob=prob,
        )
        if explain:
            forensic_dossier["threat_taxonomy"] = taxonomy_info

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ScanResult(
            sha256=sha256,
            file_name=file_name,
            file_size_bytes=file_size,
            verdict=verdict,
            malware_probability=round(prob, 4),
            confidence=confidence,
            ood_score=energy_score,
            is_ood=is_ood,
            ood_warning=ood_warning,
            latency_ms=latency_ms,
            forensic_dossier=forensic_dossier,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            pdf_version=pdf_version,
            pages_count=pages_count,
            raw_entropy=raw_entropy,
            ood_threshold=self.ood_threshold,
            threat_taxonomy=taxonomy_info,
        )

    def scan_file(
        self,
        file_path: str | Path,
        explain: bool = True,
    ) -> ScanResult:
        path = Path(file_path)
        data, _ = self.ingestion.read_bytes(path)
        return self.scan_bytes(data, file_name=path.name, explain=explain)

    @staticmethod
    def _excise_pdf_triggers_pikepdf(
        data: bytes,
        target_tokens: set[str],
        excise_all: bool = False,
    ) -> tuple[bytes | None, list[str]]:
        want_open = excise_all or any("open_action" in t or "/OpenAction" in t for t in target_tokens)
        want_aa = excise_all or any(t in ("action:aa", "script:action:aa") or ":aa" in t or "/AA" in t for t in target_tokens)
        want_names_js = excise_all or any("names_js" in t or "/Names/JavaScript" in t for t in target_tokens)
        want_embedded = excise_all or any("filespec" in t or "embedded" in t or "/EmbeddedFiles" in t for t in target_tokens)
        want_xfa = excise_all or any("xfa" in t or "/XFA" in t for t in target_tokens)
        want_annots = excise_all or any("annot" in t or "/Annot" in t for t in target_tokens)
        if not (want_open or want_aa or want_names_js or want_embedded or want_xfa or want_annots):
            want_open = want_aa = want_names_js = want_embedded = want_xfa = want_annots = True
        excised_keys: list[str] = []
        try:
            with pikepdf.open(io.BytesIO(data)) as pdf:
                mutated = False
                root = pdf.Root
                if want_open and "/OpenAction" in root:
                    del root["/OpenAction"]
                    excised_keys.append("/Root/OpenAction")
                    mutated = True
                if want_aa and "/AA" in root:
                    del root["/AA"]
                    excised_keys.append("/Root/AA")
                    mutated = True
                if "/Names" in root and isinstance(root["/Names"], pikepdf.Dictionary):
                    if want_names_js and "/JavaScript" in root["/Names"]:
                        del root["/Names"]["/JavaScript"]
                        excised_keys.append("/Root/Names/JavaScript")
                        mutated = True
                    if want_embedded and "/EmbeddedFiles" in root["/Names"]:
                        del root["/Names"]["/EmbeddedFiles"]
                        excised_keys.append("/Root/Names/EmbeddedFiles")
                        mutated = True
                if want_xfa and "/AcroForm" in root and isinstance(root["/AcroForm"], pikepdf.Dictionary):
                    if "/XFA" in root["/AcroForm"]:
                        del root["/AcroForm"]["/XFA"]
                        excised_keys.append("/Root/AcroForm/XFA")
                        mutated = True
                for p_idx, page in enumerate(pdf.pages):
                    p_obj = page.obj
                    if want_aa and "/AA" in p_obj:
                        del p_obj["/AA"]
                        excised_keys.append(f"/Page[{p_idx}]/AA")
                        mutated = True
                    if want_annots and "/Annots" in p_obj and isinstance(p_obj["/Annots"], pikepdf.Array):
                        for a_idx, annot in enumerate(p_obj["/Annots"]):
                            if isinstance(annot, pikepdf.Dictionary):
                                for ak in ("/A", "/AA"):
                                    if ak in annot:
                                        del annot[ak]
                                        excised_keys.append(f"/Page[{p_idx}]/Annots[{a_idx}]{ak}")
                                        mutated = True
                if mutated:
                    out_buf = io.BytesIO()
                    pdf.save(out_buf)
                    return out_buf.getvalue(), excised_keys
        except Exception:
            return None, []
        return None, excised_keys

    def ablate_node(
        self,
        data: bytes,
        target_node_id: str,
        file_name: str = "sample.pdf",
        ablate_mode: str = "auto",
        exclude_node_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        if not self.weights_loaded:
            raise RuntimeError("ONNX model weights unavailable")
        start_time = time.perf_counter()
        ingest_data = self.ingestion.ingest(data)
        if ingest_data.get("prediction_blockers"):
            raise RuntimeError("Ablation unavailable: training feature contract unverified")

        raw_recs = ingest_data.get("raw_records", [])
        nf_np = np.ascontiguousarray(ingest_data["node_features"], dtype=np.float32)
        nt_np = np.ascontiguousarray(ingest_data["node_types"], dtype=np.int64)
        ei_np = np.asarray(ingest_data["edge_index"], dtype=np.int64)
        er_np = np.asarray(ingest_data["edge_rel"], dtype=np.int64)
        b_np = np.ascontiguousarray(ingest_data["batch"], dtype=np.int64)
        tok_np = np.ascontiguousarray(ingest_data["ast_tokens"], dtype=np.int64)
        tab_np = np.ascontiguousarray(ingest_data["tab_features"], dtype=np.float32)

        es_np, ed_np, er_feed, em_np, he_np, _ = self._prepare_single_edges(ei_np, er_np)
        base_logits = self.bin_session.run(
            ["logits"],
            {
                "node_features": nf_np,
                "node_types": nt_np,
                "edge_src": es_np,
                "edge_dst": ed_np,
                "edge_rel": er_feed,
                "edge_mask": em_np,
                "has_edges": he_np,
                "batch": b_np,
                "ast_tokens": tok_np,
                "tabular_features": tab_np,
            },
        )[0]
        logit_before = float(np.asarray(base_logits).reshape(-1)[0])
        prob_before = _sigmoid_scalar(logit_before)
        energy_before, _ = self.calculate_energy_ood(logit_before)
        verdict_before = "MALICIOUS" if prob_before >= 0.50 else "BENIGN"

        target_idx = None
        target_rec: dict[str, Any] = {}
        for idx, rec in enumerate(raw_recs[: nf_np.shape[0]]):
            if rec.get("evidence_id") == target_node_id or rec.get("obj_ref_str") == target_node_id:
                target_idx = idx
                target_rec = rec
                break

        if target_idx is None:
            raise ValueError("ablation_target_not_observed")

        ablated_nf = nf_np.copy()
        ablated_tok = tok_np.copy()
        ablated_tab = tab_np.copy()
        masked_indices = {target_idx}

        target_eid = str(target_rec.get("evidence_id", target_node_id))
        target_kind = str(target_rec.get("kind", "pdf_object"))
        is_trigger_node = bool(target_rec.get("is_threat_trigger", False)) or target_kind in (
            "action",
            "script",
            "filespec",
        )

        extra_ids = [str(x).strip() for x in (exclude_node_ids or []) if str(x).strip()]
        for ex_id in extra_ids:
            for idx, rec in enumerate(raw_recs[: nf_np.shape[0]]):
                if rec.get("evidence_id") == ex_id or rec.get("obj_ref_str") == ex_id:
                    masked_indices.add(idx)

        if is_trigger_node:
            target_tokens: set[str] = {target_eid, str(target_rec.get("invoker", ""))}
            for m_idx in masked_indices:
                if m_idx < len(raw_recs):
                    target_tokens.add(str(raw_recs[m_idx].get("evidence_id", "")))
                    target_tokens.add(str(raw_recs[m_idx].get("invoker", "")))
            for ex_id in extra_ids:
                target_tokens.add(ex_id)

            surgical_bytes, surgical_keys = self._excise_pdf_triggers_pikepdf(
                data, target_tokens, excise_all=False
            )
            full_bytes, full_keys = self._excise_pdf_triggers_pikepdf(
                data, target_tokens, excise_all=True
            )

            before_eids = [str(r.get("evidence_id")) for r in raw_recs]
            res_surgical = (
                self.scan_bytes(surgical_bytes, file_name=f"surgical_{file_name}", explain=False)
                if surgical_bytes is not None
                else None
            )
            if full_bytes is not None and surgical_keys == full_keys and res_surgical is not None:
                res_full = res_surgical
            elif full_bytes is not None:
                res_full = self.scan_bytes(full_bytes, file_name=f"ablated_{file_name}", explain=False)
            else:
                res_full = res_surgical

            if res_surgical is not None and res_full is not None:
                after_surg_ids = {str(n.get("id")) for n in res_surgical.graph_nodes}
                surg_excised_nodes = [nid for nid in before_eids if nid not in after_surg_ids]
                surg_remaining_threats = [
                    str(n.get("id"))
                    for n in res_surgical.graph_nodes
                    if n.get("is_threat") or n.get("is_threat_trigger") or n.get("kind") in ("script", "filespec")
                ]

                after_full_ids = {str(n.get("id")) for n in res_full.graph_nodes}
                full_excised_nodes = [nid for nid in before_eids if nid not in after_full_ids]
                full_remaining_threats = [
                    str(n.get("id"))
                    for n in res_full.graph_nodes
                    if n.get("is_threat") or n.get("is_threat_trigger") or n.get("kind") in ("script", "filespec")
                ]

                use_surgical = ablate_mode == "surgical"
                chosen_res = res_surgical if use_surgical else res_full
                chosen_keys = surgical_keys if use_surgical else full_keys
                chosen_excised_nodes = surg_excised_nodes if use_surgical else full_excised_nodes
                chosen_remaining_threats = surg_remaining_threats if use_surgical else full_remaining_threats

                prob_after = float(chosen_res.malware_probability or 0.0)
                verdict_after = chosen_res.verdict
                energy_after = chosen_res.ood_score
                bounded_prob = min(max(prob_after, 1e-7), 1.0 - 1e-7)
                logit_after = math.log(bounded_prob / (1.0 - bounded_prob))
                prob_delta = round(prob_after - prob_before, 4)
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                actual_excised_nodes = max(1, len(chosen_excised_nodes))

                surg_prob = float(res_surgical.malware_probability or 0.0)
                full_prob = float(res_full.malware_probability or 0.0)

                return {
                    "file_name": file_name,
                    "target_node_id": target_eid,
                    "obj_ref": target_rec.get("obj_ref_str", "obj_1 0 R"),
                    "kind": target_kind,
                    "invoker": target_rec.get("invoker", "/Root"),
                    "is_threat_trigger": is_trigger_node,
                    "ablation_method": "pikepdf_binary_excision",
                    "ablate_mode": "surgical" if use_surgical else "all_triggers",
                    "excised_keys": chosen_keys,
                    "excised_node_ids": chosen_excised_nodes,
                    "remaining_threat_node_ids": chosen_remaining_threats,
                    "masked_node_count": actual_excised_nodes,
                    "prob_before": round(prob_before, 4),
                    "prob_after": round(prob_after, 4),
                    "prob_delta": prob_delta,
                    "prob_drop_pct": round((prob_before - prob_after) * 100.0, 2),
                    "logit_before": round(logit_before, 4),
                    "logit_after": round(logit_after, 4),
                    "ood_before": energy_before,
                    "ood_after": energy_after,
                    "verdict_before": verdict_before,
                    "verdict_after": verdict_after,
                    "surgical_prob_after": round(surg_prob, 4),
                    "surgical_prob_delta": round(surg_prob - prob_before, 4),
                    "surgical_verdict_after": res_surgical.verdict,
                    "surgical_excised_keys": surgical_keys,
                    "surgical_excised_node_ids": surg_excised_nodes,
                    "surgical_remaining_threat_node_ids": surg_remaining_threats,
                    "full_chain_prob_after": round(full_prob, 4),
                    "full_chain_prob_delta": round(full_prob - prob_before, 4),
                    "full_chain_verdict_after": res_full.verdict,
                    "full_chain_excised_keys": full_keys,
                    "full_chain_excised_node_ids": full_excised_nodes,
                    "latency_ms": latency_ms,
                }

        if is_trigger_node:
            for idx, rec in enumerate(raw_recs[: nf_np.shape[0]]):
                eid = rec.get("evidence_id", "")
                if eid.startswith(f"script:{target_eid}") or (
                    target_kind == "action" and rec.get("kind") == "script"
                ):
                    masked_indices.add(idx)
            ablated_tok = np.zeros_like(tok_np)
            feature_names = ingest_data.get("feature_names", [])
            scaler_mean = ingest_data.get("scaler_mean", [])
            scaler_scale = ingest_data.get("scaler_scale", [])
            trigger_cols = {"JS", "Javascript", "OpenAction", "AA", "Launch", "EmbeddedFiles", "XFA"}
            for f_idx, fname in enumerate(feature_names):
                if fname in trigger_cols or fname.startswith("ast_"):
                    if f_idx < ablated_tab.shape[1] and f_idx < len(scaler_mean) and f_idx < len(scaler_scale):
                        sc = scaler_scale[f_idx] if scaler_scale[f_idx] != 0 else 1.0
                        ablated_tab[0, f_idx] = float((0.0 - scaler_mean[f_idx]) / sc)

        for m_idx in masked_indices:
            if m_idx < ablated_nf.shape[0]:
                ablated_nf[m_idx] = 0.0

        if ei_np.ndim == 2 and ei_np.shape[1] > 0:
            keep_mask = np.ones((ei_np.shape[1],), dtype=bool)
            for m_idx in masked_indices:
                keep_mask &= (ei_np[0] != m_idx) & (ei_np[1] != m_idx)
            ablated_ei = ei_np[:, keep_mask]
            ablated_er = er_np[keep_mask]
        else:
            ablated_ei = ei_np
            ablated_er = er_np

        a_es, a_ed, a_er, a_em, a_he, _ = self._prepare_single_edges(ablated_ei, ablated_er)
        abl_logits = self.bin_session.run(
            ["logits"],
            {
                "node_features": ablated_nf,
                "node_types": nt_np,
                "edge_src": a_es,
                "edge_dst": a_ed,
                "edge_rel": a_er,
                "edge_mask": a_em,
                "has_edges": a_he,
                "batch": b_np,
                "ast_tokens": ablated_tok,
                "tabular_features": ablated_tab,
            },
        )[0]
        logit_after = float(np.asarray(abl_logits).reshape(-1)[0])
        prob_after = _sigmoid_scalar(logit_after)
        energy_after, _ = self.calculate_energy_ood(logit_after)
        verdict_after = "MALICIOUS" if prob_after >= 0.50 else "BENIGN"
        prob_delta = round(prob_after - prob_before, 4)
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        masked_eids = [
            str(raw_recs[i].get("evidence_id", target_eid))
            for i in sorted(masked_indices)
            if i < len(raw_recs)
        ]
        remaining_threats = [
            str(r.get("evidence_id"))
            for i, r in enumerate(raw_recs)
            if i not in masked_indices
            and (r.get("is_threat_trigger") or r.get("kind") in ("action", "script", "filespec"))
        ]
        return {
            "file_name": file_name,
            "target_node_id": target_eid,
            "obj_ref": target_rec.get("obj_ref_str", "obj_1 0 R"),
            "kind": target_kind,
            "invoker": target_rec.get("invoker", "/Root"),
            "is_threat_trigger": is_trigger_node,
            "ablation_method": "graph_tensor_counterfactual_mask",
            "ablate_mode": ablate_mode,
            "excised_keys": [],
            "excised_node_ids": masked_eids,
            "remaining_threat_node_ids": remaining_threats,
            "masked_node_count": len(masked_indices),
            "prob_before": round(prob_before, 4),
            "prob_after": round(prob_after, 4),
            "prob_delta": prob_delta,
            "prob_drop_pct": round((prob_before - prob_after) * 100.0, 2),
            "logit_before": round(logit_before, 4),
            "logit_after": round(logit_after, 4),
            "ood_before": energy_before,
            "ood_after": energy_after,
            "verdict_before": verdict_before,
            "verdict_after": verdict_after,
            "surgical_prob_after": round(prob_after, 4),
            "surgical_prob_delta": prob_delta,
            "surgical_verdict_after": verdict_after,
            "surgical_excised_keys": [],
            "surgical_excised_node_ids": masked_eids,
            "surgical_remaining_threat_node_ids": remaining_threats,
            "latency_ms": latency_ms,
        }

