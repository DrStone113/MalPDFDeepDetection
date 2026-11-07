from __future__ import annotations

from dataclasses import asdict, dataclass, field
import io
import math
import os
from pathlib import Path
import time
from typing import Any

import numpy as np
import pikepdf
import torch

from malpdf.models.pdf_transgraph import PDFTransGraph
from malpdf.scanner.forensic import ForensicAttributionEngine
from malpdf.scanner.ingestion import InstantPDFIngestion
from malpdf.scanner.taxonomy import ThreatTaxonomyClassifier

CANONICAL_V2_MODEL_PATH = (
    Path(__file__).resolve().parents[3]
    / "artifacts"
    / "models"
    / "pdf_transgraph_v2"
    / "pdf_transgraph_v2_23d_best.pt"
)
DEFAULT_MODEL_PATH = Path(os.environ["MALPDF_MODEL_PATH"]) if "MALPDF_MODEL_PATH" in os.environ else (
    CANONICAL_V2_MODEL_PATH
    if CANONICAL_V2_MODEL_PATH.is_file()
    else (
        Path(__file__).resolve().parents[3]
        / "reports"
        / "experiments"
        / "adversarial_defense"
        / "pdf_transgraph_adv_trained.pt"
    )
)
FALLBACK_MODEL_PATH = (
    Path(__file__).resolve().parents[3]
    / "reports"
    / "experiments"
    / "pdf_transgraph"
    / "pdf_transgraph_best.pt"
)


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


class MalPDFScannerEngine:
    def __init__(
        self,
        model_path: Path | str | None = None,
        scaler_path: Path | str | None = None,
        device: str = "auto",
        temperature: float = 1.0,
        ood_threshold: float = -0.85,
    ) -> None:
        self.temperature = temperature
        self.ood_threshold = ood_threshold

        if device == "auto":
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        resolved_path = None
        if model_path is not None:
            resolved_path = Path(model_path)
        elif DEFAULT_MODEL_PATH.exists():
            resolved_path = DEFAULT_MODEL_PATH
        elif FALLBACK_MODEL_PATH.exists():
            resolved_path = FALLBACK_MODEL_PATH

        if resolved_path is None or not resolved_path.is_file():
            raise FileNotFoundError(f"Trained model checkpoint unavailable: {resolved_path}")
        if not math.isfinite(temperature) or temperature <= 0:
            raise ValueError("temperature_must_be_positive_and_finite")
        state_dict = torch.load(resolved_path, map_location=self.device, weights_only=True)
        tab_dim = int(state_dict["tabular_encoder.input_layer.weight"].size(1))
        node_in_dim = int(state_dict["graph_encoder.node_feat_proj.weight"].size(1))
        self.node_in_dim: int = node_in_dim

        self.model = PDFTransGraph(
            node_in_dim=node_in_dim,
            num_node_types=9,
            num_relations=8,
            ast_vocab_size=64,
            tabular_in_features=tab_dim,
            hidden_dim=128,
        ).to(self.device)

        self.model.load_state_dict(state_dict)
        self.model.eval()
        self.model_path: Path | None = resolved_path
        self.weights_loaded: bool = state_dict is not None
        self.parameter_count: int = int(sum(p.numel() for p in self.model.parameters()))

        self.ingestion = InstantPDFIngestion(scaler_path=scaler_path, node_in_dim=node_in_dim)
        if len(self.ingestion.feature_names) != tab_dim:
            raise ValueError("checkpoint_scaler_feature_count_mismatch")
        self.forensic = ForensicAttributionEngine()
        self.taxonomy = ThreatTaxonomyClassifier(device=self.device)

    def calculate_energy_ood(self, logit: float) -> tuple[float, bool]:
        t = self.temperature
        scaled = logit / (2.0 * t)
        if abs(scaled) > 40.0:
            energy = -abs(scaled) * t
        else:
            energy = -t * math.log(math.exp(-scaled) + math.exp(scaled))

        is_ood = energy >= self.ood_threshold
        return round(energy, 4), is_ood

    def _batched_probs(
        self,
        variants: list[tuple[torch.Tensor, torch.Tensor, torch.Tensor]],
        nt: torch.Tensor,
        ei: torch.Tensor,
        er: torch.Tensor,
    ) -> list[float]:
        n_nodes = variants[0][0].size(0)
        nf_cat = torch.cat([v[0] for v in variants], dim=0)
        nt_cat = nt.repeat(len(variants))
        if ei.numel() > 0:
            ei_cat = torch.cat([ei + i * n_nodes for i in range(len(variants))], dim=1)
            er_cat = er.repeat(len(variants))
        else:
            ei_cat = ei
            er_cat = er
        b_cat = torch.arange(len(variants), device=nf_cat.device).repeat_interleave(n_nodes)
        tok_cat = torch.cat([v[1] for v in variants], dim=0)
        tab_cat = torch.cat([v[2] for v in variants], dim=0)
        logits, _ = self.model(nf_cat, nt_cat, ei_cat, er_cat, b_cat, tok_cat, tab_cat)
        return [float(p) for p in torch.sigmoid(logits).reshape(-1).cpu().tolist()]

    def _compute_xai_signals(
        self,
        nf: torch.Tensor,
        nt: torch.Tensor,
        ei: torch.Tensor,
        er: torch.Tensor,
        b: torch.Tensor,
        tok: torch.Tensor,
        tab: torch.Tensor,
        base_prob: float,
        attn_weights: torch.Tensor,
    ) -> tuple[list[float], list[float], list[float], list[float], dict[str, float]]:
        nf_grad = nf.clone().detach().requires_grad_(True)
        tab_grad = tab.clone().detach().requires_grad_(True)

        self.model.zero_grad(set_to_none=True)
        h_graph = self.model.graph_encoder(nf_grad, nt, ei, er, b)
        h_seq = self.model.ast_encoder(tok)
        h_tab = self.model.tabular_encoder(tab_grad)
        h_graph.retain_grad()
        h_seq.retain_grad()
        h_tab.retain_grad()
        z_final, fused_attn = self.model.fusion(h_graph, h_seq, h_tab)
        logits_g = self.model.classifier(z_final).squeeze(-1)
        score = logits_g.sum()
        score.backward()

        node_saliency: list[float] = []
        if nf_grad.grad is not None:
            grad_norm = (nf_grad.grad.detach() * nf.detach()).norm(p=2, dim=-1)
            grad_sum = float(grad_norm.sum().item())
            if grad_sum > 1e-9:
                node_saliency = [round(float(v / grad_sum), 4) for v in grad_norm.cpu().tolist()]
            else:
                node_saliency = [0.0 for _ in range(nf.size(0))]

        tabular_grad_importance: list[float] = []
        if tab_grad.grad is not None:
            t_attr = (tab_grad.grad.detach() * tab.detach()).squeeze(0)
            tabular_grad_importance = [round(float(x), 5) for x in t_attr.cpu().tolist()]

        edge_attention: list[float] = []
        alpha_t = getattr(self.model.graph_encoder.layer2, "last_edge_alpha", None)
        if isinstance(alpha_t, torch.Tensor) and alpha_t.numel() > 0:
            mean_alpha = alpha_t.mean(dim=-1)
            edge_attention = [round(float(x), 4) for x in mean_alpha.cpu().tolist()]

        ast_token_attention: list[float] = []
        tok_attn = getattr(self.model.ast_encoder, "last_token_attn", None)
        if isinstance(tok_attn, torch.Tensor) and tok_attn.numel() > 0:
            flat_tok = tok_attn.squeeze().cpu().tolist()
            if isinstance(flat_tok, list):
                ast_token_attention = [round(float(x), 4) for x in flat_tok]

        with torch.no_grad():
            kept_nf = nf.clone()
            if len(node_saliency) > 2:
                mean_sal = float(np.mean(node_saliency))
                for idx_n, s_val in enumerate(node_saliency):
                    if s_val < mean_sal * 0.5:
                        kept_nf[idx_n] = 0.0
            kept_tab = tab.clone()
            if len(tabular_grad_importance) > 4:
                abs_tab = [abs(x) for x in tabular_grad_importance]
                med_tab = float(np.median(abs_tab))
                for idx_t, t_val in enumerate(abs_tab):
                    if t_val < med_tab * 0.5:
                        kept_tab[0, idx_t] = 0.0

            masked_nf = nf.clone()
            if len(node_saliency) > 1:
                top_n_indices = np.argsort(node_saliency)[-max(1, len(node_saliency) // 4):]
                for idx_n in top_n_indices:
                    masked_nf[int(idx_n)] = 0.0
            masked_tok = torch.zeros_like(tok)
            masked_tab = tab.clone()
            if tabular_grad_importance:
                top_t_indices = np.argsort([abs(x) for x in tabular_grad_importance])[-4:]
                for idx_t in top_t_indices:
                    masked_tab[0, int(idx_t)] = 0.0

            gen = torch.Generator(device=nf.device)
            gen.manual_seed(42)
            variants: list[tuple[torch.Tensor, torch.Tensor, torch.Tensor]] = [
                (kept_nf, tok, kept_tab),
                (masked_nf, masked_tok, masked_tab),
            ]
            noise_norms: list[float] = []
            for _ in range(3):
                noise_nf = torch.randn(nf.shape, generator=gen, device=nf.device, dtype=nf.dtype) * 0.05
                noise_tab = torch.randn(tab.shape, generator=gen, device=tab.device, dtype=tab.dtype) * 0.05
                variants.append((nf + noise_nf, tok, tab + noise_tab))
                noise_norms.append(
                    math.sqrt(float(noise_nf.norm(p=2).item()) ** 2 + float(noise_tab.norm(p=2).item()) ** 2)
                )

            batch_probs = self._batched_probs(variants, nt, ei, er)
            suff_prob = batch_probs[0]
            occ_prob = batch_probs[1]
            fidelity_score = max(0.0, 1.0 - abs(base_prob - suff_prob))
            comprehensiveness_drop = abs(base_prob - occ_prob)
            lip_ratios = [
                abs(base_prob - p_val) / max(n_val, 1e-6) for p_val, n_val in zip(batch_probs[2:], noise_norms)
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
        active_attn = fused_attn if fused_attn is not None else attn_weights
        if active_attn is not None and active_attn.numel() >= 2:
            w_flat = active_attn.squeeze().detach().cpu().tolist()
            if isinstance(w_flat, list) and len(w_flat) >= 2:
                gw = float(w_flat[0])
                aw = float(w_flat[1])

        g_latent = (
            float((h_graph.grad.detach() * h_graph.detach()).norm(p=2).item())
            if h_graph.grad is not None
            else 0.0
        )
        a_latent = (
            float((h_seq.grad.detach() * h_seq.detach()).norm(p=2).item())
            if h_seq.grad is not None
            else 0.0
        )
        t_latent = (
            float((h_tab.grad.detach() * h_tab.detach()).norm(p=2).item())
            if h_tab.grad is not None
            else 0.0
        )
        weighted_g = g_latent * (0.5 + gw)
        weighted_a = a_latent * (0.5 + aw)
        weighted_t = t_latent
        total_latent = weighted_g + weighted_a + weighted_t
        if total_latent > 1e-9:
            graph_branch_pct = round((weighted_g / total_latent) * 100.0, 1)
            ast_branch_pct = round((weighted_a / total_latent) * 100.0, 1)
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
            raise RuntimeError("Trained model weights unavailable")
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
            nodes = [{
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
            } for record in records]
            edges = [{
                "from": edge["source"], "to": edge["target"], "arrows": "to",
                "relation": "->".join(edge.get("relation", ())), "hgt_attention": None,
            } for edge in ingest_data["raw_edges"]]
            return ScanResult(
                sha256=sha256, file_name=file_name, file_size_bytes=file_size,
                verdict="UNAVAILABLE", malware_probability=None, confidence="UNAVAILABLE",
                ood_score=None, is_ood=None, ood_warning="feature_contract_unverified",
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                forensic_dossier=dossier, graph_nodes=nodes, graph_edges=edges,
                pdf_version=pdf_version, pages_count=pages_count, raw_entropy=raw_entropy,
                ood_threshold=self.ood_threshold,
                prediction_available=False, prediction_blockers=ingest_data["prediction_blockers"],
                threat_taxonomy=taxonomy_info,
            )

        nf = ingest_data["node_features"].to(self.device)
        nt = ingest_data["node_types"].to(self.device)
        ei = ingest_data["edge_index"].to(self.device)
        er = ingest_data["edge_rel"].to(self.device)
        b = ingest_data["batch"].to(self.device)
        tok = ingest_data["ast_tokens"].to(self.device)
        tab = ingest_data["tab_features"].to(self.device)

        with torch.no_grad():
            logits, attn_weights = self.model(nf, nt, ei, er, b, tok, tab)
            prob = torch.sigmoid(logits).item()
            logit_val = logits.item()

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
            ) = self._compute_xai_signals(
                nf=nf,
                nt=nt,
                ei=ei,
                er=er,
                b=b,
                tok=tok,
                tab=tab,
                base_prob=prob,
                attn_weights=attn_weights,
            )
            forensic_dossier = self.forensic.explain(
                ingest_data,
                cross_modal_attn=attn_weights,
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
            graph_nodes.append({
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
            })

        graph_edges: list[dict[str, Any]] = []
        raw_eds = ingest_data.get("raw_edges", [])
        threat_node_ids = {r["evidence_id"] for r in raw_recs if r.get("is_threat_trigger", False) or r.get("kind") == "script"}
        for e_idx, e in enumerate(raw_eds):
            s = e.get("source", "")
            t = e.get("target", "")
            rel_pair = e.get("relation", ("pdf_object", "pdf_object"))
            rel_label = f"{rel_pair[0]}->{rel_pair[1]}" if isinstance(rel_pair, tuple) and len(rel_pair) == 2 else "ref"
            is_threat_edge = s in threat_node_ids or t in threat_node_ids
            edge_alpha = edge_attention[e_idx] if e_idx < len(edge_attention) else None
            graph_edges.append({
                "from": s,
                "to": t,
                "arrows": "to",
                "relation": rel_label,
                "is_threat_edge": is_threat_edge,
                "hgt_attention": round(float(edge_alpha), 4) if edge_alpha is not None else None,
                "color": {"color": "#FF3B30" if is_threat_edge else "#CBD5E1"},
                "width": 3.2 if is_threat_edge else 1.6,
            })

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
            raise RuntimeError("Trained model weights unavailable")
        start_time = time.perf_counter()
        ingest_data = self.ingestion.ingest(data)
        if ingest_data.get("prediction_blockers"):
            raise RuntimeError("Ablation unavailable: training feature contract unverified")
        raw_recs = ingest_data.get("raw_records", [])
        nf = ingest_data["node_features"].to(self.device)
        nt = ingest_data["node_types"].to(self.device)
        ei = ingest_data["edge_index"].to(self.device)
        er = ingest_data["edge_rel"].to(self.device)
        b = ingest_data["batch"].to(self.device)
        tok = ingest_data["ast_tokens"].to(self.device)
        tab = ingest_data["tab_features"].to(self.device)

        with torch.no_grad():
            base_logits, _ = self.model(nf, nt, ei, er, b, tok, tab)
            prob_before = float(torch.sigmoid(base_logits).item())
            logit_before = float(base_logits.item())

        energy_before, _ = self.calculate_energy_ood(logit_before)
        verdict_before = "MALICIOUS" if prob_before >= 0.50 else "BENIGN"

        target_idx = None
        target_rec: dict[str, Any] = {}
        for idx, rec in enumerate(raw_recs[: nf.size(0)]):
            if rec.get("evidence_id") == target_node_id or rec.get("obj_ref_str") == target_node_id:
                target_idx = idx
                target_rec = rec
                break

        if target_idx is None:
            raise ValueError("ablation_target_not_observed")

        ablated_nf = nf.clone()
        ablated_tok = tok.clone()
        ablated_tab = tab.clone()
        masked_indices = {target_idx}

        target_eid = str(target_rec.get("evidence_id", target_node_id))
        target_kind = str(target_rec.get("kind", "pdf_object"))
        is_trigger_node = bool(target_rec.get("is_threat_trigger", False)) or target_kind in ("action", "script", "filespec")

        extra_ids = [str(x).strip() for x in (exclude_node_ids or []) if str(x).strip()]
        for ex_id in extra_ids:
            for idx, rec in enumerate(raw_recs[: nf.size(0)]):
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
            for idx, rec in enumerate(raw_recs[: nf.size(0)]):
                eid = rec.get("evidence_id", "")
                if eid.startswith(f"script:{target_eid}") or (target_kind == "action" and rec.get("kind") == "script"):
                    masked_indices.add(idx)
            ablated_tok = torch.zeros_like(tok)
            feature_names = ingest_data.get("feature_names", [])
            scaler_mean = ingest_data.get("scaler_mean", [])
            scaler_scale = ingest_data.get("scaler_scale", [])
            trigger_cols = {"JS", "Javascript", "OpenAction", "AA", "Launch", "EmbeddedFiles", "XFA"}
            for f_idx, fname in enumerate(feature_names):
                if fname in trigger_cols or fname.startswith("ast_"):
                    if f_idx < ablated_tab.size(1) and f_idx < len(scaler_mean) and f_idx < len(scaler_scale):
                        sc = scaler_scale[f_idx] if scaler_scale[f_idx] != 0 else 1.0
                        ablated_tab[0, f_idx] = float((0.0 - scaler_mean[f_idx]) / sc)

        for m_idx in masked_indices:
            if m_idx < ablated_nf.size(0):
                ablated_nf[m_idx] = 0.0

        if ei.numel() > 0:
            keep_mask = torch.ones(ei.size(1), dtype=torch.bool, device=self.device)
            for m_idx in masked_indices:
                keep_mask &= (ei[0] != m_idx) & (ei[1] != m_idx)
            ablated_ei = ei[:, keep_mask]
            ablated_er = er[keep_mask]
        else:
            ablated_ei = ei
            ablated_er = er

        with torch.no_grad():
            abl_logits, _ = self.model(ablated_nf, nt, ablated_ei, ablated_er, b, ablated_tok, ablated_tab)
            prob_after = float(torch.sigmoid(abl_logits).item())
            logit_after = float(abl_logits.item())

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
