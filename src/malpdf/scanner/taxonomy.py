from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

import numpy as np
import torch

from malpdf.models.multilabel_threat_net import (
    MULTILABEL_THREAT_DEFINITIONS,
    PDFMultiLabelThreatNet,
)
from malpdf.scanner.forensic import DANGEROUS_PATTERNS, deobfuscate_javascript_static
from malpdf.static.obfuscation import count_escaped_pdf_names
from malpdf.static.raw_scan import scan_raw_pdf_tokens

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MULTILABEL_CONTRACT_PATH = REPO_ROOT / "configs" / "multilabel_threat_contract.json"
DEFAULT_MULTILABEL_CHECKPOINT_PATH = (
    REPO_ROOT / "artifacts" / "models" / "multilabel_threat_v2" / "multilabel_threat_net_v2_best.pt"
)

CVE_EXPLOIT_SIGNATURES: list[tuple[str, str, str]] = [
    ("CVE-2008-2992", r"\butil\.printf\s*\(", "Adobe Reader util.printf Stack Buffer Overflow"),
    ("CVE-2007-5659", r"\bCollab\.collectEmailInfo\s*\(", "Adobe Reader Collab.collectEmailInfo Buffer Overflow"),
    ("CVE-2009-0927", r"\bCollab\.getIcon\s*\(", "Adobe Reader Collab.getIcon Stack Overflow"),
    ("CVE-2009-4324", r"\bmedia\.newPlayer\s*\(", "Adobe Reader Doc.media.newPlayer Use-After-Free"),
    ("CVE-2008-0655", r"\bspell\.customDictionaryOpen\s*\(", "Adobe Reader spell.customDictionaryOpen Memory Corruption"),
    ("CVE-2010-0188", r"\bTIFF\b.*SubIFD|LibTIFF", "Adobe Reader Embedded LibTIFF Integer Overflow"),
    ("CVE-2013-2729", r"\bBMP\b.*RLE", "Adobe Reader Font/Bitmap RLE Heap Overflow"),
]

BEHAVIOR_TAG_LABELS_VI: dict[str, tuple[str, bool]] = {
    "pdf": ("Tài liệu PDF", False),
    "js-embedded": ("Có mã JavaScript", True),
    "autoaction": ("Tự chạy khi mở tệp", True),
    "names-js": ("Danh mục kịch bản ẩn", True),
    "obfuscated": ("Mã bị làm rối che giấu", True),
    "heap-staging": ("Vòng lặp nạp bộ nhớ", True),
    "cve-exploit": ("Khai thác lỗi trình đọc", True),
    "launch-action": ("Gọi lệnh máy tính", True),
    "embedded-file": ("Đính kèm tệp ẩn", True),
    "xfa": ("Biểu mẫu động XFA", True),
    "acroform": ("Biểu mẫu điền thông tin", False),
    "submit-form": ("Tự gửi dữ liệu biểu mẫu", True),
    "uri-links": ("Có liên kết web", False),
    "object-streams": ("Gộp đối tượng nén", False),
    "encrypted": ("Có đặt mật khẩu / mã hóa", False),
    "stream-anomaly": ("Cấu trúc luồng bất thường", True),
    "high-entropy": ("Mật độ dữ liệu nén cao", False),
}

CODE_PRIORITY_ORDER: list[str] = [
    "auto_open_trigger",
    "obfuscated_payload",
    "js_script_exec",
    "active_form_or_exploit",
    "embedded_dropper_or_launch",
    "buffer_loop_staging",
    "suspicious_uri_redirect",
    "structural_parser_evasion",
]


class ThreatTaxonomyClassifier:
    def __init__(
        self,
        device: str | torch.device = "cpu",
        contract_path: Path | str | None = None,
        checkpoint_path: Path | str | None = None,
    ) -> None:
        self.device = torch.device(device)
        c_path = Path(contract_path) if contract_path is not None else DEFAULT_MULTILABEL_CONTRACT_PATH
        ckpt_path = Path(checkpoint_path) if checkpoint_path is not None else DEFAULT_MULTILABEL_CHECKPOINT_PATH

        self.ml_weights_loaded = False
        self.ml_checkpoint_path: Path | None = None
        self.ml_model: PDFMultiLabelThreatNet | None = None
        self.contract: dict[str, Any] = {}
        self.label_defs: list[dict[str, Any]] = [
            {**d, "threshold": 0.50} for d in MULTILABEL_THREAT_DEFINITIONS
        ]
        self.scaler_mean: np.ndarray | None = None
        self.scaler_scale: np.ndarray | None = None

        if c_path.is_file() and ckpt_path.is_file():
            contract_data = json.loads(c_path.read_text(encoding="utf-8"))
            expected_sha = contract_data.get("checkpoint_sha256")
            if checkpoint_path is None and expected_sha:
                actual_sha = hashlib.sha256(ckpt_path.read_bytes()).hexdigest()
                if actual_sha != expected_sha:
                    raise ValueError("multilabel_checkpoint_sha256_mismatch")

            state_dict = torch.load(ckpt_path, map_location=self.device, weights_only=True)
            tab_dim = int(contract_data.get("tabular_in_features", 52))
            node_dim = int(contract_data.get("node_in_dim", 23))
            hidden_dim = int(contract_data.get("hidden_dim", 128))
            labels_cfg = contract_data.get("labels") or self.label_defs

            model = PDFMultiLabelThreatNet(
                node_in_dim=node_dim,
                num_node_types=9,
                num_relations=8,
                ast_vocab_size=int(contract_data.get("ast_vocab_size", 64)),
                tabular_in_features=tab_dim,
                hidden_dim=hidden_dim,
                num_labels=len(labels_cfg),
            ).to(self.device)
            model.load_state_dict(state_dict)
            model.eval()

            self.ml_model = model
            self.ml_weights_loaded = True
            self.ml_checkpoint_path = ckpt_path
            self.contract = contract_data
            self.label_defs = labels_cfg
            self.scaler_mean = np.array(contract_data["scaler_mean"], dtype=np.float32)
            self.scaler_scale = np.array(contract_data["scaler_scale"], dtype=np.float32)

    def _predict_multilabel_neural(
        self,
        raw_pdf_bytes: bytes,
        raw_tokens: dict[str, int],
        ingest_data: dict[str, Any],
        has_obfuscated_js: bool,
        has_embedded_file: bool,
        has_launch: bool,
        structural_uri_count: int,
    ) -> tuple[list[float], float] | None:
        if (
            not self.ml_weights_loaded
            or self.ml_model is None
            or self.scaler_mean is None
            or self.scaler_scale is None
        ):
            return None

        raw_vec = ingest_data.get("raw_feature_vec")
        ast_tokens = ingest_data.get("ast_tokens")
        if not isinstance(raw_vec, list) or len(raw_vec) != 38 or ast_tokens is None:
            return None
        if any(v is None for v in raw_vec):
            return None

        ast_stats = ingest_data.get("ast_stats") or {}
        ast_counts = ingest_data.get("ast_node_counts") or {}
        loops_flag = (
            1.0
            if (
                float(ast_stats.get("loops") or 0.0) > 0.0
                or int(ast_counts.get("ForStatement") or 0) > 0
                or int(ast_counts.get("WhileStatement") or 0) > 0
            )
            else 0.0
        )
        deobf_flag = 1.0 if has_obfuscated_js else 0.0
        uri_eff = float(max(int(raw_tokens.get("URI", 0)), structural_uri_count))
        emb_eff = float(
            max(int(raw_tokens.get("EmbeddedFile", 0)), 1 if has_embedded_file else 0)
            + max(int(raw_tokens.get("Launch", 0)), 1 if has_launch else 0)
        )
        escaped_names = float(count_escaped_pdf_names(raw_pdf_bytes)) if raw_pdf_bytes else 0.0

        extra_14 = [
            float(raw_tokens.get("AA", 0)),
            float(raw_tokens.get("Acroform", 0)),
            float(raw_tokens.get("Launch", 0)),
            float(raw_tokens.get("EmbeddedFile", 0)),
            float(raw_tokens.get("URI", 0)),
            float(raw_tokens.get("ObjStm", 0)),
            float(raw_tokens.get("Encrypt", 0)),
            float(raw_tokens.get("JBIG2Decode", 0)),
            float(raw_tokens.get("RichMedia", 0)),
            escaped_names,
            loops_flag,
            deobf_flag,
            uri_eff,
            emb_eff,
        ]
        full_52 = np.array([float(x) for x in raw_vec] + extra_14, dtype=np.float32)
        if full_52.shape[0] != self.scaler_mean.shape[0]:
            return None

        scaled = (full_52 - self.scaler_mean) / np.where(np.abs(self.scaler_scale) < 1e-6, 1.0, self.scaler_scale)
        tab_tensor = torch.tensor(scaled, dtype=torch.float32, device=self.device).unsqueeze(0)
        tok_tensor = ast_tokens.to(self.device)

        nf = ingest_data.get("node_features")
        nt = ingest_data.get("node_types")
        ei = ingest_data.get("edge_index")
        er = ingest_data.get("edge_rel")
        b = ingest_data.get("batch")
        use_graph = (
            isinstance(nf, torch.Tensor)
            and isinstance(nt, torch.Tensor)
            and isinstance(ei, torch.Tensor)
            and isinstance(er, torch.Tensor)
            and isinstance(b, torch.Tensor)
            and nf.numel() > 0
        )

        with torch.no_grad():
            if use_graph:
                logits, mal_logit, _ = self.ml_model(
                    nf.to(self.device),
                    nt.to(self.device),
                    ei.to(self.device),
                    er.to(self.device),
                    b.to(self.device),
                    tok_tensor,
                    tab_tensor,
                )
            else:
                logits, mal_logit, _ = self.ml_model(
                    None,
                    None,
                    None,
                    None,
                    None,
                    tok_tensor,
                    tab_tensor,
                )
            probs = [float(p) for p in torch.sigmoid(logits)[0].cpu().tolist()]
            aux_mal_prob = float(torch.sigmoid(mal_logit).item())
        return probs, aux_mal_prob

    def classify(
        self,
        raw_pdf_bytes: bytes,
        ingest_data: dict[str, Any],
        forensic_dossier: dict[str, Any],
        verdict: str | None,
        malware_prob: float | None,
    ) -> dict[str, Any]:
        raw_tokens = scan_raw_pdf_tokens(raw_pdf_bytes) if raw_pdf_bytes else {}
        records = ingest_data.get("raw_records") or []
        scripts = ingest_data.get("extracted_scripts") or []
        ast_stats = ingest_data.get("ast_stats") or {}
        ast_counts = ingest_data.get("ast_node_counts") or {}
        raw_entropy = float(ingest_data.get("raw_entropy") or 0.0)
        script_findings = forensic_dossier.get("script_findings") or []

        is_malicious_verdict = verdict == "MALICIOUS" or (malware_prob is not None and malware_prob >= 0.5)
        prob_val = float(malware_prob) if malware_prob is not None else 0.0

        has_open_action = (
            any(r.get("evidence_id") == "action:open_action" and r.get("is_threat_trigger") for r in records)
            or raw_tokens.get("OpenAction", 0) > 0
        )
        has_aa = (
            any(r.get("evidence_id") == "action:aa" and r.get("is_threat_trigger") for r in records)
            or raw_tokens.get("AA", 0) > 0
        )
        has_autoaction_trigger = any(
            r.get("evidence_id") in ("action:open_action", "action:aa") and r.get("is_threat_trigger")
            for r in records
        ) or (is_malicious_verdict and (has_open_action or has_aa))
        has_names_js = any(r.get("evidence_id") == "script:names_js" for r in records)
        has_js = (
            len(scripts) > 0
            or has_names_js
            or any(
                r.get("kind") == "script"
                or "/JS" in str(r.get("content_preview", ""))
                or "/JavaScript" in str(r.get("content_preview", ""))
                for r in records
            )
            or (is_malicious_verdict and (raw_tokens.get("JS", 0) > 0 or raw_tokens.get("JavaScript", 0) > 0))
        )
        has_launch = any(
            "/Launch" in str(r.get("content_preview", "")) for r in records
        ) or (is_malicious_verdict and raw_tokens.get("Launch", 0) > 0)
        has_embedded_file = (
            any(r.get("kind") == "filespec" for r in records)
            or b"/EmbeddedFiles" in raw_pdf_bytes
            or (is_malicious_verdict and raw_tokens.get("EmbeddedFile", 0) > 0)
        )
        has_xfa = any(r.get("evidence_id") == "script:acroform_xfa" for r in records) or (
            is_malicious_verdict and raw_tokens.get("XFA", 0) > 0
        )
        has_acroform = raw_tokens.get("Acroform", 0) > 0 or b"/AcroForm" in raw_pdf_bytes
        has_jbig2 = raw_tokens.get("JBIG2Decode", 0) > 0
        has_richmedia = raw_tokens.get("RichMedia", 0) > 0
        has_encrypt = raw_tokens.get("Encrypt", 0) > 0
        structural_uri_count = sum(
            1 for r in records if "/URI" in str(r.get("content_preview", "")) or "Annot" in str(r.get("invoker", ""))
        )
        has_uri = raw_tokens.get("URI", 0) > 0 or structural_uri_count > 0
        has_objstm = raw_tokens.get("ObjStm", 0) > 0
        has_submit_form = b"/SubmitForm" in raw_pdf_bytes or b"submitForm" in raw_pdf_bytes

        all_indicators: set[str] = set()
        deobf_techniques: list[str] = []
        if script_findings:
            combined_js = "\n".join(
                (str(sf.get("full_code", "")) + "\n" + str(sf.get("deobfuscated_code", "")))
                for sf in script_findings
            )
            for sf in script_findings:
                for ind in sf.get("dangerous_indicators") or []:
                    all_indicators.add(str(ind))
                for tech in sf.get("deobfuscation_techniques") or []:
                    if tech not in deobf_techniques:
                        deobf_techniques.append(str(tech))
        else:
            js_parts: list[str] = []
            for s in scripts:
                raw_code = str(s.get("code", ""))
                deobf_res = deobfuscate_javascript_static(raw_code)
                scan_txt = raw_code + (
                    "\n" + deobf_res["deobfuscated_code"] if deobf_res["deobfuscation_applied"] else ""
                )
                js_parts.append(scan_txt)
                for tech in deobf_res["deobfuscation_techniques"]:
                    if tech not in deobf_techniques:
                        deobf_techniques.append(str(tech))
                for tag, pattern, _ in DANGEROUS_PATTERNS:
                    if re.search(pattern, scan_txt, re.IGNORECASE):
                        all_indicators.add(tag)
            combined_js = "\n".join(js_parts)

        has_obfuscated_js = bool(deobf_techniques) or bool(
            all_indicators.intersection({"unescape_decode", "from_char_code", "eval_exec"})
        )
        loops_count = int(ast_stats.get("loops") or 0)
        array_expr_count = int(ast_counts.get("ArrayExpression") or 0)
        binary_expr_count = int(ast_counts.get("BinaryExpression") or 0)
        has_heap_or_buffer_staging = (
            "heap_spray_pattern" in all_indicators
            or (has_js and loops_count >= 1 and (array_expr_count >= 1 or binary_expr_count >= 1))
        )
        has_export_dropper = "export_data_object" in all_indicators or bool(
            re.search(r"\bexportDataObject\s*\(|\bimportDataObject\s*\(", combined_js, re.IGNORECASE)
        )

        matched_cves: list[tuple[str, str]] = []
        for cve_id, pattern, desc in CVE_EXPLOIT_SIGNATURES:
            if re.search(pattern, combined_js, re.IGNORECASE):
                matched_cves.append((cve_id, desc))
        if has_jbig2 and is_malicious_verdict:
            matched_cves.append(("CVE-2009-0658", "Suspicious JBIG2Decode Compressed Stream Filter"))
        if has_richmedia and is_malicious_verdict:
            matched_cves.append(("CVE-2011-0611", "Embedded RichMedia/Flash Object Trigger"))

        stream_decode_failures = sum(1 for r in records if r.get("stream_decode_failed"))
        decomp_exceeded = any(bool(r.get("decompression_ratio_exceeded")) for r in records)
        stream_mismatch = abs(raw_tokens.get("stream", 0) - raw_tokens.get("endstream", 0)) > 0
        has_stream_anomaly = decomp_exceeded or stream_decode_failures > 0 or (stream_mismatch and is_malicious_verdict)

        autoaction_sources = [
            f"{r.get('invoker')} ({r.get('obj_ref_str') or r.get('evidence_id')})"
            for r in records
            if r.get("evidence_id") in ("action:open_action", "action:aa") and r.get("is_threat_trigger")
        ]

        evidence_by_head: dict[str, tuple[str, str]] = {
            "js_script_exec": (
                f"Trích xuất được {len(scripts)} đoạn mã kịch bản chạy ngầm trong tệp"
                if scripts
                else "Ghi nhận khóa /JavaScript hoặc /JS nhúng trong cấu trúc đối tượng",
                "Không có đoạn mã kịch bản JavaScript chạy ngầm",
            ),
            "auto_open_trigger": (
                "Cài sẵn khóa tự kích hoạt ngay khi mở: " + ", ".join(autoaction_sources)
                if autoaction_sources
                else "Ghi nhận khóa tự động kích hoạt (/OpenAction hoặc /AA) trong tệp",
                "Không có lệnh tự động chạy khi mở tài liệu",
            ),
            "obfuscated_payload": (
                "Phát hiện kỹ thuật làm rối / mã hóa chuỗi ẩn ("
                + ", ".join(deobf_techniques or sorted(all_indicators) or ["escaped_tokens"])
                + ")",
                "Không thấy đoạn mã bị làm rối hay che giấu ký tự",
            ),
            "buffer_loop_staging": (
                f"Cây cú pháp AST ghi nhận {max(loops_count, 1)} vòng lặp tự ghép/nạp dữ liệu vào bộ nhớ",
                "Không có vòng lặp nạp dữ liệu bất thường vào bộ nhớ",
            ),
            "active_form_or_exploit": (
                "; ".join(f"{cid}: {cdesc}" for cid, cdesc in matched_cves)
                if matched_cves
                else "Phát hiện thành phần biểu mẫu động XFA / bộ giải mã đặc biệt đáng ngờ",
                "Không thấy dấu hiệu khai thác biểu mẫu động hay lỗi phần mềm đọc PDF",
            ),
            "embedded_dropper_or_launch": (
                "Phát hiện khóa gọi lệnh máy tính (/Launch) bên trong tệp"
                if has_launch
                else "Phát hiện tệp đính kèm ẩn (/EmbeddedFiles) hoặc lệnh tự bung tệp ra máy",
                "Không có tệp lạ đính kèm ẩn hay lệnh gọi chương trình ngoài",
            ),
            "suspicious_uri_redirect": (
                f"Phát hiện {max(raw_tokens.get('URI', 0), structural_uri_count, 1)} liên kết chuyển hướng / biểu mẫu gửi dữ liệu đáng ngờ",
                "Các liên kết (nếu có) đều ở trạng thái bình thường, không có dấu hiệu dẫn dụ độc hại",
            ),
            "structural_parser_evasion": (
                "Luồng dữ liệu nén có dấu hiệu lỗi giải nén hoặc tỷ lệ nén bất thường"
                if has_stream_anomaly
                else "Mô hình đồ thị ghi nhận cách bố trí đối tượng và luồng tham chiếu khác thường giống mã độc",
                "Cấu trúc đối tượng và luồng dữ liệu các trang hoàn toàn bình thường",
            ),
        }

        ml_out = self._predict_multilabel_neural(
            raw_pdf_bytes=raw_pdf_bytes,
            raw_tokens=raw_tokens,
            ingest_data=ingest_data,
            has_obfuscated_js=has_obfuscated_js,
            has_embedded_file=has_embedded_file or has_export_dropper,
            has_launch=has_launch,
            structural_uri_count=structural_uri_count,
        )

        explicit_critical = bool(
            matched_cves
            or has_launch
            or has_export_dropper
            or (has_autoaction_trigger and has_obfuscated_js)
        )

        ml_label_predictions: list[dict[str, Any]] = []
        analyzer_detections: list[dict[str, Any]] = []

        if ml_out is not None:
            raw_probs, aux_mal_prob = ml_out
            classification_source = "multilabel_neural_model_v2"
            if verdict in ("MALICIOUS", "BENIGN"):
                gate_open = bool(is_malicious_verdict or explicit_critical)
            else:
                gate_open = bool(is_malicious_verdict or (aux_mal_prob >= 0.50) or explicit_critical)

            fallback_overrides = {
                "active_form_or_exploit": bool(matched_cves),
                "embedded_dropper_or_launch": bool(has_launch or has_export_dropper),
                "auto_open_trigger": bool(has_autoaction_trigger and (is_malicious_verdict or has_obfuscated_js)),
                "obfuscated_payload": bool(has_obfuscated_js and (is_malicious_verdict or has_autoaction_trigger)),
                "js_script_exec": bool(has_js and (is_malicious_verdict or has_obfuscated_js)),
            }

            for idx, defn in enumerate(self.label_defs):
                lid = str(defn["id"])
                prob_k = float(raw_probs[idx])
                thr_k = float(defn.get("threshold", 0.50))
                det_k = bool(gate_open and (prob_k >= thr_k or fallback_overrides.get(lid, False)))
                if det_k and prob_k < thr_k:
                    display_prob = max(prob_k, thr_k)
                elif not gate_open:
                    display_prob = min(prob_k * max(prob_val * 1.5, 0.05), thr_k * 0.45)
                else:
                    display_prob = prob_k
                pct_k = round(display_prob * 100.0, 1)
                pos_ev, neg_ev = evidence_by_head.get(lid, (defn["desc_vi"], "Không phát hiện dấu hiệu rủi ro"))
                ev_text = pos_ev if det_k else neg_ev

                entry = {
                    "id": lid,
                    "code_name": defn["code_name"],
                    "label_vi": defn["label_vi"],
                    "category_code": defn["category_code"],
                    "category_vi": defn["category_vi"],
                    "family_code": defn["family_code"],
                    "family_vi": defn["family_vi"],
                    "behavior_tag": defn["behavior_tag"],
                    "mitre_id": defn["mitre_id"],
                    "mitre_name_vi": defn["mitre_name_vi"],
                    "mitre_tactic_vi": defn["mitre_tactic_vi"],
                    "desc_vi": defn["desc_vi"],
                    "probability": round(display_prob, 4),
                    "probability_pct": pct_k,
                    "threshold": round(thr_k, 3),
                    "detected": det_k,
                    "evidence": ev_text,
                }
                ml_label_predictions.append(entry)
                analyzer_detections.append({
                    "id": lid,
                    "analyzer": defn["label_vi"],
                    "engine_type": "Mô hình AI đa nhãn",
                    "detected": det_k,
                    "probability": round(display_prob, 4),
                    "probability_pct": pct_k,
                    "threshold": round(thr_k, 3),
                    "result": f"AI dự đoán: {pct_k:.1f}%" if det_k else f"An toàn ({pct_k:.1f}%)",
                    "evidence": ev_text,
                })
        else:
            classification_source = "structural_fallback"
            aux_mal_prob = prob_val
            heuristic_flags = {
                "js_script_exec": bool(has_js and (is_malicious_verdict or has_autoaction_trigger or has_obfuscated_js)),
                "auto_open_trigger": bool(has_autoaction_trigger),
                "obfuscated_payload": bool(has_obfuscated_js),
                "buffer_loop_staging": bool(has_heap_or_buffer_staging and (is_malicious_verdict or has_obfuscated_js)),
                "active_form_or_exploit": bool(matched_cves or (has_xfa and is_malicious_verdict)),
                "embedded_dropper_or_launch": bool(has_launch or has_export_dropper or (has_embedded_file and is_malicious_verdict)),
                "suspicious_uri_redirect": bool((has_submit_form or has_uri) and is_malicious_verdict and not has_js),
                "structural_parser_evasion": bool(has_stream_anomaly and is_malicious_verdict),
            }
            for defn in self.label_defs:
                lid = str(defn["id"])
                det_k = heuristic_flags.get(lid, False)
                pct_k = round((prob_val if det_k else 0.0) * 100.0, 1)
                pos_ev, neg_ev = evidence_by_head.get(lid, (defn["desc_vi"], "Không phát hiện dấu hiệu rủi ro"))
                ev_text = pos_ev if det_k else neg_ev
                ml_label_predictions.append({
                    "id": lid,
                    "code_name": defn["code_name"],
                    "label_vi": defn["label_vi"],
                    "category_code": defn["category_code"],
                    "category_vi": defn["category_vi"],
                    "family_code": defn["family_code"],
                    "family_vi": defn["family_vi"],
                    "behavior_tag": defn["behavior_tag"],
                    "mitre_id": defn["mitre_id"],
                    "mitre_name_vi": defn["mitre_name_vi"],
                    "mitre_tactic_vi": defn["mitre_tactic_vi"],
                    "desc_vi": defn["desc_vi"],
                    "probability": round(prob_val if det_k else 0.0, 4),
                    "probability_pct": pct_k,
                    "threshold": 0.5,
                    "detected": det_k,
                    "evidence": ev_text,
                })
                analyzer_detections.append({
                    "id": lid,
                    "analyzer": defn["label_vi"],
                    "engine_type": "Phân tích nội bộ",
                    "detected": det_k,
                    "probability": round(prob_val if det_k else 0.0, 4),
                    "probability_pct": pct_k,
                    "threshold": 0.5,
                    "result": "Phát hiện rủi ro" if det_k else "An toàn",
                    "evidence": ev_text,
                })

        active_heads = [h for h in ml_label_predictions if h["detected"]]
        active_by_id = {h["id"]: h for h in active_heads}
        detected_count = len(active_heads)

        behavior_tags: list[str] = ["pdf"]
        for h in active_heads:
            btag = str(h["behavior_tag"])
            if btag not in behavior_tags:
                behavior_tags.append(btag)
        if has_js and "js-embedded" not in behavior_tags:
            behavior_tags.append("js-embedded")
        if (has_open_action or has_aa) and is_malicious_verdict and "autoaction" not in behavior_tags:
            behavior_tags.append("autoaction")
        if has_names_js and "names-js" not in behavior_tags:
            behavior_tags.append("names-js")
        if has_obfuscated_js and "obfuscated" not in behavior_tags:
            behavior_tags.append("obfuscated")
        if has_launch and "launch-action" not in behavior_tags:
            behavior_tags.append("launch-action")
        if has_xfa and "xfa" not in behavior_tags:
            behavior_tags.append("xfa")
        if has_acroform and "acroform" not in behavior_tags:
            behavior_tags.append("acroform")
        if has_submit_form and "submit-form" not in behavior_tags:
            behavior_tags.append("submit-form")
        if has_uri and "uri-links" not in behavior_tags:
            behavior_tags.append("uri-links")
        if has_objstm and "object-streams" not in behavior_tags:
            behavior_tags.append("object-streams")
        if has_encrypt and "encrypted" not in behavior_tags:
            behavior_tags.append("encrypted")
        if raw_entropy >= 7.85 and "high-entropy" not in behavior_tags:
            behavior_tags.append("high-entropy")

        behavior_tags_vi = [
            {
                "code": tag,
                "label_vi": BEHAVIOR_TAG_LABELS_VI.get(tag, (tag, False))[0],
                "is_risk": bool(BEHAVIOR_TAG_LABELS_VI.get(tag, (tag, False))[1] and (detected_count > 0 or is_malicious_verdict)),
            }
            for tag in behavior_tags
        ]

        mitre_attack: list[dict[str, str]] = []
        seen_mitre: set[str] = set()
        ordered_active_for_mitre = [
            active_by_id[hid] for hid in CODE_PRIORITY_ORDER if hid in active_by_id
        ]
        for h in ordered_active_for_mitre:
            mid = str(h["mitre_id"])
            if mid not in seen_mitre:
                seen_mitre.add(mid)
                mitre_attack.append({
                    "id": mid,
                    "name": str(h["mitre_name_vi"]),
                    "tactic": str(h["mitre_tactic_vi"]),
                    "evidence": f"{h['evidence']} (AI: {h['probability_pct']:.1f}%)",
                })

        predicted_labels_vi = [
            {
                "id": h["id"],
                "label_vi": h["label_vi"],
                "probability_pct": h["probability_pct"],
            }
            for h in sorted(active_heads, key=lambda x: float(x["probability"]), reverse=True)
        ]

        if matched_cves:
            primary_cve = matched_cves[0][0]
            threat_label = f"Exploit.PDF.{primary_cve}"
            threat_title_vi = f"Mã độc khai thác lỗi trình đọc PDF ({primary_cve})"
            threat_categories = ["exploit", "cve-targeted", "pdf-reader"]
            categories_vi = [
                {"code": "exploit", "label_vi": "Khai thác trình đọc PDF"},
                {"code": primary_cve.lower(), "label_vi": f"Lỗi {primary_cve}"},
            ]
            family_labels = ["pdfexp", primary_cve.lower()]
            families_vi = [
                {"code": h["id"], "label_vi": f"{h['label_vi']} ({h['probability_pct']:.0f}%)"}
                for h in predicted_labels_vi[:4]
            ] or [{"code": primary_cve.lower(), "label_vi": f"Khai thác {primary_cve}"}]
            severity = "CRITICAL"
            summary_vi = (
                f"Mô hình AI đa nhãn và bộ quét cấu trúc phát hiện dấu hiệu lợi dụng lỗi bảo mật {primary_cve} "
                f"của phần mềm đọc PDF."
            )
        elif active_heads:
            active_ids = set(active_by_id.keys())
            if "active_form_or_exploit" in active_ids and "auto_open_trigger" not in active_ids:
                prefix = "Exploit.PDF"
            elif has_launch:
                prefix = "Trojan.PDF"
            elif "embedded_dropper_or_launch" in active_ids and "js_script_exec" not in active_ids:
                prefix = "Trojan-Dropper.PDF"
            elif active_ids == {"suspicious_uri_redirect"}:
                prefix = "Phishing.PDF"
            elif "buffer_loop_staging" in active_ids or (
                "auto_open_trigger" in active_ids and "obfuscated_payload" in active_ids
            ):
                prefix = "Trojan.PDFExp"
            else:
                prefix = "Trojan.PDF"

            ordered_codes = [
                str(active_by_id[hid]["code_name"])
                for hid in CODE_PRIORITY_ORDER
                if hid in active_by_id
            ]
            if has_launch and "LaunchCommand" not in ordered_codes:
                ordered_codes.insert(0, "LaunchCommand")
            top_codes = ordered_codes[:2] if ordered_codes else ["Heuristic"]
            threat_label = f"{prefix}." + ".".join(top_codes)

            threat_categories = []
            categories_vi = []
            seen_cat: set[str] = set()
            for hid in CODE_PRIORITY_ORDER:
                if hid not in active_by_id:
                    continue
                h = active_by_id[hid]
                ccode = str(h["category_code"])
                if ccode not in seen_cat:
                    seen_cat.add(ccode)
                    threat_categories.append(ccode)
                    categories_vi.append({"code": ccode, "label_vi": str(h["category_vi"])})
            if "trojan" not in seen_cat and prefix.startswith("Trojan"):
                threat_categories.insert(0, "trojan")
                categories_vi.insert(0, {"code": "trojan", "label_vi": "Mã độc ngụy trang (Trojan)"})

            family_labels = []
            for hid in CODE_PRIORITY_ORDER:
                if hid in active_by_id:
                    fcode = str(active_by_id[hid]["family_code"])
                    if fcode not in family_labels:
                        family_labels.append(fcode)

            families_vi = [
                {
                    "code": h["id"],
                    "label_vi": f"{h['label_vi']} ({h['probability_pct']:.0f}%)",
                }
                for h in predicted_labels_vi[:4]
            ]

            top_sorted = sorted(active_heads, key=lambda x: float(x["probability"]), reverse=True)
            lowered_top = [
                (str(h["label_vi"])[0].lower() + str(h["label_vi"])[1:])
                if str(h["label_vi"])
                else ""
                for h in top_sorted[:2]
            ]
            top_two_names = " & ".join(x for x in lowered_top if x)
            threat_title_vi = f"AI phát hiện {detected_count} hành vi nguy hiểm: {top_two_names}"
            detail_parts = [
                f"{h['label_vi']} ({h['probability_pct']:.1f}%)"
                for h in top_sorted[:4]
            ]
            summary_vi = (
                f"Mô hình AI đa nhãn tự quét đặc trưng tệp và nhận diện {detected_count}/8 nhóm hành vi độc hại: "
                + ", ".join(detail_parts)
                + "."
            )
            severity = "CRITICAL" if (is_malicious_verdict and detected_count >= 3) else "HIGH"
        elif is_malicious_verdict:
            threat_label = "HEUR:Trojan.PDF.StructuralAnomaly"
            threat_title_vi = "AI phát hiện cấu trúc tệp bất thường giống mã độc"
            threat_categories = ["trojan", "structural-evasion"]
            categories_vi = [{"code": "structural-evasion", "label_vi": "Cấu trúc PDF dị thường"}]
            family_labels = ["pdfheur", "gnn-structural"]
            families_vi = [{"code": "gnn-structural", "label_vi": f"Cấu trúc đáng ngờ ({prob_val * 100:.0f}%)"}]
            severity = "HIGH"
            summary_vi = (
                f"Mô hình AI ghi nhận {prob_val * 100:.1f}% dấu hiệu cấu trúc bên trong tệp trùng khớp với mẫu PDF độc hại."
            )
        else:
            threat_label = "Clean.PDF.Verified"
            threat_title_vi = "Tài liệu PDF an toàn — Không phát hiện hành vi độc hại"
            threat_categories = ["clean"]
            categories_vi = [{"code": "clean", "label_vi": "An toàn"}]
            family_labels = []
            families_vi = []
            severity = "SAFE"
            summary_vi = (
                "Mô hình AI đa nhãn đã tự kiểm tra toàn bộ 8 nhóm hành vi nguy hiểm trên tệp này và không phát hiện dấu hiệu mã độc."
            )

        return {
            "classification_source": classification_source,
            "model_name": "PDFMultiLabelThreatNet" if self.ml_weights_loaded else "StructuralFallback",
            "ml_weights_loaded": self.ml_weights_loaded,
            "aux_malware_probability": round(float(aux_mal_prob), 4),
            "threat_label": threat_label,
            "threat_title_vi": threat_title_vi,
            "severity": severity,
            "summary_vi": summary_vi,
            "threat_categories": threat_categories,
            "categories_vi": categories_vi,
            "family_labels": family_labels,
            "families_vi": families_vi,
            "predicted_labels_vi": predicted_labels_vi,
            "behavior_tags": behavior_tags,
            "behavior_tags_vi": behavior_tags_vi,
            "mitre_attack": mitre_attack,
            "matched_cves": [{"cve_id": c, "description": d} for c, d in matched_cves],
            "detected_count": detected_count,
            "total_analyzers": len(analyzer_detections),
            "ml_label_predictions": ml_label_predictions,
            "analyzer_detections": analyzer_detections,
        }
