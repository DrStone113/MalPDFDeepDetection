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
from malpdf.models.multilabel_threat_net_v4 import (
    MULTILABEL_V4_CONTRACT_VERSION,
    MultiLabelV4Config,
    PDFMultiLabelThreatNetV4,
    load_multilabel_v4_npz,
)
from malpdf.models.v4_graph_numpy import (
    build_runtime_multilabel_v4_feed_np,
    validate_multilabel_v4_contract_np,
)
from malpdf.scanner.forensic import (
    DANGEROUS_PATTERNS,
    deobfuscate_javascript_static,
    reconcile_taxonomy_observations,
    verified_zero_js_disproven_heads,
)
from malpdf.static.obfuscation import MAX_PDF_BYTES, count_escaped_pdf_names
from malpdf.static.raw_scan import scan_raw_pdf_tokens

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MULTILABEL_V4_CONTRACT_PATH = REPO_ROOT / "configs" / "multilabel_threat_v4_contract.json"
DEFAULT_MULTILABEL_V4_CHECKPOINT_PATH = (
    REPO_ROOT / "artifacts" / "models" / "multilabel_threat_v4" / "multilabel_threat_net_v4_seed42.npz"
)
LEGACY_MULTILABEL_V2_CONTRACT_PATH = REPO_ROOT / "configs" / "multilabel_threat_contract.json"
LEGACY_MULTILABEL_V2_CHECKPOINT_PATH = (
    REPO_ROOT / "artifacts" / "models" / "multilabel_threat_v2" / "multilabel_threat_net_v2_best.pt"
)
DEFAULT_MULTILABEL_CONTRACT_PATH = DEFAULT_MULTILABEL_V4_CONTRACT_PATH
DEFAULT_MULTILABEL_CHECKPOINT_PATH = DEFAULT_MULTILABEL_V4_CHECKPOINT_PATH

CVE_EXPLOIT_SIGNATURES: list[tuple[str, str, str]] = [
    ("CVE-2008-2992", r"\butil\.printf\s*\(", "Adobe Reader util.printf Stack Buffer Overflow"),
    ("CVE-2007-5659", r"\bCollab\.collectEmailInfo\s*\(", "Adobe Reader Collab.collectEmailInfo Buffer Overflow"),
    ("CVE-2009-0927", r"\bCollab\.getIcon\s*\(", "Adobe Reader Collab.getIcon Stack Overflow"),
    ("CVE-2009-4324", r"\bmedia\.newPlayer\s*\(", "Adobe Reader Doc.media.newPlayer Use-After-Free"),
    (
        "CVE-2008-0655",
        r"\bspell\.customDictionaryOpen\s*\(",
        "Adobe Reader spell.customDictionaryOpen Memory Corruption",
    ),
    ("CVE-2010-0188", r"\bTIFF\b.*SubIFD|LibTIFF", "Adobe Reader Embedded LibTIFF Integer Overflow"),
    ("CVE-2013-2729", r"\bBMP\b.*RLE", "Adobe Reader Font/Bitmap RLE Heap Overflow"),
]

BEHAVIOR_TAG_LABELS_VI: dict[str, tuple[str, bool]] = {
    "pdf": ("Tài liệu PDF", False),
    "js-embedded": ("Có mã JavaScript", True),
    "autoaction": ("Tự chạy khi mở tệp", True),
    "names-js": ("Danh mục JavaScript (/Names)", True),
    "obfuscated": ("Chuỗi hoặc mã bị làm rối", True),
    "heap-staging": ("Vòng lặp trong JavaScript", True),
    "cve-exploit": ("Khớp mẫu lỗ hổng trình đọc", True),
    "launch-action": ("Khởi chạy lệnh ngoài (/Launch)", True),
    "embedded-file": ("Tệp đính kèm nhúng", True),
    "xfa": ("Biểu mẫu động XFA", True),
    "acroform": ("Biểu mẫu điền thông tin", False),
    "submit-form": ("Tự gửi dữ liệu biểu mẫu", True),
    "uri-links": ("Có liên kết web", False),
    "object-streams": ("Luồng đối tượng nén (/ObjStm)", False),
    "encrypted": ("Có đặt mật khẩu / mã hóa", False),
    "stream-anomaly": ("Bất thường giải mã luồng", True),
    "high-entropy": ("Độ hỗn loạn dữ liệu cao", False),
}

_OBFUSCATION_LABELS_VI: dict[str, str] = {
    "fromCharCode_decode": "ghép ký tự String.fromCharCode",
    "unescape_percent_decode": "mã hóa phần trăm (%u / unescape)",
    "hex_escape_decode": "chuỗi thoát thập lục phân (\\xNN)",
    "unicode_escape_decode": "chuỗi thoát Unicode (\\uNNNN)",
    "string_concat_fold": "nối chuỗi phân mảnh",
    "unescape_decode": "gọi hàm unescape()",
    "from_char_code": "gọi String.fromCharCode()",
    "eval_exec": "gọi hàm eval()",
}


def _lowercase_leading_phrase(text: str) -> str:
    if not text or text.startswith("JavaScript"):
        return text
    return text[0].lower() + text[1:]


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


def _is_v4_npz_checkpoint(path: Path) -> bool:
    if path.suffix.lower() == ".npz":
        return True
    if not path.is_file():
        return False
    import zipfile

    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return any(name.endswith(".npy") for name in zf.namelist())
    except Exception:
        return False


def _is_v4_contract_file(path: Path) -> bool:
    if not path.is_file():
        return path.name == DEFAULT_MULTILABEL_V4_CONTRACT_PATH.name
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("contract_version") == MULTILABEL_V4_CONTRACT_VERSION
    except Exception:
        return False


class ThreatTaxonomyClassifier:
    def __init__(
        self,
        device: str | torch.device = "cpu",
        contract_path: Path | str | None = None,
        checkpoint_path: Path | str | None = None,
    ) -> None:
        self.device = torch.device(device)
        if contract_path is None and checkpoint_path is None:
            if DEFAULT_MULTILABEL_V4_CONTRACT_PATH.is_file() and DEFAULT_MULTILABEL_V4_CHECKPOINT_PATH.is_file():
                c_path = DEFAULT_MULTILABEL_V4_CONTRACT_PATH
                ckpt_path = DEFAULT_MULTILABEL_V4_CHECKPOINT_PATH
            else:
                c_path = LEGACY_MULTILABEL_V2_CONTRACT_PATH
                ckpt_path = LEGACY_MULTILABEL_V2_CHECKPOINT_PATH
        elif contract_path is not None and checkpoint_path is None:
            c_path = Path(contract_path)
            is_v4_c = _is_v4_contract_file(c_path)
            ckpt_path = DEFAULT_MULTILABEL_V4_CHECKPOINT_PATH if is_v4_c else LEGACY_MULTILABEL_V2_CHECKPOINT_PATH
        elif contract_path is None and checkpoint_path is not None:
            ckpt_path = Path(checkpoint_path)
            is_v4_ckpt = _is_v4_npz_checkpoint(ckpt_path)
            c_path = DEFAULT_MULTILABEL_V4_CONTRACT_PATH if is_v4_ckpt else LEGACY_MULTILABEL_V2_CONTRACT_PATH
        else:
            c_path = Path(contract_path)  # type: ignore[arg-type]
            ckpt_path = Path(checkpoint_path)  # type: ignore[arg-type]

        self.ml_weights_loaded = False
        self.is_v4 = False
        self.model_version = "StructuralFallback"
        self.classification_source_name = "structural_fallback"
        self.ml_checkpoint_path: Path | None = None
        self.ml_model: PDFMultiLabelThreatNet | PDFMultiLabelThreatNetV4 | None = None
        self.contract: dict[str, Any] = {}
        self.label_defs: list[dict[str, Any]] = [{**d, "threshold": 0.50} for d in MULTILABEL_THREAT_DEFINITIONS]
        self.scaler_mean: np.ndarray | None = None
        self.scaler_scale: np.ndarray | None = None
        self.tab29_center: np.ndarray | None = None
        self.tab29_scale: np.ndarray | None = None
        self.label_temperatures: np.ndarray | None = None
        self.mal_temperature: float = 1.0

        if c_path.is_file() and ckpt_path.is_file():
            contract_data = json.loads(c_path.read_text(encoding="utf-8"))
            if contract_data.get("contract_version") == MULTILABEL_V4_CONTRACT_VERSION:
                validate_multilabel_v4_contract_np(contract_data)
                expected_sha = contract_data.get("weights_npz_sha256")
                if checkpoint_path is None and expected_sha:
                    actual_sha = hashlib.sha256(ckpt_path.read_bytes()).hexdigest()
                    if actual_sha != expected_sha:
                        raise ValueError("multilabel_v4_npz_sha256_mismatch")
                cfg = MultiLabelV4Config(**contract_data["model_config"])
                model_v4 = PDFMultiLabelThreatNetV4(cfg).to(self.device)
                load_multilabel_v4_npz(model_v4, ckpt_path, map_location=self.device)
                model_v4.eval()
                self.ml_model = model_v4
                self.ml_weights_loaded = True
                self.is_v4 = True
                self.model_version = str(contract_data.get("model_version") or "PDFMultiLabelThreatNet v4")
                self.classification_source_name = "multilabel_neural_model_v4"
                self.ml_checkpoint_path = ckpt_path
                self.contract = contract_data
                self.label_defs = contract_data["labels"]
                self.tab29_center = np.asarray(contract_data["tab29_center"], dtype=np.float64)
                self.tab29_scale = np.asarray(contract_data["tab29_scale"], dtype=np.float64)
                self.label_temperatures = np.asarray(contract_data["label_temperatures"], dtype=np.float64)
                self.mal_temperature = float(contract_data["mal_temperature"])
            else:
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
                self.is_v4 = False
                self.model_version = "PDFMultiLabelThreatNet v2"
                self.classification_source_name = "multilabel_neural_model_v2"
                self.ml_checkpoint_path = ckpt_path
                self.contract = contract_data
                self.label_defs = labels_cfg
                self.scaler_mean = np.array(contract_data["scaler_mean"], dtype=np.float32)
                self.scaler_scale = np.array(contract_data["scaler_scale"], dtype=np.float32)

    def _predict_multilabel_v4(
        self,
        raw_pdf_bytes: bytes,
        raw_tokens: dict[str, int],
        ingest_data: dict[str, Any],
        escaped_names: float,
        has_obfuscated_js: bool,
        all_indicators: set[str],
        matched_cves: list[tuple[str, str]],
        has_export_dropper: bool,
        has_launch: bool,
        has_submit_form: bool,
        has_embedded_file: bool,
        has_stream_anomaly: bool,
        v4_graph_feed: dict[str, np.ndarray] | None,
    ) -> tuple[list[float], float] | None:
        if (
            not self.ml_weights_loaded
            or not isinstance(self.ml_model, PDFMultiLabelThreatNetV4)
            or self.tab29_center is None
            or self.tab29_scale is None
            or self.label_temperatures is None
        ):
            return None
        feed = build_runtime_multilabel_v4_feed_np(
            raw_pdf_bytes=raw_pdf_bytes,
            raw_tokens=raw_tokens,
            ingest_data=ingest_data,
            tab29_center=self.tab29_center,
            tab29_scale=self.tab29_scale,
            escaped_names=escaped_names,
            has_obfuscated_js=has_obfuscated_js,
            all_indicators=all_indicators,
            matched_cves=matched_cves,
            has_export_dropper=has_export_dropper,
            has_launch=has_launch,
            has_submit_form=has_submit_form,
            has_embedded_file=has_embedded_file,
            has_stream_anomaly=has_stream_anomaly,
            v4_graph_feed=v4_graph_feed,
        )
        if feed is None:
            return None
        dev = self.device
        with torch.no_grad():
            out = self.ml_model(
                torch.from_numpy(feed["tabular_features"]).to(dev),
                torch.from_numpy(feed["action_ir_features"]).to(dev),
                torch.from_numpy(feed["action_ir_active"].squeeze(-1) > 0.5).to(dev),
                torch.from_numpy(feed["node_features"]).to(dev),
                torch.from_numpy(feed["node_types"]).to(dev),
                torch.from_numpy(feed["deg_features"]).to(dev),
                torch.from_numpy(feed["node_pad_mask"] > 0.5).to(dev),
                torch.from_numpy(feed["spd"]).to(dev),
                torch.from_numpy(feed["direct_rel"]).to(dev),
                torch.from_numpy(feed["root_depth"]).to(dev),
                torch.from_numpy(feed["sink_dist"]).to(dev),
                torch.from_numpy(feed["summary_12"]).to(dev),
                torch.from_numpy(feed["aux_telemetry_features"]).to(dev),
            )
            lbl_z = out["label_logits"][0].detach().cpu().numpy().astype(np.float64)
            mal_z = float(out["mal_logit"].reshape(-1)[0].item())
        scaled_lbl = np.clip(lbl_z / self.label_temperatures, -40.0, 40.0)
        probs = [float(p) for p in (1.0 / (1.0 + np.exp(-scaled_lbl))).tolist()]
        scaled_mal = max(-40.0, min(40.0, mal_z / self.mal_temperature))
        aux_mal_prob = float(1.0 / (1.0 + np.exp(-scaled_mal)))
        return probs, aux_mal_prob

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
        if not self.ml_weights_loaded or self.ml_model is None or self.scaler_mean is None or self.scaler_scale is None:
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
        escaped_names = (
            float(count_escaped_pdf_names(raw_pdf_bytes, max_bytes=max(MAX_PDF_BYTES, len(raw_pdf_bytes))))
            if raw_pdf_bytes
            else 0.0
        )

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
        v4_graph_feed: dict[str, np.ndarray] | None = None,
    ) -> dict[str, Any]:
        raw_tokens = ingest_data.get("raw_tokens") or (scan_raw_pdf_tokens(raw_pdf_bytes) if raw_pdf_bytes else {})
        records = ingest_data.get("raw_records") or []
        scripts = ingest_data.get("extracted_scripts") or []
        ast_stats = ingest_data.get("ast_stats") or {}
        raw_entropy = float(ingest_data.get("raw_entropy") or 0.0)
        script_findings = forensic_dossier.get("threat_scripts") or []

        is_malicious_verdict = verdict == "MALICIOUS" or (malware_prob is not None and malware_prob >= 0.5)
        prob_val = float(malware_prob) if malware_prob is not None else 0.0

        autoaction_records = [
            record
            for record in records
            if record.get("is_threat_trigger") and record.get("evidence_id") in ("action:open_action", "action:aa")
        ]
        has_autoaction_trigger = bool(autoaction_records)
        has_names_js = any(r.get("evidence_id") == "script:names_js" for r in records)
        has_js = (
            bool(scripts) or has_names_js or any(r.get("evidence_id", "").startswith("script:action:") for r in records)
        )
        has_launch = any(r.get("action_type") == "/Launch" for r in records)
        has_embedded_file = (
            any(r.get("kind") == "filespec" for r in records)
            or b"/EmbeddedFiles" in raw_pdf_bytes
            or raw_tokens.get("EmbeddedFile", 0) > 0
        )
        xfa_analysis = ingest_data.get("xfa_analysis", {})
        has_xfa = xfa_analysis.get("present") or any(r.get("evidence_id") == "script:acroform_xfa" for r in records)
        has_acroform = raw_tokens.get("Acroform", 0) > 0 or b"/AcroForm" in raw_pdf_bytes
        has_encrypt = raw_tokens.get("Encrypt", 0) > 0
        encryption = ingest_data.get("encryption_analysis", {})
        password_locked = encryption.get("password_locked", False)
        structural_uri_count = sum(
            1 for r in records if "/URI" in str(r.get("content_preview", "")) or "Annot" in str(r.get("invoker", ""))
        )
        has_uri = raw_tokens.get("URI", 0) > 0 or structural_uri_count > 0
        has_objstm = raw_tokens.get("ObjStm", 0) > 0
        has_submit_form = any(r.get("action_type") == "/SubmitForm" for r in records)

        all_indicators: set[str] = set()
        deobf_techniques: list[str] = []
        js_semantics = ingest_data.get("js_semantics", {})
        if script_findings:
            script_findings = [
                finding
                for finding in script_findings
                if not (finding.get("is_verified_benign") and finding.get("intent_codes") == ["empty_noop"])
            ]
            combined_js = "\n".join(
                (str(sf.get("full_code", "")) + "\n" + str(sf.get("deobfuscated_code", ""))) for sf in script_findings
            )
            for sf in script_findings:
                for ind in sf.get("dangerous_indicators") or []:
                    all_indicators.add(str(ind))
                for tech in sf.get("deobfuscation_techniques") or []:
                    if tech not in deobf_techniques:
                        deobf_techniques.append(str(tech))
        else:
            js_parts: list[str] = []
            intents = js_semantics.get("per_script_intents", [])
            for index, s in enumerate(scripts):
                if (
                    index < len(intents)
                    and intents[index].get("is_verified_benign")
                    and intents[index].get("intent_codes") == ["empty_noop"]
                ):
                    continue
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

        all_indicators.update(js_semantics.get("dangerous_indicators", ()))
        if "evasive_obfuscation_techniques" in js_semantics:
            deobf_techniques = list(js_semantics["evasive_obfuscation_techniques"])
        elif js_semantics.get("is_verified_benign_js"):
            deobf_techniques = [
                technique
                for technique in deobf_techniques
                if technique not in {"string_concat_fold", "unicode_escape_decode"}
            ]
        has_obfuscated_js = bool(deobf_techniques) or bool(
            all_indicators.intersection({"unescape_decode", "from_char_code", "eval_exec"})
        )
        loops_count = int(ast_stats.get("loops") or 0)
        has_export_dropper = "export_data_object" in all_indicators or bool(
            re.search(r"\bexportDataObject\s*\(|\bimportDataObject\s*\(", combined_js, re.IGNORECASE)
        )

        matched_cves: list[tuple[str, str]] = []
        for cve_id, pattern, desc in CVE_EXPLOIT_SIGNATURES:
            if re.search(pattern, combined_js, re.IGNORECASE):
                matched_cves.append((cve_id, desc))
        stream_decode_failures = sum(1 for r in records if r.get("stream_decode_failed"))
        decomp_exceeded = any(bool(r.get("decompression_ratio_exceeded")) for r in records)
        has_stream_anomaly = decomp_exceeded or stream_decode_failures > 0

        autoaction_sources = [str(r.get("invoker") or r["evidence_id"]) for r in autoaction_records]
        obf_keys = deobf_techniques or sorted(
            all_indicators.intersection({"unescape_decode", "from_char_code", "eval_exec"})
        )
        obf_labels = [_OBFUSCATION_LABELS_VI.get(k, k) for k in obf_keys]
        anomaly_parts: list[str] = []
        if stream_decode_failures > 0:
            anomaly_parts.append(f"gặp {stream_decode_failures} lỗi giải mã luồng")
        if decomp_exceeded:
            anomaly_parts.append("vượt ngưỡng tỷ lệ giải nén")

        has_unextracted_js = (not password_locked) and (
            "javascript_body_unavailable" in (js_semantics.get("unverified_reasons") or ())
        )
        observations = {
            "js_script_exec": (
                f"Trích xuất được {len(scripts)} đoạn JavaScript"
                if scripts
                else "Ghi nhận khóa JavaScript trong cấu trúc tệp"
                if has_js
                else "Ghi nhận khóa JavaScript chưa trích xuất được thân mã trong cấu trúc tệp"
                if has_unextracted_js
                else None
            ),
            "auto_open_trigger": (
                "Ghi nhận hành động tự động tại: " + ", ".join(autoaction_sources) if autoaction_sources else None
            ),
            "obfuscated_payload": (
                "Dấu hiệu làm rối trong JavaScript: " + ", ".join(obf_labels) if has_obfuscated_js else None
            ),
            "buffer_loop_staging": (
                f"Ghi nhận {loops_count} vòng lặp trong mã JavaScript" if loops_count > 0 and has_js else None
            ),
            "active_form_or_exploit": (
                "Dấu hiệu tĩnh khớp mẫu nhận diện: " + ", ".join(cid for cid, _ in matched_cves)
                if matched_cves
                else None
            ),
            "embedded_dropper_or_launch": (
                "Ghi nhận hành động /Launch"
                if has_launch
                else "Ghi nhận lệnh xuất hoặc nhập dữ liệu tệp trong JavaScript"
                if has_export_dropper
                else None
            ),
            "suspicious_uri_redirect": ("Ghi nhận hành động gửi biểu mẫu (/SubmitForm)" if has_submit_form else None),
            "structural_parser_evasion": (", ".join(anomaly_parts).capitalize() + "." if has_stream_anomaly else None),
        }

        escaped_names = (
            float(count_escaped_pdf_names(raw_pdf_bytes, max_bytes=max(MAX_PDF_BYTES, len(raw_pdf_bytes))))
            if raw_pdf_bytes
            else 0.0
        )
        suppressed_heads = reconcile_taxonomy_observations(
            observations, ingest_data, verdict
        ) | verified_zero_js_disproven_heads(observations, ingest_data, escaped_names)

        blocked_scan = verdict == "UNAVAILABLE" or bool(ingest_data.get("prediction_blockers"))
        if blocked_scan:
            ml_out = None
        elif self.is_v4:
            ml_out = self._predict_multilabel_v4(
                raw_pdf_bytes=raw_pdf_bytes,
                raw_tokens=raw_tokens,
                ingest_data=ingest_data,
                escaped_names=escaped_names,
                has_obfuscated_js=has_obfuscated_js,
                all_indicators=all_indicators,
                matched_cves=matched_cves,
                has_export_dropper=has_export_dropper,
                has_launch=has_launch or raw_tokens.get("Launch", 0) > 0,
                has_submit_form=has_submit_form,
                has_embedded_file=has_embedded_file or has_export_dropper,
                has_stream_anomaly=has_stream_anomaly,
                v4_graph_feed=v4_graph_feed,
            )
        else:
            ml_out = self._predict_multilabel_neural(
                raw_pdf_bytes=raw_pdf_bytes,
                raw_tokens=raw_tokens,
                ingest_data=ingest_data,
                has_obfuscated_js=has_obfuscated_js,
                has_embedded_file=has_embedded_file or has_export_dropper,
                has_launch=has_launch or raw_tokens.get("Launch", 0) > 0,
                structural_uri_count=structural_uri_count,
            )

        raw_probs, aux_mal_prob = ml_out if ml_out is not None else (None, None)
        classification_source = self.classification_source_name if raw_probs is not None else "structural_fallback"
        ml_label_predictions: list[dict[str, Any]] = []
        analyzer_detections: list[dict[str, Any]] = []

        observed_label_names = {
            "js_script_exec": "JavaScript nhúng",
            "auto_open_trigger": "Hành động tự động",
            "obfuscated_payload": "Dấu hiệu làm rối mã JavaScript",
            "buffer_loop_staging": "Vòng lặp trong JavaScript",
            "active_form_or_exploit": "Biểu mẫu động hoặc API khai thác",
            "embedded_dropper_or_launch": "Tệp đính kèm hoặc lệnh /Launch",
            "suspicious_uri_redirect": "Chuyển hướng URL hoặc gửi biểu mẫu",
            "structural_parser_evasion": "Bất thường khi giải mã cấu trúc",
        }
        for idx, definition in enumerate(self.label_defs):
            lid = str(definition["id"])
            score = float(raw_probs[idx]) if raw_probs is not None else None
            threshold = float(definition.get("threshold", 0.50)) if score is not None else None
            flag_enabled = bool(definition.get("model_flag_enabled", True))
            evidence = observations.get(lid)
            model_flagged = (
                flag_enabled
                and lid not in suppressed_heads
                and score is not None
                and threshold is not None
                and score >= threshold
            )
            observed = evidence is not None
            status = "observed" if observed else "model_signal" if model_flagged else "not_observed"
            details = evidence or (
                "Điểm mô hình vượt ngưỡng, chưa có bằng chứng tĩnh tương ứng."
                if model_flagged
                else "Chưa ghi nhận trong phân tích tĩnh."
            )
            assessment = {
                "probability": round(score, 4) if score is not None else None,
                "probability_pct": round(score * 100.0, 2) if score is not None else None,
                "threshold": round(threshold, 3) if threshold is not None else None,
                "detected": observed,
                "evidence_status": status,
                "model_flagged": model_flagged,
                "evidence": details,
            }
            label = observed_label_names.get(lid, definition["label_vi"]) if observed else definition["label_vi"]
            ml_label_predictions.append({**definition, "label_vi": label, **assessment})
            analyzer_detections.append(
                {
                    "id": lid,
                    "analyzer": label,
                    "engine_type": "PyTorch Multi-Label AI" if score is not None else "Phân tích tĩnh",
                    **assessment,
                    "result": {
                        "observed": "Có dấu hiệu tĩnh",
                        "model_signal": "Tín hiệu mô hình",
                        "not_observed": "Chưa ghi nhận dấu hiệu",
                    }[status],
                }
            )

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
        if has_autoaction_trigger and "autoaction" not in behavior_tags:
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
                "is_risk": bool(
                    BEHAVIOR_TAG_LABELS_VI.get(tag, (tag, False))[1] and (detected_count > 0 or is_malicious_verdict)
                ),
            }
            for tag in behavior_tags
        ]
        if password_locked:
            behavior_tags.append("encrypted-password-locked")
            behavior_tags_vi.append(
                {
                    "code": "encrypted-password-locked",
                    "label_vi": "Cần mật khẩu để kiểm tra cấu trúc và nội dung PDF",
                    "is_risk": True,
                }
            )

        mitre_attack: list[dict[str, str]] = []
        seen_mitre: set[str] = set()
        ordered_active_for_mitre = [active_by_id[hid] for hid in CODE_PRIORITY_ORDER if hid in active_by_id]
        for h in ordered_active_for_mitre:
            mid = str(h["mitre_id"])
            if mid not in seen_mitre:
                seen_mitre.add(mid)
                mitre_attack.append(
                    {
                        "id": mid,
                        "name": str(h["mitre_name_vi"]),
                        "tactic": str(h["mitre_tactic_vi"]),
                        "evidence": h["evidence"],
                    }
                )

        predicted_labels_vi = [
            {
                "id": h["id"],
                "label_vi": h["label_vi"],
                "probability_pct": h["probability_pct"],
            }
            for h in sorted(active_heads, key=lambda x: x["probability"] or 0.0, reverse=True)
        ]

        if matched_cves:
            primary_cve = matched_cves[0][0]
            threat_label = f"Exploit.PDF.{primary_cve}"
            threat_title_vi = f"Dấu hiệu tĩnh khớp mẫu {primary_cve}"
            threat_categories = ["exploit", "cve-targeted", "pdf-reader"]
            categories_vi = [
                {"code": "exploit", "label_vi": "Khai thác trình đọc PDF"},
                {"code": primary_cve.lower(), "label_vi": f"Lỗi {primary_cve}"},
            ]
            family_labels = ["pdfexp", primary_cve.lower()]
            families_vi = [{"code": h["id"], "label_vi": str(h["label_vi"])} for h in predicted_labels_vi[:4]] or [
                {"code": primary_cve.lower(), "label_vi": f"Khai thác {primary_cve}"}
            ]
            severity = "CRITICAL"
            summary_vi = f"Dấu hiệu tĩnh trong tệp khớp mẫu nhận diện {primary_cve}."
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

            ordered_codes = [str(active_by_id[hid]["code_name"]) for hid in CODE_PRIORITY_ORDER if hid in active_by_id]
            if not is_malicious_verdict:
                prefix = "Indicators.PDF"
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
                    "label_vi": str(h["label_vi"]),
                }
                for h in predicted_labels_vi[:4]
            ]

            top_sorted = sorted(active_heads, key=lambda x: x["probability"] or 0.0, reverse=True)
            lowered_top = [_lowercase_leading_phrase(str(h["label_vi"])) for h in top_sorted[:2] if str(h["label_vi"])]
            top_two_names = " và ".join(lowered_top)
            threat_title_vi = f"Ghi nhận {detected_count} nhóm dấu hiệu tĩnh: {top_two_names}"
            if len(top_sorted) > 2:
                detail_parts = [str(h["label_vi"]) for h in top_sorted[:4]]
                summary_vi = "Các nhóm ghi nhận gồm: " + ", ".join(detail_parts) + "."
            else:
                ev_parts = [str(h["evidence"]) for h in top_sorted[:2] if h.get("evidence")]
                summary_vi = (
                    "Bằng chứng trực tiếp: " + "; ".join(ev_parts) + "."
                    if ev_parts
                    else "Phân tích tĩnh đã ghi nhận các dấu hiệu trên."
                )
            severity = "CRITICAL" if (is_malicious_verdict and detected_count >= 3) else "HIGH"
        elif is_malicious_verdict:
            threat_label = "HEUR:Trojan.PDF.StructuralAnomaly"
            threat_title_vi = "Điểm mô hình vượt ngưỡng cảnh báo"
            threat_categories = ["trojan", "structural-evasion"]
            categories_vi = [{"code": "structural-evasion", "label_vi": "Cấu trúc PDF bất thường"}]
            family_labels = ["pdfheur", "gnn-structural"]
            families_vi = [{"code": "gnn-structural", "label_vi": f"Cấu trúc bất thường ({prob_val * 100:.0f}%)"}]
            severity = "HIGH"
            summary_vi = (
                f"Điểm mô hình {prob_val * 100:.2f}%. "
                "Phân tích tĩnh chưa ghi nhận dấu hiệu cụ thể nào trong 8 nhóm kiểm tra."
            )
        else:
            threat_label = "Clean.PDF.Verified" if verdict == "BENIGN" else "Analysis.Unavailable"
            threat_title_vi = (
                "Điểm mô hình dưới ngưỡng cảnh báo" if verdict == "BENIGN" else "Chưa có điểm đánh giá tệp"
            )
            threat_categories = []
            categories_vi = []
            family_labels = []
            families_vi = []
            severity = "SAFE" if verdict == "BENIGN" else "UNAVAILABLE"
            summary_vi = "Phân tích tĩnh chưa ghi nhận dấu hiệu cụ thể nào trong 8 nhóm kiểm tra."

        if password_locked:
            warning = "PDF bị khóa bằng mật khẩu. Cấu trúc và nội dung bên trong chưa được kiểm tra."
            summary_vi = f"{warning} {summary_vi}" if is_malicious_verdict else warning
            if not is_malicious_verdict:
                threat_label = "Analysis.PasswordLocked"
                threat_title_vi = "Chưa kiểm tra được nội dung PDF bị khóa"
                severity = "UNAVAILABLE"

        return {
            "classification_source": classification_source,
            "model_name": "PDFMultiLabelThreatNet" if self.ml_weights_loaded else "StructuralFallback",
            "model_version": self.model_version if self.ml_weights_loaded else "StructuralFallback",
            "ml_weights_loaded": self.ml_weights_loaded,
            "aux_malware_probability": round(float(aux_mal_prob), 4) if aux_mal_prob is not None else None,
            "threat_label": threat_label,
            "threat_title_vi": threat_title_vi,
            "evidence_scope": "static_analysis",
            "severity": severity,
            "summary_vi": summary_vi,
            "threat_categories": threat_categories,
            "categories_vi": categories_vi,
            "family_labels": family_labels,
            "families_vi": families_vi,
            "predicted_labels_vi": predicted_labels_vi,
            "behavior_tags": behavior_tags,
            "encryption_analysis": encryption,
            "matched_signatures": ingest_data.get("signature_matches", []),
            "qr_analysis": ingest_data.get("qr_analysis", {}),
            "differential_analysis": ingest_data.get("differential_analysis", {}),
            "xfa_analysis": xfa_analysis,
            "polyglot_analysis": ingest_data.get("polyglot_analysis") or {},
            "behavior_tags_vi": behavior_tags_vi,
            "mitre_attack": mitre_attack,
            "matched_cves": [{"cve_id": c, "description": d} for c, d in matched_cves],
            "detected_count": detected_count,
            "model_flagged_count": sum(h["model_flagged"] for h in ml_label_predictions),
            "total_analyzers": len(analyzer_detections),
            "ml_label_predictions": ml_label_predictions,
            "analyzer_detections": analyzer_detections,
        }
