from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

import numpy as np
import onnxruntime as ort

PROD_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROD_ROOT.parent
for candidate_src in (PROD_ROOT / "src", REPO_ROOT / "src"):
    if candidate_src.is_dir() and str(candidate_src) not in sys.path:
        sys.path.insert(0, str(candidate_src))

from malpdf.models.v4_graph_numpy import (
    ACTION_IR_DIM,
    AUX_TELEMETRY_V4_DIM,
    EXPECTED_MULTILABEL_V4_ONNX_INPUTS,
    EXPECTED_MULTILABEL_V4_ONNX_OUTPUTS,
    MULTILABEL_V4_CONTRACT_VERSION,
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

DEFAULT_ML_V4_CONTRACT_PATH = PROD_ROOT / "configs" / "multilabel_threat_v4_contract.json"
DEFAULT_ML_V4_ONNX_PATH = PROD_ROOT / "models" / "multilabel_threat_net_v4.onnx"
LEGACY_ML_V2_CONTRACT_PATH = PROD_ROOT / "configs" / "multilabel_threat_contract.json"
LEGACY_ML_V2_ONNX_PATH = PROD_ROOT / "models" / "multilabel_threat_net_v2.onnx"
DEFAULT_ML_CONTRACT_PATH = DEFAULT_ML_V4_CONTRACT_PATH
DEFAULT_ONNX_MANIFEST_PATH = PROD_ROOT / "configs" / "onnx_manifest.json"
DEFAULT_ML_ONNX_PATH = DEFAULT_ML_V4_ONNX_PATH


def _sigmoid_np(x: np.ndarray | float) -> np.ndarray | float:
    clipped = np.clip(x, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def _to_numpy(val: Any, dtype: Any) -> np.ndarray:
    if hasattr(val, "detach"):
        return val.detach().cpu().numpy().astype(dtype, copy=False)
    return np.asarray(val, dtype=dtype)


class ONNXThreatTaxonomyClassifier:
    def __init__(
        self,
        contract_path: Path | str | None = None,
        onnx_path: Path | str | None = None,
        manifest_path: Path | str | None = None,
    ) -> None:
        man_path = Path(manifest_path) if manifest_path is not None else DEFAULT_ONNX_MANIFEST_PATH
        manifest = json.loads(man_path.read_text(encoding="utf-8")) if man_path.is_file() else {}
        ml_meta = manifest.get("multilabel_model") or {}

        use_manifest = contract_path is None and onnx_path is None
        if use_manifest:
            if ml_meta.get("filename"):
                m_path = PROD_ROOT / "models" / str(ml_meta["filename"])
                c_name = str(
                    ml_meta.get("contract_filename")
                    or (
                        "multilabel_threat_v4_contract.json"
                        if "v4" in str(ml_meta["filename"]).lower()
                        else "multilabel_threat_contract.json"
                    )
                )
                c_path = PROD_ROOT / "configs" / c_name
                if not c_path.is_file() and (REPO_ROOT / "configs" / c_name).is_file():
                    c_path = REPO_ROOT / "configs" / c_name
            elif DEFAULT_ML_V4_ONNX_PATH.is_file():
                m_path = DEFAULT_ML_V4_ONNX_PATH
                c_path = (
                    DEFAULT_ML_V4_CONTRACT_PATH
                    if DEFAULT_ML_V4_CONTRACT_PATH.is_file()
                    else (REPO_ROOT / "configs" / DEFAULT_ML_V4_CONTRACT_PATH.name)
                )
            else:
                m_path = LEGACY_ML_V2_ONNX_PATH
                c_path = (
                    LEGACY_ML_V2_CONTRACT_PATH
                    if LEGACY_ML_V2_CONTRACT_PATH.is_file()
                    else (REPO_ROOT / "configs" / LEGACY_ML_V2_CONTRACT_PATH.name)
                )
        elif contract_path is not None and onnx_path is None:
            c_path = Path(contract_path)
            is_v4_c = False
            if c_path.is_file():
                try:
                    is_v4_c = (
                        json.loads(c_path.read_text(encoding="utf-8")).get("contract_version")
                        == MULTILABEL_V4_CONTRACT_VERSION
                    )
                except Exception:
                    is_v4_c = False
            else:
                is_v4_c = c_path.name == DEFAULT_ML_V4_CONTRACT_PATH.name
            m_path = DEFAULT_ML_V4_ONNX_PATH if is_v4_c else LEGACY_ML_V2_ONNX_PATH
        elif contract_path is None and onnx_path is not None:
            m_path = Path(onnx_path)
            is_v4_onnx = False
            if m_path.is_file():
                probe_opts = ort.SessionOptions()
                probe_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_DISABLE_ALL
                probe_sess = ort.InferenceSession(
                    str(m_path), sess_options=probe_opts, providers=["CPUExecutionProvider"]
                )
                probe_inputs = {inp.name for inp in probe_sess.get_inputs()}
                is_v4_onnx = {"action_ir_features", "aux_telemetry_features"}.issubset(probe_inputs)
            else:
                is_v4_onnx = m_path.name == DEFAULT_ML_V4_ONNX_PATH.name
            c_name = "multilabel_threat_v4_contract.json" if is_v4_onnx else "multilabel_threat_contract.json"
            c_path = PROD_ROOT / "configs" / c_name
            if not c_path.is_file() and (REPO_ROOT / "configs" / c_name).is_file():
                c_path = REPO_ROOT / "configs" / c_name
        else:
            c_path = Path(contract_path)  # type: ignore[arg-type]
            m_path = Path(onnx_path)  # type: ignore[arg-type]

        self.ml_weights_loaded = False
        self.is_v4 = False
        self.model_version = "StructuralFallback"
        self.classification_source_name = "structural_fallback"
        self.ml_session: ort.InferenceSession | None = None
        self.label_defs: list[dict[str, Any]] = []
        self.scaler_mean: np.ndarray | None = None
        self.scaler_scale: np.ndarray | None = None
        self.tab29_center: np.ndarray | None = None
        self.tab29_scale: np.ndarray | None = None
        self.label_temperatures: np.ndarray | None = None
        self.mal_temperature: float = 1.0

        if c_path.is_file() and m_path.is_file():
            if use_manifest and ml_meta:
                expected_sha = ml_meta.get("sha256")
                if expected_sha and hashlib.sha256(m_path.read_bytes()).hexdigest() != expected_sha:
                    raise ValueError("multilabel_onnx_sha256_mismatch")
                expected_c_sha = ml_meta.get("contract_sha256")
                if expected_c_sha:
                    raw_c = c_path.read_bytes()
                    if (
                        hashlib.sha256(raw_c).hexdigest() != expected_c_sha
                        and hashlib.sha256(raw_c.replace(b"\r\n", b"\n")).hexdigest() != expected_c_sha
                    ):
                        raise ValueError("multilabel_contract_sha256_mismatch")

            contract_data = json.loads(c_path.read_text(encoding="utf-8"))
            is_v4 = contract_data.get("contract_version") == MULTILABEL_V4_CONTRACT_VERSION
            if is_v4:
                validate_multilabel_v4_contract_np(contract_data)

            opts = ort.SessionOptions()
            opts.graph_optimization_level = (
                ort.GraphOptimizationLevel.ORT_ENABLE_BASIC if is_v4 else ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            )
            opts.intra_op_num_threads = 2
            opts.inter_op_num_threads = 1
            opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
            sess = ort.InferenceSession(
                str(m_path),
                sess_options=opts,
                providers=["CPUExecutionProvider"],
            )
            if is_v4:
                in_list = sess.get_inputs()
                out_list = sess.get_outputs()
                if tuple(i.name for i in in_list) != EXPECTED_MULTILABEL_V4_ONNX_INPUTS:
                    raise ValueError("invalid_multilabel_v4_onnx_inputs")
                if tuple(o.name for o in out_list) != EXPECTED_MULTILABEL_V4_ONNX_OUTPUTS:
                    raise ValueError("invalid_multilabel_v4_onnx_outputs")
                in_shapes = {i.name: i.shape for i in in_list}
                out_shapes = {o.name: o.shape for o in out_list}
                if (
                    int(in_shapes["tabular_features"][-1]) != 29
                    or int(in_shapes["action_ir_features"][-1]) != ACTION_IR_DIM
                    or int(in_shapes["node_features"][-1]) != 23
                    or int(in_shapes["aux_telemetry_features"][-1]) != AUX_TELEMETRY_V4_DIM
                    or int(out_shapes["label_logits"][-1]) != 8
                ):
                    raise ValueError("invalid_multilabel_v4_onnx_shapes")
                self.ml_session = sess
                self.is_v4 = True
                self.model_version = str(contract_data.get("model_version") or "PDFMultiLabelThreatNet v4")
                self.classification_source_name = "multilabel_neural_model_v4"
                self.label_defs = contract_data["labels"]
                self.tab29_center = np.asarray(contract_data["tab29_center"], dtype=np.float64)
                self.tab29_scale = np.asarray(contract_data["tab29_scale"], dtype=np.float64)
                self.label_temperatures = np.asarray(contract_data["label_temperatures"], dtype=np.float64)
                self.mal_temperature = float(contract_data["mal_temperature"])
                self.ml_weights_loaded = True
            else:
                self.ml_session = sess
                self.is_v4 = False
                self.model_version = "PDFMultiLabelThreatNet v2"
                self.classification_source_name = "multilabel_neural_model_v2"
                self.label_defs = contract_data.get("labels") or self.label_defs
                self.scaler_mean = np.array(contract_data["scaler_mean"], dtype=np.float32)
                raw_scale = np.array(contract_data["scaler_scale"], dtype=np.float32)
                self.scaler_scale = np.where(np.abs(raw_scale) < 1e-6, 1.0, raw_scale)
                self.ml_weights_loaded = True

    def _predict_multilabel_v4_onnx(
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
            or not self.is_v4
            or self.ml_session is None
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
        label_logits, mal_logit = self.ml_session.run(None, feed)
        lbl_z = np.asarray(label_logits, dtype=np.float64)[0]
        mal_z = float(np.asarray(mal_logit, dtype=np.float64).reshape(-1)[0])
        probs = [float(p) for p in _sigmoid_np(lbl_z / self.label_temperatures).tolist()]  # type: ignore[union-attr]
        aux_mal_prob = float(_sigmoid_np(mal_z / self.mal_temperature))
        return probs, aux_mal_prob

    def _predict_multilabel_onnx(
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
            or self.ml_session is None
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

        tab_52 = ((full_52 - self.scaler_mean) / self.scaler_scale).astype(np.float32)[None, :]
        tok_np = _to_numpy(ast_tokens, np.int64)
        if tok_np.ndim == 1:
            tok_np = tok_np[None, :]

        nf_raw = ingest_data.get("node_features")
        nt_raw = ingest_data.get("node_types")
        ei_raw = ingest_data.get("edge_index")
        er_raw = ingest_data.get("edge_rel")
        b_raw = ingest_data.get("batch")

        if nf_raw is not None and nt_raw is not None and b_raw is not None:
            nf_np = _to_numpy(nf_raw, np.float32)
            nt_np = _to_numpy(nt_raw, np.int64)
            b_np = _to_numpy(b_raw, np.int64)
            use_graph = np.array([1.0 if nf_np.shape[0] > 0 else 0.0], dtype=np.float32)
            if ei_raw is not None and er_raw is not None:
                ei_np = _to_numpy(ei_raw, np.int64)
                er_np = _to_numpy(er_raw, np.int64)
            else:
                ei_np = np.zeros((2, 0), dtype=np.int64)
                er_np = np.zeros((0,), dtype=np.int64)
        else:
            nf_np = np.zeros((1, 23), dtype=np.float32)
            nt_np = np.array([8], dtype=np.int64)
            b_np = np.zeros((1,), dtype=np.int64)
            ei_np = np.zeros((2, 0), dtype=np.int64)
            er_np = np.zeros((0,), dtype=np.int64)
            use_graph = np.array([0.0], dtype=np.float32)

        if ei_np.ndim == 2 and ei_np.shape[1] > 0:
            es_np = np.ascontiguousarray(ei_np[0], dtype=np.int64)
            ed_np = np.ascontiguousarray(ei_np[1], dtype=np.int64)
            er_feed = np.ascontiguousarray(er_np, dtype=np.int64)
            em_np = np.ones((ei_np.shape[1], 1), dtype=np.float32)
            he_np = np.array([1.0], dtype=np.float32)
        else:
            es_np = np.zeros((1,), dtype=np.int64)
            ed_np = np.zeros((1,), dtype=np.int64)
            er_feed = np.zeros((1,), dtype=np.int64)
            em_np = np.zeros((1, 1), dtype=np.float32)
            he_np = np.array([0.0], dtype=np.float32)

        label_logits, mal_logit = self.ml_session.run(
            None,
            {
                "node_features": np.ascontiguousarray(nf_np, dtype=np.float32),
                "node_types": np.ascontiguousarray(nt_np, dtype=np.int64),
                "edge_src": es_np,
                "edge_dst": ed_np,
                "edge_rel": er_feed,
                "edge_mask": em_np,
                "has_edges": he_np,
                "use_graph_flag": use_graph,
                "batch": np.ascontiguousarray(b_np, dtype=np.int64),
                "ast_tokens": np.ascontiguousarray(tok_np, dtype=np.int64),
                "tabular_features": np.ascontiguousarray(tab_52, dtype=np.float32),
            },
        )
        probs = [float(p) for p in _sigmoid_np(np.asarray(label_logits)[0]).tolist()]
        aux_mal_prob = float(_sigmoid_np(float(np.asarray(mal_logit).reshape(-1)[0])))
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
            ml_out = self._predict_multilabel_v4_onnx(
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
            ml_out = self._predict_multilabel_onnx(
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
                    "engine_type": "ONNX Multi-Label AI" if score is not None else "Phân tích tĩnh",
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
        for hid in CODE_PRIORITY_ORDER:
            if hid not in active_by_id:
                continue
            h = active_by_id[hid]
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
            {"id": h["id"], "label_vi": h["label_vi"], "probability_pct": h["probability_pct"]}
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

            families_vi = [{"code": h["id"], "label_vi": str(h["label_vi"])} for h in predicted_labels_vi[:4]]

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
            "model_name": "PDFMultiLabelThreatNet-ONNX" if self.ml_weights_loaded else "StructuralFallback",
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
