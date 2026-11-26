from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import sys

import pikepdf
import pymupdf as fitz
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_DIR = REPO_ROOT / "production"
if str(PROD_DIR) not in sys.path:
    sys.path.insert(0, str(PROD_DIR))

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.models.v4_graph_numpy import EXPECTED_MULTILABEL_HEAD_IDS_V4, validate_multilabel_v4_contract_np
from malpdf.scanner.ai_explainer import AIThreatExplainer
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.taxonomy import (
    LEGACY_MULTILABEL_V2_CHECKPOINT_PATH,
    LEGACY_MULTILABEL_V2_CONTRACT_PATH,
    ThreatTaxonomyClassifier,
)
from onnx_engine import ONNXMalPDFScannerEngine
from onnx_taxonomy import LEGACY_ML_V2_CONTRACT_PATH, LEGACY_ML_V2_ONNX_PATH, ONNXThreatTaxonomyClassifier


def _build_multipage_navigation_benign_pdf(pages_target: int = 67) -> bytes:
    base_bytes = load_real_benign_bytes()
    with pikepdf.open(io.BytesIO(base_bytes)) as pdf:
        while len(pdf.pages) < pages_target:
            with pikepdf.open(io.BytesIO(base_bytes)) as src:
                for page in src.pages:
                    if len(pdf.pages) >= pages_target:
                        break
                    pdf.pages.append(page)
        pdf.Root["/OpenAction"] = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.FitH, None])
        buf = io.BytesIO()
        pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate)
        return buf.getvalue()


def _build_zero_js_phishing_pdf() -> bytes:
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Link,
                Rect=pikepdf.Array([40, 620, 320, 660]),
                A=pikepdf.Dictionary(
                    S=pikepdf.Name.URI,
                    URI=pikepdf.String("http://198.51.100.44/microsoft-oauth-login/verify-password"),
                ),
            )
        )
        pdf.pages[0].obj["/Annots"] = pikepdf.Array([annot])
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()


def test_multilabel_v4_pytorch_and_onnx_parity_and_multipage_book_clean() -> None:
    pt = MalPDFScannerEngine(device="cpu")
    ox = ONNXMalPDFScannerEngine()
    assert pt.is_v4 and ox.is_v4
    assert pt.taxonomy.is_v4 and ox.taxonomy.is_v4
    assert pt.taxonomy.model_version == ox.taxonomy.model_version == "PDFMultiLabelThreatNet v4"

    book_bytes = _build_multipage_navigation_benign_pdf(67)
    threat_bytes = load_real_threat_bytes()
    cleaned_bytes, audit = PDFDisarmer().sanitize_bytes(threat_bytes, file_name="real_threat_document.pdf")
    assert audit.is_sanitized
    assert len(cleaned_bytes) > 0.8 * len(threat_bytes)
    with (
        fitz.open(stream=threat_bytes, filetype="pdf") as orig_doc,
        fitz.open(stream=cleaned_bytes, filetype="pdf") as clean_doc,
    ):
        assert len(clean_doc) == len(orig_doc)
        clean_txt = "\n".join(p.get_text("text") for p in clean_doc).strip()
        assert len(clean_txt) > 0 and clean_txt == "\n".join(p.get_text("text") for p in orig_doc).strip()

    for name, sample, expected_verdict in (
        ("winforms_67p_book.pdf", book_bytes, "BENIGN"),
        ("real_threat_document.pdf", threat_bytes, "MALICIOUS"),
        ("disarmed_threat.pdf", cleaned_bytes, "BENIGN"),
    ):
        r_pt = pt.scan_bytes(sample, file_name=name, explain=True)
        r_ox = ox.scan_bytes(sample, file_name=name, explain=True)
        assert r_pt.verdict == r_ox.verdict == expected_verdict
        t_pt = r_pt.threat_taxonomy
        t_ox = r_ox.threat_taxonomy
        assert t_pt["classification_source"] == t_ox["classification_source"] == "multilabel_neural_model_v4"
        assert tuple(h["id"] for h in t_pt["ml_label_predictions"]) == EXPECTED_MULTILABEL_HEAD_IDS_V4
        assert tuple(h["id"] for h in t_ox["ml_label_predictions"]) == EXPECTED_MULTILABEL_HEAD_IDS_V4
        for h_pt, h_ox in zip(t_pt["ml_label_predictions"], t_ox["ml_label_predictions"], strict=True):
            assert abs(float(h_pt["probability"]) - float(h_ox["probability"])) <= 1e-4
            assert h_pt["model_flagged"] == h_ox["model_flagged"]
            assert h_pt["evidence_status"] == h_ox["evidence_status"]
        if expected_verdict == "BENIGN":
            assert t_pt["detected_count"] == t_ox["detected_count"] == 0
            assert t_pt["model_flagged_count"] == t_ox["model_flagged_count"] == 0
            assert all(h["probability"] < h["threshold"] for h in t_pt["ml_label_predictions"])

        cw = r_ox.forensic_dossier["cross_modal_weights"]
        assert cw["modality_schema"] == "v4_dag_action_ir_tabular"
        assert "action_ir_weight" in cw and "tabular_weight" in cw and "graph_weight" in cw
        assert cw["tabular_weight"] + cw["graph_weight"] + cw["action_ir_weight"] == pytest.approx(1.0, abs=1e-3)
        assert "action_ir_pct" in r_ox.forensic_dossier["modality_breakdown"]

    ingest_book = ox.ingestion.ingest(book_bytes)
    codec_capped = {**ingest_book, "non_js_triggers": ["codec_inspection_limit"]}
    tax_capped = ox.taxonomy.classify(book_bytes, codec_capped, {}, "BENIGN", 0.01)
    assert tax_capped["model_flagged_count"] == 0
    assert all(h["evidence_status"] == "not_observed" for h in tax_capped["ml_label_predictions"])

    explainer = AIThreatExplainer()
    ans_id = explainer.answer_question(ox.scan_bytes(book_bytes, explain=True).to_dict(), "bạn là model gì?")
    assert "PDFMultiLabelThreatNet v4" in ans_id
    assert "PDFMultiLabelThreatNet v2" not in ans_id
    ans_why = explainer.answer_question(
        ox.scan_bytes(book_bytes, explain=True).to_dict(), "tại sao đánh giá mức độ này?"
    )
    assert "mã JavaScript" not in ans_why


def test_zero_js_malicious_phishing_suppresses_js_heads_but_fails_closed_on_incomplete_inspection() -> None:
    ox = ONNXMalPDFScannerEngine()
    phishing_pdf = _build_zero_js_phishing_pdf()
    res = ox.scan_bytes(phishing_pdf, file_name="phishing_no_js.pdf", explain=True)
    assert res.verdict == "MALICIOUS"
    by_id = {h["id"]: h for h in res.threat_taxonomy["ml_label_predictions"]}
    for js_head in ("js_script_exec", "obfuscated_payload", "buffer_loop_staging"):
        assert by_id[js_head]["evidence_status"] == "not_observed"
        assert by_id[js_head]["model_flagged"] is False

    ing = ox.ingestion.ingest(phishing_pdf)
    incomplete = {**ing, "non_js_triggers": ["supplemental_inspection_incomplete"]}
    from malpdf.scanner.forensic import verified_zero_js_disproven_heads

    assert verified_zero_js_disproven_heads({}, incomplete, 0.0) == set()
    locked = {**ing, "encryption_analysis": {"password_locked": True, "graph_inspected": False}}
    assert verified_zero_js_disproven_heads({}, locked, 0.0) == set()


def test_explicit_legacy_v2_taxonomy_and_contract_validation_guardrails() -> None:
    pt_v2 = ThreatTaxonomyClassifier(
        device="cpu",
        contract_path=LEGACY_MULTILABEL_V2_CONTRACT_PATH,
        checkpoint_path=LEGACY_MULTILABEL_V2_CHECKPOINT_PATH,
    )
    ox_v2 = ONNXThreatTaxonomyClassifier(
        contract_path=LEGACY_ML_V2_CONTRACT_PATH,
        onnx_path=LEGACY_ML_V2_ONNX_PATH,
    )
    assert pt_v2.ml_weights_loaded and not pt_v2.is_v4
    assert ox_v2.ml_weights_loaded and not ox_v2.is_v4
    benign = load_real_benign_bytes()
    ing = MalPDFScannerEngine(device="cpu").ingestion.ingest(benign)
    r_pt = pt_v2.classify(benign, ing, {}, "BENIGN", 0.02)
    r_ox = ox_v2.classify(benign, ing, {}, "BENIGN", 0.02)
    assert r_pt["classification_source"] == r_ox["classification_source"] == "multilabel_neural_model_v2"

    contract = json.loads((REPO_ROOT / "configs" / "multilabel_threat_v4_contract.json").read_text(encoding="utf-8"))
    validate_multilabel_v4_contract_np(contract)

    swapped = copy.deepcopy(contract)
    swapped["labels"][5], swapped["labels"][6] = swapped["labels"][6], swapped["labels"][5]
    with pytest.raises(ValueError, match="invalid_multilabel_v4_head_order"):
        validate_multilabel_v4_contract_np(swapped)

    bad_temp = copy.deepcopy(contract)
    bad_temp["label_temperatures"][0] = 0.0
    with pytest.raises(ValueError, match="invalid_multilabel_v4_label_temperatures"):
        validate_multilabel_v4_contract_np(bad_temp)

    bad_thr = copy.deepcopy(contract)
    bad_thr["labels"][0]["model_flag_enabled"] = True
    bad_thr["labels"][0]["threshold"] = 1.05
    with pytest.raises(ValueError, match="invalid_multilabel_v4_enabled_threshold_range"):
        validate_multilabel_v4_contract_np(bad_thr)

    bad_mcfg = copy.deepcopy(contract)
    bad_mcfg["model_config"]["num_labels"] = 1
    with pytest.raises(ValueError, match="invalid_multilabel_v4_model_config"):
        validate_multilabel_v4_contract_np(bad_mcfg)


def test_review_hardening_ast_telemetry_19d_legacy_graph_and_coverage_gates(tmp_path: Path) -> None:
    import numpy as np

    from malpdf.models.v4_graph_numpy import build_runtime_multilabel_v4_feed_np
    from malpdf.scanner.ai_explainer import AIThreatExplainer
    from malpdf.scanner.forensic import reconcile_taxonomy_observations, verified_zero_js_disproven_heads

    contract = json.loads((REPO_ROOT / "configs" / "multilabel_threat_v4_contract.json").read_text(encoding="utf-8"))
    center = np.asarray(contract["tab29_center"], dtype=np.float64)
    scale = np.asarray(contract["tab29_scale"], dtype=np.float64)

    benign = load_real_benign_bytes()
    ing = MalPDFScannerEngine(device="cpu").ingestion.ingest(benign)
    ing_19 = {
        **ing,
        "node_features": np.zeros((2, 19), dtype=np.float32),
        "node_types": np.array([0, 2], dtype=np.int64),
        "edge_index": np.array([[0], [1]], dtype=np.int64),
        "edge_rel": np.array([0], dtype=np.int64),
        "ast_stats": {"total_nodes": 20.0, "max_depth": 4.0, "loops": 1.0, "computed_members": 2.0, "call_count": 4.0},
        "ast_node_counts": {"CallExpression": 4, "ForStatement": 1},
    }
    feed = build_runtime_multilabel_v4_feed_np(
        raw_pdf_bytes=benign,
        raw_tokens=ing["raw_tokens"],
        ingest_data=ing_19,
        tab29_center=center,
        tab29_scale=scale,
        escaped_names=0.0,
        has_obfuscated_js=False,
        all_indicators=set(),
        matched_cves=[],
        has_export_dropper=False,
        has_launch=False,
        has_submit_form=False,
        has_embedded_file=False,
        has_stream_anomaly=False,
        v4_graph_feed=None,
    )
    assert feed is not None
    assert feed["node_features"].shape == (1, 2, 23)
    assert feed["aux_telemetry_features"][0, 3] == pytest.approx(float(np.log1p(20.0)), abs=1e-5)
    assert feed["aux_telemetry_features"][0, 7] == pytest.approx(0.20, abs=1e-5)

    mismatch_ing = {
        **ing,
        "extracted_scripts": [],
        "raw_tokens": {**ing["raw_tokens"], "JS": 0, "JavaScript": 0, "XFA": 0},
        "differential_analysis": {
            "has_differential_evasion": True,
            "anomalies": ["parser_trigger_visibility_mismatch"],
        },
    }
    assert verified_zero_js_disproven_heads({}, mismatch_ing, 0.0) == set()

    hex_benign_ing = {
        **ing,
        "extracted_scripts": [],
        "raw_tokens": {**ing["raw_tokens"], "JS": 0, "JavaScript": 0, "XFA": 0},
        "evasion_unpack_audit": {"objstm_unpack_complete": True, "hex_escaped_names_decoded": ["JS"]},
    }
    sup = reconcile_taxonomy_observations({}, hex_benign_ing, "BENIGN")
    assert {"js_script_exec", "obfuscated_payload", "buffer_loop_staging"}.isdisjoint(sup)

    v2_named_v4_pt = tmp_path / "baseline-for-v4.pt"
    v2_named_v4_pt.write_bytes(LEGACY_MULTILABEL_V2_CHECKPOINT_PATH.read_bytes())
    pt_single = ThreatTaxonomyClassifier(device="cpu", checkpoint_path=v2_named_v4_pt)
    assert pt_single.ml_weights_loaded and not pt_single.is_v4

    v2_named_v4_onnx = tmp_path / "baseline-for-v4.onnx"
    v2_named_v4_onnx.write_bytes(LEGACY_ML_V2_ONNX_PATH.read_bytes())
    ox_single = ONNXThreatTaxonomyClassifier(onnx_path=v2_named_v4_onnx)
    assert ox_single.ml_weights_loaded and not ox_single.is_v4

    explainer = AIThreatExplainer()
    ans_v2 = explainer.answer_question(
        {
            "verdict": "BENIGN",
            "malware_probability": 0.01,
            "file_name": "legacy.pdf",
            "forensic_dossier": {"model_generation": "v2", "modality_schema": "v2_graph_ast"},
            "threat_taxonomy": {"model_version": "PDFMultiLabelThreatNet v4"},
        },
        "xin chào model gì",
    )
    assert "PDF-TransGraph v2" in ans_v2
