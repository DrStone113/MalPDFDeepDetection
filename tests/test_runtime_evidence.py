from __future__ import annotations

import ast
import email
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import importlib
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pymupdf as fitz
from pypdf.generic import DictionaryObject, NameObject
import pytest
import torch

from malpdf.cdr import fixtures
from malpdf.cdr.engine import PDFDisarmer
from malpdf.gateway.mail_filter import MailGatewayFilter
from malpdf.scanner import engine, ingestion
from malpdf.scanner.ai_explainer import AIThreatExplainer
from malpdf.scanner.forensic import ForensicAttributionEngine, deobfuscate_javascript_static
from malpdf.scanner.ingestion import InstantPDFIngestion, _build_hex_dump_lines, _extract_object_metadata


def test_explicit_missing_checkpoint_is_not_replaced_by_another_model(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        engine.MalPDFScannerEngine(model_path=tmp_path / "not_trained.pt", device="cpu")


def test_missing_default_checkpoints_never_produce_random_inference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "DEFAULT_MODEL_PATH", tmp_path / "primary.pt")
    monkeypatch.setattr(engine, "FALLBACK_MODEL_PATH", tmp_path / "fallback.pt")
    try:
        scanner = engine.MalPDFScannerEngine(device="cpu")
    except FileNotFoundError:
        return
    assert scanner.weights_loaded is False
    with pytest.raises(RuntimeError, match="(?i)model|checkpoint|weight|unavailable"):
        scanner.scan_bytes(b"", explain=False)


def test_missing_scaler_does_not_silently_create_identity_normalization(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        InstantPDFIngestion(scaler_path=tmp_path / "missing_scaler.json")


@pytest.mark.parametrize(
    "payload",
    [
        {"feature_names": ["PdfSize", "Pages"], "mean": [0.0], "scale": [1.0, 1.0]},
        {"feature_names": ["PdfSize"], "mean": [0.0], "scale": [0.0]},
        {"feature_names": ["PdfSize"], "mean": [float("nan")], "scale": [1.0]},
        {"feature_names": ["PdfSize"], "mean": [0.0], "scale": [float("inf")]},
        {"feature_names": ["PdfSize", "PdfSize"], "mean": [0.0, 0.0], "scale": [1.0, 1.0]},
    ],
    ids=["shape_mismatch", "zero_scale", "nan_mean", "infinite_scale", "duplicate_features"],
)
def test_invalid_scaler_is_rejected_before_inference(tmp_path: Path, payload: dict) -> None:
    scaler_path = tmp_path / "invalid_scaler.json"
    scaler_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        InstantPDFIngestion(scaler_path=scaler_path)


def test_missing_fixture_is_reported_without_generating_a_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture_dir = tmp_path / "fixtures"
    monkeypatch.setattr(fixtures, "FIXTURES_DIR", fixture_dir)
    monkeypatch.setattr(fixtures, "BENIGN_FIXTURE_PATH", fixture_dir / "real_benign_document.pdf")
    monkeypatch.setattr(fixtures, "THREAT_FIXTURE_PATH", fixture_dir / "real_threat_document.pdf")

    def reject_generation() -> bytes:
        pytest.fail("Missing fixture triggered document generation instead of reporting missing evidence")

    if hasattr(fixtures, "_build_rich_document_bytes"):
        monkeypatch.setattr(fixtures, "_build_rich_document_bytes", reject_generation)
    with pytest.raises(FileNotFoundError):
        fixtures.load_real_benign_bytes()
    assert not list(tmp_path.rglob("*.pdf"))


def test_production_api_has_no_simulated_mail_endpoint() -> None:
    app_source = Path(__file__).resolve().parents[1] / "src" / "malpdf" / "web" / "app.py"
    tree = ast.parse(app_source.read_text(encoding="utf-8"))
    routes = {
        decorator.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call)
        and decorator.args
        and isinstance(decorator.args[0], ast.Constant)
        and isinstance(decorator.args[0].value, str)
    }
    assert "/api/gateway/simulate" not in routes


def test_app_import_does_not_generate_fixtures() -> None:
    app_source = Path(__file__).resolve().parents[1] / "src" / "malpdf" / "web" / "app.py"
    tree = ast.parse(app_source.read_text(encoding="utf-8"))
    calls = [node.value for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)]
    assert not any(isinstance(call.func, ast.Name) and call.func.id == "ensure_real_fixtures" for call in calls)


@pytest.mark.parametrize("verdict,probability", [("MALICIOUS", 0.99), ("BENIGN", 0.01)])
def test_explanation_does_not_invent_exploits_or_safety_certification(verdict: str, probability: float) -> None:
    scan = {
        "file_name": "reviewed_document.pdf",
        "verdict": verdict,
        "malware_probability": probability,
        "pages_count": 2,
        "file_size_bytes": 4096,
        "forensic_dossier": {"trigger_objects": [], "threat_scripts": []},
    }
    explainer = AIThreatExplainer()
    explanation = explainer.explain_threat(scan)
    answer = explainer.answer_question(scan, "Tài liệu này có nội dung gì?")
    serialized = json.dumps(explanation, ensure_ascii=False) + answer
    for unsupported_claim in (
        "CVSS 9.8",
        "Memory Corruption",
        "Use-After-Free",
        "hoàn toàn an toàn",
        "an toàn tuyệt đối",
        "tuân thủ nghiêm ngặt chuẩn ISO",
        "tuân thủ nghiêm ngặt tiêu chuẩn quốc tế ISO",
        "CLEAN & VERIFIED",
        "Tệp gốc đã được tự động lưu",
    ):
        assert unsupported_claim not in serialized


def test_health_does_not_claim_readiness_without_loaded_weights(monkeypatch: pytest.MonkeyPatch) -> None:
    web = importlib.import_module("malpdf.web.app")
    monkeypatch.setattr(web.scanner, "weights_loaded", False)
    with TestClient(web.app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["weights_loaded"] is False
    assert response.json()["status"] == "unavailable"


@pytest.mark.parametrize("data", [b"", b"not a PDF", b"%PDF-1.7\n%%EOF\n"], ids=["empty", "missing_header", "missing_catalog"])
def test_invalid_document_never_becomes_a_fabricated_graph(data: bytes) -> None:
    ingestion = InstantPDFIngestion()
    with pytest.raises(ValueError):
        ingestion.ingest(data)


def test_empty_bytes_have_no_hexadecimal_evidence() -> None:
    assert _build_hex_dump_lines(b"") == []


def test_unknown_object_offset_has_no_fabricated_byte_location() -> None:
    direct_dictionary = DictionaryObject({NameObject("/Type"): NameObject("/Catalog")})
    metadata = _extract_object_metadata(direct_dictionary, b"unrelated reviewed bytes", fallback_index=91)
    assert metadata["offset_hex"] is None
    assert metadata["hex_dump"] == []


def _disconnected_observations() -> dict:
    return {
        "raw_records": [
            {"evidence_id": "catalog:root", "kind": "catalog", "obj_ref_str": "1 0 R", "invoker": "/Root"},
            {
                "evidence_id": "action:unreachable",
                "kind": "action",
                "obj_ref_str": "3 0 R",
                "invoker": "/Unknown",
                "is_threat_trigger": True,
            },
        ],
        "raw_edges": [],
        "extracted_scripts": [],
        "ast_stats": {},
        "ast_node_counts": {},
        "pages_count": 0,
    }


def test_unmeasured_explanation_metrics_remain_unavailable() -> None:
    dossier = ForensicAttributionEngine().explain(_disconnected_observations(), malware_prob=0.8)
    for key in ("fidelity_score", "comprehensiveness_drop", "sparsity_index", "lipschitz_stability"):
        assert dossier["xai_metrics"][key] is None
    assert dossier["cross_modal_weights"] is None
    assert dossier["cross_attention_matrix"] == []
    assert all(value is None for value in dossier["modality_breakdown"].values())


def test_measured_explanation_metrics_are_retained() -> None:
    measured = {
        "fidelity_score": 0.87,
        "comprehensiveness_drop": 0.13,
        "sparsity_index": 42.0,
        "lipschitz_stability": 0.09,
        "graph_branch_pct": 40.0,
        "ast_branch_pct": 35.0,
        "tabular_branch_pct": 25.0,
    }
    dossier = ForensicAttributionEngine().explain(
        _disconnected_observations(),
        cross_modal_attn=torch.tensor([0.6, 0.4]),
        malware_prob=0.8,
        xai_proof_metrics=measured,
    )
    for key in ("fidelity_score", "comprehensiveness_drop", "sparsity_index", "lipschitz_stability"):
        assert dossier["xai_metrics"][key] == pytest.approx(measured[key])
    assert dossier["cross_modal_weights"] == {"graph_weight": 0.6, "ast_weight": 0.4}
    assert dossier["modality_breakdown"] == {"graph_pct": 40.0, "ast_pct": 35.0, "tabular_pct": 25.0}


def test_attack_path_requires_observed_edges() -> None:
    dossier = ForensicAttributionEngine().explain(_disconnected_observations(), malware_prob=0.8)
    assert len(dossier["attack_path"]) <= 1
    assert " -> " not in dossier["attack_path_string"]


def test_cdr_integrity_audit_is_backed_by_content_and_text_equality() -> None:
    raw_bytes = fixtures.load_real_benign_bytes()
    cleaned_bytes, audit = PDFDisarmer().sanitize_bytes(raw_bytes, file_name="real_benign_document.pdf")
    with fitz.open(stream=raw_bytes, filetype="pdf") as original:
        original_pages = len(original)
        original_text = "\n".join(page.get_text() for page in original)
    with fitz.open(stream=cleaned_bytes, filetype="pdf") as cleaned:
        sanitized_pages = len(cleaned)
        extracted_text = "\n".join(page.get_text() for page in cleaned)
    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)
    assert sanitized_pages == original_pages
    assert len(extracted_text) > 0
    assert extracted_text == original_text
    assert audit.text_integrity_verified is True
    assert audit.content_streams_preserved is True


def _use_unverified_scaler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    raw_scaler = json.loads(ingestion.DEFAULT_SCALER_PATH.read_text(encoding="utf-8"))
    raw_scaler.pop("contract_version", None)
    raw_scaler.pop("fitted_on", None)
    unverified_path = tmp_path / "unverified_scaler.json"
    unverified_path.write_text(json.dumps(raw_scaler), encoding="utf-8")
    monkeypatch.setattr(ingestion, "DEFAULT_SCALER_PATH", unverified_path)
    return unverified_path


def test_unverified_training_feature_contract_blocks_model_predictions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_unverified_scaler(tmp_path, monkeypatch)
    raw_bytes = fixtures.load_real_threat_bytes()
    scanner = engine.MalPDFScannerEngine(device="cpu")
    result = scanner.scan_bytes(raw_bytes, file_name="real_threat_document.pdf", explain=True)
    assert result.prediction_available is False
    assert result.verdict == "UNAVAILABLE"
    assert result.confidence == "UNAVAILABLE"
    assert result.malware_probability is None
    assert result.ood_score is None
    assert len(result.forensic_dossier["trigger_objects"]) > 0
    assert len(result.forensic_dossier["threat_scripts"]) > 0


def test_unmeasured_training_features_are_unknown_instead_of_proxy_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_unverified_scaler(tmp_path, monkeypatch)
    ing = InstantPDFIngestion()
    observations = ing.ingest(fixtures.load_real_benign_bytes())
    assert observations["tab_features"] is None
    assert len(observations["raw_feature_vec"]) == len(observations["feature_names"])
    features = dict(zip(observations["feature_names"], observations["raw_feature_vec"]))
    for name in (
        "byte_image_file_encoded_ratio",
        "byte_image_file_persisted_ratio",
        "stream_truncation_ratio",
        "evasive_timeout_anomaly",
        "flag_decompression_ratio_exceeded",
        "is_truncated_stream",
        "flag_spec_violation_flood",
        "flag_excessive_object_graph",
        "flag_ast_complexity_truncated",
    ):
        assert features[name] is None
    assert observations["prediction_blockers"]


def test_mail_attachment_is_held_when_prediction_contract_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_unverified_scaler(tmp_path, monkeypatch)
    raw_bytes = fixtures.load_real_benign_bytes()
    message = MIMEMultipart()
    message["From"] = "reviewed-fixture@example.test"
    message["To"] = "reviewer@example.test"
    message["Subject"] = "Reviewed on-disk fixture inspection"
    message.attach(MIMEText("Reviewed local integration fixture.", "plain"))
    attachment = MIMEApplication(raw_bytes, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="real_benign_document.pdf")
    message.attach(attachment)
    gateway = MailGatewayFilter(quarantine_dir=tmp_path / "quarantine", device="cpu")
    output_bytes, report = gateway.process_email_bytes(message.as_bytes())
    assert report.action_taken == "HELD_FOR_REVIEW"
    assert report.unavailable_attachments == 1
    assert report.malicious_attachments == 0
    assert report.total_attachments == 1
    assert report.attachments[0].verdict == "UNAVAILABLE"
    assert report.attachments[0].malware_probability is None
    output_message = email.message_from_bytes(output_bytes)
    assert output_message.get("X-MalPDF-Inspection") != "CLEAN"


def test_verified_v2_contract_measures_real_features_without_proxy_formula() -> None:
    ing = InstantPDFIngestion()
    assert ing.contract_verified is True
    observations = ing.ingest(fixtures.load_real_benign_bytes())
    assert observations["tab_features"] is not None
    assert not observations["prediction_blockers"]
    features = dict(zip(observations["feature_names"], observations["raw_feature_vec"]))
    assert features["byte_image_file_encoded_ratio"] == pytest.approx(1.0)
    assert features["flag_decompression_ratio_exceeded"] == 0.0
    assert observations["node_features"].shape[1] == 23


def test_static_js_deobfuscation_decodes_obfuscated_payloads() -> None:
    obfuscated = (
        "var a = String.fromCharCode(97, 112, 112, 46, 97, 108, 101, 114, 116);"
        "var b = unescape('%u0065%u0076%u0061%u006c');"
        "var c = '\\x75\\x74\\x69\\x6c\\x2e\\x70\\x72\\x69\\x6e\\x74\\x66';"
    )
    res = deobfuscate_javascript_static(obfuscated)
    assert res["deobfuscation_applied"] is True
    assert "fromCharCode_decode" in res["deobfuscation_techniques"]
    assert "unescape_percent_decode" in res["deobfuscation_techniques"]
    assert "hex_escape_decode" in res["deobfuscation_techniques"]
    assert "app.alert" in res["deobfuscated_code"]
    assert "eval" in res["deobfuscated_code"]
    assert "util.printf" in res["deobfuscated_code"]


def test_ai_explainer_multi_intent_qa_and_cdr_context() -> None:
    scanner = engine.MalPDFScannerEngine(device="cpu")
    res = scanner.scan_bytes(fixtures.load_real_threat_bytes(), file_name="real_threat_document.pdf", explain=True)
    scan_dict = res.to_dict()
    explainer = AIThreatExplainer()
    cdr_audit = {
        "is_sanitized": True,
        "removed_triggers": ["/Root/OpenAction", "/Root/AA", "/Root/Names/JavaScript"],
        "original_size_bytes": 15000,
        "sanitized_size_bytes": 14800,
        "original_pages": 2,
        "sanitized_pages": 2,
        "text_integrity_verified": True,
        "disarm_latency_ms": 12.4,
        "post_scan_verification": {
            "prob_before": scan_dict["malware_probability"],
            "prob_after": 0.0312,
            "verdict_after": "BENIGN",
        },
    }
    ans_cdr = explainer.answer_question(scan_dict, "Kết quả tẩy độc CDR và mã JavaScript của tệp này?", cdr_audit=cdr_audit)
    assert "6.02%" not in ans_cdr
    assert "3.12%" in ans_cdr
    assert "JavaScript" in ans_cdr or "Script" in ans_cdr
    ans_xai = explainer.answer_question(scan_dict, "Giải thích chỉ số toán học XAI Fidelity và OOD của mô hình?")
    assert "Fidelity" in ans_xai
    assert "OOD" in ans_xai


def _numeric_graph(sha256: str) -> dict:
    return {
        "sha256": sha256,
        "num_nodes": 1,
        "num_edges": 0,
        "node_features": [[0.0] * 19],
        "node_types": [0],
        "edge_src": [],
        "edge_dst": [],
        "edge_rel": [],
    }


def test_graph_cache_missing_expected_document_is_rejected() -> None:
    contract = importlib.import_module("malpdf.data.graph_contract")
    observed_sha = "a" * 64
    missing_sha = "b" * 64
    with pytest.raises(ValueError, match="(?i)missing"):
        contract.index_measured_graphs([_numeric_graph(observed_sha)], {observed_sha, missing_sha})


def test_graph_cache_zero_node_record_is_rejected() -> None:
    contract = importlib.import_module("malpdf.data.graph_contract")
    sha256 = "a" * 64
    empty_graph = {
        "sha256": sha256,
        "num_nodes": 0,
        "num_edges": 0,
        "node_features": [],
        "node_types": [],
        "edge_src": [],
        "edge_dst": [],
        "edge_rel": [],
    }
    with pytest.raises(ValueError):
        contract.index_measured_graphs([empty_graph], {sha256})


def test_graph_cache_keeps_real_zero_values_and_empty_edge_sets() -> None:
    contract = importlib.import_module("malpdf.data.graph_contract")
    sha256 = "a" * 64
    graph = _numeric_graph(sha256)
    indexed = contract.index_measured_graphs([graph], {sha256})
    assert indexed == {sha256: graph}
    assert indexed[sha256]["node_features"] == [[0.0] * 19]
    assert indexed[sha256]["num_edges"] == 0


def test_graph_cache_duplicate_document_is_rejected() -> None:
    contract = importlib.import_module("malpdf.data.graph_contract")
    sha256 = "a" * 64
    with pytest.raises(ValueError):
        contract.index_measured_graphs([_numeric_graph(sha256), _numeric_graph(sha256)], {sha256})


def test_threat_taxonomy_and_virustotal_hash_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = importlib.import_module("malpdf.scanner.engine")
    fixtures = importlib.import_module("malpdf.cdr.fixtures")
    cdr_engine = importlib.import_module("malpdf.cdr.engine")
    from malpdf.scanner.ai_explainer import AIThreatExplainer

    scanner = engine.MalPDFScannerEngine(device="cpu")
    threat_bytes = fixtures.load_real_threat_bytes()
    benign_bytes = fixtures.load_real_benign_bytes()

    threat_res = scanner.scan_bytes(threat_bytes, file_name="real_threat_document.pdf", explain=True)
    tax = threat_res.threat_taxonomy
    assert tax["classification_source"] == "multilabel_neural_model_v2"
    assert tax["model_name"] == "PDFMultiLabelThreatNet"
    assert tax["ml_weights_loaded"] is True
    assert len(tax["ml_label_predictions"]) == 8
    pred_map = {p["id"]: p for p in tax["ml_label_predictions"]}
    for must_detect in ("js_script_exec", "auto_open_trigger", "obfuscated_payload", "buffer_loop_staging"):
        assert pred_map[must_detect]["detected"] is True
        assert pred_map[must_detect]["probability"] >= 0.80
    assert tax["threat_label"] == "Trojan.PDFExp.AutoAction.ObfuscatedJS"
    assert "trojan" in tax["threat_categories"]
    assert "pdfexp" in tax["threat_categories"]
    for expected_tag in ("pdf", "js-embedded", "autoaction", "obfuscated"):
        assert expected_tag in tax["behavior_tags"]
    assert tax["detected_count"] >= 4
    assert tax["total_analyzers"] == 8
    mitre_ids = {m["id"] for m in tax["mitre_attack"]}
    assert {"T1204.002", "T1059.007", "T1027"}.issubset(mitre_ids)
    assert "Action (/OpenAction)" in threat_res.forensic_dossier["attack_path"]

    benign_res = scanner.scan_bytes(benign_bytes, file_name="real_benign_document.pdf", explain=True)
    assert benign_res.threat_taxonomy["classification_source"] == "multilabel_neural_model_v2"
    assert benign_res.threat_taxonomy["threat_label"] == "Clean.PDF.Verified"
    assert benign_res.threat_taxonomy["detected_count"] == 0
    assert benign_res.threat_taxonomy["mitre_attack"] == []
    assert all(p["detected"] is False and p["probability"] < 0.15 for p in benign_res.threat_taxonomy["ml_label_predictions"])

    disarmed_bytes, cdr_log = cdr_engine.PDFDisarmer().sanitize_bytes(threat_bytes, file_name="real_threat_document.pdf")
    assert len(disarmed_bytes) > 0.8 * len(threat_bytes)
    assert cdr_log.sanitized_pages == cdr_log.original_pages
    import pymupdf as fitz
    with fitz.open(stream=disarmed_bytes, filetype="pdf") as doc:
        extracted_text = "".join(page.get_text("text") for page in doc)
    assert len(extracted_text.strip()) > 0
    disarmed_res = scanner.scan_bytes(disarmed_bytes, file_name="disarmed.pdf", explain=True)
    assert disarmed_res.threat_taxonomy["classification_source"] == "multilabel_neural_model_v2"
    assert disarmed_res.threat_taxonomy["threat_label"] == "Clean.PDF.Verified"
    assert disarmed_res.threat_taxonomy["detected_count"] == 0
    assert all(p["detected"] is False and p["probability"] < 0.15 for p in disarmed_res.threat_taxonomy["ml_label_predictions"])

    explainer = AIThreatExplainer()
    qa_tax = explainer.answer_question(threat_res.to_dict(), "Nó là loại mã độc gì như VirusTotal?")
    assert "Trojan.PDFExp.AutoAction.ObfuscatedJS" in qa_tax
    assert "T1204.002" in qa_tax

    web_app = importlib.import_module("malpdf.web.app")
    from fastapi.testclient import TestClient

    client = TestClient(web_app.app)
    assert client.get(f"/api/vt/{threat_res.sha256}").status_code == 404
