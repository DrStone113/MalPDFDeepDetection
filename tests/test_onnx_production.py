from __future__ import annotations

from pathlib import Path
import sys

from fastapi.testclient import TestClient
import pymupdf as fitz
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_DIR = REPO_ROOT / "production"
if str(PROD_DIR) not in sys.path:
    sys.path.insert(0, str(PROD_DIR))

import app as prod_entrypoint
from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.scanner.engine import MalPDFScannerEngine
from onnx_engine import ONNXMalPDFScannerEngine
from web_service import app as prod_web_app


def _extract_pdf_text_and_pages(pdf_bytes: bytes) -> tuple[int, str]:
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        pages = len(doc)
        text = "\n".join(page.get_text("text") for page in doc).strip()
        return pages, text


def test_onnx_engine_matches_pytorch_on_real_fixtures() -> None:
    threat_bytes = load_real_threat_bytes()
    benign_bytes = load_real_benign_bytes()

    pt_engine = MalPDFScannerEngine(device="cpu")
    onnx_engine = ONNXMalPDFScannerEngine()
    for scanner in (pt_engine, onnx_engine):
        assert scanner.tabular_in_features == 29
    assert onnx_engine.decision_threshold == pytest.approx(pt_engine.decision_threshold, abs=1e-6)
    assert onnx_engine.temperature == pytest.approx(pt_engine.temperature, abs=1e-6)

    pt_threat = pt_engine.scan_bytes(threat_bytes, file_name="real_threat_document.pdf", explain=True)
    ox_threat = onnx_engine.scan_bytes(threat_bytes, file_name="real_threat_document.pdf", explain=True)

    assert ox_threat.verdict == pt_threat.verdict == "MALICIOUS"
    assert ox_threat.malware_probability is not None and pt_threat.malware_probability is not None
    assert abs(ox_threat.malware_probability - pt_threat.malware_probability) <= 1e-4
    assert ox_threat.threat_taxonomy["ml_weights_loaded"] is True
    assert ox_threat.threat_taxonomy["threat_label"] == pt_threat.threat_taxonomy["threat_label"]
    assert ox_threat.threat_taxonomy["detected_count"] == pt_threat.threat_taxonomy["detected_count"]
    assert ox_threat.forensic_dossier["cross_attention_matrix_status"] == "measured_occlusion_saliency"
    assert len(ox_threat.forensic_dossier["cross_attention_matrix"]) > 0
    assert ox_threat.forensic_dossier["ast_token_attribution_source"] == "observed_node_frequency"

    pt_benign = pt_engine.scan_bytes(benign_bytes, file_name="real_benign_document.pdf", explain=True)
    ox_benign = onnx_engine.scan_bytes(benign_bytes, file_name="real_benign_document.pdf", explain=True)

    assert ox_benign.verdict == pt_benign.verdict == "BENIGN"
    assert ox_benign.malware_probability is not None and pt_benign.malware_probability is not None
    assert abs(ox_benign.malware_probability - pt_benign.malware_probability) <= 1e-4
    assert ox_benign.threat_taxonomy["detected_count"] == 0
    assert ox_benign.threat_taxonomy["severity"] == "SAFE"
    assert ox_benign.threat_taxonomy["threat_label"] == "Clean.PDF.Verified"
    assert all(
        not h["detected"] and h["probability_pct"] < 25.0 for h in ox_benign.threat_taxonomy["ml_label_predictions"]
    )
    assert all(
        not h["detected"] and h["probability_pct"] < 25.0 for h in pt_benign.threat_taxonomy["ml_label_predictions"]
    )

    cleaned, audit = PDFDisarmer().sanitize_bytes(threat_bytes)
    assert audit.is_sanitized
    assert len(cleaned) > 0.8 * len(threat_bytes)
    pages, content = _extract_pdf_text_and_pages(cleaned)
    assert content and (pages, content) == _extract_pdf_text_and_pages(threat_bytes)
    pt_cleaned = pt_engine.scan_bytes(cleaned, explain=False)
    ox_cleaned = onnx_engine.scan_bytes(cleaned, explain=False)
    assert ox_cleaned.verdict == pt_cleaned.verdict
    assert ox_cleaned.malware_probability == pytest.approx(pt_cleaned.malware_probability, abs=1e-4)


def test_onnx_logits_match_pytorch_on_phase_2_byte_stress() -> None:
    from scripts.deploy.export_onnx_models import verify_stress_parity

    pt_engine = MalPDFScannerEngine(device="cpu")
    onnx_engine = ONNXMalPDFScannerEngine()
    assert verify_stress_parity(pt_engine.model, onnx_engine.bin_session, pt_engine.ingestion) < 1e-5


def test_explicit_legacy_checkpoints_keep_their_feature_contract() -> None:
    pytorch = MalPDFScannerEngine(
        model_path=REPO_ROOT / "artifacts/models/pdf_transgraph_v2/pdf_transgraph_v2_23d_best.pt",
        device="cpu",
    )
    onnx = ONNXMalPDFScannerEngine(model_path=PROD_DIR / "models/pdf_transgraph_v2.onnx")
    for scanner in (pytorch, onnx):
        assert scanner.tabular_in_features == 38
        assert scanner.temperature == 1.0
        assert scanner.decision_threshold == 0.5
    benign = load_real_benign_bytes()
    pt_result = pytorch.scan_bytes(benign, explain=False)
    ort_result = onnx.scan_bytes(benign, explain=False)
    assert pt_result.verdict == ort_result.verdict == "BENIGN"
    assert ort_result.malware_probability == pytest.approx(pt_result.malware_probability, abs=1e-4)


def test_production_web_service_endpoints_and_cdr_integrity() -> None:
    threat_bytes = load_real_threat_bytes()
    benign_bytes = load_real_benign_bytes()
    orig_pages, orig_text = _extract_pdf_text_and_pages(threat_bytes)
    assert orig_pages >= 1
    assert len(orig_text) > 0

    client = TestClient(prod_web_app)

    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "MalPDF" in r_root.text
    assert "require-trusted-types-for 'script'" in r_root.headers.get("content-security-policy", "")
    assert r_root.headers.get("x-content-type-options") == "nosniff"
    assert "x-frame-options" not in {k.lower() for k in r_root.headers.keys()}

    r_head = client.head("/")
    assert r_head.status_code == 200

    r_ui = client.get("/ui")
    assert r_ui.status_code == 200
    assert "require-trusted-types-for 'script'" in r_ui.headers.get("content-security-policy", "")

    from malpdf.web.http import STATIC_ASSETS

    for route in STATIC_ASSETS:
        assert client.get(route).status_code == 200

    r_fav = client.get("/favicon.ico")
    assert r_fav.status_code == 200

    r_env = client.get("/env-config.js")
    assert r_env.status_code == 200

    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    health_json = r_health.json()
    expected_scanner = ONNXMalPDFScannerEngine()
    assert health_json["runtime"] == "onnxruntime"
    assert health_json["model"] == (
        "PDF-TransGraph v4 (23D ONNX)" if expected_scanner.is_v4 else "PDF-TransGraph v3.2b (23D ONNX)"
    )
    assert health_json["temperature"] == pytest.approx(expected_scanner.temperature, abs=1e-5)
    assert health_json["decision_threshold"] == pytest.approx(expected_scanner.decision_threshold, abs=1e-5)
    assert health_json["prediction_available"] is True
    assert health_json["multilabel_weights_loaded"] is True
    assert health_json["cdr_engine"] == "pikepdf-inplace"

    r_scan = client.post(
        "/api/scan",
        files={"file": ("real_threat_document.pdf", threat_bytes, "application/pdf")},
    )
    assert r_scan.status_code == 200
    scan_json = r_scan.json()
    scan_id = scan_json["scan_id"]
    assert scan_json["verdict"] == "MALICIOUS"
    assert scan_json["threat_taxonomy"]["detected_count"] >= 3

    r_ablate = client.post(
        "/api/xai/ablate",
        data={"node_id": "action:open_action", "scan_id": scan_id},
    )
    assert r_ablate.status_code == 200
    abl_json = r_ablate.json()
    assert abl_json["ablation_method"] == "pikepdf_binary_excision"
    assert abl_json["prob_after"] < 0.50

    r_ablate_surgical = client.post(
        "/api/xai/ablate",
        data={
            "node_id": "action:open_action",
            "scan_id": scan_id,
            "ablate_mode": "surgical",
        },
    )
    assert r_ablate_surgical.status_code == 200
    surg_json = r_ablate_surgical.json()
    assert "/Root/OpenAction" in surg_json["excised_keys"]
    assert "action:open_action" in surg_json["excised_node_ids"]
    assert len(surg_json["remaining_threat_node_ids"]) >= 1

    r_ablate_cum = client.post(
        "/api/xai/ablate",
        data={
            "node_id": "script:names_js",
            "scan_id": scan_id,
            "ablate_mode": "surgical",
            "exclude_node_ids": "action:open_action,action:aa",
        },
    )
    assert r_ablate_cum.status_code == 200
    cum_json = r_ablate_cum.json()
    assert cum_json["verdict_after"] == "BENIGN"
    assert cum_json["prob_after"] < 0.50
    assert cum_json["remaining_threat_node_ids"] == []

    r_mail_job = client.post(f"/api/gateway/inspect-job/{scan_id}")
    assert r_mail_job.status_code == 200
    mail_job_json = r_mail_job.json()
    assert mail_job_json["action"] == "SANITIZED_ATTACHMENT"
    assert mail_job_json["has_sanitized_eml"] is True
    r_mail_dl = client.get(f"/api/gateway/download/eml/{mail_job_json['eml_job_id']}")
    assert r_mail_dl.status_code == 200
    assert len(r_mail_dl.content) > 500

    r_disarm = client.post(f"/api/disarm/{scan_id}")
    assert r_disarm.status_code == 200
    disarm_json = r_disarm.json()
    assert disarm_json["post_scan_verification"]["verdict_after"] == "BENIGN"

    r_dl = client.get(f"/api/download/sanitized/{scan_id}")
    assert r_dl.status_code == 200
    cleaned_bytes = r_dl.content

    assert len(cleaned_bytes) > 0.8 * len(threat_bytes)
    sanitized_pages, extracted_text = _extract_pdf_text_and_pages(cleaned_bytes)
    assert sanitized_pages == orig_pages
    assert len(extracted_text) > 0
    assert extracted_text == orig_text

    r_benign = client.post(
        "/api/scan",
        files={"file": ("real_benign_document.pdf", benign_bytes, "application/pdf")},
    )
    assert r_benign.status_code == 200
    assert r_benign.json()["verdict"] == "BENIGN"


def test_zerogpu_entrypoint_decorator_registered() -> None:
    status_text = prod_entrypoint.zerogpu_accelerator_check("verify")
    assert "ONNX Runtime" in status_text
    assert "verify" in status_text


def test_onnx_engine_scans_pdf_above_legacy_10mib_cap() -> None:
    import io
    import os

    import pikepdf

    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        pdf.pages[0]["/Payload"] = pdf.make_stream(os.urandom(12 * 1024 * 1024))
        buf = io.BytesIO()
        pdf.save(buf)
    large_pdf = buf.getvalue()
    assert len(large_pdf) > 10 * 1024 * 1024

    onnx_engine = ONNXMalPDFScannerEngine()
    result = onnx_engine.scan_bytes(large_pdf, file_name="large_12mib.pdf", explain=True)
    assert result.prediction_available is True
    assert result.prediction_blockers == []
    assert result.threat_taxonomy["ml_weights_loaded"] is True
    assert result.file_size_bytes == len(large_pdf)


def test_onnx_engine_accepts_crlf_and_lf_contract_digest(tmp_path: Path, monkeypatch) -> None:
    import pytest

    import onnx_engine as oe

    is_v4_default = (PROD_DIR / "models" / "pdf_transgraph_v4.onnx").is_file() and (
        PROD_DIR / "configs" / "transgraph_v4_contract.json"
    ).is_file()
    contract_name = "transgraph_v4_contract.json" if is_v4_default else "transgraph_v3_contract.json"
    attr_name = "DEFAULT_V4_CONTRACT_PATH" if is_v4_default else "DEFAULT_V3_CONTRACT_PATH"
    err_match = "transgraph_v4_contract_sha256_mismatch" if is_v4_default else "transgraph_v3_contract_sha256_mismatch"

    contract_path = PROD_DIR / "configs" / contract_name
    lf_bytes = contract_path.read_bytes().replace(b"\r\n", b"\n")
    crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")

    tmp_contract = tmp_path / contract_name
    monkeypatch.setattr(oe, attr_name, tmp_contract)

    for raw_variant in (lf_bytes, crlf_bytes):
        tmp_contract.write_bytes(raw_variant)
        scanner = ONNXMalPDFScannerEngine()
        assert (scanner.is_v4 if is_v4_default else scanner.is_v3) is True
        assert scanner.tabular_in_features == 29

    tmp_contract.write_bytes(lf_bytes + b"\n ")
    with pytest.raises(ValueError, match=err_match):
        ONNXMalPDFScannerEngine()


def test_pytorch_and_onnx_conformal_analysis_and_prod_disarm_mode_parity() -> None:
    pytorch = MalPDFScannerEngine(device="cpu")
    onnx = ONNXMalPDFScannerEngine()
    threat = load_real_threat_bytes()
    for name, data in (
        ("real_threat_document.pdf", threat),
        ("real_benign_document.pdf", load_real_benign_bytes()),
    ):
        for explain in (False, True):
            pt_result = pytorch.scan_bytes(data, file_name=name, explain=explain)
            onnx_result = onnx.scan_bytes(data, file_name=name, explain=explain)
            pt_conformal = pt_result.forensic_dossier["conformal_analysis"]
            onnx_conformal = onnx_result.forensic_dossier["conformal_analysis"]
            case = f"{name}, explain={explain}"
            assert onnx_conformal["conformal_state"] == pt_conformal["conformal_state"], case
            assert isinstance(pt_conformal["reject_for_cdr"], bool), case
            assert onnx_conformal["reject_for_cdr"] is pt_conformal["reject_for_cdr"], case
            for metric in ("p_benign", "p_malicious"):
                assert 0.0 <= pt_conformal[metric] <= 1.0, case
                assert 0.0 <= onnx_conformal[metric] <= 1.0, case
                assert onnx_conformal[metric] == pytest.approx(pt_conformal[metric], abs=1e-3), (case, metric)

    client = TestClient(prod_web_app)
    scan = client.post("/api/scan", files={"file": ("real_threat_document.pdf", threat, "application/pdf")})
    assert scan.status_code == 200, scan.text
    scan_id = scan.json()["scan_id"]

    invalid = client.post(f"/api/disarm/{scan_id}?mode=invalid")
    assert invalid.status_code == 400, invalid.text
    assert invalid.json()["detail"] == "invalid_disarm_mode"

    disarm = client.post(f"/api/disarm/{scan_id}?mode=minimal_cut&include_preview_images=false")
    assert disarm.status_code == 200, disarm.text
    audit = disarm.json()
    assert audit["is_sanitized"] is True
    assert audit["visual_similarity"]["mean_ssim"] >= 0.95

    download = client.get(f"/api/download/sanitized/{scan_id}")
    assert download.status_code == 200
    assert len(download.content) > 0.8 * len(threat)
    pages, content = _extract_pdf_text_and_pages(download.content)
    assert content and (pages, content) == _extract_pdf_text_and_pages(threat)
