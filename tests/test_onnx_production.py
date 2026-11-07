from __future__ import annotations

from pathlib import Path
import sys

from fastapi.testclient import TestClient
import pymupdf as fitz

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_DIR = REPO_ROOT / "production"
if str(PROD_DIR) not in sys.path:
    sys.path.insert(0, str(PROD_DIR))

from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.scanner.engine import MalPDFScannerEngine
import app as prod_entrypoint
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

    pt_threat = pt_engine.scan_bytes(threat_bytes, file_name="real_threat_document.pdf", explain=True)
    ox_threat = onnx_engine.scan_bytes(threat_bytes, file_name="real_threat_document.pdf", explain=True)

    assert ox_threat.verdict == pt_threat.verdict == "MALICIOUS"
    assert ox_threat.malware_probability is not None and pt_threat.malware_probability is not None
    assert abs(ox_threat.malware_probability - pt_threat.malware_probability) <= 1e-3
    assert ox_threat.threat_taxonomy["ml_weights_loaded"] is True
    assert ox_threat.threat_taxonomy["threat_label"] == pt_threat.threat_taxonomy["threat_label"]
    assert ox_threat.threat_taxonomy["detected_count"] == pt_threat.threat_taxonomy["detected_count"]
    assert ox_threat.forensic_dossier["cross_attention_matrix_status"] == "measured_gradient_saliency"
    assert len(ox_threat.forensic_dossier["cross_attention_matrix"]) > 0

    pt_benign = pt_engine.scan_bytes(benign_bytes, file_name="real_benign_document.pdf", explain=True)
    ox_benign = onnx_engine.scan_bytes(benign_bytes, file_name="real_benign_document.pdf", explain=True)

    assert ox_benign.verdict == pt_benign.verdict == "BENIGN"
    assert ox_benign.malware_probability is not None and pt_benign.malware_probability is not None
    assert abs(ox_benign.malware_probability - pt_benign.malware_probability) <= 1e-3
    assert ox_benign.threat_taxonomy["detected_count"] == 0
    assert ox_benign.threat_taxonomy["severity"] == "SAFE"
    assert ox_benign.threat_taxonomy["threat_label"] == "Clean.PDF.Verified"
    assert all(not h["detected"] and h["probability_pct"] < 25.0 for h in ox_benign.threat_taxonomy["ml_label_predictions"])
    assert all(not h["detected"] and h["probability_pct"] < 25.0 for h in pt_benign.threat_taxonomy["ml_label_predictions"])


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

    r_head = client.head("/")
    assert r_head.status_code == 200

    r_ui = client.get("/ui")
    assert r_ui.status_code == 200

    r_fav = client.get("/favicon.ico")
    assert r_fav.status_code == 200

    r_env = client.get("/env-config.js")
    assert r_env.status_code == 200

    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    health_json = r_health.json()
    assert health_json["runtime"] == "onnxruntime"
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

