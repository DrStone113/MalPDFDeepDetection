from __future__ import annotations

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pymupdf as fitz
import importlib
import pytest
from fastapi.testclient import TestClient

from malpdf.web.store import ScanJobStore

from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.web.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_scan_session(tmp_path, monkeypatch):
    module = importlib.import_module("malpdf.web.app")
    monkeypatch.setattr(module, "store", ScanJobStore(quarantine_dir=tmp_path / "quarantine"))
    monkeypatch.setattr(module, "ACTIVE_JOB_ID", None)
    monkeypatch.setattr(module, "EML_STORE", {})
    monkeypatch.setattr(module.gateway, "quarantine_dir", tmp_path / "quarantine")


def _scan_fixture(kind: str):
    data = load_real_threat_bytes() if kind == "threat" else load_real_benign_bytes()
    return client.post("/api/scan", files={"file": (f"reviewed_{kind}.pdf", data, "application/pdf")})


def _extract_pdf_text(data: bytes) -> tuple[int, str]:
    with fitz.open(stream=data, filetype="pdf") as doc:
        text = "\n".join(p.get_text() for p in doc).strip()
        return len(doc), text


def test_index_page_returns_html() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "MalPDF DeepDetection" in response.text
    assert "vis-network" in response.text


def test_health_endpoint() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["prediction_available"] is True
    assert "PDF-TransGraph" in data["model"]
    assert data["cdr_engine"] == "pikepdf-inplace"


def test_upload_real_benign_and_disarm_preserves_text() -> None:
    raw_bytes = load_real_benign_bytes()
    orig_pages, orig_text = _extract_pdf_text(raw_bytes)
    assert len(orig_text) > 100

    scan_res = client.post(
        "/api/scan",
        files={"file": ("real_benign_document.pdf", raw_bytes, "application/pdf")},
    )
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["verdict"] == "BENIGN"
    assert scan_data["malware_probability"] is not None
    assert scan_data["malware_probability"] < 0.50
    assert "scan_id" in scan_data

    disarm_res = client.post("/api/disarm")
    assert disarm_res.status_code == 200
    audit = disarm_res.json()
    assert audit["sanitized_pages"] == orig_pages

    dl_res = client.get("/api/download/sanitized")
    assert dl_res.status_code == 200
    cleaned_bytes = dl_res.content
    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)

    clean_pages, clean_text = _extract_pdf_text(cleaned_bytes)
    assert clean_pages == orig_pages
    assert clean_text == orig_text


def test_upload_real_threat_and_disarm_strips_triggers_preserves_text() -> None:
    raw_bytes = load_real_threat_bytes()
    orig_pages, orig_text = _extract_pdf_text(raw_bytes)
    assert len(orig_text) > 100

    scan_res = client.post(
        "/api/scan",
        files={"file": ("real_threat_document.pdf", raw_bytes, "application/pdf")},
    )
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["verdict"] == "MALICIOUS"
    assert scan_data["malware_probability"] is not None
    assert scan_data["malware_probability"] >= 0.50
    scan_id = scan_data["scan_id"]

    disarm_res = client.post(f"/api/disarm/{scan_id}")
    assert disarm_res.status_code == 200
    audit = disarm_res.json()
    assert audit["is_sanitized"] is True
    assert len(audit["removed_triggers"]) > 0
    assert audit["sanitized_pages"] == orig_pages
    assert audit["post_scan_verification"]["verdict_after"] == "BENIGN"
    assert audit["post_scan_verification"]["prob_after"] < scan_data["malware_probability"]

    dl_res = client.get(f"/api/download/sanitized/{scan_id}")
    assert dl_res.status_code == 200
    cleaned_bytes = dl_res.content
    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)

    clean_pages, clean_text = _extract_pdf_text(cleaned_bytes)
    assert clean_pages == orig_pages
    assert clean_text == orig_text


def test_uploaded_reviewed_fixtures_are_scanned() -> None:
    t_res = _scan_fixture("threat")
    assert t_res.status_code == 200
    assert t_res.json()["verdict"] == "MALICIOUS"

    b_res = _scan_fixture("benign")
    assert b_res.status_code == 200
    assert b_res.json()["verdict"] == "BENIGN"


def test_scan_jobs_list_and_detail() -> None:
    _scan_fixture("benign")
    list_res = client.get("/api/scans")
    assert list_res.status_code == 200
    jobs = list_res.json()
    assert isinstance(jobs, list)
    assert len(jobs) > 0
    scan_id = jobs[0]["scan_id"]

    detail_res = client.get(f"/api/scans/{scan_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["scan_id"] == scan_id
    assert "scan_result" in detail


def test_visual_diff_render() -> None:
    b_res = _scan_fixture("threat")
    scan_id = b_res.json()["scan_id"]
    client.post(f"/api/disarm/{scan_id}")

    diff_res = client.get(f"/api/diff/render/{scan_id}?page=0")
    assert diff_res.status_code == 200
    diff_data = diff_res.json()
    assert diff_data["scan_id"] == scan_id
    assert diff_data["is_disarmed"] is True
    assert diff_data["original_render_uri"].startswith("data:image/png;base64,")
    assert diff_data["sanitized_render_uri"].startswith("data:image/png;base64,")


def test_inspect_eml_file_and_download() -> None:
    threat_pdf = load_real_threat_bytes()
    msg = MIMEMultipart()
    msg["From"] = "external.threat@attacker-domain.org"
    msg["To"] = "victim.cfo@enterprise-corp.com"
    msg["Subject"] = "Urgent Wire Transfer Invoice Attachment"
    msg["Message-ID"] = "<mid-test-eml-001@enterprise.gateway>"
    msg.attach(MIMEText("Please process the attached invoice immediately.", "plain"))

    part = MIMEApplication(threat_pdf, _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename="invoice_wire_2026.pdf")
    msg.attach(part)
    eml_bytes = msg.as_bytes()

    res = client.post(
        "/api/gateway/inspect-eml",
        files={"file": ("urgent_invoice.eml", eml_bytes, "message/rfc822")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["malicious_attachments"] == 1
    assert data["unavailable_attachments"] == 0
    assert data["action_taken"] == "DISARMED_AND_QUARANTINED"
    assert data["has_sanitized_eml"] is True
    eml_job_id = data["eml_job_id"]

    dl_res = client.get(f"/api/gateway/download/eml/{eml_job_id}")
    assert dl_res.status_code == 200
    assert len(dl_res.content) > 100
    assert b"X-MalPDF-Inspection: THREATS_DETECTED_AND_DISARMED" in dl_res.content


def test_quarantine_list_and_download() -> None:
    q_res = client.get("/api/quarantine/list")
    assert q_res.status_code == 200
    q_list = q_res.json()
    assert isinstance(q_list, list)
    if q_list:
        stored_name = q_list[0]["stored_name"]
        dl = client.get(f"/api/quarantine/download/{stored_name}")
        assert dl.status_code == 200
        assert len(dl.content) > 0


def test_xai_ablation_endpoint() -> None:
    t_res = _scan_fixture("threat")
    scan_id = t_res.json()["scan_id"]
    ablate_res = client.post("/api/xai/ablate", data={"node_id": "action:open_action", "scan_id": scan_id})
    assert ablate_res.status_code == 200
    abl = ablate_res.json()
    assert abl["verdict_before"] == "MALICIOUS"
    assert abl["verdict_after"] == "BENIGN"
    assert abl["prob_after"] < abl["prob_before"]


def test_ai_threat_explainer_and_chat_endpoint() -> None:
    t_res = _scan_fixture("threat")
    data = t_res.json()
    assert "ai_threat_explanation" in data
    ai_info = data["ai_threat_explanation"]
    assert ai_info["danger_level"] in ("CRITICAL", "HIGH")
    assert ai_info["explanation_method"] == "deterministic_evidence_summary"
    assert ai_info["danger_score"] is not None
    assert ai_info["danger_score"] >= 50.0
    assert len(ai_info["danger_analysis"]) == 3
    assert len(ai_info["technical_breakdown"]) > 0
    assert "remediation" in ai_info
    assert "llm_compact_context" in ai_info
    assert "llm_system_prompt" in ai_info
    assert ai_info["preferred_webllm_model"] == "Qwen2.5-1.5B-Instruct-q4f16_1-MLC"
    assert ai_info["fallback_webllm_model"] == "Llama-3.2-1B-Instruct-q4f16_1-MLC"
    compact_ctx = ai_info["llm_compact_context"]
    assert compact_ctx["status"] == "Malicious"
    assert compact_ctx["verdict"] == "MALICIOUS"
    assert "threat_type" in compact_ctx
    assert "details" in compact_ctx

    scan_id = data["scan_id"]
    chat_res = client.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "Tệp này nguy hiểm thế nào đối với máy tính?"},
    )
    assert chat_res.status_code == 200
    chat_data = chat_res.json()
    assert "answer" in chat_data
    assert len(chat_data["answer"]) > 50
    assert data["verdict"] in chat_data["answer"]
    assert chat_data["mode"] == "deterministic_fallback"
    assert chat_data["llm_compact_context"]["status"] == "Malicious"
    assert "MalPDF DeepDetection" in chat_data["llm_system_prompt"]

    model_q_res = client.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "ban la model gi?"},
    )
    assert model_q_res.status_code == 200
    model_q_ans = model_q_res.json()["answer"]
    assert "Qwen2.5-1.5B-Instruct" in model_q_ans
    assert "MalPDF DeepDetection" in model_q_ans

    hello_res = client.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "hello"},
    )
    assert hello_res.status_code == 200
    assert "Xin chào" in hello_res.json()["answer"]


def test_webllm_client_ai_and_hardware_fallback_markup_present() -> None:
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert "checkSystemRequirements" in html
    assert "navigator.gpu" in html
    assert "navigator.deviceMemory" in html
    assert "Qwen2.5-1.5B-Instruct-q4f16_1-MLC" in html
    assert "Llama-3.2-1B-Instruct-q4f16_1-MLC" in html
    assert "ai-hardware-fallback-banner" in html
    assert "buildCompactScanContextJSON" in html
    assert "initWebLLMEngine" in html
    assert "_isRefusalOrBrokenLLMReply" in html
    assert "_describeGraphNodeVi" in html
    assert "setGraphLayoutMode" in html
    assert "toggleThreatOnlyFilter" in html


def test_demo_routes_are_absent() -> None:
    for endpoint in ("/api/fixture/threat", "/api/fixture/benign", "/api/fixtures/info"):
        assert client.get(endpoint).status_code == 404
    assert client.post("/api/gateway/simulate").status_code == 404
