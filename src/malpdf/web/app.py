from __future__ import annotations

import base64
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import time
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
import pymupdf as fitz
import torch

from malpdf.cdr.engine import PDFDisarmer
from malpdf.gateway.mail_filter import EmailInspectionReport, MailGatewayFilter
from malpdf.scanner.ai_explainer import (
    AIThreatExplainer,
    CLIENT_LLM_SYSTEM_PROMPT,
    DEFAULT_WEBLLM_MODEL,
    FALLBACK_WEBLLM_MODEL,
)
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.web.store import ScanJob, ScanJobStore

MAX_UPLOAD_BYTES = 32 * 1024 * 1024
PDF_MAGIC = b"%PDF-"
PDF_MAGIC_SEARCH_WINDOW = 1024

app = FastAPI(title="MalPDF DeepDetection Web Service")

scanner = MalPDFScannerEngine(device="cpu")
disarmer = PDFDisarmer()
ai_explainer = AIThreatExplainer()
QUARANTINE_DIR = os.environ.get("MALPDF_QUARANTINE_DIR", "data/quarantine")
store = ScanJobStore(max_jobs=200, quarantine_dir=QUARANTINE_DIR)
gateway = MailGatewayFilter(scanner_engine=scanner, disarmer=disarmer, quarantine_dir=QUARANTINE_DIR, device="cpu")


SERVICE_STARTED_AT = time.time()
ACTIVE_JOB_ID: str | None = None
EML_STORE: dict[str, tuple[bytes, EmailInspectionReport]] = {}
_RENDER_CACHE: dict[tuple[str, int], tuple[str, int]] = {}


def _validate_pdf_bytes(content: bytes) -> None:
    if not content:
        raise HTTPException(status_code=400, detail="empty_upload")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="size_limit_exceeded")
    if PDF_MAGIC not in content[:PDF_MAGIC_SEARCH_WINDOW]:
        raise HTTPException(status_code=415, detail="not_a_pdf_missing_header")


def _get_active_or_latest_job(scan_id: str | None = None) -> ScanJob:
    global ACTIVE_JOB_ID
    target_id = scan_id or ACTIVE_JOB_ID
    if target_id:
        job = store.get_job(target_id)
        if job:
            return job
        if scan_id is not None:
            raise HTTPException(status_code=404, detail="scan_job_not_found")
    jobs = store.list_jobs(limit=1)
    if jobs:
        ACTIVE_JOB_ID = jobs[0].scan_id
        return jobs[0]
    raise HTTPException(status_code=409, detail="no_document_staged_upload_first")


def _render_page_png_base64(pdf_bytes: bytes, page_idx: int = 0, cache_key: str = "") -> tuple[str, int]:
    if not pdf_bytes:
        return "", 0
    key = cache_key or hashlib.sha256(pdf_bytes).hexdigest()
    cached = _RENDER_CACHE.get((key, page_idx))
    if cached is not None:
        return cached
    try:
        with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
            total_pages = len(doc)
            if page_idx < 0 or page_idx >= total_pages:
                page_idx = 0
            if total_pages == 0:
                return "", 0
            pix = doc[page_idx].get_pixmap(dpi=108)
            png_bytes = pix.tobytes("png")
            b64_str = base64.b64encode(png_bytes).decode("ascii")
            result = (f"data:image/png;base64,{b64_str}", total_pages)
            if len(_RENDER_CACHE) >= 128:
                _RENDER_CACHE.pop(next(iter(_RENDER_CACHE)), None)
            _RENDER_CACHE[(key, page_idx)] = result
            return result
    except Exception:
        return "", 0


def _gateway_record(rep: EmailInspectionReport, msg_id: str, subject: str, fallback_size: int) -> dict[str, Any]:
    att = rep.attachments[0] if rep.attachments else None
    cdr_audit = att.cdr_audit if att and att.cdr_audit else {}
    return {
        "msg_id": msg_id,
        "eml_job_id": msg_id,
        "message_id_header": rep.message_id,
        "subject": subject,
        "sender": rep.sender.split("@")[0],
        "sender_full": rep.sender,
        "recipient": rep.recipient,
        "attachment": att.filename if att else "None",
        "sha256": att.sha256 if att else "",
        "size_bytes": att.size_bytes if att else fallback_size,
        "verdict": att.verdict if att else "NOT_SCANNED",
        "malware_probability": att.malware_probability if att else None,
        "is_ood": att.is_ood if att else None,
        "disarmed": att.disarmed if att else False,
        "action": rep.action_taken,
        "latency_ms": rep.processing_latency_ms,
        "removed_triggers": cdr_audit.get("removed_triggers", []),
        "sha256_after": cdr_audit.get("sha256_after", att.sha256 if att else ""),
        "size_retention_pct": cdr_audit.get("size_retention_pct"),
        "preserved_pages": cdr_audit.get("sanitized_pages", 0),
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    template_path = Path(os.environ.get("MALPDF_TEMPLATE_PATH", Path(__file__).parent / "templates" / "index.html"))
    return template_path.read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, Any]:
    model = scanner.model
    hgt_layers = sum(1 for name in ("layer1", "layer2", "layer3") if hasattr(model.graph_encoder, name))
    ast_layers = len(getattr(getattr(model.ast_encoder, "encoder", None), "layers", []) or [])
    recent_jobs = store.list_jobs(limit=10)
    node_dim = getattr(scanner, "node_in_dim", 19)
    model_name = f"PDF-TransGraph v2 ({node_dim}D)" if node_dim == 23 else "PDF-TransGraph"
    return {
        "status": "healthy" if scanner.weights_loaded else "unavailable",
        "prediction_available": bool(scanner.weights_loaded),
        "prediction_blockers": [],
        "model": model_name,
        "node_in_dim": node_dim,
        "ood_threshold": scanner.ood_threshold,
        "cdr_engine": "pikepdf-inplace",
        "device": str(scanner.device),
        "cuda_available": bool(torch.cuda.is_available()),
        "weights_loaded": scanner.weights_loaded,
        "checkpoint": scanner.model_path.name if scanner.model_path else None,
        "parameter_count": scanner.parameter_count,
        "hgt_layers": hgt_layers,
        "ast_encoder_layers": ast_layers,
        "tabular_features": int(model.tabular_encoder.input_layer.in_features),
        "torch_version": torch.__version__,
        "python_version": platform.python_version(),
        "uptime_s": round(time.time() - SERVICE_STARTED_AT, 1),
        "total_jobs": len(recent_jobs),
        "quarantined_files": len(store.list_quarantine()),
        "events_logged": len(store.get_audit_logs()),
    }


@app.get("/api/session")
def get_session_state() -> dict[str, Any]:
    global ACTIVE_JOB_ID
    if not ACTIVE_JOB_ID:
        jobs = store.list_jobs(limit=1)
        if jobs:
            ACTIVE_JOB_ID = jobs[0].scan_id
    if ACTIVE_JOB_ID:
        job = store.get_job(ACTIVE_JOB_ID)
        if job:
            return {
                "scan_id": job.scan_id,
                "staged": True,
                "file_name": job.file_name,
                "size_bytes": job.file_size_bytes,
                "sha256": job.sha256,
                "has_scan": job.scan_result is not None,
                "has_cdr": job.cdr_audit is not None,
                "has_sanitized": job.sanitized_bytes is not None,
            }
    return {
        "scan_id": None,
        "staged": False,
        "file_name": "",
        "size_bytes": 0,
        "sha256": "",
        "has_scan": False,
        "has_cdr": False,
        "has_sanitized": False,
    }


@app.get("/api/scans")
def list_scans(batch_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    jobs = store.list_jobs(batch_id=batch_id, limit=limit)
    return [j.to_summary() for j in jobs]


@app.get("/api/scans/{scan_id}")
def get_scan_detail(scan_id: str) -> dict[str, Any]:
    job = store.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan_job_not_found")
    detail = job.to_detail()
    scan_res = detail.get("scan_result")
    cdr_dict = detail.get("cdr_audit") if isinstance(detail.get("cdr_audit"), dict) else None
    if scan_res and isinstance(scan_res, dict):
        scan_res["ai_threat_explanation"] = ai_explainer.explain_threat(scan_res, cdr_audit=cdr_dict)
    return detail


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict[str, bool]:
    deleted = store.delete_job(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="scan_job_not_found")
    return {"deleted": True}


@app.post("/api/scan")
async def scan_uploaded_file(file: UploadFile = File(...)) -> dict[str, Any]:
    global ACTIVE_JOB_ID
    content = await file.read()
    _validate_pdf_bytes(content)
    filename = Path(file.filename or "uploaded_document.pdf").name
    job = store.create_job(raw_bytes=content, file_name=filename)
    ACTIVE_JOB_ID = job.scan_id
    store.set_status(job.scan_id, "SCANNING")
    try:
        scan_res = await run_in_threadpool(scanner.scan_bytes, content, filename, True)
    except (ValueError, RuntimeError) as exc:
        store.set_status(job.scan_id, "FAILED", error=str(exc))
        raise HTTPException(status_code=422 if isinstance(exc, ValueError) else 503, detail=str(exc)) from exc
    store.attach_scan_result(job.scan_id, scan_res)
    res_dict = scan_res.to_dict()
    res_dict["scan_id"] = job.scan_id
    res_dict["ai_threat_explanation"] = ai_explainer.explain_threat(res_dict)
    return res_dict


@app.post("/api/scan/batch")
async def scan_batch_files(files: list[UploadFile] = File(...)) -> list[dict[str, Any]]:
    global ACTIVE_JOB_ID
    results: list[dict[str, Any]] = []
    batch_token = f"batch-{int(time.time())}"
    for f in files:
        job = None
        content = await f.read()
        try:
            _validate_pdf_bytes(content)
            filename = Path(f.filename or "uploaded_document.pdf").name
            job = store.create_job(raw_bytes=content, file_name=filename, batch_id=batch_token)
            ACTIVE_JOB_ID = job.scan_id
            store.set_status(job.scan_id, "SCANNING")
            scan_res = await run_in_threadpool(scanner.scan_bytes, content, filename, True)
            store.attach_scan_result(job.scan_id, scan_res)
            res_dict = scan_res.to_dict()
            res_dict["scan_id"] = job.scan_id
            res_dict["ai_threat_explanation"] = ai_explainer.explain_threat(res_dict)
            results.append(res_dict)
        except Exception as exc:
            if job is not None:
                store.set_status(job.scan_id, "FAILED", error=str(exc))
            results.append({"file_name": f.filename, "error": str(exc), "status": "FAILED"})
    return results


@app.post("/api/ai/chat")
def ai_chat_about_scan(payload: dict[str, Any]) -> dict[str, Any]:
    scan_id = payload.get("scan_id")
    question = str(payload.get("question", "")).strip()
    if not question:
        raise HTTPException(status_code=400, detail="question_empty")
    job = store.get_job(scan_id) if scan_id else _get_active_or_latest_job()
    if not job or not job.scan_result:
        raise HTTPException(status_code=404, detail="no_scan_data_for_ai_analysis")
    scan_dict = job.scan_result.to_dict()
    cdr_dict = job.cdr_audit.to_dict() if job.cdr_audit is not None and hasattr(job.cdr_audit, "to_dict") else (
        job.cdr_audit if isinstance(job.cdr_audit, dict) else None
    )
    answer = ai_explainer.answer_question(scan_dict, question, cdr_audit=cdr_dict)
    compact_ctx = ai_explainer.build_compact_llm_context(scan_dict, cdr_audit=cdr_dict)
    return {
        "scan_id": job.scan_id,
        "file_name": job.file_name,
        "question": question,
        "answer": answer,
        "mode": "deterministic_fallback",
        "llm_compact_context": compact_ctx,
        "llm_system_prompt": CLIENT_LLM_SYSTEM_PROMPT,
        "preferred_webllm_model": DEFAULT_WEBLLM_MODEL,
        "fallback_webllm_model": FALLBACK_WEBLLM_MODEL,
    }


@app.post("/api/xai/ablate")
async def ablate_graph_node(
    node_id: str = Form(...),
    scan_id: str | None = Form(default=None),
    ablate_mode: str = Form(default="auto"),
    exclude_node_ids: str | None = Form(default=None),
) -> dict[str, Any]:
    job = _get_active_or_latest_job(scan_id)
    parsed_excludes = (
        [x.strip() for x in exclude_node_ids.split(",") if x.strip()]
        if exclude_node_ids
        else None
    )
    try:
        res = await run_in_threadpool(
            scanner.ablate_node,
            job.raw_bytes,
            node_id,
            job.file_name,
            ablate_mode,
            parsed_excludes,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.record_audit(
        "XAI_ABLATION",
        {
            "scan_id": job.scan_id,
            "file_name": job.file_name,
            "target_node_id": res["target_node_id"],
            "verdict": res["verdict_after"],
            "prob_before": res["prob_before"],
            "prob_after": res["prob_after"],
            "prob_delta": res["prob_delta"],
            "latency_ms": res["latency_ms"],
            "action": f"Gỡ thử {res['target_node_id']} ({res['prob_delta'] * 100:+.1f}%)",
        },
    )
    return res


@app.post("/api/disarm")
async def disarm_pdf(file: UploadFile | None = File(default=None)) -> dict[str, Any]:
    global ACTIVE_JOB_ID
    if file is not None:
        content = await file.read()
        _validate_pdf_bytes(content)
        filename = Path(file.filename or "uploaded_document.pdf").name
        job = store.create_job(raw_bytes=content, file_name=filename)
        ACTIVE_JOB_ID = job.scan_id
    else:
        job = _get_active_or_latest_job()

    return await run_in_threadpool(_execute_disarm_for_job, job)


@app.post("/api/disarm/{scan_id}")
def disarm_specific_job(scan_id: str) -> dict[str, Any]:
    job = store.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan_job_not_found")
    return _execute_disarm_for_job(job)


def _execute_disarm_for_job(job: ScanJob) -> dict[str, Any]:
    raw_bytes = job.raw_bytes
    filename = job.file_name
    if job.scan_result:
        pre_scan = job.scan_result.to_dict()
    else:
        scan_res = scanner.scan_bytes(raw_bytes, file_name=filename, explain=True)
        store.attach_scan_result(job.scan_id, scan_res)
        pre_scan = scan_res.to_dict()

    store.set_status(job.scan_id, "DISARMING")
    try:
        sanitized_bytes, audit = disarmer.sanitize_bytes(raw_bytes, file_name=filename)
    except Exception as exc:
        store.set_status(job.scan_id, "FAILED", error=str(exc))
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.attach_sanitized(job.scan_id, sanitized_bytes, audit)

    post_scan = scanner.scan_bytes(sanitized_bytes, file_name=f"sanitized_{filename}", explain=True)
    pre_dossier = pre_scan.get("forensic_dossier", {}) or {}
    audit_dict = audit.to_dict()
    audit_dict["scan_id"] = job.scan_id
    audit_dict["post_scan_verification"] = {
        "verdict_before": pre_scan.get("verdict", "UNKNOWN"),
        "verdict_after": post_scan.verdict,
        "prob_before": pre_scan.get("malware_probability", 0.0),
        "prob_after": post_scan.malware_probability,
        "scripts_before": len(pre_dossier.get("threat_scripts", [])),
        "scripts_after": len(post_scan.forensic_dossier.get("threat_scripts", [])),
        "triggers_before": len(pre_dossier.get("trigger_objects", [])),
        "triggers_after": len(post_scan.forensic_dossier.get("trigger_objects", [])),
        "ood_before": pre_scan.get("ood_score", 0.0),
        "ood_after": post_scan.ood_score,
        "rescan_latency_ms": post_scan.latency_ms,
        "integrity_assertions": {
            "size_retained_over_80pct": len(sanitized_bytes) > 0.8 * len(raw_bytes),
            "pages_equal": audit.sanitized_pages == audit.original_pages,
            "text_stream_intact": audit.text_integrity_verified,
            "content_streams_preserved": audit.content_streams_preserved,
            "resources_preserved": audit.resources_preserved,
        },
    }
    audit_dict["ai_threat_explanation"] = ai_explainer.explain_threat(pre_scan, cdr_audit=audit_dict)
    return audit_dict


@app.get("/api/download/sanitized")
def download_sanitized() -> Response:
    job = _get_active_or_latest_job()
    if not job.sanitized_bytes:
        raise HTTPException(status_code=409, detail="no_sanitized_output_run_disarm_first")
    clean_name = f"sanitized_{job.file_name or 'document.pdf'}"
    return Response(
        content=job.sanitized_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{clean_name}"'},
    )


@app.get("/api/download/sanitized/{scan_id}")
@app.get("/api/disarm/download/{scan_id}")
def download_sanitized_by_id(scan_id: str) -> Response:
    job = store.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan_job_not_found")
    if not job.sanitized_bytes:
        raise HTTPException(status_code=409, detail="no_sanitized_output_run_disarm_first")
    clean_name = f"sanitized_{job.file_name or 'document.pdf'}"
    return Response(
        content=job.sanitized_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{clean_name}"'},
    )


@app.get("/api/diff/render")
@app.get("/api/diff/render/{scan_id}")
def render_visual_diff(scan_id: str = "latest", page: int = Query(default=0)) -> dict[str, Any]:
    if scan_id == "latest":
        job = _get_active_or_latest_job()
    else:
        job = store.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan_job_not_found")
    orig_key = f"{job.sha256}:orig"
    clean_sha = job.cdr_audit.sha256_after if job.cdr_audit else "none"
    clean_key = f"{clean_sha}:clean"
    orig_b64, total_orig = _render_page_png_base64(job.raw_bytes, page_idx=page, cache_key=orig_key)
    clean_b64, total_clean = _render_page_png_base64(job.sanitized_bytes or b"", page_idx=page, cache_key=clean_key)
    return {
        "scan_id": job.scan_id,
        "page": page,
        "total_pages": max(total_orig, total_clean),
        "original_render_uri": orig_b64,
        "sanitized_render_uri": clean_b64,
        "is_disarmed": job.sanitized_bytes is not None,
    }


def _wrap_pdf_bytes_as_rfc822_eml(pdf_bytes: bytes, pdf_filename: str) -> bytes:
    msg = MIMEMultipart()
    msg["From"] = "sender.document@mail-gateway.enterprise"
    msg["To"] = "recipient.inbox@mail-gateway.enterprise"
    msg["Subject"] = f"[Kiểm tra đính kèm PDF] {pdf_filename}"
    msg["Message-ID"] = f"<eml-{hashlib.sha256(pdf_bytes).hexdigest()[:12]}@malpdf.gateway>"
    msg.attach(MIMEText(f"Email đính kèm tài liệu PDF: {pdf_filename}", "plain", "utf-8"))
    part = MIMEApplication(pdf_bytes, _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename=pdf_filename)
    msg.attach(part)
    return msg.as_bytes()


def _process_and_store_eml(raw_eml_bytes: bytes, filename: str) -> dict[str, Any]:
    job_id = f"eml-{int(time.time())}-{hashlib.sha256(raw_eml_bytes).hexdigest()[:8]}"
    sanitized_eml_bytes, report = gateway.process_email_bytes(raw_eml_bytes)
    EML_STORE[job_id] = (sanitized_eml_bytes, report)
    store.record_audit(
        "EML_INSPECTION",
        {
            "job_id": job_id,
            "filename": filename,
            "file_name": filename,
            "subject": report.subject,
            "sender": report.sender,
            "verdict": "MALICIOUS" if report.malicious_attachments > 0 else "BENIGN",
            "attachments_count": report.total_attachments,
            "malicious_count": report.malicious_attachments,
            "latency_ms": report.processing_latency_ms,
            "action": report.action_taken,
        },
    )
    rep_dict = report.to_dict()
    rep_dict["eml_job_id"] = job_id
    rep_dict["filename"] = filename
    rep_dict["has_sanitized_eml"] = True
    rep_dict["action"] = "SANITIZED_ATTACHMENT" if report.malicious_attachments > 0 else "DELIVERED_CLEAN"
    return rep_dict


@app.post("/api/gateway/inspect-eml")
async def inspect_eml_file(file: UploadFile = File(...)) -> dict[str, Any]:
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="empty_eml_upload")
    filename = Path(file.filename or "inbound_email.eml").name
    if PDF_MAGIC in raw_bytes[:PDF_MAGIC_SEARCH_WINDOW] and b"Content-Type:" not in raw_bytes[:1024]:
        raw_eml_bytes = _wrap_pdf_bytes_as_rfc822_eml(raw_bytes, filename)
        eml_filename = f"{Path(filename).stem}.eml"
    else:
        raw_eml_bytes = raw_bytes
        eml_filename = filename
    return await run_in_threadpool(_process_and_store_eml, raw_eml_bytes, eml_filename)


@app.post("/api/gateway/inspect-job")
@app.post("/api/gateway/inspect-job/{scan_id}")
async def inspect_staged_job_as_eml(scan_id: str | None = None) -> dict[str, Any]:
    job = _get_active_or_latest_job(scan_id)
    raw_eml_bytes = _wrap_pdf_bytes_as_rfc822_eml(job.raw_bytes, job.file_name)
    eml_filename = f"{Path(job.file_name).stem}.eml"
    return await run_in_threadpool(_process_and_store_eml, raw_eml_bytes, eml_filename)


@app.get("/api/gateway/download/eml/{job_id}")
def download_sanitized_eml(job_id: str) -> Response:
    if job_id not in EML_STORE:
        raise HTTPException(status_code=404, detail="eml_job_not_found")
    eml_bytes, rep = EML_STORE[job_id]
    safe_name = f"sanitized_{rep.subject[:24].replace(' ', '_')}.eml"
    return Response(
        content=eml_bytes,
        media_type="message/rfc822",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@app.get("/api/gateway/history")
def gateway_history() -> dict[str, Any]:
    records = [
        _gateway_record(report, job_id, report.subject, 0)
        for job_id, (_, report) in EML_STORE.items()
    ]
    reports = [report for _, report in EML_STORE.values()]
    intercepted = sum(report.malicious_attachments > 0 for report in reports)
    held = sum(report.action_taken == "HELD_FOR_REVIEW" for report in reports)
    return {
        "results": records,
        "summary": {
            "total_emails": len(reports),
            "intercepted_threats": intercepted,
            "passed_clean": sum(report.action_taken == "PASSED" for report in reports),
            "held_for_review": held,
            "avg_latency_ms": round(sum(report.processing_latency_ms for report in reports) / len(reports), 2) if reports else None,
        },
    }


@app.get("/api/quarantine/list")
def list_quarantine() -> list[dict[str, Any]]:
    return store.list_quarantine()


@app.get("/api/quarantine/download/{stored_name}")
def download_quarantined_file(stored_name: str) -> Response:
    content = store.get_quarantine_bytes(stored_name)
    if not content:
        raise HTTPException(status_code=404, detail="quarantine_item_not_found")
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{stored_name}"'},
    )


@app.get("/api/audit/logs")
def get_siem_audit_logs() -> dict[str, Any]:
    logs = store.get_audit_logs(limit=200)
    threats = sum(1 for e in logs if e.get("details", {}).get("verdict") == "MALICIOUS" or e.get("event") == "QUARANTINE_ISOLATED")
    disarmed = sum(1 for e in logs if e.get("event") == "DISARM_COMPLETED")
    avg_lat = None
    latencies = [e.get("details", {}).get("latency_ms") for e in logs if isinstance(e.get("details", {}).get("latency_ms"), (int, float))]
    if latencies:
        avg_lat = round(sum(latencies) / len(latencies), 2)
    return {
        "logs": logs,
        "stats": {
            "total_events": len(logs),
            "threats_flagged": threats,
            "files_disarmed": disarmed,
            "avg_latency_ms": avg_lat,
        },
    }


@app.get("/api/report/export")
def export_forensic_report(scan_id: str | None = None) -> Response:
    job = _get_active_or_latest_job(scan_id)
    if not job.scan_result:
        raise HTTPException(status_code=409, detail="no_scan_result_available")
    sha_short = (job.sha256 or "report")[:10]
    cdr_export = job.cdr_audit.to_dict() if job.cdr_audit else None
    if cdr_export:
        cdr_export["page_previews"] = [
            {k: v for k, v in p.items() if k != "image_data_uri"} for p in cdr_export.get("page_previews", [])
        ]
    report_payload = {
        "platform": "MalPDF DeepDetection - XAI & Active CDR Dossier",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": job.scan_id,
        "file_name": job.file_name,
        "sha256": job.sha256,
        "model_checkpoint": scanner.model_path.name if scanner.model_path else None,
        "weights_loaded": scanner.weights_loaded,
        "scan_result": job.scan_result.to_dict(),
        "cdr_audit": cdr_export,
        "recent_audit_events": store.get_audit_logs(limit=20),
    }
    json_bytes = json.dumps(report_payload, indent=2, ensure_ascii=False).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="forensic_dossier_{sha_short}.json"'},
    )
