from __future__ import annotations

from html.parser import HTMLParser
import importlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from fastapi.testclient import TestClient
import pikepdf
import pymupdf as fitz
import pytest
import torch

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.forensic import classify_prediction_confidence, is_suspicious_uri
from malpdf.web.store import ScanJobStore

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_DIR = REPO_ROOT / "production"
if str(PROD_DIR) not in sys.path:
    sys.path.insert(0, str(PROD_DIR))

from onnx_engine import ONNXMalPDFScannerEngine  # noqa: E402


@pytest.fixture(scope="module")
def engines() -> tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine]:
    return MalPDFScannerEngine(device="cpu"), ONNXMalPDFScannerEngine()


def _assert_cdr_integrity(raw_bytes: bytes, cleaned_bytes: bytes, audit) -> None:
    is_sanitized = audit["is_sanitized"] if isinstance(audit, dict) else audit.is_sanitized
    quarantine_rec = audit.get("quarantine_recommended") if isinstance(audit, dict) else audit.quarantine_recommended
    orig_pages = audit["original_pages"] if isinstance(audit, dict) else audit.original_pages
    san_pages = audit["sanitized_pages"] if isinstance(audit, dict) else audit.sanitized_pages
    assert is_sanitized is True
    assert not quarantine_rec
    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)
    with (
        fitz.open(stream=raw_bytes, filetype="pdf") as orig_doc,
        fitz.open(stream=cleaned_bytes, filetype="pdf") as clean_doc,
    ):
        assert len(orig_doc) == len(clean_doc) == orig_pages == san_pages
        orig_text = "\n".join(page.get_text("text") for page in orig_doc).strip()
        clean_text = "\n".join(page.get_text("text") for page in clean_doc).strip()
        assert len(orig_text) > 0
        assert clean_text == orig_text


class _AttrParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.root_attrs: dict[str, str | None] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "html" and not self.root_attrs:
            self.root_attrs = dict(attrs)


def _dump_dom_attrs(tmp_path: Path, name: str, html_body: str) -> dict[str, str | None]:
    candidates = [
        os.environ.get("MALPDF_TEST_BROWSER"),
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    browser = next((str(p) for p in candidates if p and Path(p).is_file()), None)
    if not browser:
        pytest.skip("Headless Chromium binary unavailable")
    target = tmp_path / name
    target.write_text(html_body, encoding="utf-8")
    proc = subprocess.run(
        [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            f"--user-data-dir={tmp_path / f'prof_{name}'}",
            "--dump-dom",
            "--timeout=10000",
            target.as_uri(),
        ],
        capture_output=True,
        timeout=30,
        check=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    parser = _AttrParser()
    parser.feed(proc.stdout.decode("utf-8", errors="replace"))
    return parser.root_attrs


def _assert_clean_scan_both(engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine], pdf_bytes: bytes) -> None:
    pt_res, onnx_res = (engine.scan_bytes(pdf_bytes, explain=True) for engine in engines)
    assert pt_res.verdict == onnx_res.verdict == "BENIGN"
    assert pt_res.is_ood is False and onnx_res.is_ood is False
    assert abs(pt_res.malware_probability - onnx_res.malware_probability) <= 1e-5
    for res in (pt_res, onnx_res):
        assert res.threat_taxonomy["detected_count"] == 0
        assert not [
            head["id"]
            for head in res.threat_taxonomy["ml_label_predictions"]
            if head["evidence_status"] != "not_observed"
        ]
        assert res.forensic_dossier["conformal_analysis"]["conformal_state"] == "CERTIFIED_BENIGN"


def test_disarmed_acroform_and_widgets_rescan_clean_without_false_signals(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    base_threat = load_real_threat_bytes()
    base_benign = load_real_benign_bytes()
    disarmer = PDFDisarmer()

    with pikepdf.open(io.BytesIO(base_threat)) as pdf:
        field = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Widget,
                FT=pikepdf.Name.Tx,
                T="applicant",
                V="Nguyen Van A",
                Rect=pikepdf.Array([50, 100, 220, 125]),
                AA=pikepdf.Dictionary(
                    F=pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="AFNumber_Format(2,0,0,0,'',true);")
                ),
            )
        )
        pdf.pages[0].obj.Annots = pikepdf.Array([field])
        pdf.Root.AcroForm = pdf.make_indirect(pikepdf.Dictionary(Fields=pikepdf.Array([field])))
        buf_1 = io.BytesIO()
        pdf.save(buf_1)
    form_threat = buf_1.getvalue()

    with pikepdf.open(io.BytesIO(form_threat)) as pdf, pikepdf.open(io.BytesIO(base_benign)) as donor:
        for _ in range(19):
            pdf.pages.extend(donor.pages)
        buf_40 = io.BytesIO()
        pdf.save(buf_40)
    form_40p = buf_40.getvalue()

    for raw in (form_threat, form_40p):
        cleaned, audit = disarmer.sanitize_bytes(raw)
        _assert_cdr_integrity(raw, cleaned, audit)
        _assert_clean_scan_both(engines, cleaned)


def test_multipage_links_outlines_and_struct_tree_avoid_budget_false_signals(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    base_threat = load_real_threat_bytes()
    base_benign = load_real_benign_bytes()
    disarmer = PDFDisarmer()

    with pikepdf.open(io.BytesIO(base_threat)) as pdf, pikepdf.open(io.BytesIO(base_benign)) as donor:
        for _ in range(30):
            pdf.pages.extend(donor.pages)
        for page_idx, page in enumerate(pdf.pages):
            annots = [
                pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Annot,
                        Subtype=pikepdf.Name.Link,
                        Rect=pikepdf.Array([50, 50 + idx * 20, 200, 65 + idx * 20]),
                        A=pikepdf.Dictionary(
                            S=pikepdf.Name.URI,
                            URI=f"https://doi.org/10.1000/p{page_idx}_{idx}",
                        ),
                    )
                )
                for idx in range(3)
            ]
            page.obj.Annots = pikepdf.Array(annots)

        outlines = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Outlines))
        items = [
            pdf.make_indirect(
                pikepdf.Dictionary(
                    Title=f"Section {idx + 1}",
                    Parent=outlines,
                    Dest=pikepdf.Array([pdf.pages[idx % len(pdf.pages)].obj, pikepdf.Name.Fit]),
                )
            )
            for idx in range(40)
        ]
        for idx in range(len(items) - 1):
            items[idx].Next = items[idx + 1]
            items[idx + 1].Prev = items[idx]
        outlines.First = items[0]
        outlines.Last = items[-1]
        outlines.Count = len(items)
        pdf.Root.Outlines = outlines

        struct_elems = [pikepdf.Dictionary(Type=pikepdf.Name.StructElem, S=pikepdf.Name.P, K=idx) for idx in range(500)]
        pdf.Root.StructTreeRoot = pdf.make_indirect(
            pikepdf.Dictionary(Type=pikepdf.Name.StructTreeRoot, K=pikepdf.Array(struct_elems))
        )
        buf = io.BytesIO()
        pdf.save(buf)

    raw = buf.getvalue()
    cleaned, audit = disarmer.sanitize_bytes(raw)
    _assert_cdr_integrity(raw, cleaned, audit)
    for engine in engines:
        ing = engine.ingestion.ingest(cleaned)
        assert "action_inspection_limit" not in ing["non_js_triggers"]
    _assert_clean_scan_both(engines, cleaned)


def test_stream_interior_tokens_disproven_while_real_syntax_disagreements_fail_closed(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    base_threat = load_real_threat_bytes()
    base_benign = load_real_benign_bytes()
    disarmer = PDFDisarmer()

    with pikepdf.open(io.BytesIO(base_threat)) as pdf:
        xmp = (
            b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
            b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
            b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            b"<dc:format>application/octet-stream objective /URI /JS</dc:format>"
            b"</rdf:Description>"
            b'</rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
        )
        pdf.Root.Metadata = pdf.make_stream(xmp)
        buf = io.BytesIO()
        pdf.save(buf, compress_streams=False)

    raw = buf.getvalue()
    cleaned, audit = disarmer.sanitize_bytes(raw)
    _assert_cdr_integrity(raw, cleaned, audit)
    _assert_clean_scan_both(engines, cleaned)

    # Independent closing-marker guards, excluded-stream control, and xref-valid hex-escaped /#4a#53 fail closed.
    smuggled_xmp = (
        b"<rdf:Description>endstream\n99 0 obj\n<< /S /JavaScript /JS (eval('1')) >>\nendobj</rdf:Description>"
    )
    with pikepdf.open(io.BytesIO(base_benign)) as pdf:
        pdf.Root.Metadata = pdf.make_stream(xmp)
        pdf.Root.PayloadStream = pdf.make_stream(smuggled_xmp)
        buf_smuggle = io.BytesIO()
        pdf.save(buf_smuggle, compress_streams=False)
    smuggled_bytes = buf_smuggle.getvalue()
    assert b"endstream\n99 0 obj" in smuggled_bytes

    with pikepdf.open(io.BytesIO(base_benign)) as pdf:
        pdf.Root.Metadata = pdf.make_stream(xmp)
        pdf.Root.PayloadStream = pdf.make_stream(b"<rdf:Description>endobj</rdf:Description>")
        buf_endobj = io.BytesIO()
        pdf.save(buf_endobj, compress_streams=False)
    endobj_only_bytes = buf_endobj.getvalue()

    with pikepdf.open(io.BytesIO(base_benign)) as pdf:
        pdf.Root.Metadata = pdf.make_stream(xmp)
        js_obj = pdf.make_indirect(
            pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pdf.make_stream(b"var marker = 'endstream';"))
        )
        pdf.Root.Names = pikepdf.Dictionary(JavaScript=pikepdf.Dictionary(Names=pikepdf.Array(["k", js_obj])))
        buf_excl = io.BytesIO()
        pdf.save(buf_excl, compress_streams=False)
    excluded_smuggle_bytes = buf_excl.getvalue()

    with pikepdf.open(io.BytesIO(base_benign)) as pdf:
        pdf.Root.Metadata = pdf.make_stream(xmp)
        js_clean = pdf.make_indirect(
            pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pdf.make_stream(b"var marker = 'clean';"))
        )
        pdf.Root.Names = pikepdf.Dictionary(JavaScript=pikepdf.Dictionary(Names=pikepdf.Array(["k", js_clean])))
        buf_excl_clean = io.BytesIO()
        pdf.save(buf_excl_clean, compress_streams=False)
    excluded_clean_bytes = buf_excl_clean.getvalue()

    with pikepdf.open(io.BytesIO(base_benign)) as pdf:
        pdf.Root.XJSNM2 = pikepdf.String("test")
        buf_hex = io.BytesIO()
        pdf.save(buf_hex, compress_streams=False)
    hex_escaped_bytes = buf_hex.getvalue().replace(b"/XJSNM2", b"/#4a#53")
    assert b"/#4a#53" in hex_escaped_bytes

    for engine in engines:
        assert engine.ingestion.ingest(cleaned)["structural_audit"]["stream_interior_tokens"] == {
            "obj": 1,
            "stream": 1,
            "JS": 1,
            "URI": 1,
        }
        assert engine.ingestion.ingest(smuggled_bytes)["structural_audit"]["stream_interior_tokens"] == {}
        assert engine.ingestion.ingest(endobj_only_bytes)["structural_audit"]["stream_interior_tokens"] == {}
        assert engine.ingestion.ingest(excluded_smuggle_bytes)["structural_audit"]["stream_interior_tokens"] == {}
        excl_clean_audit = engine.ingestion.ingest(excluded_clean_bytes)["structural_audit"]["stream_interior_tokens"]
        assert excl_clean_audit == {"obj": 1, "stream": 1, "JS": 1, "URI": 1}

        smuggle_res = engine.scan_bytes(smuggled_bytes, explain=True)
        assert "javascript_body_unavailable" in smuggle_res.forensic_dossier["js_semantics"]["unverified_reasons"]
        assert any(
            head["evidence_status"] != "not_observed" for head in smuggle_res.threat_taxonomy["ml_label_predictions"]
        )

        hex_res = engine.scan_bytes(hex_escaped_bytes, explain=True)
        assert hex_res.forensic_dossier["evasion_unpack_audit"]["hex_escaped_names_decoded"] == 1
        assert "hex_escaped_pdf_names" in hex_res.forensic_dossier["js_semantics"]["unverified_reasons"]
        assert hex_res.verdict == "MALICIOUS"
        assert hex_res.threat_taxonomy["detected_count"] > 0


@pytest.mark.parametrize("mode", ["full", "minimal_cut"])
def test_sub_threshold_navigation_and_cf_cdr_certify_benign_and_scrub_media(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine], mode: str
) -> None:
    base_benign = load_real_benign_bytes()
    disarmer = PDFDisarmer()

    with pikepdf.open(io.BytesIO(base_benign)) as pdf:
        del pdf.pages[1:]
        pdf.Root.OpenAction = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.XYZ, 0, 792, 0])
        pdf.pages[0].obj.AA = pikepdf.Dictionary(
            O=pikepdf.Dictionary(Type=pikepdf.Name.Action, S=pikepdf.Name.Named, N=pikepdf.Name.FirstPage)
        )
        pdf.Root.Names = pikepdf.Dictionary(
            JavaScript=pikepdf.Dictionary(
                Names=pikepdf.Array(
                    ["k", pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="eval('1');"))]
                )
            )
        )
        buf = io.BytesIO()
        pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    raw = buf.getvalue()

    rescore = (lambda c: engines[1].scan_bytes(c, explain=False).to_dict()) if mode == "minimal_cut" else None
    cleaned, audit = disarmer.sanitize_bytes(raw, mode=mode, rescore_fn=rescore)
    _assert_cdr_integrity(raw, cleaned, audit)
    _assert_clean_scan_both(engines, cleaned)

    # Both full and minimal_cut scrub /AF and /Screen annotations.
    with pikepdf.open(io.BytesIO(base_benign)) as pdf:
        ef_stream = pdf.make_stream(b"payload")
        ef_stream["/Type"] = pikepdf.Name.EmbeddedFile
        fs = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Filespec,
                F="note.txt",
                EF=pikepdf.Dictionary(F=ef_stream),
            )
        )
        pdf.Root.AF = pikepdf.Array([fs])
        screen = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Screen,
                Rect=pikepdf.Array([10, 10, 80, 30]),
            )
        )
        pdf.pages[0].obj.Annots = pikepdf.Array([screen])
        buf_media = io.BytesIO()
        pdf.save(buf_media)

    cleaned_media, media_audit = disarmer.sanitize_bytes(buf_media.getvalue(), mode=mode)
    _assert_cdr_integrity(buf_media.getvalue(), cleaned_media, media_audit)
    with pikepdf.open(io.BytesIO(cleaned_media)) as clean_pdf:
        assert "/AF" not in clean_pdf.Root
        assert not any(str(a.get("/Subtype")) == "/Screen" for a in (clean_pdf.pages[0].obj.get("/Annots") or []))


def test_confidence_conformal_threat_and_official_domains(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    thr = 0.057277346240410046
    assert classify_prediction_confidence(0.060, thr, False) == "LOW"
    assert classify_prediction_confidence(0.60, thr, False) == "MEDIUM"
    assert classify_prediction_confidence(0.95, thr, False) == "HIGH"
    assert classify_prediction_confidence(0.003, thr, False) == "HIGH"
    assert classify_prediction_confidence(0.030, thr, False) == "MEDIUM"
    assert classify_prediction_confidence(0.050, thr, False) == "LOW"
    assert classify_prediction_confidence(0.003, thr, True) == "LOW"

    threat = load_real_threat_bytes()
    for engine in engines:
        res = engine.scan_bytes(threat, explain=True)
        assert res.verdict == "MALICIOUS"
        assert res.confidence == "HIGH"
        assert res.forensic_dossier["conformal_analysis"]["conformal_state"] == "CERTIFIED_MALICIOUS"

    cutoff_logit = -3.455364465713501
    pt_engine, onnx_engine = engines
    orig_pt_fwd = pt_engine._forward
    orig_onnx_run = onnx_engine._run_binary

    try:
        pt_engine._forward = lambda *args: (torch.tensor([[cutoff_logit]], dtype=torch.float32), None)
        onnx_engine._run_binary = lambda *args: (
            torch.tensor([[cutoff_logit]], dtype=torch.float32).numpy(),
            None,
            None,
            None,
        )
        benign = load_real_benign_bytes()
        pt_cutoff = pt_engine.scan_bytes(benign, explain=False)
        onnx_cutoff = onnx_engine.scan_bytes(benign, explain=False)
        assert pt_cutoff.malware_probability == onnx_cutoff.malware_probability
        assert pt_cutoff.confidence == onnx_cutoff.confidence
    finally:
        pt_engine._forward = orig_pt_fwd
        onnx_engine._run_binary = orig_onnx_run

    for benign_url in (
        "https://hcmut.edu.vn/program",
        "https://chinhphu.vn/van-ban",
        "https://www.iso.org/standard/75839.html",
        "https://orcid.org/0000-0002-1825-0097",
    ):
        suspicious, reasons = is_suspicious_uri(benign_url, lure_phrases={"confirm your identity", "review and sign"})
        assert suspicious is False and reasons == []

    phishing, p_reasons = is_suspicious_uri(
        "https://portal-verify.invalid/login", lure_phrases={"confirm your identity", "review and sign"}
    )
    assert phishing is True and "phishing_lure_context" in p_reasons


@pytest.mark.parametrize("app_module", ["malpdf.web.app", "production.web_service"])
def test_web_cdr_rescan_stateless_and_scan_assessment_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, app_module: str
) -> None:
    assert not hasattr(ScanJobStore, "find_sanitized_provenance")
    module = importlib.import_module(app_module)
    monkeypatch.setattr(module.session_registry, "quarantine_root", tmp_path / "quarantine")
    app = module.app if app_module == "malpdf.web.app" else module.production_router
    from fastapi import FastAPI

    host_app = app if isinstance(app, FastAPI) else FastAPI()
    if not isinstance(app, FastAPI):
        host_app.include_router(app)
    client = TestClient(host_app)

    threat = load_real_threat_bytes()
    scan_r = client.post("/api/scan", files={"file": ("real_threat_document.pdf", threat, "application/pdf")})
    assert scan_r.status_code == 200
    scan_id = scan_r.json()["scan_id"]

    disarm_r = client.post(f"/api/disarm/{scan_id}?include_preview_images=false")
    assert disarm_r.status_code == 200
    assert disarm_r.json()["is_sanitized"] is True

    dl_r = client.get(f"/api/download/sanitized/{scan_id}")
    assert dl_r.status_code == 200
    cleaned_bytes = dl_r.content
    _assert_cdr_integrity(threat, cleaned_bytes, disarm_r.json())

    rescan_r = client.post("/api/scan", files={"file": ("sanitized_real_threat.pdf", cleaned_bytes, "application/pdf")})
    assert rescan_r.status_code == 200
    rescan = rescan_r.json()
    assert "cdr_provenance" not in rescan
    assert rescan["verdict"] == "BENIGN"
    assert rescan["is_ood"] is False
    assert rescan["threat_taxonomy"]["detected_count"] == 0
    assert all(h["evidence_status"] == "not_observed" for h in rescan["threat_taxonomy"]["ml_label_predictions"])
    assert rescan["forensic_dossier"]["conformal_analysis"]["conformal_state"] == "CERTIFIED_BENIGN"

    detail_r = client.get(f"/api/scans/{rescan['scan_id']}")
    assert detail_r.status_code == 200
    assert "cdr_provenance" not in detail_r.json()["scan_result"]

    with pikepdf.open(io.BytesIO(cleaned_bytes)) as pdf:
        pdf.Root.InfoMarker = pikepdf.String("modified-bytes")
        buf_mod = io.BytesIO()
        pdf.save(buf_mod)
    modified_bytes = buf_mod.getvalue()
    batch_r = client.post(
        "/api/scan/batch",
        files=[
            ("files", ("sanitized_real_threat.pdf", cleaned_bytes, "application/pdf")),
            ("files", ("sanitized_real_threat.pdf", modified_bytes, "application/pdf")),
        ],
    )
    assert batch_r.status_code == 200
    batch_items = batch_r.json()
    assert all("cdr_provenance" not in item and item["verdict"] == "BENIGN" for item in batch_items)

    core_js = client.get("/assets/dashboard-core.js").text
    app_js = client.get("/assets/dashboard-app.js").text
    assert "cdr_provenance" not in core_js
    inline_core = re.sub(r"^export\s+", "", core_js, flags=re.MULTILINE)
    start_marker = "function formatRatioPercent(value)"
    end_marker = "function applyJsThreatHighlights("
    conformal_js = start_marker + app_js.split(start_marker, 1)[1].split(end_marker, 1)[0]

    assess_cases = [
        rescan,
        {**rescan, "threat_taxonomy": {**rescan["threat_taxonomy"], "detected_count": 1}},
        {
            **rescan,
            "forensic_dossier": {
                **rescan["forensic_dossier"],
                "threat_scripts": [{"script_id": "s1", "code": "app.alert(1);"}],
            },
        },
    ]
    conformal_cases = [
        (
            {"conformal_state": "DRIFT_OOD_EMPTY", "credibility": 0.005, "confidence": 0.99},
            {"verdict": "BENIGN", "is_ood": False},
        ),
        (
            {"conformal_state": "DRIFT_OOD_EMPTY", "credibility": 0.005, "confidence": 0.99},
            {"verdict": "MALICIOUS", "is_ood": False},
        ),
        (
            {"conformal_state": "DRIFT_OOD_EMPTY", "credibility": 0.005, "confidence": 0.99},
            {"verdict": "BENIGN", "is_ood": True},
        ),
        ({"conformal_state": "DRIFT_OOD_EMPTY", "credibility": 0.005, "confidence": 0.99}, {"verdict": "BENIGN"}),
        (
            {"conformal_state": "CERTIFIED_BENIGN", "credibility": 0.88, "confidence": 0.99},
            {"verdict": "BENIGN", "is_ood": False},
        ),
        (
            {"conformal_state": "CERTIFIED_MALICIOUS", "credibility": 0.92, "confidence": 0.99},
            {"verdict": "MALICIOUS", "is_ood": False},
        ),
        (
            {"conformal_state": "AMBIGUOUS_BOTH", "credibility": 0.25, "confidence": 0.99},
            {"verdict": "BENIGN", "is_ood": False},
        ),
        ({}, {"verdict": "BENIGN", "is_ood": False}),
    ]
    page = (
        '<!doctype html><html><head><meta charset="utf-8"></head><body>'
        '<div id="conformal-status"></div><span id="conformal-state-badge"></span>'
        '<span id="conformal-credibility"></span><script>\n'
        + inline_core
        + "\n"
        + conformal_js
        + "\nconst aCases = "
        + json.dumps(assess_cases)
        + ";\nconst cCases = "
        + json.dumps(conformal_cases)
        + ";\n"
        + "document.documentElement.setAttribute('data-assess', JSON.stringify(aCases.map(scanAssessment)));\n"
        + "const cOut = cCases.map(([a, d]) => { renderConformalAnalysis(a, d); const b = document.getElementById('conformal-state-badge'); return { text: b.textContent, state: b.dataset.state, hidden: document.getElementById('conformal-status').hidden }; });\n"
        + "document.documentElement.setAttribute('data-conformal', JSON.stringify(cOut));\n"
        + "</script></body></html>"
    )
    attrs = _dump_dom_attrs(tmp_path, f"stateless_{app_module.replace('.', '_')}.html", page)
    a_out = json.loads(attrs["data-assess"])
    assert a_out[0] == {
        "tone": "clear",
        "title": "Không tìm thấy dấu hiệu nguy hiểm",
        "guidance": "Đã kiểm tra cấu trúc PDF, luồng dữ liệu và 8 nhóm dấu hiệu tĩnh. Bạn có thể mở đọc tài liệu bình thường.",
    }
    assert a_out[1]["tone"] == "caution"
    assert a_out[1]["title"] == "Cần lưu ý trước khi mở tệp"
    assert a_out[2]["tone"] == "caution"
    assert a_out[2]["title"] == "Cần lưu ý trước khi mở tệp"

    c_out = json.loads(attrs["data-conformal"])
    assert c_out == [
        {"text": "Dưới ngưỡng cảnh báo · Ngoài dải chuẩn 99%", "state": "DRIFT_OOD_EMPTY", "hidden": False},
        {"text": "Lệch phân phối (Drift) · Đẩy CDR", "state": "DRIFT_OOD_EMPTY", "hidden": False},
        {"text": "Lệch phân phối (Drift) · Đẩy CDR", "state": "DRIFT_OOD_EMPTY", "hidden": False},
        {"text": "Lệch phân phối (Drift) · Đẩy CDR", "state": "DRIFT_OOD_EMPTY", "hidden": False},
        {"text": "Chứng nhận an toàn (Conformal)", "state": "CERTIFIED_BENIGN", "hidden": False},
        {"text": "Chứng nhận nguy hiểm (Conformal)", "state": "CERTIFIED_MALICIOUS", "hidden": False},
        {"text": "Vùng lưỡng lự · Đẩy CDR", "state": "AMBIGUOUS_BOTH", "hidden": False},
        {"text": "--", "state": "", "hidden": True},
    ]


@pytest.mark.parametrize("app_module", ["malpdf.web.app", "production.web_service"])
def test_disarm_route_and_store_fail_closed_on_residual_threat_and_stale_redisarm(
    monkeypatch: pytest.MonkeyPatch, app_module: str
) -> None:
    mod = importlib.import_module(app_module)
    raw_threat = load_real_threat_bytes()
    client = TestClient(mod.app)

    health_resp = client.get("/api/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    disarm_ok = client.post(
        "/api/disarm?include_preview_images=false",
        files={"file": ("threat.pdf", raw_threat, "application/pdf")},
    )
    assert disarm_ok.status_code == 200
    ok_body = disarm_ok.json()
    scan_id = ok_body["scan_id"]
    assert ok_body["is_sanitized"] is True
    assert ok_body["download_ready"] is True
    assert ok_body["status"] == "DISARMED"
    dl_ok = client.get(f"/api/download/sanitized/{scan_id}")
    assert dl_ok.status_code == 200
    _assert_cdr_integrity(raw_threat, dl_ok.content, ok_body)

    orig_scan = mod.scanner.scan_bytes

    def forced_residual_malicious(data: bytes, file_name: str = "sample.pdf", explain: bool = True, **kw):
        res = orig_scan(data, file_name=file_name, explain=explain, **kw)
        if str(file_name).startswith("sanitized_"):
            res.verdict = "MALICIOUS"
            res.malware_probability = 0.91
        return res

    monkeypatch.setattr(mod.scanner, "scan_bytes", forced_residual_malicious)
    disarm_bad = client.post(f"/api/disarm/{scan_id}?include_preview_images=false")
    assert disarm_bad.status_code == 200
    bad_body = disarm_bad.json()
    assert bad_body["is_sanitized"] is False
    assert bad_body["quarantine_recommended"] is True
    assert bad_body["download_ready"] is False
    assert bad_body["status"] == "FAILED"
    assert client.get(f"/api/download/sanitized/{scan_id}").status_code == 409

    monkeypatch.setattr(mod.scanner, "scan_bytes", orig_scan)
    re_ok = client.post(f"/api/disarm/{scan_id}?include_preview_images=false")
    assert re_ok.status_code == 200
    assert re_ok.json()["download_ready"] is True
    assert client.get(f"/api/download/sanitized/{scan_id}").status_code == 200

    def exploding_rescan(data: bytes, file_name: str = "sample.pdf", explain: bool = True, **kw):
        if str(file_name).startswith("sanitized_"):
            raise RuntimeError("rescan_engine_fault")
        return orig_scan(data, file_name=file_name, explain=explain, **kw)

    monkeypatch.setattr(mod.scanner, "scan_bytes", exploding_rescan)
    err_resp = client.post(f"/api/disarm/{scan_id}?include_preview_images=false")
    assert err_resp.status_code == 422
    assert client.get(f"/api/download/sanitized/{scan_id}").status_code == 409


def test_store_protects_inflight_jobs_and_rejects_deleted_or_unverified_disarm(tmp_path: Path) -> None:
    raw = load_real_benign_bytes()
    cleaned, audit = PDFDisarmer().sanitize_bytes(load_real_threat_bytes())
    store = ScanJobStore(max_jobs=2, quarantine_dir=tmp_path / "q", max_total_bytes=len(raw) * 2)

    active = store.create_job(raw, "inflight.pdf")
    store.set_status(active.scan_id, "DISARMING")
    idle = store.create_job(raw, "idle.pdf")
    newest = store.create_job(raw, "newest.pdf")
    assert store.get_job(active.scan_id) is not None
    assert store.get_job(idle.scan_id) is None
    assert store.get_job(newest.scan_id) is not None

    assert (
        store.attach_sanitized("job-deleted", cleaned, audit, {"verdict_after": "BENIGN", "prediction_available": True})
        is False
    )
    assert store.attach_sanitized(newest.scan_id, cleaned, audit, {"verdict_after": "BENIGN"}) is False
    assert store.get_job(newest.scan_id).sanitized_bytes is None
    assert store.get_job(newest.scan_id).status == "FAILED"
