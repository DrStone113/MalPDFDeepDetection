from __future__ import annotations

import io
from pathlib import Path

import pymupdf as fitz
import pikepdf

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import ensure_real_fixtures, load_real_benign_bytes, load_real_threat_bytes
from malpdf.scanner.engine import MalPDFScannerEngine


def _extract_all_text(pdf_bytes: bytes) -> str:
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        return "\n".join(page.get_text() for page in doc).strip()


def test_cdr_removes_direct_nested_action_without_changing_page_content() -> None:
    original = load_real_benign_bytes()
    with pikepdf.open(io.BytesIO(original)) as pdf:
        nested_action = pikepdf.Dictionary(
            S=pikepdf.Name("/URI"), URI=pikepdf.String("https://example.invalid"),
            Next=pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS=pikepdf.String("app.alert('controlled-test');")),
        )
        annotation = pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"), Subtype=pikepdf.Name("/Link"),
            Rect=pikepdf.Array([0, 0, 10, 10]), A=nested_action,
        )
        pdf.pages[0].obj.Annots = pikepdf.Array([annotation])
        buffer = io.BytesIO()
        pdf.save(buffer)
        raw = buffer.getvalue()
    cleaned, audit = PDFDisarmer().sanitize_bytes(raw)
    assert len(cleaned) > 0.8 * len(raw)
    assert audit.sanitized_pages == audit.original_pages
    assert len(_extract_all_text(cleaned)) > 0
    assert _extract_all_text(cleaned) == _extract_all_text(raw)
    with pikepdf.open(io.BytesIO(cleaned)) as pdf:
        action = pdf.pages[0].obj.Annots[0].A.Next
        assert "/JS" not in action
        assert action.get("/S") != pikepdf.Name("/JavaScript")


def test_cdr_disarmer_in_place_mutation_and_integrity() -> None:
    raw_bytes = load_real_threat_bytes()
    orig_text = _extract_all_text(raw_bytes)
    assert len(orig_text) > 100

    disarmer = PDFDisarmer()
    cleaned_bytes, audit = disarmer.sanitize_bytes(raw_bytes, file_name="real_threat_document.pdf")

    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)
    assert audit.sanitized_pages == audit.original_pages
    assert audit.original_pages >= 2
    assert len(audit.removed_triggers) >= 1

    cleaned_text = _extract_all_text(cleaned_bytes)
    assert len(cleaned_text) > 100
    assert cleaned_text == orig_text

    with pikepdf.open(io.BytesIO(cleaned_bytes)) as pdf:
        assert len(pdf.pages) == audit.original_pages
        assert "/OpenAction" not in pdf.Root
        assert "/AA" not in pdf.Root
        if "/Names" in pdf.Root:
            assert "/JavaScript" not in pdf.Root["/Names"]


def test_cdr_disarm_benign_file_preserves_100_percent_content() -> None:
    raw_bytes = load_real_benign_bytes()
    orig_text = _extract_all_text(raw_bytes)
    assert len(orig_text) > 100

    disarmer = PDFDisarmer()
    cleaned_bytes, audit = disarmer.sanitize_bytes(raw_bytes, file_name="real_benign_document.pdf")

    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)
    assert audit.sanitized_pages == audit.original_pages
    cleaned_text = _extract_all_text(cleaned_bytes)
    assert cleaned_text == orig_text


def test_cdr_disarm_file_workflow(tmp_path: Path) -> None:
    _, threat_fixture_path = ensure_real_fixtures()
    raw_bytes = threat_fixture_path.read_bytes()
    orig_text = _extract_all_text(raw_bytes)

    input_file = tmp_path / "threat_sample.pdf"
    input_file.write_bytes(raw_bytes)
    output_file = tmp_path / "threat_sample_sanitized.pdf"

    disarmer = PDFDisarmer()
    out_path, audit = disarmer.sanitize_file(input_file, output_path=output_file)

    assert out_path.exists()
    cleaned_bytes = out_path.read_bytes()
    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)
    assert audit.file_name == "threat_sample.pdf"
    assert audit.sanitized_pages == audit.original_pages
    assert audit.disarm_latency_ms > 0.0
    assert _extract_all_text(cleaned_bytes) == orig_text


def test_cdr_disarmed_pdf_removes_scripts_without_inventing_a_verdict(tmp_path: Path) -> None:
    raw_pdf = load_real_threat_bytes()
    input_file = tmp_path / "raw_active.pdf"
    input_file.write_bytes(raw_pdf)

    disarmer = PDFDisarmer()
    sanitized_file = tmp_path / "disarmed.pdf"
    _, audit = disarmer.sanitize_file(input_file, output_path=sanitized_file)
    cleaned_bytes = sanitized_file.read_bytes()
    assert len(cleaned_bytes) > 0.8 * len(raw_pdf)
    assert audit.sanitized_pages == audit.original_pages
    assert len(_extract_all_text(cleaned_bytes)) > 0
    assert _extract_all_text(cleaned_bytes) == _extract_all_text(raw_pdf)

    scanner = MalPDFScannerEngine(device="cpu")
    raw_result = scanner.scan_file(input_file, explain=True)
    disarmed_result = scanner.scan_file(sanitized_file, explain=True)

    assert raw_result.verdict == "MALICIOUS"
    assert disarmed_result.verdict == "BENIGN"
    assert raw_result.malware_probability is not None
    assert disarmed_result.malware_probability is not None
    assert raw_result.malware_probability > disarmed_result.malware_probability
    assert len(raw_result.forensic_dossier["threat_scripts"]) > 0
    assert len(disarmed_result.forensic_dossier.get("threat_scripts", [])) == 0


def test_cdr_handles_unfilterable_dctdecode_image_streams_in_resources() -> None:
    raw_pdf = load_real_benign_bytes()
    orig_text = _extract_all_text(raw_pdf)
    with pikepdf.open(io.BytesIO(raw_pdf)) as pdf:
        jpeg_stream = pdf.make_stream(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9")
        jpeg_stream["/Type"] = pikepdf.Name("/XObject")
        jpeg_stream["/Subtype"] = pikepdf.Name("/Image")
        jpeg_stream["/Width"] = 1
        jpeg_stream["/Height"] = 1
        jpeg_stream["/ColorSpace"] = pikepdf.Name("/DeviceRGB")
        jpeg_stream["/BitsPerComponent"] = 8
        jpeg_stream["/Filter"] = pikepdf.Name("/DCTDecode")
        for page in pdf.pages:
            if "/Resources" not in page.obj:
                page.obj["/Resources"] = pikepdf.Dictionary()
            if "/XObject" not in page.obj["/Resources"]:
                page.obj["/Resources"]["/XObject"] = pikepdf.Dictionary()
            page.obj["/Resources"]["/XObject"]["/ImLogo"] = jpeg_stream
        out = io.BytesIO()
        pdf.save(out)
        pdf_with_dct = out.getvalue()

    cleaned_bytes, audit = PDFDisarmer().sanitize_bytes(pdf_with_dct, file_name="report_with_logo.pdf")
    assert len(cleaned_bytes) > 0.8 * len(pdf_with_dct)
    assert audit.sanitized_pages == audit.original_pages
    cleaned_text = _extract_all_text(cleaned_bytes)
    assert len(cleaned_text) > 0
    assert cleaned_text == orig_text
    assert audit.content_streams_preserved is True
    assert audit.resources_preserved is True

