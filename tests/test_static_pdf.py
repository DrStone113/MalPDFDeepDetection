"""Synthetic-only tests for the non-executing static PDF inspector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pymupdf
from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DecodedStreamObject, DictionaryObject, NameObject, NumberObject, TextStringObject

from malpdf.cli import main
from malpdf.static import FeatureStatus, StaticInspectionLimits, StaticPDFAnalyzer
from malpdf.static.compatibility_resolution import build_resolution_rows, render_resolution_markdown
from malpdf.static.coverage import build_feature_compatibility_rows, render_feature_coverage_markdown
from malpdf.static.pdf_parser import parse_pdf_header
from malpdf.static.raw_scan import scan_raw_pdf_tokens
from malpdf.static.rit_reference import TEXT_THRESHOLD_CHARACTERS, inspect_rit_reference_features
from malpdf.static.result import StaticInspectionResult
from malpdf.static.schema import PROTOCOL_G_REQUIRED_FEATURES, RIT_FEATURES


def _name(value: str) -> NameObject:
    return NameObject(value)


def _synthetic_pdf(
    path: Path,
    *,
    pages: int = 1,
    encrypted: bool = False,
    text: str | None = None,
    active_indicators: bool = True,
    include_images: bool = True,
    shared_image: bool = False,
) -> None:
    """Create an inert, local-only PDF fixture; no content is ever executed."""
    writer = PdfWriter()
    shared_image_reference = None
    for _ in range(pages):
        page = writer.add_blank_page(width=200, height=200)
        resources = DictionaryObject()
        font = DictionaryObject({
            _name("/Type"): _name("/Font"), _name("/Subtype"): _name("/Type1"), _name("/BaseFont"): _name("/Helvetica"),
        })
        resources[_name("/Font")] = DictionaryObject({_name("/F1"): writer._add_object(font)})  # noqa: SLF001 - fixture-only pypdf API
        if text is not None:
            content = DecodedStreamObject()
            content.set_data(f"BT /F1 12 Tf ({text}) Tj ET".encode("ascii"))
            page[_name("/Contents")] = writer._add_object(content)  # noqa: SLF001 - fixture-only pypdf API
        if include_images:
            if shared_image_reference is None or not shared_image:
                image = DecodedStreamObject()
                image.set_data(b"\x00\x00\x00")
                image.update({
                    _name("/Type"): _name("/XObject"), _name("/Subtype"): _name("/Image"), _name("/Width"): NumberObject(1),
                    _name("/Height"): NumberObject(1), _name("/ColorSpace"): _name("/DeviceRGB"), _name("/BitsPerComponent"): NumberObject(8),
                })
                shared_image_reference = writer._add_object(image)  # noqa: SLF001 - fixture-only pypdf API
            resources[_name("/XObject")] = DictionaryObject({_name("/Im1"): shared_image_reference})
        page[_name("/Resources")] = resources
    writer.add_metadata({_name("/Title"): "Synthetic benign metadata"})
    root = writer._root_object  # noqa: SLF001 - fixture-only pypdf API
    if active_indicators:
        root[_name("/OpenAction")] = DictionaryObject({_name("/S"): _name("/URI"), _name("/URI"): TextStringObject("https://example.invalid")})
        root[_name("/AA")] = DictionaryObject({_name("/S"): _name("/Launch"), _name("/F"): TextStringObject("not-executed")})
        root[_name("/XFA")] = ArrayObject()
        root[_name("/RichMedia")] = DictionaryObject()
        root[_name("/Names")] = DictionaryObject({
            _name("/JavaScript"): DictionaryObject({_name("/Names"): ArrayObject([
                TextStringObject("noop"), DictionaryObject({_name("/S"): _name("/JavaScript"), _name("/JS"): TextStringObject("")}),
            ])}),
            _name("/EmbeddedFiles"): DictionaryObject({
                _name("/Names"): ArrayObject([
                    TextStringObject("harmless.txt"),
                    DictionaryObject({_name("/Type"): _name("/Filespec"), _name("/EF"): DictionaryObject({_name("/F"): DictionaryObject({_name("/Type"): _name("/EmbeddedFile")})})}),
                ]),
            }),
        })
    if encrypted:
        writer.encrypt("synthetic-password")
    with path.open("wb") as handle:
        writer.write(handle)
    if text is not None and not encrypted:
        # Use the reference parser's own safe document-generation API so the
        # fixture has a genuine extractable text layer for PyMuPDF tests.
        document = pymupdf.open(path)
        for page_index in range(document.page_count):
            document[page_index].insert_text((36, 72), text)
        temporary = path.with_suffix(".rewritten.pdf")
        document.save(temporary)
        document.close()
        temporary.replace(path)


def _reference_fixture(
    path: Path,
    *,
    pages: int = 1,
    title: str | None = None,
    text: str = "",
    attachments: int = 0,
    xmp: bool = False,
) -> None:
    """Generate a deterministic harmless fixture with PyMuPDF only."""
    document = pymupdf.open()
    for _ in range(pages):
        page = document.new_page()
        if text:
            page.insert_text((36, 72), text)
    metadata = {
        "title": "" if title is None else title,
        "author": "", "subject": "", "keywords": "", "creator": "", "producer": "",
        "creationDate": "", "modDate": "", "trapped": "",
    }
    document.set_metadata(metadata)
    for index in range(attachments):
        document.embfile_add(f"harmless-{index}.txt", b"safe synthetic text")
    if xmp:
        document.set_xml_metadata('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF/></x:xmpmeta>')
    document.save(path)
    document.close()


def _reference_values(path: Path) -> dict[str, int | float]:
    """Independent direct expression of the published PDFMalExtract contract."""
    document = pymupdf.open(stream=path.read_bytes(), filetype="pdf")
    metadata = document.metadata
    found = 0
    text = ""
    for page_index in range(len(document)):
        text += document[page_index].get_text()
        if len(text) > TEXT_THRESHOLD_CHARACTERS:
            found = 1
            break
    values = {
        "pdfsize": path.stat().st_size // 1000,
        "metadata size": len(str(metadata).encode("utf-8")),
        "pages": document.page_count,
        "xref length": document.xref_length(),
        "title length": len(metadata["title"]) if metadata["title"] else 0,
        "isEncrypted": int(bool(metadata["encryption"])),
        "embedded files": document.embfile_count(),
        "images": sum(len(document[index].get_images()) for index in range(len(document))),
        "contains_text": found,
        "pdf_ver": float(metadata["format"][4:7]),
    }
    document.close()
    return values


def test_valid_synthetic_pdf_collects_safe_static_values(tmp_path: Path):
    path = tmp_path / "synthetic.pdf"
    _synthetic_pdf(path, pages=2, text="This is a harmless synthetic text fixture with more than fifty characters for a threshold check.")

    result = StaticPDFAnalyzer().inspect(path)

    assert result.input["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result.input["size_bytes"] == path.stat().st_size
    assert result.diagnostics["file_header"]["pdf_header_present"] is True
    assert result.features["pages"] == 2
    assert result.features["title length"] == len("Synthetic benign metadata")
    assert result.features["contains_text"] == 1
    assert result.features["images"] == 2
    assert result.features["JavaScript"] >= 1
    assert result.features["JS"] >= 1
    assert result.features["URI"] >= 1
    assert result.features["OpenAction"] >= 1
    assert result.features["Launch"] >= 1
    assert result.features["EmbeddedFile"] >= 1
    assert result.diagnostics["parsed_structural_indicators"]["JavaScript"] >= 1
    assert result.diagnostics["parsed_structural_indicators"]["JS"] >= 1
    assert result.diagnostics["parsed_structural_indicators"]["URI"] >= 1
    assert result.diagnostics["parsed_structural_indicators"]["OpenAction"] >= 1
    assert result.diagnostics["parsed_structural_indicators"]["Launch"] >= 1
    assert result.diagnostics["parsed_structural_indicators"]["EmbeddedFile"] >= 1
    assert result.features["embedded files"] == 1
    assert result.safety == {
        "active_content_executed": False,
        "embedded_payload_executed": False,
        "external_uri_followed": False,
        "external_application_invoked": False,
    }


def test_non_pdf_and_malformed_files_return_structured_partial_results(tmp_path: Path):
    non_pdf = tmp_path / "not-a-pdf.txt"
    non_pdf.write_bytes(b"plain bytes /URI")
    malformed = tmp_path / "truncated.pdf"
    malformed.write_bytes(b"%PDF-1.7\n1 0 obj << /URI (https://example.invalid) >>")

    non_pdf_result = StaticPDFAnalyzer().inspect(non_pdf)
    malformed_result = StaticPDFAnalyzer().inspect(malformed)

    assert non_pdf_result.errors[0].code == "not_pdf"
    assert non_pdf_result.features["URI"] == 1
    assert malformed_result.diagnostics["file_header"]["pdf_header_present"] is True
    assert malformed_result.features["URI"] == 1
    assert malformed_result.parser["success"] is False
    assert any(issue.code == "parser_failure" for issue in malformed_result.errors)


def test_encrypted_fixture_is_detected_without_decryption(tmp_path: Path):
    path = tmp_path / "encrypted.pdf"
    _synthetic_pdf(path, encrypted=True)

    result = StaticPDFAnalyzer().inspect(path)

    assert result.parser["success"] is True
    assert result.parser["encrypted"] is True
    # PDFMalExtract skips source rows whose PyMuPDF metadata is unavailable;
    # the pypdf safety diagnostic still detects encryption without a password.
    assert result.features["isEncrypted"] is None
    assert result.features["pages"] is None
    assert any(issue.code == "encrypted_pdf_partial_extraction" for issue in result.warnings)


def test_size_and_resource_limits_fail_safely(tmp_path: Path):
    path = tmp_path / "limited.pdf"
    _synthetic_pdf(path, pages=2)

    size_limited = StaticPDFAnalyzer(StaticInspectionLimits(max_file_size_bytes=10)).inspect(path)
    page_limited = StaticPDFAnalyzer(StaticInspectionLimits(max_pages=1)).inspect(path)
    object_limited = StaticPDFAnalyzer(StaticInspectionLimits(max_objects=1)).inspect(path)

    assert any(issue.code == "file_size_limit" for issue in size_limited.errors)
    assert page_limited.features["pages"] is None
    assert any(issue.code == "page_limit" for issue in page_limited.warnings)
    assert object_limited.parser["resource_limit_reached"] is True


def test_raw_text_false_positive_is_not_parser_confirmed_action(tmp_path: Path):
    path = tmp_path / "string-only.pdf"
    _synthetic_pdf(path, text="The inert text literal /JavaScript is not an action dictionary.", active_indicators=False)

    result = StaticPDFAnalyzer().inspect(path)

    assert result.features["JavaScript"] >= 1
    assert result.diagnostics["parsed_structural_indicators"]["JavaScript"] == 0
    assert scan_raw_pdf_tokens(b"(/JavaScript)")["JavaScript"] == 1


def test_output_is_deterministic_and_json_serializable(tmp_path: Path):
    path = tmp_path / "deterministic.pdf"
    _synthetic_pdf(path)
    analyzer = StaticPDFAnalyzer()

    first = analyzer.inspect(path).to_dict()
    second = analyzer.inspect(path).to_dict()

    assert first == second
    assert json.loads(json.dumps(first, allow_nan=False))["input"]["sha256"] == first["input"]["sha256"]


def test_reference_metadata_features_match_published_pymupdf_contract(tmp_path: Path):
    path = tmp_path / "reference.pdf"
    _reference_fixture(path, pages=2, title="Short title", text="x" * 51, attachments=1, xmp=True)

    result = StaticPDFAnalyzer().inspect(path)

    assert {feature: result.features[feature] for feature in (
        "pdfsize", "metadata size", "pages", "xref length", "title length", "isEncrypted",
        "embedded files", "images", "contains_text", "pdf_ver",
    )} == _reference_values(path)
    assert result.diagnostics["pdfsize"]["canonical_conversion"] == "int(size_bytes / 1000)"
    assert result.diagnostics["rit_reference_diagnostics"]["metadata_content_redacted"] is True


def test_pdfsize_is_decimal_and_truncated_not_binary_kibibytes(tmp_path: Path):
    path = tmp_path / "size.pdf"
    _reference_fixture(path, text="x" * 51)
    result = StaticPDFAnalyzer().inspect(path)

    assert result.features["pdfsize"] == path.stat().st_size // 1000
    assert result.features["pdfsize"] != path.stat().st_size / 1024


def test_metadata_and_title_contracts_cover_absent_ascii_unicode_and_xmp(tmp_path: Path):
    absent = tmp_path / "absent-title.pdf"
    ascii_title = tmp_path / "ascii-title.pdf"
    unicode_title = tmp_path / "unicode-title.pdf"
    xmp = tmp_path / "xmp.pdf"
    _reference_fixture(absent)
    _reference_fixture(ascii_title, title="ABCDE")
    _reference_fixture(unicode_title, title="Café Δ")
    _reference_fixture(xmp, title="ABCDE", xmp=True)

    absent_result = StaticPDFAnalyzer().inspect(absent)
    ascii_result = StaticPDFAnalyzer().inspect(ascii_title)
    unicode_result = StaticPDFAnalyzer().inspect(unicode_title)
    xmp_result = StaticPDFAnalyzer().inspect(xmp)

    assert absent_result.features["title length"] == 0
    assert ascii_result.features["title length"] == _reference_values(ascii_title)["title length"] == 5
    assert unicode_result.features["title length"] == _reference_values(unicode_title)["title length"]
    assert xmp_result.features["metadata size"] == _reference_values(xmp)["metadata size"]
    assert absent_result.features["metadata size"] == _reference_values(absent)["metadata size"]
    assert ascii_result.features["metadata size"] == _reference_values(ascii_title)["metadata size"]


def test_pages_xref_images_and_attachments_use_reference_counts(tmp_path: Path):
    no_image_or_attachment = tmp_path / "no-image.pdf"
    one_image = tmp_path / "one-image.pdf"
    repeated_image = tmp_path / "repeated-image.pdf"
    _reference_fixture(no_image_or_attachment, pages=1)
    _synthetic_pdf(one_image, pages=1, active_indicators=False, include_images=True)
    _synthetic_pdf(repeated_image, pages=2, active_indicators=False, include_images=True, shared_image=True)

    no_image_result = StaticPDFAnalyzer().inspect(no_image_or_attachment)
    one_image_result = StaticPDFAnalyzer().inspect(one_image)
    repeated_image_result = StaticPDFAnalyzer().inspect(repeated_image)

    assert no_image_result.features["images"] == 0
    assert no_image_result.features["embedded files"] == 0
    assert one_image_result.features["images"] == _reference_values(one_image)["images"] == 1
    # PDFMalExtract sums page.get_images(): one shared image reference on two
    # pages is counted twice, rather than deduplicated by image object identity.
    assert repeated_image_result.features["images"] == _reference_values(repeated_image)["images"] == 2
    assert repeated_image_result.features["pages"] == 2
    assert repeated_image_result.features["xref length"] == _reference_values(repeated_image)["xref length"]


def test_contains_text_distinguishes_threshold_and_failure_sentinel(tmp_path: Path, monkeypatch):
    exact_threshold = tmp_path / "exact-threshold.pdf"
    above_threshold = tmp_path / "above-threshold.pdf"
    # PyMuPDF appends a line ending for this fixture, so 49/50 source
    # characters exercise extracted lengths of 50/51 respectively.
    _reference_fixture(exact_threshold, text="x" * 49)
    _reference_fixture(above_threshold, text="x" * 50)

    assert StaticPDFAnalyzer().inspect(exact_threshold).features["contains_text"] == 0
    assert StaticPDFAnalyzer().inspect(above_threshold).features["contains_text"] == 1

    class FailingDocument:
        metadata = {
            "format": "PDF 1.7", "title": "", "encryption": None,
        }
        page_count = 1

        def xref_length(self):
            return 1

        def __len__(self):
            raise RuntimeError("synthetic text-loop failure")

        def close(self):
            return None

    monkeypatch.setattr("malpdf.static.rit_reference.pymupdf.open", lambda **_: FailingDocument())
    failed = inspect_rit_reference_features(b"%PDF-1.7", 8, StaticInspectionLimits())
    assert failed.features["contains_text"] == -1
    assert failed.features["embedded files"] == 0
    assert any(issue.code == "reference_text_or_attachment_failure" for issue in failed.warnings)


def test_image_failure_uses_only_the_released_negative_sentinel(monkeypatch):
    class Page:
        def get_text(self):
            return ""

        def get_images(self):
            raise RuntimeError("synthetic image-loop failure")

    class FailingImageDocument:
        metadata = {"format": "PDF 1.7", "title": "", "encryption": None}
        page_count = 1

        def xref_length(self):
            return 1

        def embfile_count(self):
            return 0

        def __len__(self):
            return 1

        def __getitem__(self, index):
            return Page()

        def close(self):
            return None

    monkeypatch.setattr("malpdf.static.rit_reference.pymupdf.open", lambda **_: FailingImageDocument())
    failed = inspect_rit_reference_features(b"%PDF-1.7", 8, StaticInspectionLimits())
    assert failed.features["images"] == -1
    assert any(issue.code == "reference_image_count_failure" for issue in failed.warnings)


def test_missing_feature_never_passes_the_gate_or_receives_zero_imputation(tmp_path: Path):
    path = tmp_path / "gate.pdf"
    _reference_fixture(path, text="x" * 51)
    result = StaticPDFAnalyzer().inspect(path)
    features = dict(result.features)
    features.pop("pdfsize")
    broken = StaticInspectionResult(
        input=result.input,
        parser=result.parser,
        features=features,
        compatibility=result.compatibility,
        diagnostics=result.diagnostics,
    )
    gate = broken.protocol_g_drop3constant_gate()

    assert gate.passed is False
    assert gate.compatible_feature_count == 37
    assert gate.blocking_features == ({"feature": "pdfsize", "reason": "missing feature"},)


def test_pdf_version_preserves_normal_unusual_and_malformed_states(tmp_path: Path):
    normal = tmp_path / "normal.pdf"
    unusual = tmp_path / "unusual.pdf"
    malformed = tmp_path / "malformed-version.pdf"
    _reference_fixture(normal)
    _reference_fixture(unusual)
    unusual.write_bytes(unusual.read_bytes().replace(b"%PDF-1.7", b"%PDF-5.0", 1))
    malformed.write_bytes(normal.read_bytes().replace(b"%PDF-1.7", b"%PDF-X.Y", 1))

    normal_result = StaticPDFAnalyzer().inspect(normal)
    unusual_result = StaticPDFAnalyzer().inspect(unusual)
    malformed_result = StaticPDFAnalyzer().inspect(malformed)

    assert normal_result.features["pdf_ver"] == 1.7
    assert unusual_result.features["pdf_ver"] == 5.0
    assert malformed_result.features["pdf_ver"] is None
    assert any(issue.code == "not_pdf" for issue in malformed_result.errors)


def test_objstm_and_raw_counting_reproduce_pdfmalextract_overlap_rules():
    data = (
        b"obj endobj stream endstream xref startxref /Page /Pages "
        b"/ObjStm /BaseEncoding j/BaseEncoding /JavaScript"
    )
    counts = scan_raw_pdf_tokens(data)

    assert counts["obj"] == 1
    assert counts["endobj"] == 1
    assert counts["stream"] == 1
    assert counts["endstream"] == 1
    assert counts["xref"] == 1
    assert counts["startxref"] == 1
    assert counts["page_command"] == 1
    assert counts["ObjStm"] == 1
    assert counts["BaseEncoding"] == 1


def test_fixed_schema_order_and_gate_accepts_all_verified_reference_values(tmp_path: Path):
    path = tmp_path / "schema.pdf"
    _synthetic_pdf(path)
    result = StaticPDFAnalyzer().inspect(path)
    gate = result.protocol_g_drop3constant_gate()

    assert list(result.features) == list(RIT_FEATURES)
    assert len(result.features) == 41
    assert set(PROTOCOL_G_REQUIRED_FEATURES).isdisjoint({"Acroform", "Colors", "BaseEncoding"})
    assert result.compatibility["JavaScript"] == FeatureStatus.IMPLEMENTED_VERIFIED_SEMANTICS
    assert result.compatibility["pdfsize"] == FeatureStatus.IMPLEMENTED_VERIFIED_SEMANTICS
    assert result.features["pdfsize"] == path.stat().st_size // 1000
    assert result.features["metadata size"] is not None
    assert gate.passed is True
    assert gate.compatible_feature_count == 38
    assert gate.blocking_features == ()


def test_coverage_table_uses_all_rit_features_and_existing_shap_ranks():
    root = Path(__file__).resolve().parents[1]
    rows = build_feature_compatibility_rows(root)
    markdown = render_feature_coverage_markdown(rows)

    assert [row["rit_feature"] for row in rows] == list(RIT_FEATURES)
    assert len(rows) == 41
    assert sum(row["implementation_status"] == "IMPLEMENTED_VERIFIED_SEMANTICS" for row in rows) == 41
    assert sum(row["implementation_status"] == "IMPLEMENTED_PROVISIONAL" for row in rows) == 0
    assert sum(row["implementation_status"] == "AMBIGUOUS" for row in rows) == 0
    assert next(row for row in rows if row["rit_feature"] == "JavaScript")["shap_rank"] == 1
    assert "Gate result: **PASS**" in markdown


def test_resolution_table_closes_exactly_the_original_ten_blockers():
    rows = build_resolution_rows()
    markdown = render_resolution_markdown(rows)

    assert [row["rit_feature"] for row in rows] == [
        "pdfsize", "metadata size", "pages", "xref length", "title length", "embedded files", "images", "contains_text", "pdf_ver", "ObjStm",
    ]
    assert all(row["final_status"] == "IMPLEMENTED_VERIFIED_SEMANTICS" for row in rows)
    assert "v1 baseline | 31 | 7 | 3 | 0 | 28 / 38 FAIL" in markdown
    assert "| v2 implementation | 41 | 0 | 0 | 0 | 38 / 38 PASS |" in markdown


def test_cli_inspection_json_and_human_output(tmp_path: Path, capsys):
    path = tmp_path / "cli.pdf"
    _synthetic_pdf(path)

    assert main(["inspect", str(path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["safety"]["active_content_executed"] is False
    assert main(["inspect", str(path)]) == 0
    assert "No malware probability or verdict is produced." in capsys.readouterr().out


def test_header_parser_preserves_unusual_version_without_rejecting_it():
    header = parse_pdf_header(b"%PDF-5.0\n")
    assert header["pdf_header_present"] is True
    assert header["header_version_string"] == "5.0"
    assert header["header_version_numeric"] == 5.0


def test_static_implementation_does_not_contain_dangerous_execution_operations():
    static_root = Path(__file__).resolve().parents[1] / "src" / "malpdf" / "static"
    source = "\n".join(path.read_text(encoding="utf-8") for path in static_root.glob("*.py"))
    for forbidden in ("os.startfile", "subprocess", "webbrowser.open", "requests.", "eval(", "exec("):
        assert forbidden not in source
