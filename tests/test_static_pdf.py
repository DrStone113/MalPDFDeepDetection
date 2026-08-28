"""Synthetic-only tests for the non-executing static PDF inspector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DecodedStreamObject, DictionaryObject, NameObject, NumberObject, TextStringObject

from malpdf.cli import main
from malpdf.static import FeatureStatus, StaticInspectionLimits, StaticPDFAnalyzer
from malpdf.static.coverage import build_feature_compatibility_rows, render_feature_coverage_markdown
from malpdf.static.pdf_parser import parse_pdf_header
from malpdf.static.raw_scan import scan_raw_pdf_tokens
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
) -> None:
    """Create an inert, local-only PDF fixture; no content is ever executed."""
    writer = PdfWriter()
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
        image = DecodedStreamObject()
        image.set_data(b"\x00\x00\x00")
        image.update({
            _name("/Type"): _name("/XObject"), _name("/Subtype"): _name("/Image"), _name("/Width"): NumberObject(1),
            _name("/Height"): NumberObject(1), _name("/ColorSpace"): _name("/DeviceRGB"), _name("/BitsPerComponent"): NumberObject(8),
        })
        resources[_name("/XObject")] = DictionaryObject({_name("/Im1"): writer._add_object(image)})  # noqa: SLF001
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
    assert result.features["isEncrypted"] == 1
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


def test_fixed_schema_order_and_gate_refuses_provisional_or_missing_values(tmp_path: Path):
    path = tmp_path / "schema.pdf"
    _synthetic_pdf(path)
    result = StaticPDFAnalyzer().inspect(path)
    gate = result.protocol_g_drop3constant_gate()

    assert list(result.features) == list(RIT_FEATURES)
    assert len(result.features) == 41
    assert set(PROTOCOL_G_REQUIRED_FEATURES).isdisjoint({"Acroform", "Colors", "BaseEncoding"})
    assert result.compatibility["JavaScript"] == FeatureStatus.IMPLEMENTED_VERIFIED_SEMANTICS
    assert result.compatibility["pdfsize"] == FeatureStatus.AMBIGUOUS
    assert gate.passed is False
    assert gate.compatible_feature_count == 28
    assert {item["feature"] for item in gate.blocking_features} == {
        "pdfsize", "metadata size", "pages", "xref length", "title length", "embedded files", "images", "contains_text", "pdf_ver", "ObjStm",
    }
    assert result.features["pdfsize"] is None
    assert result.features["metadata size"] is None


def test_coverage_table_uses_all_rit_features_and_existing_shap_ranks():
    root = Path(__file__).resolve().parents[1]
    rows = build_feature_compatibility_rows(root)
    markdown = render_feature_coverage_markdown(rows)

    assert [row["rit_feature"] for row in rows] == list(RIT_FEATURES)
    assert len(rows) == 41
    assert sum(row["implementation_status"] == "IMPLEMENTED_VERIFIED_SEMANTICS" for row in rows) == 31
    assert sum(row["implementation_status"] == "IMPLEMENTED_PROVISIONAL" for row in rows) == 7
    assert sum(row["implementation_status"] == "AMBIGUOUS" for row in rows) == 3
    assert next(row for row in rows if row["rit_feature"] == "JavaScript")["shap_rank"] == 1
    assert "Gate result: **FAIL**" in markdown


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
