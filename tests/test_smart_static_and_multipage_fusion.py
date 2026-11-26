from __future__ import annotations

import io
import math
import struct
import zlib

import numpy as np
import pikepdf
from production.onnx_engine import ONNXMalPDFScannerEngine
import pymupdf
from pypdf import PdfReader
import pytest

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.extraction.media import inspect_font
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.static_evidence import (
    calibrated_probability,
    compute_benign_structural_consistency,
    fuse_neural_and_static_evidence,
)


@pytest.fixture(scope="module")
def engines():
    return MalPDFScannerEngine(device="cpu"), ONNXMalPDFScannerEngine()


def _build_valid_large_sfnt_bytes(target_size: int = 1_600_000, *, place_head_at_tail: bool = False) -> bytes:
    """Build a structurally valid SFNT TrueType font whose decoded size exceeds legacy 1–4 MiB shared caps."""
    head_body = bytearray(54)
    struct.pack_into(">I", head_body, 0, 0x00010000)
    struct.pack_into(">I", head_body, 12, 0x5F0F3CF5)
    struct.pack_into(">H", head_body, 18, 2048)
    struct.pack_into(">hhhh", head_body, 36, -200, -300, 1800, 1900)
    head_padded = bytes(head_body) + b"\x00\x00"

    maxp_body = struct.pack(">IH", 0x00010000, 1250) + b"\x00\x00"
    glyf_len = max(4096, ((target_size - 256) // 4) * 4)
    # Deterministic pseudo-glyph contours mixed with compressible runs (realistic ~8-15x Flate ratio)
    rng = np.random.default_rng(20261126)
    glyf_header = rng.integers(0, 256, size=8192, dtype=np.uint8).tobytes()
    glyf_body = glyf_header + b"\x00" * (glyf_len - len(glyf_header))

    num_tables = 3
    dir_size = 12 + num_tables * 16
    if place_head_at_tail:
        # Order offsets: glyf first (so head & maxp sit past the 64 KiB prefix!), tags sorted alphabetically
        glyf_off = dir_size
        head_off = glyf_off + len(glyf_body)
        maxp_off = head_off + len(head_padded)
    else:
        glyf_off = dir_size + len(head_padded) + len(maxp_body)
        head_off = dir_size
        maxp_off = head_off + len(head_padded)

    # SFNT requires tags in ascending alphabetical order: b"glyf" < b"head" < b"maxp"
    entries = [
        (b"glyf", 0, glyf_off, len(glyf_body)),
        (b"head", 0, head_off, 54),
        (b"maxp", 0, maxp_off, 6),
    ]
    power = 1 << (num_tables.bit_length() - 1)
    sfnt_header = struct.pack(
        ">4sHHHH",
        b"\x00\x01\x00\x00",
        num_tables,
        power * 16,
        power.bit_length() - 1,
        num_tables * 16 - power * 16,
    )
    table_dir = b"".join(struct.pack(">4sIII", tag, csum, off, length) for tag, csum, off, length in entries)
    total_len = max(off + ((length + 3) & ~3) for _, _, off, length in entries)
    buf = bytearray(total_len)
    buf[:12] = sfnt_header
    buf[12:dir_size] = table_dir
    buf[glyf_off : glyf_off + len(glyf_body)] = glyf_body
    buf[head_off : head_off + 54] = head_body
    buf[maxp_off : maxp_off + 6] = maxp_body[:6]
    return bytes(buf)


def test_sfnt_prefix_only_inspection_handles_late_head_and_catches_bad_bounds() -> None:
    full_font = _build_valid_large_sfnt_bytes(512_000, place_head_at_tail=True)
    prefix = full_font[:65536]
    assert len(full_font) > len(prefix)

    info = inspect_font(prefix, inspect_table_data=False, measured_length=len(full_font))
    assert info["prefix_only"] is True
    assert info["complete"] is True
    assert info["reason_codes"] == []

    truncated_info = inspect_font(prefix, inspect_table_data=False, measured_length=len(prefix) + 100)
    assert "font_table_bounds_invalid" in truncated_info["reason_codes"]

    with pytest.raises(ValueError, match="measured_length_smaller_than_prefix"):
        inspect_font(prefix, inspect_table_data=False, measured_length=1024)


def test_winforms_scale_67_page_multifont_pdf_is_benign_and_cdr_clean(engines) -> None:
    """Regression for BUG-036 (`Winforms_merged.pdf`): 67 pages + >7.5 MiB cumulative SFNT fonts."""
    base_bytes = load_real_benign_bytes()
    fonts_raw = [
        _build_valid_large_sfnt_bytes(1_950_000, place_head_at_tail=True),
        _build_valid_large_sfnt_bytes(1_850_000, place_head_at_tail=False),
        _build_valid_large_sfnt_bytes(2_100_000, place_head_at_tail=True),
        _build_valid_large_sfnt_bytes(1_900_000, place_head_at_tail=False),
    ]
    assert sum(len(f) for f in fonts_raw) > 7_500_000

    with pikepdf.open(io.BytesIO(base_bytes)) as pdf, pikepdf.open(io.BytesIO(base_bytes)) as donor:
        while len(pdf.pages) < 67:
            pdf.pages.append(donor.pages[0])
        del pdf.pages[67:]

        font_dict = pikepdf.Dictionary()
        for idx, font_bytes in enumerate(fonts_raw):
            ff2 = pdf.make_stream(zlib.compress(font_bytes, level=6), Length1=len(font_bytes))
            ff2.Filter = pikepdf.Name.FlateDecode
            desc = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name.FontDescriptor,
                    FontName=pikepdf.Name(f"/ABCDEF+WinformsFont{idx}"),
                    Flags=32,
                    FontBBox=pikepdf.Array([-200, -300, 1800, 1900]),
                    ItalicAngle=0,
                    Ascent=900,
                    Descent=-200,
                    CapHeight=700,
                    StemV=80,
                    FontFile2=ff2,
                )
            )
            font_obj = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name.Font,
                    Subtype=pikepdf.Name.TrueType,
                    BaseFont=pikepdf.Name(f"/ABCDEF+WinformsFont{idx}"),
                    FontDescriptor=desc,
                )
            )
            font_dict[f"/WF{idx}"] = font_obj

        res = pdf.pages[0].obj.get("/Resources")
        if not isinstance(res, pikepdf.Dictionary):
            res = pikepdf.Dictionary()
            pdf.pages[0].obj.Resources = res
        existing_fonts = res.get("/Font")
        if isinstance(existing_fonts, pikepdf.Dictionary):
            for k, v in font_dict.items():
                existing_fonts[k] = v
        else:
            res.Font = font_dict

        out = io.BytesIO()
        pdf.save(out)
        merged_pdf = out.getvalue()

    pt_res, ox_res = [eng.scan_bytes(merged_pdf, file_name="Winforms_merged.pdf", explain=True) for eng in engines]
    for res in (pt_res, ox_res):
        assert res.pages_count == 67
        assert res.verdict == "BENIGN"
        assert res.malware_probability < 0.05
        assert res.forensic_dossier["codec_anomalies"] == []
        assert res.forensic_dossier["conformal_analysis"]["conformal_state"] == "CERTIFIED_BENIGN"
        assert res.threat_taxonomy["detected_count"] == 0
    assert abs(pt_res.malware_probability - ox_res.malware_probability) <= 1e-5

    cleaned, audit = PDFDisarmer().sanitize_bytes(merged_pdf, file_name="Winforms_merged.pdf")
    assert audit.is_sanitized is True
    assert audit.quarantine_recommended is False
    assert audit.residual_codec_anomalies == []
    assert len(cleaned) > 0.8 * len(merged_pdf)
    assert audit.sanitized_pages == audit.original_pages == 67
    orig_reader, clean_reader = PdfReader(io.BytesIO(merged_pdf)), PdfReader(io.BytesIO(cleaned))
    assert len(clean_reader.pages) == 67
    orig_txt = "".join(p.extract_text() for p in orig_reader.pages[:3])
    clean_txt = "".join(p.extract_text() for p in clean_reader.pages[:3])
    assert len(clean_txt.strip()) > 0 and clean_txt == orig_txt


def test_high_compression_benign_mask_stream_and_benign_incremental_openaction_edit(engines, tmp_path) -> None:
    # 1. Clean 2.5 MiB sparse/white bitmap stream compressing >250x into <10 KiB
    sparse_pixels = b"\xff" * (2_500_000)
    compressed = zlib.compress(sparse_pixels, level=9)
    assert len(compressed) < 10_000 and (len(sparse_pixels) / len(compressed)) > 200.0

    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        img = pdf.make_stream(
            compressed,
            Type=pikepdf.Name.XObject,
            Subtype=pikepdf.Name.Image,
            Width=2000,
            Height=1250,
            BitsPerComponent=8,
            ColorSpace=pikepdf.Name.DeviceGray,
            Filter=pikepdf.Name.FlateDecode,
        )
        res = pdf.pages[0].obj.get("/Resources") or pikepdf.Dictionary()
        xobj = res.get("/XObject") if isinstance(res.get("/XObject"), pikepdf.Dictionary) else pikepdf.Dictionary()
        xobj["/CleanMask"] = img
        res["/XObject"] = xobj
        pdf.pages[0].obj.Resources = res
        buf = io.BytesIO()
        pdf.save(buf)
        high_ratio_pdf = buf.getvalue()

    for eng in engines:
        scan = eng.scan_bytes(high_ratio_pdf, explain=True)
        assert scan.verdict == "BENIGN"
        assert scan.forensic_dossier["codec_anomalies"] == []

    # 2. Benign incremental save removing benign /OpenAction [page0 /FitH null] with zero added triggers
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        pdf.Root.OpenAction = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.FitH, None])
        b0 = io.BytesIO()
        pdf.save(b0)
    inc_path = tmp_path / "benign_annotated_save.pdf"
    inc_path.write_bytes(b0.getvalue())
    with pymupdf.open(inc_path) as mdoc:
        mdoc.xref_set_key(mdoc.pdf_catalog(), "OpenAction", "null")
        mdoc.set_metadata({"modDate": "D:20261126083000"})
        mdoc.saveIncr()
    inc_bytes = inc_path.read_bytes()
    assert inc_bytes.count(b"%%EOF") >= 2

    for eng in engines:
        scan_inc = eng.scan_bytes(inc_bytes, explain=True)
        assert scan_inc.verdict == "BENIGN"
        assert scan_inc.forensic_dossier["differential_analysis"]["has_differential_evasion"] is False


def test_late_page_qr_quishing_detected_despite_earlier_overlays(engines) -> None:
    zxingcpp = pytest.importorskip("zxingcpp")
    qr_uri = "https://portal-doc-verify.example.net/document/8812"
    barcode = np.asarray(zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode, qr_uri, width=220, height=220))

    base = load_real_benign_bytes()
    with pikepdf.open(io.BytesIO(base)) as pdf, pikepdf.open(io.BytesIO(base)) as donor:
        while len(pdf.pages) < 15:
            pdf.pages.append(donor.pages[0])
        del pdf.pages[15:]

        # Add 8 benign Adobe official large links on pages 0..7 to compete for text slots
        for p_idx in range(8):
            annot = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name.Annot,
                    Subtype=pikepdf.Name.Link,
                    Rect=pikepdf.Array([20, 20, 480, 520]),
                    A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI="https://www.adobe.com/acrobat"),
                )
            )
            pdf.pages[p_idx].obj.Annots = pikepdf.Array([annot])

        # Put QR image + Vietnamese scan lure text on last page (index 14)
        last_page = pdf.pages[14].obj
        qr_img = pdf.make_stream(
            zlib.compress(barcode.tobytes()),
            Type=pikepdf.Name.XObject,
            Subtype=pikepdf.Name.Image,
            Width=barcode.shape[1],
            Height=barcode.shape[0],
            BitsPerComponent=8,
            ColorSpace=pikepdf.Name.DeviceGray,
            Filter=pikepdf.Name.FlateDecode,
        )
        font = pikepdf.Dictionary(Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Helvetica)
        last_page.Resources = pikepdf.Dictionary(
            Font=pikepdf.Dictionary(F1=font),
            XObject=pikepdf.Dictionary(QR1=qr_img),
        )
        last_page.Contents = pdf.make_stream(
            b"BT /F1 12 Tf 40 700 Td (Vui long quet ma QR de xac minh tai khoan ngay) Tj ET\n"
            b"q 180 0 0 180 60 420 cm /QR1 Do Q"
        )
        out = io.BytesIO()
        pdf.save(out)
        late_qr_pdf = out.getvalue()

    for eng in engines:
        res = eng.scan_bytes(late_qr_pdf, explain=True)
        assert res.verdict == "MALICIOUS"
        assert res.forensic_dossier["qr_analysis"]["has_qr_threat"] is True
        assert 14 in res.forensic_dossier["qr_analysis"]["qr_pages"]

    _, audit = PDFDisarmer().sanitize_bytes(late_qr_pdf)
    assert audit.is_sanitized is False
    assert audit.quarantine_recommended is True
    assert audit.residual_qr_anomalies


def test_policy_fusion_graded_probabilities_extreme_thresholds_and_conformal_purity(engines) -> None:
    single = fuse_neural_and_static_evidence(
        raw_logit=-5.0,
        raw_prob=0.006,
        threshold=0.26913,
        temperature=1.00725,
        hard_reasons={"/FileAttachment"},
    )
    multi = fuse_neural_and_static_evidence(
        raw_logit=-2.0,
        raw_prob=0.12,
        threshold=0.26913,
        temperature=1.00725,
        hard_reasons={"/Launch", "polyglot_payload", "javascript_malicious_indicators"},
    )
    assert single["applied"] is True and multi["applied"] is True
    assert 0.885 <= single["fused_prob"] < multi["fused_prob"] <= 0.999

    for extreme_thr in (0.9995, math.nextafter(1.0, 0.0)):
        ext = fuse_neural_and_static_evidence(
            raw_logit=-4.0,
            raw_prob=0.018,
            threshold=extreme_thr,
            temperature=1.0,
            hard_reasons={"polyglot_payload"},
        )
        assert ext["fused_prob"] >= extreme_thr
        assert math.isfinite(ext["fused_logit"])
        assert calibrated_probability(ext["fused_logit"], 1.0) == ext["fused_prob"]

    # Truncated /BaseFont / preview never raises IndexError
    consistency = compute_benign_structural_consistency(
        {
            "pages_count": 2,
            "raw_records": [
                {"kind": "catalog", "content_preview": ""},
                {"kind": "pages", "content_preview": "/BaseFont /   "},
            ],
        }
    )
    assert consistency["consistency_score"] >= 0.6

    # Malformed /Predictor in retained page stream does not crash CDR digesting
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        contents = pdf.pages[0].obj.get("/Contents")
        stream_obj = contents[0] if isinstance(contents, pikepdf.Array) else contents
        stream_obj["/DecodeParms"] = pikepdf.Dictionary(Predictor=pikepdf.Name.Invalid)
        bad_pred_buf = io.BytesIO()
        pdf.save(bad_pred_buf)
    clean_pred, pred_audit = PDFDisarmer().sanitize_bytes(bad_pred_buf.getvalue())
    assert pred_audit.sanitized_pages == pred_audit.original_pages
    assert len(clean_pred) > int(0.8 * len(bad_pred_buf.getvalue()))

    # Conformal purity on policy override (ZIP suffix appended to benign PDF):
    poly_pdf = load_real_benign_bytes() + b"PK\x03\x04" + b"\x00" * 26
    for eng in engines:
        res = eng.scan_bytes(poly_pdf, explain=True)
        assert res.verdict == "MALICIOUS"
        conf = res.forensic_dossier["conformal_analysis"]
        assert conf["policy_override"] is True
        assert conf["policy_reject_for_cdr"] is True
        assert conf["score_source"] == "policy_fusion"
        # Evaluator state & set match raw neural p-values without fake CERTIFIED_MALICIOUS
        assert conf["conformal_state"] != "CERTIFIED_MALICIOUS"
        if conf["conformal_state"] == "CERTIFIED_BENIGN":
            assert conf["prediction_set"] == ["BENIGN"]

    # True threat fixture natively achieves CERTIFIED_MALICIOUS with policy_override == False
    threat_bytes = load_real_threat_bytes()
    for eng in engines:
        t_res = eng.scan_bytes(threat_bytes, explain=True)
        assert t_res.verdict == "MALICIOUS"
        t_conf = t_res.forensic_dossier["conformal_analysis"]
        assert t_conf["policy_override"] is False
        assert t_conf["conformal_state"] == "CERTIFIED_MALICIOUS"
