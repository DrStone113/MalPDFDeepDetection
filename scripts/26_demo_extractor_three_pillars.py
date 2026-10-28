from decimal import Decimal
import hashlib
import json
import struct

from malpdf.extraction.arlington_expression import Symbol, Unknown, evaluate
from malpdf.extraction.carving import RecursiveCarver
from malpdf.extraction.content_stream import inspect_content_stream
from malpdf.extraction.media import jbig2_structure
from malpdf.static.code_inspector import VMInspectionLimits
from malpdf.static.execution import UNLIMITED


class DemoContext:
    version = (1, 7)

    def value(self, path):
        mapping = {"@N": Decimal(8), "N": Decimal(8), "@Name": Symbol("Catalog")}
        return mapping.get(path, Unknown(("value_absent",)))

    def present(self, path):
        return path in ("N", "@N", "@Name")


def demo_jbig2():
    prefix = b"\x97JB2\r\n\x1a\n\x00"
    seg0 = struct.pack(">IBB", 0, 48, 0) + bytes([1]) + struct.pack(">I", 8) + struct.pack(">II", 16, 8)
    seg1 = struct.pack(">IBB", 1, 38, 0x20) + bytes([0]) + bytes([1]) + struct.pack(">I", 4) + b"\x00\x00\x00\x00"
    seg2 = struct.pack(">IBB", 2, 51, 0) + bytes([0]) + struct.pack(">I", 0)
    data = prefix + seg0 + seg1 + seg2
    return jbig2_structure(data)


def demo_content_stream():
    stream_data = (
        b"BT /F1 12 Tf 72 712 Td (Visible text in document) Tj ET\n"
        b"BT /F1 12 Tf 3 Tr 72 650 Td (Phishing credential payload hidden with Tr 3) Tj ET\n"
        b"BT /F1 0 Tf 72 600 Td (Invisible zero font size text) Tj ET\n"
        b"BT /F1 12 Tf 1 1 1 rg 72 550 Td (White on white keyword stuffing) Tj ET\n"
        b"BT /F1 12 Tf 99999 99999 Td (Off page text coordinates) Tj ET\n"
    )
    return inspect_content_stream(stream_data, boundary_box=[0, 0, 612, 792])


def demo_arlington():
    ctx = DemoContext()
    ctx.page_count = lambda: 12
    ctx.page_number = lambda: 3
    ctx.is_direct = lambda path: path == "DirectCatalog"
    queries = [
        "fn:IsNumber(42)",
        "fn:IsNumber(@Name)",
        "fn:DefaultValue(10, @N)",
        "fn:DefaultValue(10, null)",
        "fn:RequiredValue(42, 42)",
        "fn:RequiredValue(42, 99)",
        "fn:PageCount()",
        "fn:PageNumber()",
        "fn:InKeyList(42, [1, 42, 99])",
        "fn:MustBeDirect(DirectCatalog)",
        "fn:HasValue(42)",
    ]
    results = {}
    for q in queries:
        val = evaluate(q, ctx)
        results[q] = int(val) if hasattr(val, "to_integral_value") else str(val) if not isinstance(val, bool) else val
    return results


def demo_carver():
    data = b"BT /F1 14 Tf 3 Tr (Exfiltrated hidden text) Tj ET"
    digest = hashlib.sha256(data).hexdigest()
    carver = RecursiveCarver("a" * 64, VMInspectionLimits())
    identity = carver.add(data, parent_id="root", decoded_sha256=digest, hint="content_stream")
    result = carver.finish(UNLIMITED)
    record = result["records"][0]
    analysis = result["analyses"][identity]
    return {
        "artifact_kind": record["kind"],
        "artifact_status": record["status"],
        "artifact_reason_codes": record["reason_codes"],
        "total_chars": analysis["total_characters"],
        "invisible_chars": analysis["invisible_characters"],
        "invisible_ratio": analysis["invisible_character_ratio"],
        "has_tr3": analysis["has_text_rendering_mode_3"],
    }


def main():
    report = {
        "jbig2_structure_demo": demo_jbig2(),
        "content_stream_demo": demo_content_stream(),
        "arlington_predicates_demo": demo_arlington(),
        "carver_integration_demo": demo_carver(),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
