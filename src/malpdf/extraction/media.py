"""Static image, font and SWF structure inspection without page rendering."""

from collections import Counter
import hashlib
import struct
import zlib


class MediaIssue(Exception):
    def __init__(self, code: str, status: str = "decode_error", details: dict | None = None) -> None:
        self.code, self.status, self.details = code, status, details or {}


def digest(data: bytes | memoryview) -> str:
    return hashlib.sha256(data).hexdigest()


def jpeg_structure(data: bytes) -> dict:
    result = {"format": "jpeg", "width": None, "height": None, "components": None,
              "bits_per_component": None, "segments": [], "scan_count": 0,
              "complete": False, "reason_codes": []}
    if not data.startswith(b"\xff\xd8"):
        raise MediaIssue("jpeg_signature_invalid")
    offset, entropy = 2, False
    try:
        while offset < len(data):
            if entropy:
                marker = data.find(b"\xff", offset)
                if marker < 0:
                    break
                offset = marker
            if data[offset] != 255:
                raise MediaIssue("jpeg_marker_invalid")
            start = offset
            while offset < len(data) and data[offset] == 255:
                offset += 1
            if offset == len(data):
                break
            code = data[offset]
            offset += 1
            if entropy and (code == 0 or 0xD0 <= code <= 0xD7):
                continue
            entropy = False
            if code == 0xD9:
                if not result["scan_count"] or result["width"] is None:
                    raise MediaIssue("jpeg_image_structure_incomplete")
                result.update(complete=True, end_offset=offset)
                if offset < len(data):
                    result.update(complete=False, reason_codes=["image_trailing_data"],
                                  trailing_bytes=len(data) - offset, trailing_sha256=digest(data[offset:]))
                return result
            if code in {0, 0xD8} or 0xD0 <= code <= 0xD7:
                raise MediaIssue("jpeg_marker_invalid")
            if code == 1:
                continue
            if offset + 2 > len(data):
                break
            length = int.from_bytes(data[offset:offset + 2], "big")
            if length < 2 or offset + length > len(data):
                raise MediaIssue("jpeg_segment_truncated")
            body = memoryview(data)[offset + 2:offset + length]
            result["segments"].append({"marker": code, "offset": start, "size_bytes": length,
                                       "sha256": digest(body)})
            if code in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                if len(body) < 6 or len(body) != 6 + 3 * body[5]:
                    raise MediaIssue("jpeg_frame_invalid")
                geometry = (int.from_bytes(body[3:5], "big"), int.from_bytes(body[1:3], "big"), body[5], body[0])
                if not all(geometry):
                    raise MediaIssue("jpeg_frame_invalid")
                previous = tuple(result[key] for key in ("width", "height", "components", "bits_per_component"))
                if result["width"] is not None and previous != geometry:
                    raise MediaIssue("jpeg_frame_conflict")
                result.update(zip(("width", "height", "components", "bits_per_component"), geometry))
            if code == 0xDA:
                if len(body) < 4 or len(body) != 1 + 2 * body[0] + 3:
                    raise MediaIssue("jpeg_scan_header_invalid")
                result["scan_count"] += 1
                entropy = True
            offset += length
        raise MediaIssue("jpeg_end_marker_missing")
    except MediaIssue as error:
        result["reason_codes"] = [error.code]
        raise MediaIssue(error.code, details=result) from None


def png_structure(data: bytes) -> dict:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise MediaIssue("png_signature_invalid")
    offset, seen, chunks = 8, set(), []
    result = {"format": "png", "complete": False, "reason_codes": [], "chunks": chunks}
    while offset < len(data):
        if offset + 12 > len(data):
            raise MediaIssue("png_chunk_truncated", details=result)
        length = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + length
        if end > len(data) or any(not (65 <= char <= 90 or 97 <= char <= 122) for char in kind):
            raise MediaIssue("png_chunk_invalid", details=result)
        body = memoryview(data)[offset + 8:end - 4]
        expected = int.from_bytes(data[end - 4:end], "big")
        if zlib.crc32(body, zlib.crc32(kind)) & 0xFFFFFFFF != expected:
            raise MediaIssue("png_crc_mismatch", details=result)
        chunks.append({"type": kind.decode("ascii"), "offset": offset, "size_bytes": length, "sha256": digest(body)})
        if not seen and kind != b"IHDR":
            raise MediaIssue("png_header_missing", details=result)
        if kind == b"IHDR":
            if seen or length != 13:
                raise MediaIssue("png_header_invalid", details=result)
            width, height, bits, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", body)
            allowed = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
            if not width or not height or bits not in allowed.get(color, set()) or compression or filtering or interlace not in (0, 1):
                raise MediaIssue("png_header_invalid", details=result)
            result.update(width=width, height=height, bits_per_component=bits, color_type=color,
                          components={0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color], interlaced=bool(interlace))
        if kind == b"IEND":
            if length or b"IDAT" not in seen:
                raise MediaIssue("png_end_invalid", details=result)
            result.update(complete=end == len(data), reason_codes=[] if end == len(data) else ["image_trailing_data"])
            return result
        seen.add(kind)
        offset = end
    raise MediaIssue("png_end_missing", details=result)


def jpx_structure(data: bytes) -> dict:
    boxes = []
    codestream = memoryview(data)
    if data.startswith(b'\x00\x00\x00\x0cjP  \r\n\x87\n'):
        offset, streams = 0, []
        while offset < len(data):
            if offset + 8 > len(data):
                raise MediaIssue('jpx_box_truncated')
            length, kind = struct.unpack_from('>I4s', data, offset)
            header = 8
            if length == 1:
                if offset + 16 > len(data):
                    raise MediaIssue('jpx_box_truncated')
                length = int.from_bytes(data[offset + 8:offset + 16], 'big')
                header = 16
            if length == 0:
                length = len(data) - offset
            if length < header or offset + length > len(data):
                raise MediaIssue('jpx_box_bounds_invalid')
            boxes.append({'type_hex': kind.hex(), 'offset': offset, 'size_bytes': length})
            if kind == b'jp2c':
                streams.append(memoryview(data)[offset + header:offset + length])
            offset += length
        if len(streams) != 1:
            raise MediaIssue('jpx_codestream_count_unsupported', 'unsupported')
        codestream = streams[0]
    if len(codestream) < 42 or codestream[:4] != b'\xff\x4f\xff\x51':
        raise MediaIssue('jpx_signature_invalid')
    length = int.from_bytes(codestream[4:6], 'big')
    width, height, x_offset, y_offset = struct.unpack_from('>IIII', codestream, 8)
    components = int.from_bytes(codestream[40:42], 'big')
    if not components or length != 38 + components * 3 or 4 + length > len(codestream):
        raise MediaIssue('jpx_size_marker_invalid')
    precisions = [int(codestream[42 + index * 3]) for index in range(components)]
    if width <= x_offset or height <= y_offset:
        raise MediaIssue('jpx_geometry_invalid')
    if codestream[-2:] != b'\xff\xd9':
        raise MediaIssue('jpx_end_marker_missing')
    return {'format': 'jpx', 'width': width - x_offset, 'height': height - y_offset, 'components': components,
            'bits_per_component': (precisions[0] & 127) + 1 if len(set(precisions)) == 1 else None,
            'signed_components': any(value & 128 for value in precisions), 'boxes': boxes,
            'complete': True, 'reason_codes': [], 'scope': 'JP2 box bounds and codestream SIZ/EOC framing; entropy data validated separately'}



JBIG2_SEGMENT_TYPES = {
    0: "symbol_dictionary",
    4: "intermediate_text_region",
    6: "immediate_text_region",
    7: "immediate_lossless_text_region",
    16: "pattern_dictionary",
    20: "intermediate_halftone_region",
    22: "immediate_halftone_region",
    23: "immediate_lossless_halftone_region",
    36: "intermediate_generic_region",
    38: "immediate_generic_region",
    39: "immediate_lossless_generic_region",
    40: "intermediate_generic_refinement_region",
    42: "immediate_generic_refinement_region",
    43: "immediate_lossless_generic_refinement_region",
    48: "page_information",
    49: "end_of_page",
    50: "end_of_stripe",
    51: "end_of_file",
    52: "profiles",
    53: "tables",
    62: "extension",
}


def jbig2_structure(data: bytes) -> dict:
    if not data:
        raise MediaIssue("jbig2_data_empty")
    result = {
        "format": "jbig2",
        "complete": False,
        "reason_codes": [],
        "has_file_header": False,
        "file_organization": "embedded",
        "number_of_pages_known": False,
        "declared_pages": None,
        "segment_count": 0,
        "segment_types_present": {},
        "segments": [],
        "width": None,
        "height": None,
        "components": 1,
        "bits_per_component": 1,
        "has_end_of_file": False,
        "scope": "JBIG2 segment framing, headers and referred-to segment graph only; no image rendering or decompression",
        "rendering_performed": False,
        "pixel_decode_performed": False,
    }
    if data.startswith(b"\x97JB2\r\n\x1a\n"):
        result["has_file_header"] = True
        if len(data) < 9:
            raise MediaIssue("jbig2_file_header_truncated", details=result)
        flags = data[8]
        result["file_organization"] = "sequential" if not (flags & 1) else "random_access"
        pages_known = bool(flags & 2)
        result["number_of_pages_known"] = pages_known
        offset = 9
        if pages_known:
            if len(data) < 13:
                raise MediaIssue("jbig2_file_header_truncated", details=result)
            result["declared_pages"] = int.from_bytes(data[9:13], "big")
            offset = 13
    else:
        offset = 0
    seen_numbers = set()
    reasons = set()
    type_counts = Counter()
    while offset < len(data):
        if offset + 11 > len(data):
            reasons.add("jbig2_segment_header_truncated")
            result["reason_codes"] = sorted(reasons)
            raise MediaIssue("jbig2_segment_header_truncated", details=result)
        seg_number = int.from_bytes(data[offset:offset + 4], "big")
        if seg_number in seen_numbers:
            reasons.add("jbig2_duplicate_segment_number")
        seen_numbers.add(seg_number)
        header_flags = data[offset + 4]
        deferred = bool(header_flags & 0x80)
        page_assoc_size = 4 if (header_flags & 0x40) else 1
        seg_type = header_flags & 0x3F
        type_name = JBIG2_SEGMENT_TYPES.get(seg_type, "unknown_type")
        if seg_type not in JBIG2_SEGMENT_TYPES:
            reasons.add("jbig2_unknown_segment_type")
        type_counts[type_name] += 1
        ref_byte = data[offset + 5]
        short_count = (ref_byte >> 5) & 0x07
        cur = offset + 6
        if short_count <= 4:
            ref_count = short_count
        else:
            if cur + 4 > len(data):
                reasons.add("jbig2_segment_header_truncated")
                result["reason_codes"] = sorted(reasons)
                raise MediaIssue("jbig2_segment_header_truncated", details=result)
            ref_count = int.from_bytes(data[cur:cur + 4], "big")
            cur += 4
            if ref_count > 65536:
                reasons.add("jbig2_excessive_reference_count")
            flag_bytes = (ref_count + 1) // 8
            if cur + flag_bytes > len(data):
                reasons.add("jbig2_segment_header_truncated")
                result["reason_codes"] = sorted(reasons)
                raise MediaIssue("jbig2_segment_header_truncated", details=result)
            cur += flag_bytes
        ref_num_size = 1 if seg_number <= 256 else 2 if seg_number <= 65536 else 4
        if cur + ref_count * ref_num_size > len(data):
            reasons.add("jbig2_segment_header_truncated")
            result["reason_codes"] = sorted(reasons)
            raise MediaIssue("jbig2_segment_header_truncated", details=result)
        referred_segments = []
        for _ in range(ref_count):
            ref_target = int.from_bytes(data[cur:cur + ref_num_size], "big")
            cur += ref_num_size
            if ref_target >= seg_number:
                reasons.add("jbig2_forward_segment_reference")
            referred_segments.append(ref_target)
        if cur + page_assoc_size > len(data):
            reasons.add("jbig2_segment_header_truncated")
            result["reason_codes"] = sorted(reasons)
            raise MediaIssue("jbig2_segment_header_truncated", details=result)
        page_assoc = int.from_bytes(data[cur:cur + page_assoc_size], "big")
        cur += page_assoc_size
        if cur + 4 > len(data):
            reasons.add("jbig2_segment_header_truncated")
            result["reason_codes"] = sorted(reasons)
            raise MediaIssue("jbig2_segment_header_truncated", details=result)
        data_length = int.from_bytes(data[cur:cur + 4], "big")
        cur += 4
        if data_length == 0xFFFFFFFF:
            reasons.add("jbig2_unknown_data_length")
            seg_body = memoryview(data)[cur:]
            cur = len(data)
        else:
            if cur + data_length > len(data):
                reasons.add("jbig2_segment_truncated")
                result["reason_codes"] = sorted(reasons)
                raise MediaIssue("jbig2_segment_truncated", details=result)
            seg_body = memoryview(data)[cur:cur + data_length]
            cur += data_length
        if seg_type == 48 and len(seg_body) >= 8:
            page_width, page_height = struct.unpack_from(">II", seg_body, 0)
            if result["width"] is None:
                result["width"] = page_width
                result["height"] = page_height
            elif result["width"] != page_width or result["height"] != page_height:
                reasons.add("jbig2_page_geometry_conflict")
        seg_record = {
            "segment_number": seg_number,
            "type": seg_type,
            "type_name": type_name,
            "deferred_non_retain": deferred,
            "page_association": page_assoc,
            "referred_to_segments": referred_segments,
            "size_bytes": len(seg_body),
            "offset": offset,
            "header_bytes": cur - offset - len(seg_body),
            "sha256": digest(seg_body),
        }
        result["segments"].append(seg_record)
        offset = cur
        if seg_type == 51:
            result["has_end_of_file"] = True
            if offset < len(data):
                result["trailing_bytes"] = len(data) - offset
                result["trailing_sha256"] = digest(data[offset:])
                reasons.add("image_trailing_data")
            break
    result["segment_count"] = len(result["segments"])
    result["segment_types_present"] = dict(type_counts)
    result["complete"] = not bool(reasons)
    result["reason_codes"] = sorted(reasons)
    return result


def inspect_image(data: bytes, context: dict | None = None) -> dict:
    context = context or {}
    if data.startswith(b"\xff\xd8"):
        result = jpeg_structure(data)
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        result = png_structure(data)
    elif data.startswith((b'\x00\x00\x00\x0cjP  \r\n\x87\n', b'\xff\x4f\xff\x51')):
        result = jpx_structure(data)
    elif data.startswith(b"\x97JB2\r\n\x1a\n") or context.get("codec") in {"/JBIG2Decode", "/JB2"}:
        result = jbig2_structure(data)
    elif all(type(context.get(key)) is int for key in ("width", "height", "components", "bits_per_component")):

        width, height, components, bits = (context[key] for key in ("width", "height", "components", "bits_per_component"))
        if min(width, height, components) < 1 or bits not in (1, 2, 4, 8, 16):
            raise MediaIssue("raster_geometry_invalid")
        expected = ((width * components * bits + 7) // 8) * height
        result = {"format": "raw_raster", "width": width, "height": height, "components": components,
                  "bits_per_component": bits, "expected_bytes": expected, "observed_bytes": len(data),
                  "complete": expected == len(data), "reason_codes": [] if expected == len(data) else ["raster_size_mismatch"]}
    else:
        raise MediaIssue("image_format_or_context_unavailable", "unsupported")
    result.update(scope="encoded image structure or declared raster geometry only; no page rendering or exploit verdict",
                  rendering_performed=False, pixel_decode_performed=False)
    return result


def table_checksum(data: bytes | memoryview, *, head: bool = False) -> int:
    aligned = len(data) // 4 * 4
    total = sum(word[0] for word in struct.iter_unpack('>I', memoryview(data)[:aligned]))
    total += int.from_bytes(bytes(data[aligned:]).ljust(4, b'\0'), 'big') if aligned < len(data) else 0
    if head and len(data) > 8:
        total -= int.from_bytes(bytes(data[8:12]).ljust(4, b'\0'), 'big')
    return total & 0xFFFFFFFF


def inspect_font(data: bytes) -> dict:
    result = {"format": "sfnt", "complete": False, "reason_codes": [], "tables": [],
              "scope": "font directory, bounds, checksums and selected scalar metadata; glyph programs never executed",
              "font_execution_performed": False, "font_validity_verified": False}
    if data[:4] not in {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}:
        raise MediaIssue("font_container_unsupported", "unsupported", result)
    if len(data) < 12:
        raise MediaIssue("font_directory_truncated", details=result)
    count, search, selector, shift = struct.unpack_from(">HHHH", data, 4)
    if not count or 12 + count * 16 > len(data):
        raise MediaIssue("font_directory_truncated", details=result)
    power = 1 << (count.bit_length() - 1)
    reasons, seen, ranges = set(), set(), []
    if (search, selector, shift) != (power * 16, power.bit_length() - 1, count * 16 - power * 16):
        reasons.add("font_search_parameters_invalid")
    tags = []
    for index in range(count):
        tag, checksum, offset, length = struct.unpack_from(">4sIII", data, 12 + index * 16)
        tags.append(tag)
        if tag in seen:
            reasons.add("font_duplicate_table")
        seen.add(tag)
        item = {"tag_hex": tag.hex(), "offset": offset, "size_bytes": length, "checksum_declared": checksum,
                "bounds_verified": offset >= 12 + count * 16 and offset + length <= len(data), "checksum_verified": False}
        result["tables"].append(item)
        if not item["bounds_verified"]:
            reasons.add("font_table_bounds_invalid")
            continue
        if offset % 4:
            reasons.add("font_table_alignment_invalid")
        body = memoryview(data)[offset:offset + length]
        item.update(sha256=digest(body), checksum_verified=table_checksum(body, head=tag == b"head") == checksum)
        if not item["checksum_verified"]:
            reasons.add("font_table_checksum_mismatch")
        if length:
            ranges.append((offset, offset + length))
        if tag == b"head" and length >= 54:
            result["units_per_em"] = int.from_bytes(body[18:20], "big")
            result["bounding_box"] = list(struct.unpack_from(">hhhh", body, 36))
        if tag == b"maxp" and length >= 6:
            result["glyph_count"] = int.from_bytes(body[4:6], "big")
    if tags != sorted(tags):
        reasons.add("font_table_order_invalid")
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        reasons.add("font_table_overlap")
    result.update(table_count=count, complete=not reasons, reason_codes=sorted(reasons),
                  instruction_tables_present=bool(seen & {b"fpgm", b"prep", b"cvt "}),
                  svg_table_present=b"SVG " in seen, cff_table_present=bool(seen & {b"CFF ", b"CFF2"}))
    return result


def inspect_flash(data: bytes, *, budget, max_expansion_ratio: int, retain=None) -> dict:
    from malpdf.extraction.filters import _Stopped, _flate
    result = {"format": "swf", "complete": False, "reason_codes": [], "tags": [],
              "scope": "SWF header and tag boundaries/hashes only; no ActionScript or playback execution",
              "execution_performed": False}
    if len(data) < 8 or data[:3] not in {b"FWS", b"CWS", b"ZWS"}:
        raise MediaIssue("flash_header_invalid", details=result)
    declared = int.from_bytes(data[4:8], "little")
    result.update(version=data[3], declared_size_bytes=declared, compressed=data[:3] != b"FWS")
    if declared < 8:
        raise MediaIssue("flash_length_invalid", details=result)
    if data[:3] == b"ZWS":
        raise MediaIssue("flash_lzma_not_supported", "unsupported", result)
    body = data[8:]
    if data[:3] == b"CWS":
        try:
            body = _flate(body, min(budget.remaining, len(body) * max_expansion_ratio))
        except _Stopped as error:
            prefix = error.prefix or b""
            budget.remaining -= len(prefix)
            result.update(decoded_prefix_bytes=len(prefix), decoded_prefix_sha256=digest(prefix))
            if retain is not None:
                result["decoded_prefix_retention"] = retain(prefix)
            raise MediaIssue(error.code, error.status, result) from None
        budget.remaining -= len(body)
    result.update(decoded_bytes=len(body), decoded_sha256=digest(body))
    if len(body) + 8 != declared:
        raise MediaIssue("flash_length_mismatch", details=result)
    if not body:
        raise MediaIssue("flash_movie_header_truncated", details=result)
    rectangle_bits = body[0] >> 3
    offset = (5 + 4 * rectangle_bits + 7) // 8
    if not rectangle_bits or offset + 4 > len(body):
        raise MediaIssue("flash_movie_header_truncated", details=result)
    result.update(frame_rate_fixed=int.from_bytes(body[offset:offset + 2], "little"),
                  declared_frames=int.from_bytes(body[offset + 2:offset + 4], "little"))
    offset += 4
    while offset < len(body):
        start = offset
        if offset + 2 > len(body):
            raise MediaIssue("flash_tag_header_truncated", details=result)
        header = int.from_bytes(body[offset:offset + 2], "little")
        offset += 2
        code, length = header >> 6, header & 63
        if length == 63:
            if offset + 4 > len(body):
                raise MediaIssue("flash_tag_header_truncated", details=result)
            length = int.from_bytes(body[offset:offset + 4], "little")
            offset += 4
        if offset + length > len(body):
            raise MediaIssue("flash_tag_body_truncated", details=result)
        result["tags"].append({"code": code, "decoded_offset": start, "size_bytes": length,
                               "sha256": digest(memoryview(body)[offset:offset + length]),
                               "script_candidate": code in {12, 59, 72, 82}})
        offset += length
        if code == 0:
            if length:
                raise MediaIssue("flash_end_tag_invalid", details=result)
            result.update(complete=offset == len(body), reason_codes=[] if offset == len(body) else ["flash_trailing_data"],
                          tag_counts={str(key): value for key, value in Counter(tag["code"] for tag in result["tags"]).items()},
                          script_tag_count=sum(tag["script_candidate"] for tag in result["tags"]))
            return result
    raise MediaIssue("flash_end_tag_missing", details=result)
