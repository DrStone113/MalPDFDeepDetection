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


def inspect_image(data: bytes, context: dict | None = None) -> dict:
    context = context or {}
    if data.startswith(b"\xff\xd8"):
        result = jpeg_structure(data)
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        result = png_structure(data)
    elif data.startswith((b'\x00\x00\x00\x0cjP  \r\n\x87\n', b'\xff\x4f\xff\x51')):
        result = jpx_structure(data)
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
