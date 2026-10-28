"""Native image samples from memory only; never open or render a PDF page."""

import hashlib
import struct

from malpdf.extraction.media import MediaIssue, jpeg_structure, jpx_structure, jbig2_structure


def decode_image(data: bytes, codec: str, parameters: dict | None, cap: int,
                 context: dict | None = None) -> tuple[bytes, dict]:
    import pymupdf
    parameters, context = parameters or {}, context or {}
    if codec == '/CCITTFaxDecode':
        return decode_fax(data, parameters, cap, context)
    if codec in {'/JBIG2Decode', '/JB2'}:
        return decode_jbig2(data, parameters, cap, context)
    if parameters:
        raise MediaIssue("image_decode_parameters_unsupported", "unsupported")
    if codec == "/DCTDecode":
        structural = jpeg_structure(data)
        if not structural["complete"]:
            raise MediaIssue("jpeg_structure_incomplete", details=structural)
    elif codec == "/JPXDecode":
        structural = jpx_structure(data)
    else:
        raise MediaIssue("image_codec_unsupported", "unsupported")
    width, height, components, bits = (structural[key] for key in ("width", "height", "components", "bits_per_component"))
    if min(width, height) < 1 or bits != 8 or components not in {1, 3} or structural.get('signed_components'):
        raise MediaIssue("image_component_layout_unsupported", "unsupported")
    if any(type(context.get(key)) is int and context[key] != actual for key, actual in
           (("width", width), ("height", height), ("components", components), ("bits_per_component", bits))):
        raise MediaIssue("image_declared_geometry_mismatch")
    if width * height * components > cap:
        raise MediaIssue("image_decoded_byte_limit", "resource_limit")
    try:
        pixmap = pymupdf.Pixmap(data)
        if pixmap.alpha or (pixmap.width, pixmap.height, pixmap.n) != (width, height, components):
            raise MediaIssue("image_component_layout_unsupported", "unsupported")
        samples = pixmap.samples
    except MediaIssue:
        raise
    except Exception:
        raise MediaIssue("image_codec_failed") from None
    if len(samples) != width * height * components:
        raise MediaIssue("image_sample_length_mismatch")
    metadata = {"backend": "MuPDF image codec", "width": width, "height": height,
                "components": components, "bits_per_component": bits, "format": structural["format"],
                "output_sha256": hashlib.sha256(samples).hexdigest(), "output_bytes": len(samples),
                "scope": "native image samples before PDF Decode/color management; no PDF page rendering",
                "rendering_performed": False, "library_version": pymupdf.VersionFitz}
    return samples, metadata


def decode_fax(data: bytes, parameters: dict, cap: int, context: dict) -> tuple[bytes, dict]:
    import pymupdf
    allowed = {'/K', '/Columns', '/Rows', '/EndOfLine', '/EncodedByteAlign', '/EndOfBlock',
               '/BlackIs1', '/DamagedRowsBeforeError'}
    if set(parameters) - allowed:
        raise MediaIssue('fax_parameters_unsupported', 'unsupported')
    for name, value in parameters.items():
        expected = bool if name in {'/EndOfLine', '/EncodedByteAlign', '/EndOfBlock', '/BlackIs1'} else int
        if type(value) is not expected:
            raise MediaIssue('fax_parameter_type_invalid')
    width = parameters.get('/Columns', context.get('width', 1728))
    height = parameters.get('/Rows', 0) or context.get('height', 0)
    mode = parameters.get('/K', 0)
    if not 0 < width <= 0xFFFFFFFF or not 0 < height <= 0xFFFFFFFF:
        raise MediaIssue('fax_geometry_unavailable', 'unsupported')
    if any(type(context.get(key)) is int and context[key] != value for key, value in
           (('width', width), ('height', height), ('bits_per_component', 1), ('components', 1))):
        raise MediaIssue('image_declared_geometry_mismatch')
    if parameters.get('/DamagedRowsBeforeError', 0) != 0:
        raise MediaIssue('fax_damaged_row_recovery_unsupported', 'unsupported')
    if mode == 0 and not parameters.get('/EndOfLine', False) or mode < 0 and parameters.get('/EncodedByteAlign', False):
        raise MediaIssue('fax_alignment_mode_unsupported', 'unsupported')
    row_bytes = (width + 7) // 8
    if row_bytes * height > cap:
        raise MediaIssue('image_decoded_byte_limit', 'resource_limit')
    tags = [(256, 4, width), (257, 4, height), (258, 3, 1), (259, 3, 4 if mode < 0 else 3),
            (262, 3, 0), (273, 4, 0), (278, 4, height), (279, 4, len(data))]
    if mode >= 0:
        tags.append((292, 4, (1 if mode > 0 else 0) | (4 if parameters.get('/EncodedByteAlign', False) else 0)))
    tags.sort()
    offset = 8 + 2 + len(tags) * 12 + 4
    header = b'II' + struct.pack('<HIH', 42, 8, len(tags))
    header += b''.join(struct.pack('<HHII', tag, kind, 1, offset if tag == 273 else value) for tag, kind, value in tags)
    header += b'\0' * 4
    pymupdf.TOOLS.reset_mupdf_warnings()
    try:
        pixmap = pymupdf.Pixmap(header + data)
        if (pixmap.width, pixmap.height, pixmap.n) != (width, height, 1) or pixmap.alpha:
            raise MediaIssue('fax_native_geometry_mismatch')
        pixels = pixmap.samples
        if pymupdf.TOOLS.mupdf_warnings():
            raise MediaIssue('fax_native_recovery_notice')
    except MediaIssue:
        raise
    except Exception:
        raise MediaIssue('fax_codec_failed') from None
    output = bytearray(row_bytes * height)
    black_is_one = parameters.get('/BlackIs1', False)
    for row in range(height):
        for column in range(width):
            sample = pixels[row * width + column]
            if sample not in (0, 255):
                raise MediaIssue('fax_nonbinary_sample')
            if (sample == 0) == black_is_one:
                output[row * row_bytes + column // 8] |= 128 >> (column % 8)
    body = bytes(output)
    return body, {'backend': 'MuPDF TIFF fax codec', 'width': width, 'height': height, 'components': 1,
        'bits_per_component': 1, 'output_bytes': len(body), 'output_sha256': hashlib.sha256(body).hexdigest(),
        'format': 'ccitt_fax', 'scope': 'declared rows decoded in memory; EOB and compressed-byte consumption unverified',
        'reason_codes': ['fax_consumption_unverified'], 'rendering_performed': False, 'library_version': pymupdf.VersionFitz}


def decode_jbig2(data: bytes, parameters: dict, cap: int, context: dict) -> tuple[bytes, dict]:
    structural = jbig2_structure(data)
    if not structural["complete"]:
        raise MediaIssue("jbig2_structure_incomplete", details=structural)
    width = structural.get("width") or context.get("width")
    height = structural.get("height") or context.get("height")
    if not width or not height or min(width, height) < 1:
        raise MediaIssue("jbig2_geometry_unavailable", "unsupported", details=structural)
    if any(type(context.get(key)) is int and context[key] != actual for key, actual in
           (("width", width), ("height", height))):
        raise MediaIssue("image_declared_geometry_mismatch", details=structural)
    row_bytes = (width + 7) // 8
    total_bytes = row_bytes * height
    if total_bytes > cap:
        raise MediaIssue("image_decoded_byte_limit", "resource_limit", details=structural)
    metadata = {
        "backend": "JBIG2 structural framing",
        "width": width,
        "height": height,
        "components": 1,
        "bits_per_component": 1,
        "format": "jbig2",
        "output_sha256": hashlib.sha256(data).hexdigest(),
        "output_bytes": len(data),
        "segment_count": structural["segment_count"],
        "segment_types_present": structural["segment_types_present"],
        "scope": "JBIG2 segment framing and declared geometry without pixel decompression",
        "rendering_performed": False,
        "pixel_decode_performed": False,
    }
    return data, metadata

