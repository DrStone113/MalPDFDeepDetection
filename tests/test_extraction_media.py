"""Only in-memory generated codec, image, font and inert SWF fixtures."""

from dataclasses import replace
import hashlib
import io
import json
import struct
import zlib

import pytest
import pymupdf
from pypdf.generic import EncodedStreamObject, NameObject, NumberObject

from malpdf.extraction.carving import RecursiveCarver
from malpdf.extraction.filters import DecodeBudget, FilterLimits, decode_filters
from malpdf.extraction.media import MediaIssue, inspect_flash, inspect_font, inspect_image, jpeg_structure, png_structure
from malpdf.extraction.streams import StreamCollector
from malpdf.static.code_inspector import VMInspectionLimits
from malpdf.static.execution import UNLIMITED


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jpeg() -> bytes:
    image = pymupdf.Pixmap(pymupdf.csGRAY, 8, 8, bytes([42]) * 64, False)
    return image.tobytes('jpeg')


def png() -> bytes:
    image = pymupdf.Pixmap(pymupdf.csRGB, 2, 2, bytes([10, 20, 30]) * 4, False)
    return image.tobytes('png')


def font() -> bytes:
    body = struct.pack('>IH', 0x10000, 12)
    checksum = (0x10000 + (12 << 16)) & 0xFFFFFFFF
    return struct.pack('>4sHHHH', b'\x00\x01\x00\x00', 1, 16, 0, 0) + struct.pack(
        '>4sIII', b'maxp', checksum, 28, len(body)) + body + b'\0\0'


def flash(*, compressed: bool = False, script: bool = True) -> bytes:
    rectangle = b'\x08\x00'
    body = rectangle + struct.pack('<HH', 24 * 256, 1)
    if script:
        body += struct.pack('<H', (82 << 6) | 4) + b'\0\0\0\0'
    body += b'\0\0'
    return (b'CWS' if compressed else b'FWS') + bytes([10]) + struct.pack('<I', len(body) + 8) + (zlib.compress(body) if compressed else body)


@pytest.mark.parametrize('size', [1, 100, 20000])
def test_verified_flate_member_preserves_all_trailing_bytes_without_hiding_anomaly(size: int) -> None:
    payload = b'inert verified payload'
    suffix = b'x' * size
    raw = zlib.compress(payload) + suffix
    retained = {}
    def retain(data):
        retained[sha(data)] = data
        return {'sha256': sha(data), 'size_bytes': len(data), 'status': 'retained'}
    result = decode_filters(raw, ['/FlateDecode'], recover_trailing=True, retain=retain)
    assert result.data == payload and result.metadata['output_complete']
    assert not result.metadata['complete'] and result.metadata['status'] == 'partial'
    trailing = result.metadata['steps'][0]['trailing_data']
    assert trailing['offset'] == len(zlib.compress(payload)) and trailing['sha256'] == sha(suffix)
    assert retained[trailing['sha256']] == suffix
    assert result.metadata['decoded_byte_debit'] == len(payload)
    assert 'inert verified payload' not in json.dumps(result.metadata)
    strict = decode_filters(raw, ['/FlateDecode'])
    assert strict.data is None and strict.metadata['reason_codes'] == ['trailing_flate_data']


def test_verified_recovery_can_feed_a_later_filter_but_corrupt_checksum_cannot() -> None:
    raw = zlib.compress(b'4142>') + b'inert suffix'
    result = decode_filters(raw, ['/FlateDecode', '/ASCIIHexDecode'], recover_trailing=True)
    assert result.data == b'AB' and result.metadata['status'] == 'partial'
    assert result.metadata['steps'][1]['complete']
    bad = zlib.compress(b'4142>')[:-1] + b'\0'
    result = decode_filters(bad, ['/FlateDecode', '/ASCIIHexDecode'], recover_trailing=True)
    assert result.data is None and result.metadata['steps'][1]['status'] == 'not_run'


def test_recovered_member_still_respects_predictors_and_shared_budget() -> None:
    raw = zlib.compress(b'\0ABC') + b'suffix'
    result = decode_filters(raw, ['/FlateDecode'], recover_trailing=True,
        decode_parms={'/Predictor': 15, '/Columns': 3})
    assert result.data == b'ABC' and result.metadata['decoded_byte_debit'] == 4
    budget = DecodeBudget(2)
    result = decode_filters(raw, ['/FlateDecode'], recover_trailing=True, budget=budget)
    assert result.data is None and result.metadata['status'] == 'resource_limit' and budget.remaining == 0


def test_native_jpeg_decodes_image_samples_without_opening_or_rendering_pdf(monkeypatch) -> None:
    data = jpeg()
    def forbidden(*args, **kwargs):
        pytest.fail('PDF opening or rendering must not occur')
    monkeypatch.setattr(pymupdf, 'open', forbidden)
    monkeypatch.setattr(pymupdf.Page, 'get_pixmap', forbidden)
    result = decode_filters(data, ['/DCTDecode'], media_codecs=True)
    assert result.metadata['complete'] and len(result.data) == 64
    assert all(abs(value - 42) <= 2 for value in result.data)
    image = result.metadata['steps'][0]['image_codec']
    assert image['width'] == image['height'] == 8 and image['components'] == 1
    assert image['rendering_performed'] is False
    assert decode_filters(data, ['/DCTDecode']).metadata['status'] == 'unsupported'


@pytest.mark.parametrize('change,reason', [('short', 'jpeg_end_marker_missing'),
    ('wrong_geometry', 'image_declared_geometry_mismatch'), ('budget', 'image_decoded_byte_limit'),
    ('parameters', 'image_decode_parameters_unsupported')])
def test_image_decoder_refuses_unverified_boundaries_geometry_and_parameters(change: str, reason: str) -> None:
    data = jpeg()
    options = {'media_codecs': True}
    if change == 'short':
        data = data[:-2]
    elif change == 'wrong_geometry':
        options['image_context'] = {'width': 123}
    elif change == 'budget':
        options['limits'] = FilterLimits(max_stage_bytes=3)
    else:
        options['decode_parms'] = {'/ColorTransform': 0}
    result = decode_filters(data, ['/DCTDecode'], **options)
    assert result.data is None and reason in result.metadata['reason_codes']


def test_native_jpx_decodes_generated_lossless_pixels() -> None:
    image_module = pytest.importorskip('PIL.Image')
    features = pytest.importorskip('PIL.features')
    if not features.check('jpg_2000'):
        pytest.skip('Synthetic JPX encoder is unavailable')
    buffer = io.BytesIO()
    image_module.frombytes('RGB', (2, 2), bytes([10, 20, 30]) * 4).save(buffer, format='JPEG2000', irreversible=False)
    result = decode_filters(buffer.getvalue(), ['/JPXDecode'], media_codecs=True)
    assert result.data == bytes([10, 20, 30]) * 4 and result.metadata['complete']


@pytest.mark.parametrize('builder,inspector', [(jpeg, jpeg_structure), (png, png_structure)])
def test_image_structure_metadata_is_complete_without_pixel_or_page_rendering(builder, inspector) -> None:
    data = builder()
    result = inspector(data)
    assert result['complete'] and result['width'] > 0 and result['height'] > 0
    assert inspect_image(data)['pixel_decode_performed'] is False
    assert data == builder()


def test_png_crc_failure_and_raw_raster_length_do_not_become_successes() -> None:
    data = bytearray(png())
    data[-1] ^= 1
    with pytest.raises(MediaIssue, match='png_crc_mismatch'):
        png_structure(bytes(data))
    context = {'width': 3, 'height': 2, 'components': 1, 'bits_per_component': 1}
    assert inspect_image(b'\0\0', context)['complete']
    result = inspect_image(b'\0', context)
    assert not result['complete'] and result['reason_codes'] == ['raster_size_mismatch']


def test_font_directory_checksums_bounds_and_glyph_count_are_static() -> None:
    data = font()
    result = inspect_font(data)
    assert result['complete'] and result['glyph_count'] == 12
    assert result['font_execution_performed'] is result['font_validity_verified'] is False
    changed = bytearray(data)
    changed[32] ^= 1
    result = inspect_font(bytes(changed))
    assert not result['complete'] and 'font_table_checksum_mismatch' in result['reason_codes']
    changed = bytearray(data)
    struct.pack_into('>I', changed, 20, 999999)
    assert 'font_table_bounds_invalid' in inspect_font(bytes(changed))['reason_codes']


@pytest.mark.parametrize('compressed', [False, True])
def test_flash_tag_inventory_never_executes_actions_and_uses_shared_budget(compressed: bool) -> None:
    data = flash(compressed=compressed)
    budget = DecodeBudget(1000)
    result = inspect_flash(data, budget=budget, max_expansion_ratio=100)
    assert result['complete'] and result['script_tag_count'] == 1
    assert result['execution_performed'] is False
    assert budget.remaining == (1000 - result['decoded_bytes'] if compressed else 1000)
    assert result['tags'][0]['code'] == 82


@pytest.mark.parametrize('mode', ['length', 'tag', 'compressed', 'lzma'])
def test_flash_malformed_and_unavailable_streams_retain_explicit_causes(mode: str) -> None:
    data = bytearray(flash(compressed=mode == 'compressed'))
    if mode == 'length':
        struct.pack_into('<I', data, 4, 1000)
    elif mode == 'tag':
        struct.pack_into('<H', data, 14, (82 << 6) | 50)
    elif mode == 'compressed':
        data[-1] ^= 1
    else:
        data[:3] = b'ZWS'
    with pytest.raises(MediaIssue) as caught:
        inspect_flash(bytes(data), budget=DecodeBudget(1000), max_expansion_ratio=100)
    assert caught.value.code and caught.value.status in {'decode_error', 'unsupported'}


def test_vm_stream_collector_routes_verified_recovery_and_preserves_geometry() -> None:
    body = zlib.compress(b'\x01\x02') + b'extra'
    stream = EncodedStreamObject()
    stream._data = body
    stream.update({NameObject('/Filter'): NameObject('/FlateDecode'), NameObject('/Subtype'): NameObject('/Image'),
                   NameObject('/Width'): NumberObject(2), NameObject('/Height'): NumberObject(1),
                   NameObject('/BitsPerComponent'): NumberObject(8), NameObject('/ColorSpace'): NameObject('/DeviceGray')})
    collector = StreamCollector('a' * 64, VMInspectionLimits())
    routed = []
    collector.artifact_sink = lambda data, entry: routed.append((data, entry))
    collector.observe(stream, backend='pypdf', source_id='source', object_number=1, generation=0, offset=10)
    result = collector.finish(UNLIMITED)
    assert result['status'] == 'partial' and not result['complete']
    assert routed[0][0] == b'\x01\x02' and routed[0][1]['artifact_context']['width'] == 2


@pytest.mark.parametrize('builder,kind', [(jpeg, 'jpeg'), (png, 'png'), (font, 'sfnt_font'), (flash, 'flash')])
def test_vm_carver_analyzes_media_instead_of_blanket_unsupported(builder, kind: str) -> None:
    data = builder()
    worker = RecursiveCarver('a' * 64, VMInspectionLimits())
    identity = worker.add(data, parent_id='source', decoded_sha256=sha(data))
    result = worker.finish(UNLIMITED)
    assert result['records'][0]['kind'] == kind and result['records'][0]['status'] == 'observed'
    assert result['analyses'][identity]['complete']
