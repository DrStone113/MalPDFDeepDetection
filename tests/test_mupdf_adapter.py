"""MuPDF native inventory regressions using generated inert PDF objects only."""

from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
import hashlib
import json
import subprocess
import sys

import pikepdf
import pymupdf
import pytest
from pypdf.generic import IndirectObject, NullObject, NumberObject

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.mupdf_adapter import MuPDFReader
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.parser_views import _RawBudget, inspect_parser_views
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.recovery import projected_object


def fixture(values=b'', objects=()):
    source = b'%PDF-1.7\n'
    entries = {}
    bodies = [(1, 0, b'<< /Type /Catalog /Pages 2 0 R ' + values + b' >>'),
              (2, 0, b'<< /Type /Pages /Count 0 /Kids [] >>'), *objects]
    for number, generation, body in bodies:
        entries[number] = len(source), generation
        source += f'{number} {generation} obj\n'.encode() + body + b'\nendobj\n'
    offset, count = len(source), max(entries) + 1
    source += f'xref\n0 {count}\n'.encode() + b'0000000000 65535 f \n'
    for number in range(1, count):
        position, generation = entries.get(number, (0, 0))
        source += f'{position:010d} {generation:05d} '.encode() + (b'n' if number in entries else b'f') + b' \n'
    return source + b'trailer\n<< /Root 1 0 R /Size ' + str(count).encode() + b' >>\nstartxref\n' + str(offset).encode() + b'\n%%EOF\n'


@contextmanager
def reader(data, limits=None):
    value = MuPDFReader(data, limits or CodeInspectionLimits())
    try:
        yield value
    finally:
        value.close()


def root(adapter, budget=None):
    return adapter.object({'number': 1, 'generation': None, 'offset': None}, budget or _RawBudget(1024**2))


def test_native_inventory_does_not_call_pypdf_object_parser_or_canonical_container_text(monkeypatch):
    import pypdf
    import pypdf.generic
    from malpdf.static import recovery
    def forbidden(*args, **kwargs):
        raise AssertionError('Independent native inventory must not reparse object dictionaries')
    data = fixture(b'/Probe << /JS (var inertCanary = 1;) /N 12 /Items [false null /URI] >>')
    original = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(pypdf.PdfReader, '__init__', forbidden)
    monkeypatch.setattr(pypdf.generic, 'read_object', forbidden)
    monkeypatch.setattr(recovery, 'read_object', forbidden)
    monkeypatch.setattr(pikepdf.Pdf, 'open', forbidden)
    monkeypatch.setattr(pymupdf.Document, 'xref_object', forbidden)
    monkeypatch.setattr(pymupdf.Document, 'xref_stream', forbidden)
    monkeypatch.setattr(pymupdf.Document, 'save', forbidden)
    monkeypatch.setattr(pymupdf.Page, 'get_pixmap', forbidden)
    with reader(data) as adapter:
        value, complete, reasons = root(adapter)
        assert complete and reasons == []
        assert str(value.raw_get('/Probe').raw_get('/JS')) == 'var inertCanary = 1;'
        assert adapter.version['adapter'] == 'mupdf-native-object-v1'
        assert 'inertCanary' not in json.dumps(projected_object(value, include_fields=True))
    assert hashlib.sha256(data).hexdigest() == original


@pytest.mark.parametrize(('encoded', 'expected'), [
    (b'()', b''), (b'<>', b''), (b'<6100ff807a>', b'a\x00\xff\x80z'),
    (b'(a\\(b\\)\\040c\\n)', b'a(b) c\n'), (b'<000102030405>', bytes(range(6))),
    (b'<feff004103a9>', b'\xfe\xff\x00A\x03\xa9'),
])
def test_native_strings_preserve_original_bytes_including_nul_and_unicode(encoded, expected):
    with reader(fixture(b'/Probe ' + encoded)) as adapter:
        value, complete, reasons = root(adapter)
    assert complete and not reasons
    assert value.raw_get('/Probe').original_bytes == expected


@pytest.mark.parametrize('number', [-(2**45), 2**45, 2**53 + 1, 2**63 - 1])
def test_native_int64_values_are_not_truncated_to_int32_or_converted_to_float(number):
    with reader(fixture(b'/Probe ' + str(number).encode())) as adapter:
        value, complete, reasons = root(adapter)
    assert complete and not reasons
    assert type(value.raw_get('/Probe')) is NumberObject
    assert int(value.raw_get('/Probe')) == number


def test_native_real_keeps_selected_decimal_lexeme_and_original_parser_disagreement():
    data = fixture(b'/Probe 0.123456789012345678901234567890')
    with reader(data) as adapter:
        value, complete, reasons = root(adapter)
    assert complete and not reasons
    assert isinstance(value.raw_get('/Probe'), Decimal)
    assert value.raw_get('/Probe') == Decimal('0.12345679')
    inventory = inspect_parser_views(data, CodeInspectionLimits())
    differences = [item for item in inventory['comparisons'] if item['object_number'] == 1 and item['right_backend'] == 'MuPDF']
    assert differences and any(item['projection_equal'] is False for item in differences)
    assert all(item['generation_verified'] is False for item in differences)


def test_references_keep_their_native_generation_without_loading_the_target():
    data = fixture(b'/Probe 3 7 R /Missing 99 11 R', [(3, 7, b'<< /Value 4 >>')])
    with reader(data) as adapter:
        value, complete, reasons = root(adapter)
        candidates = list(adapter.candidates())
    assert complete and not reasons
    for name, number, generation in (('/Probe', 3, 7), ('/Missing', 99, 11)):
        reference = value.raw_get(name)
        assert isinstance(reference, IndirectObject)
        assert (reference.idnum, reference.generation, reference.pdf) == (number, generation, None)
    assert all(item['generation'] is None and item['offset'] is None for item in candidates)


@pytest.mark.parametrize('values', [b'/Probe /N#FF', b'/K#FF 12 /Known 4'])
def test_unrepresentable_names_cannot_be_reported_as_confirmed_null_or_absent(values):
    data = fixture(values)
    inventory = inspect_parser_views(data, CodeInspectionLimits())
    native = next(view for view in inventory['views'] if view['backend'] == 'MuPDF')
    node = next(item for item in native['records'] if item['object_number'] == 1)
    assert node['status'] == 'partial'
    assert 'inventory_scalar_encoding_unavailable' in node['reason_codes']
    assert not node['projection']['projection_complete']
    assert not node['projection']['key_enumeration_complete']
    assert all(not field['complete'] for field in node['projection']['key_projections'])
    bundle = normalize_profile({'status': 'complete', 'raw_layout': inspect_raw_layout(data),
                               'parser_analysis': inventory}, hashlib.sha256(data).hexdigest(), 'deep-static')
    validate_bundle(bundle)


def test_supported_names_booleans_and_explicit_null_retain_their_types():
    with reader(fixture(b'/Probe /N#C3#A9 /True true /False false /Nil null')) as adapter:
        value, complete, reasons = root(adapter)
    assert complete and not reasons
    assert str(value.raw_get('/Probe')) == '/Né'
    assert value.raw_get('/True').value is True and value.raw_get('/False').value is False
    assert isinstance(value.raw_get('/Nil'), NullObject)


def test_native_depth_and_node_limits_keep_partial_prefixes():
    for values in (b'/Probe ' + b'[' * 12 + b'1' + b']' * 12,
                   b'/Probe [' + b'1 ' * 1500 + b']'):
        with reader(fixture(values)) as adapter:
            value, complete, reasons = root(adapter)
        assert not complete and reasons == ['inventory_projection_limit']
        assert '/Probe' in value and '/Type' in value


def test_native_string_byte_limit_is_explicit_and_preserves_other_fields():
    data = fixture(b'/Probe (inert) /Known 8')
    with reader(data) as adapter:
        adapter.limits = replace(CodeInspectionLimits(), max_file_bytes=3)
        value, complete, reasons = root(adapter)
    assert not complete and reasons == ['inventory_projection_limit']
    assert value.raw_get('/Known') == 8


def stream_fixture(payload):
    body = b'<< /Length ' + str(len(payload)).encode() + b' /Filter /FlateDecode >>\nstream\n' + payload + b'\nendstream'
    return fixture(b'/Probe 3 0 R /Other 4 0 R', [(3, 0, body), (4, 0, body)])


def test_raw_streams_use_the_shared_budget_without_decoding(monkeypatch):
    payload = b'inert raw bytes without a valid Flate body'
    data = stream_fixture(payload)
    def forbidden(*args, **kwargs):
        raise AssertionError('Native decoded stream must not be called')
    monkeypatch.setattr(pymupdf.Document, 'xref_stream', forbidden)
    with reader(data) as adapter:
        budget = _RawBudget(len(payload))
        first, complete, reasons = adapter.object({'number': 3}, budget)
        assert complete and not reasons and first._data == payload
        assert budget.remaining == 0
        second, complete, reasons = adapter.object({'number': 4}, budget)
        assert not complete and reasons == ['inventory_raw_byte_limit']
        assert second._data == b'' and budget.remaining == 0


def test_genuine_empty_stream_is_observed_with_zero_budget():
    with reader(stream_fixture(b'')) as adapter:
        value, complete, reasons = adapter.object({'number': 3}, _RawBudget(0))
    assert complete and not reasons and value._data == b''


def test_raw_limit_does_not_turn_missing_stream_bytes_into_an_empty_stream_measurement(monkeypatch):
    from malpdf.extraction import parser_views
    monkeypatch.setattr(parser_views, '_RawBudget', lambda *args: _RawBudget(0))
    inventory = inspect_parser_views(stream_fixture(b'benign'), CodeInspectionLimits())
    native = next(view for view in inventory['views'] if view['backend'] == 'MuPDF')
    stream = next(item for item in native['records'] if item['object_number'] == 3)
    assert 'inventory_raw_byte_limit' in stream['reason_codes']
    assert stream['projection']['stream_sha256'] is None
    assert stream['raw_retention'] is None


def test_orchestrator_import_does_not_load_the_platform_specific_worker():
    process = subprocess.run([sys.executable, '-c',
        "import sys; import malpdf.extraction.orchestrator; assert 'malpdf.static.profile_worker' not in sys.modules"],
        check=True, capture_output=True, timeout=20)
    assert process.stdout == b'' and process.stderr == b''
