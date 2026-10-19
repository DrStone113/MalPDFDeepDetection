"""Incomplete native projections cannot certify values or parser conflicts."""

import hashlib

import pytest
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject

from malpdf.extraction.parser_views import _RawBudget, inspect_parser_views, merge_views
from malpdf.extraction.qpdf_adapter import QPDFReader
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.recovery import projected_object
from test_mupdf_adapter import fixture


@pytest.mark.parametrize('container', [ArrayObject, lambda values: DictionaryObject({
    NameObject(f'/K{index:04d}'): value for index, value in enumerate(values)})])
def test_truncated_nested_container_marks_its_root_field_incomplete(container):
    value = DictionaryObject({NameObject('/A'): NumberObject(7),
        NameObject('/Probe'): container([NumberObject(1) for _ in range(1100)])})
    result = projected_object(value, include_fields=True, limits=CodeInspectionLimits())
    fields = {field['key_sha256']: field for field in result['key_projections']}
    assert not result['projection_complete'] and not result['key_enumeration_complete']
    assert fields[hashlib.sha256(b'/A').hexdigest()]['complete']
    assert not fields[hashlib.sha256(b'/Probe').hexdigest()]['complete']


def test_merger_does_not_report_a_confirmed_conflict_using_a_truncated_field():
    left = projected_object(DictionaryObject({NameObject('/Probe'): ArrayObject([NumberObject(1)] * 1100)}), include_fields=True)
    right = projected_object(DictionaryObject({NameObject('/Probe'): ArrayObject([NumberObject(1)])}), include_fields=True)
    views = []
    for backend, projection in [('pypdf', left), ('QPDF', right)]:
        views.append({'backend': backend, 'complete': False, 'records': [{
            'id': backend + ':1', 'object_number': 1, 'generation': 0, 'projection': projection}]})
    comparisons, complete = merge_views(views)
    assert complete and len(comparisons) == 1
    assert comparisons[0]['projection_equal'] is None
    assert comparisons[0]['key_differences'] == []
    assert comparisons[0]['result'] == 'projection_unavailable'


def test_depth_failure_does_not_invalidate_a_later_independent_scalar():
    nested = NumberObject(1)
    for _ in range(12):
        nested = ArrayObject([nested])
    result = projected_object(DictionaryObject({NameObject('/A'): nested, NameObject('/B'): NumberObject(7)}), include_fields=True)
    fields = {field['key_sha256']: field for field in result['key_projections']}
    assert not result['projection_complete']
    assert not fields[hashlib.sha256(b'/A').hexdigest()]['complete']
    assert fields[hashlib.sha256(b'/B').hexdigest()]['complete']


def wide_stream():
    body = b'<< /Length 6 /Probe [' + b'1 ' * 1100 + b'] >>\nstream\nbenign\nendstream'
    return fixture(b'/Probe 3 0 R', [(3, 0, body)])


def test_qpdf_reports_both_projection_exhaustion_and_raw_byte_exhaustion():
    reader = QPDFReader(wide_stream(), CodeInspectionLimits())
    try:
        value, complete, reasons = reader.object({'number': 3, 'generation': 0}, _RawBudget(0))
    finally:
        reader.close()
    assert not complete and value._data == b''
    assert set(reasons) == {'inventory_projection_limit', 'inventory_raw_byte_limit'}


def test_inventory_propagates_combined_limits_without_empty_hash_or_confirmed_fields(monkeypatch):
    from malpdf.extraction import parser_views
    monkeypatch.setattr(parser_views, '_RawBudget', lambda *args: _RawBudget(0))
    inventory = inspect_parser_views(wide_stream(), CodeInspectionLimits())
    qpdf = next(view for view in inventory['views'] if view['backend'] == 'QPDF')
    stream = next(item for item in qpdf['records'] if item['object_number'] == 3)
    assert stream['status'] == 'partial' and stream['raw_retention'] is None
    assert stream['projection']['stream_sha256'] is None
    assert not stream['projection']['key_enumeration_complete']
    assert not any(field['complete'] for field in stream['projection']['key_projections'])
    assert 'inventory_projection_limit' in stream['reason_codes']
    assert 'inventory_raw_byte_limit' in stream['reason_codes']
