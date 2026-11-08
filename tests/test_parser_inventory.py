"""Independent native parsing and comparison of generated benign PDF bytes."""

from copy import deepcopy
from dataclasses import replace
from functools import partial
import hashlib
import io
import json
import os
import re

import pikepdf
import pytest
from pypdf import PdfWriter
from pypdf.generic import (ArrayObject, DictionaryObject, EncodedStreamObject, FloatObject,
    NameObject, NumberObject, TextStringObject)
import zlib

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.parser_views import inspect_parser_views, merge_views
from malpdf.extraction.qpdf_adapter import QPDFReader
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.recovery import projected_object


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture_pdf(*, compressed=False):
    writer = PdfWriter()
    writer.add_blank_page(72,72)
    root = writer._root_object
    root[NameObject('/PrivateCanary')] = DictionaryObject({NameObject('/Label'):TextStringObject('inert private canary'),
        NameObject('/Number'):FloatObject('1.500'),NameObject('/Values'):ArrayObject([NumberObject(1),NumberObject(2)])})
    root[NameObject('/OpenAction')] = DictionaryObject({NameObject('/S'):NameObject('/JavaScript'),
        NameObject('/JS'):TextStringObject('var harmlessInventoryFixture = 1;')})
    stream = EncodedStreamObject()
    stream._data = zlib.compress(b'inert fixture stream')
    stream[NameObject('/Filter')] = NameObject('/FlateDecode')
    root[NameObject('/PrivateStream')] = writer._add_object(stream)
    buffer = io.BytesIO()
    writer.write(buffer)
    if not compressed:
        return buffer.getvalue()
    output = io.BytesIO()
    with pikepdf.Pdf.open(io.BytesIO(buffer.getvalue())) as document:
        document.save(output,object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return output.getvalue()


def generation_pdf():
    objects = [(1,0,b'<< /Type /Catalog /Pages 2 0 R /Probe 4 7 R >>'),
               (2,0,b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>'),
               (3,0,b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources <<>> >>'),
               (4,7,b'<< /Flag 123 /JS (var inert = 1;) >>')]
    data,offsets = b'%PDF-1.7\n',[]
    for number,generation,body in objects:
        offsets.append(len(data))
        data += f'{number} {generation} obj\n'.encode() + body + b'\nendobj\n'
    xref = len(data)
    data += b'xref\n0 5\n0000000000 65535 f \n'
    data += b''.join(f'{offset:010d} {generation:05d} n \n'.encode() for offset,(_,generation,_) in zip(offsets,objects))
    data += b'trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n' + str(xref).encode() + b'\n%%EOF\n'
    return data,offsets


def profile(data, inventory):
    return {'status':'complete','raw_layout':inspect_raw_layout(data),'parser_analysis':inventory}


def test_native_views_read_original_bytes_and_agree_without_rendering_or_decoding(monkeypatch):
    data = fixture_pdf()
    def forbidden(*args,**kwargs):
        raise AssertionError('Native save/decode API must not run')
    monkeypatch.setattr(pikepdf.Pdf,'save',forbidden)
    monkeypatch.setattr(pikepdf.Object,'read_bytes',forbidden)
    import pymupdf
    monkeypatch.setattr(pymupdf.Document,'xref_stream',forbidden)
    monkeypatch.setattr(pymupdf.Document,'save',forbidden)
    monkeypatch.setattr(pymupdf.Page,'get_pixmap',forbidden)
    result = inspect_parser_views(data,CodeInspectionLimits())
    assert {view['backend'] for view in result['views']} == {'pypdf','QPDF','MuPDF'}
    assert result['complete'] is True
    assert all(comparison['result'] == 'projection_equal' for comparison in result['comparisons'])
    qpdf = next(view for view in result['views'] if view['backend'] == 'QPDF')
    assert qpdf['repair_requested'] is False and qpdf['version']['qpdf'] == pikepdf.__libqpdf_version__
    assert all(node['byte_offset'] is not None for node in qpdf['records'])
    assert 'inert private canary' not in json.dumps(result) and 'harmlessInventoryFixture' not in json.dumps(result)
    bundle = normalize_profile(profile(data,result),sha(data),'deep-static')
    validate_bundle(bundle)
    assert bundle['coverage_report']['backends']['qpdf']['observation_status'] == 'observed'
    assert bundle['coverage_report']['backends']['MuPDF']['graph_observation_status'] == 'not_run'
    assert all(feature['observation_status'] == 'partial' for feature in bundle['feature_store']['records'] if feature['feature_name'].startswith('inventory_'))


def test_qpdf_preserves_nonzero_generation_verified_offsets_and_mupdf_uncertainty():
    data,offsets = generation_pdf()
    result = inspect_parser_views(data,CodeInspectionLimits())
    qpdf = next(view for view in result['views'] if view['backend'] == 'QPDF')
    node = next(node for node in qpdf['records'] if node['object_number'] == 4)
    assert node['generation'] == 7 and node['byte_offset'] == offsets[3]
    mupdf = next(view for view in result['views'] if view['backend'] == 'MuPDF')
    assert all(node['generation'] is None and node['byte_offset'] is None for node in mupdf['records'])
    pairs = [comparison for comparison in result['comparisons'] if comparison['object_number'] == 4]
    assert any(row['left_backend'] == 'pypdf' and row['right_backend'] == 'QPDF' and row['generation_verified'] for row in pairs)
    assert all(row['generation_verified'] is False for row in pairs if row['right_backend'] == 'MuPDF')


def test_qpdf_compressed_objects_have_container_identity_and_unknown_file_offset():
    data = fixture_pdf(compressed=True)
    result = inspect_parser_views(data,CodeInspectionLimits())
    qpdf = next(view for view in result['views'] if view['backend'] == 'QPDF')
    compressed = [node for node in qpdf['records'] if node['xref'].get('xref_type') == 2]
    assert compressed and all(node['generation'] == 0 and node['byte_offset'] is None for node in compressed)
    assert all(type(node['xref']['object_stream_number']) is int and type(node['xref']['object_stream_index']) is int for node in compressed)
    assert result['comparisons']


def test_field_projections_are_optional_and_do_not_change_original_hashes():
    value = DictionaryObject({NameObject('/Known'):NumberObject(123),NameObject('/Private'):TextStringObject('inert canary')})
    old,new = projected_object(value),projected_object(value,include_fields=True)
    assert {key:new[key] for key in old} == old
    assert len(new['key_projections']) == 2 and new['key_enumeration_complete']
    assert sha(b'/Private') in {row['key_sha256'] for row in new['key_projections']}
    assert 'inert canary' not in json.dumps(new)
    many = DictionaryObject({NameObject('/K'+str(index)):NumberObject(index) for index in range(70)})
    truncated = projected_object(many,include_fields=True)
    assert truncated['projection_complete'] is True and truncated['key_enumeration_complete'] is False
    assert len(truncated['key_projections']) == 64


def test_qpdf_decimal_projection_preserves_native_precision_without_float_cast():
    from decimal import Decimal
    from malpdf.extraction.parser_views import _RawBudget


    with pikepdf.Pdf.new(conversion_mode='explicit') as document, pikepdf.explicit_conversion():
        value = document.make_indirect(pikepdf.Object.parse(b'<< /Number 0.123456789012345678901234567890 >>'))
        adapter = QPDFReader.__new__(QPDFReader)
        adapter.library,adapter.document,adapter.limits = pikepdf,document,CodeInspectionLimits()
        converted,complete,reasons = adapter.object({'number':value.objgen[0],'generation':value.objgen[1]},_RawBudget(100))
        assert complete and not reasons
        assert str(converted.raw_get('/Number')) == '0.123456789012345678901234567890'
        assert isinstance(converted.raw_get('/Number'),Decimal)
        rounded = DictionaryObject({NameObject('/Number'):FloatObject('0.12345678901234568')})
        assert projected_object(converted)['projected_values_sha256'] != projected_object(rounded)['projected_values_sha256']


@pytest.mark.parametrize('difference',['generation','stream'])
def test_generation_and_raw_stream_conflicts_are_preserved_with_localization(difference):
    data = fixture_pdf()
    result = inspect_parser_views(data,CodeInspectionLimits())
    left,right = result['views'][:2]
    node = next(row for row in right['records'] if row['projection']['stream_sha256'])
    if difference == 'generation':
        node['generation'] = 7
    else:
        node['projection']['stream_sha256'] = 'e'*64
    result['comparisons'],_ = merge_views(result['views'])
    expected = 'generation_selection_conflict' if difference == 'generation' else 'value_projection_conflict'
    assert any(row['result'] == expected for row in result['comparisons'])
    bundle = normalize_profile(profile(data,result),sha(data),'deep-static')
    assert any(row['reason_code'] == expected and row['fields'] for row in bundle['evidence_store']['conflicts'])


def test_differential_merger_localizes_key_values_without_resolving_disagreements():
    data = fixture_pdf()
    result = inspect_parser_views(data,CodeInspectionLimits())
    left,right = result['views'][:2]
    node = next(row for row in right['records'] if row['projection']['key_projections'])
    target = next(row for row in left['records'] if row['object_number'] == node['object_number'] and row['generation'] == node['generation'])
    key = target['projection']['key_projections'][0]['key_sha256']
    node['projection']['projected_values_sha256'] = 'f'*64
    next(row for row in node['projection']['key_projections'] if row['key_sha256'] == key)['value_sha256'] = 'e'*64
    comparisons,complete = merge_views(result['views'])
    assert complete
    conflict = next(row for row in comparisons if row['left_id'] == target['id'] and row['right_id'] == node['id'])
    assert conflict['result'] == 'value_projection_conflict'
    assert {'key_sha256':key,'difference':'value_projection_conflict'} in conflict['key_differences']
    result['comparisons'] = comparisons
    bundle = normalize_profile(profile(data,result),sha(data),'deep-static')
    assert any(row['reason_code'] == 'value_projection_conflict' for row in bundle['evidence_store']['conflicts'])
    assert bundle['evidence_store']['conflicts'][0]['resolution'].startswith('unresolved')


@pytest.mark.parametrize('complete',[True,False])
def test_missing_objects_stay_scoped_to_the_actual_enumeration(complete):
    result = inspect_parser_views(fixture_pdf(),CodeInspectionLimits())
    left,right = deepcopy(result['views'][:2])
    missing = right['records'].pop()
    right['complete'] = complete
    comparisons,_ = merge_views([left,right])
    item = next(
        row for row in comparisons if row['object_number'] == missing['object_number'] and row['right_id'] is None)
    assert item['result'] == ('only_in_enumerated_view' if complete else 'not_observed_in_partial_view')
    assert item['projection_equal'] is None


def test_multiple_generations_are_not_aliased_to_one_unknown_mupdf_generation():
    data,_ = generation_pdf()
    result = inspect_parser_views(data,CodeInspectionLimits())
    known,unknown = deepcopy(result['views'][1:])
    node = next(row for row in known['records'] if row['object_number'] == 4)
    extra = deepcopy(node)
    extra.update(id='distinct-synthetic-generation',generation=0)
    known['records'].append(extra)
    comparisons,_ = merge_views([known,unknown])
    rows = [row for row in comparisons if row['object_number'] == 4]
    assert len(rows) == 3 and all(not row['generation_verified'] for row in rows)
    assert all(row['projection_equal'] is None for row in rows)


@pytest.mark.parametrize('failure',['object_limit','raw_limit','metadata_limit','backend_missing','bad_retention'])
def test_bounded_failures_preserve_prior_observations_and_fixed_reasons(failure,monkeypatch):
    from malpdf.extraction import parser_views
    data,limits = fixture_pdf(),CodeInspectionLimits()
    kwargs = {}
    if failure == 'object_limit':
        limits = replace(limits,max_objects=1)
    elif failure == 'raw_limit':


        class EmptyBudget:
            def __init__(self,*args):
                self.remaining = 0
        monkeypatch.setattr(parser_views,'_RawBudget',EmptyBudget)
    elif failure == 'metadata_limit':
        kwargs['max_metadata_bytes'] = 3000
    elif failure == 'backend_missing':
        def unavailable(*args):
            raise ImportError('private canary dependency diagnostic')
        monkeypatch.setattr(parser_views,'QPDFReader',unavailable)
    else:
        kwargs['retain'] = lambda data:{'sha256':'0'*64,'size_bytes':len(data),'status':'retained'}
    result = inspect_parser_views(data,limits,**kwargs)
    assert result['complete'] is False
    assert result['views'] and any(view['records'] for view in result['views'])
    assert 'private canary' not in json.dumps(result)
    if failure == 'backend_missing':
        failed = next(view for view in result['views'] if view['backend'] == 'QPDF')
        assert failed['status'] == 'unsupported' and failed['records'] == []
        assert next(view for view in result['views'] if view['backend'] == 'MuPDF')['records']
    if failure == 'metadata_limit':
        assert result['reason_codes'] == ['inventory_metadata_limit']
        assert len(json.dumps(result,separators=(',',':')).encode()) <= 3000


def test_encrypted_fixture_does_not_attempt_passwords_or_publish_content():
    writer = PdfWriter()
    writer.add_blank_page(72,72)
    writer.encrypt('synthetic fixture password')
    output = io.BytesIO()
    writer.write(output)
    result = inspect_parser_views(output.getvalue(),CodeInspectionLimits())
    assert all(view['status'] == 'encrypted' and view['records'] == [] for view in result['views'])
    assert 'synthetic fixture password' not in json.dumps(result)


def test_qpdf_refusal_preserves_other_views_and_redacted_late_parser_notices():
    data = re.sub(rb'startxref\n\d+\n',b'startxref\n0\n',fixture_pdf())
    result = inspect_parser_views(data,CodeInspectionLimits())
    qpdf = next(view for view in result['views'] if view['backend'] == 'QPDF')
    assert qpdf['status'] == 'partial' and not qpdf['records']
    pypdf = next(view for view in result['views'] if view['backend'] == 'pypdf')
    assert pypdf['warnings']['count'] > 0 and not pypdf['complete']
    mupdf = next(view for view in result['views'] if view['backend'] == 'MuPDF')
    assert mupdf['records'] and all(node['is_synthetic_repaired'] for node in mupdf['records'])
    pairs = [row for row in result['comparisons'] if row['right_backend'] == 'QPDF']
    assert pairs and all(row['result'] == 'not_observed_in_partial_view' for row in pairs)
    assert 'harmlessInventoryFixture' not in json.dumps(result)


def test_inventory_input_identity_and_export_references_are_checked():
    data = fixture_pdf()
    with pytest.raises(ValueError,match='inventory_input_invalid'):
        inspect_parser_views(bytearray(data),CodeInspectionLimits())
    with pytest.raises(ValueError,match='inventory_input_invalid'):
        inspect_parser_views(data,CodeInspectionLimits(max_file_bytes=10))
    result = inspect_parser_views(data,CodeInspectionLimits())
    with pytest.raises(ValueError,match='parser_inventory_document_mismatch'):
        normalize_profile(profile(data,{**result,'document_sha256':'a'*64}),sha(data),'deep-static')
    broken = deepcopy(result)
    broken['comparisons'][0]['left_id'] = 'missing-source'
    with pytest.raises(ValueError,match='parser_comparison_source_missing'):
        normalize_profile(profile(data,broken),sha(data),'deep-static')
    broken = deepcopy(result)
    broken['views'][0]['records'].append(broken['views'][0]['records'][0])
    with pytest.raises(ValueError,match='duplicate_parser_object_identity'):
        normalize_profile(profile(data,broken),sha(data),'deep-static')


def _inventory_checkpoint_then_stall(connection,path,boundary,digest,limits,*args,prepared):
    import time
    os.setsid()
    assert prepared['static']['input']['sha256']==digest
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':prepared}).encode())
    time.sleep(30)


@pytest.mark.skipif(os.name != 'posix', reason='Requires Linux fork, process groups and resource limits')
def test_worker_timeout_keeps_native_inventory_and_primary_checkpoint(tmp_path,monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context = multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *args:context)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args:1)
    data = fixture_pdf()



    limits=CodeInspectionLimits(wall_seconds=1,cpu_seconds=1)
    prepared={'status':'complete','errors':[],
        'static':{'input':{'sha256':sha(data)},'features':{'JS':1}},'code':None,
        'raw_layout':inspect_raw_layout(data),'parser_analysis':inspect_parser_views(data,limits)}
    monkeypatch.setattr(profile_worker,'_profile_child',partial(_inventory_checkpoint_then_stall,prepared=prepared))
    result = profile_worker.profile_pdf(tmp_path/'unused.pdf',boundary=tmp_path,digest=sha(data),
        analysis_version='v9',extraction_profile='deep-static',limits=limits)
    assert result['status'] == 'timeout' and result['worker_cleanup_complete']
    assert result['parser_analysis']['worker_failure_codes'] == ['wall_timeout']
    bundle = normalize_profile(result,sha(data),'deep-static')
    assert bundle['status'] == 'timeout'
    assert any(record['kind'] == 'parser_object' for record in bundle['evidence_store']['records'])


@pytest.mark.skipif(os.name != 'posix', reason='Requires the Linux disposable parser worker and resource limits')
def test_isolated_inventory_preserves_primary_and_parent_verified_raw_streams(tmp_path):
    from malpdf.static.profile_worker import profile_pdf
    data = fixture_pdf()
    path = tmp_path/'synthetic.pdf'
    path.write_bytes(data)
    limits = CodeInspectionLimits(wall_seconds=20,cpu_seconds=12)
    baseline = profile_pdf(path,boundary=tmp_path,digest=sha(data),limits=limits,analysis_version='v9')
    result = extract_pdf(path,boundary=tmp_path,limits=limits,raw_artifact_dir=tmp_path/'blobs')
    primary = next(record for record in result['evidence_store']['records'] if record['kind'] == 'primary_checkpoint' and record['evidence_id'] == 'primary:'+sha(data))
    assert primary['details']['features'] == baseline['static']['features']
    assert primary['details']['source_profile']['code'] == baseline['code']
    assert primary['details']['source_profile']['analysis_v8'] == baseline['analysis_v8']
    nodes = [record for record in result['evidence_store']['records'] if record['kind'] == 'parser_object']
    assert {node['backend'] for node in nodes} == {'pypdf','QPDF','MuPDF'}
    retained = [node['details']['raw_retention'] for node in nodes if node['details']['raw_retention']]
    assert retained and all(item['parent_verification_status'] == 'verified' for item in retained)
    assert path.read_bytes() == data
    assert result['coverage_report']['worker']['worker_cleanup_complete']
