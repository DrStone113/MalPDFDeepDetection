"""Only generated benign bytes: bounded recursion, provenance and failure cases."""

from copy import deepcopy
import hashlib
import io
import json
import os
import stat
import struct
import zipfile

import pytest
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject, TextStringObject

from malpdf.extraction.carving import CarvingLimits, RecursiveCarver, artifact_kind
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.triggers import plan_triggers
from malpdf.static.analyzer import StaticPDFAnalyzer
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.safety import StaticInspectionLimits


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(members, *, compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=compression) as writer:
        for name, body in members:
            writer.writestr(name, body)
    return output.getvalue()


def pdf(*bodies, action=False):
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    for index, body in enumerate(bodies):
        stream = DecodedStreamObject()
        stream.set_data(body)
        writer._root_object[NameObject('/Private' + str(index))] = writer._add_object(stream)
    if action:
        writer._root_object[NameObject('/OpenAction')] = DictionaryObject({
            NameObject('/S'): NameObject('/JavaScript'), NameObject('/JS'): TextStringObject('var inertFixture = 1;')})
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def carver(*, limits=None, code=None, root='a' * 64, checkpoint=None):
    return RecursiveCarver(root, code or CodeInspectionLimits(), limits=limits, checkpoint=checkpoint)


def admit(worker, body, **kwargs):
    return worker.add(body, parent_id=kwargs.pop('parent_id', 'synthetic-source'), decoded_sha256=sha(body), **kwargs)


def test_snapshot_preserves_canonical_values_without_a_temporary_child_pdf(tmp_path):
    data = pdf(action=True)
    path = tmp_path / 'benign.pdf'
    path.write_bytes(data)
    analyzer = StaticPDFAnalyzer()
    on_disk = analyzer.inspect(path)
    snapshot = analyzer.inspect_snapshot(data, expected_sha256=sha(data))
    assert snapshot.features == on_disk.features
    assert snapshot.parser == on_disk.parser
    assert snapshot.diagnostics == on_disk.diagnostics
    assert snapshot.errors == on_disk.errors
    assert snapshot.input['path'] is None and snapshot.input['sha256'] == sha(data)
    assert path.read_bytes() == data


@pytest.mark.parametrize(('body', 'digest', 'limit', 'code'), [
    (bytearray(b'abc'), None, 100, 'invalid_snapshot'),
    (b'abc', 'b' * 64, 100, 'snapshot_checksum_mismatch'),
    (b'abc', None, 2, 'file_size_limit'),
])
def test_snapshot_rejects_invalid_identity_and_size_before_parsing(body, digest, limit, code):
    result = StaticPDFAnalyzer(StaticInspectionLimits(max_file_size_bytes=limit)).inspect_snapshot(body, expected_sha256=digest)
    assert result.errors[0].code == code and result.errors[0].fatal
    assert result.parser['success'] is False


def test_archive_is_bounded_in_memory_and_names_never_become_paths(monkeypatch):
    data = archive([('../canary.js', b'var inert = 1;'), ('empty', b''), ('unknown.bin', b'inert bytes')])
    def forbidden(*args, **kwargs):
        raise AssertionError('Archive extraction APIs must never run')
    for name in ('open', 'read', 'extract', 'extractall'):
        monkeypatch.setattr(zipfile.ZipFile, name, forbidden)
    worker = carver()
    admit(worker, data)
    result = worker.finish(1000)
    rows = next(analysis['zip_members'] for analysis in result['analyses'].values() if 'zip_members' in analysis)
    assert rows[0]['unsafe_path'] is True
    assert all(row['status'] == 'observed' for row in rows)
    assert {entry['kind'] for entry in result['records']} == {'zip', 'javascript_candidate', 'empty', 'unknown'}
    assert result['status'] == 'partial'  # Unknown binary remains unsupported.
    assert result['decoded_bytes_used'] == 25
    script = next(analysis for analysis in result['analyses'].values() if 'ast' in analysis)
    assert script['ast']['node_count'] > 0 and script['execution_performed'] is False
    assert 'canary.js' not in json.dumps(result) and 'var inert' not in json.dumps(result)


def test_deflate_crc_failure_retains_prefix_without_routing_it():
    data = bytearray(archive([('inert.js', b'var safeFixture = 1;')], compression=zipfile.ZIP_DEFLATED))
    central = data.index(b'PK\x01\x02')
    # Matching but false CRC in both headers must fail after bounded decoding.
    struct.pack_into('<I', data, 14, 123)
    struct.pack_into('<I', data, central + 16, 123)
    worker = carver()
    root = admit(worker, bytes(data))
    result = worker.finish(1000)
    row = result['analyses'][root]['zip_members'][0]
    assert row['status'] == 'decode_error' and row['artifact_id'] is None
    assert row['observed_prefix_bytes'] == len(b'var safeFixture = 1;')
    assert row['retention']['sha256'] == sha(b'var safeFixture = 1;')
    assert len(result['records']) == 1


@pytest.mark.parametrize('mode', ['encrypted', 'unsupported', 'symlink', 'header_mismatch', 'descriptor_mismatch'])
def test_archive_member_failures_are_explicit(mode):
    if mode == 'symlink':
        info = zipfile.ZipInfo('alias')
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        data = bytearray(archive([(info, b'inert target')]))
    else:
        data = bytearray(archive([('inert.js', b'var safe = 1;')]))
    central = data.index(b'PK\x01\x02')
    if mode in {'encrypted', 'descriptor_mismatch'}:
        flag = 1 if mode == 'encrypted' else 8
        struct.pack_into('<H', data, 6, flag)
        struct.pack_into('<H', data, central + 8, flag)
    if mode == 'unsupported':
        struct.pack_into('<H', data, 8, 12)
        struct.pack_into('<H', data, central + 10, 12)
    if mode == 'header_mismatch':
        struct.pack_into('<I', data, 18, 1)
    worker = carver()
    identifier = admit(worker, bytes(data))
    result = worker.finish(1000)
    row = result['analyses'][identifier]['zip_members'][0]
    expected = {'encrypted': 'encrypted', 'unsupported': 'unsupported', 'symlink': 'unsupported',
                'header_mismatch': 'decode_error', 'descriptor_mismatch': 'decode_error'}[mode]
    assert row['status'] == expected and row['artifact_id'] is None
    assert len(result['records']) == 1


def test_data_descriptor_supported_without_zipfile_decompressor():
    class ForwardOnly(io.BytesIO):
        def seekable(self):
            return False
        def seek(self, *args):
            raise io.UnsupportedOperation('synthetic forward-only output')
    output = ForwardOnly()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as writer:
        writer.writestr('inert.js', 'var safe = 1;')
    worker = carver()
    identifier = admit(worker, output.getvalue())
    result = worker.finish(1000)
    assert result['analyses'][identifier]['zip_members'][0]['status'] == 'observed'


@pytest.mark.parametrize(('limits', 'remaining', 'reason'), [
    (CarvingLimits(max_depth=1), 1000, 'artifact_analysis_partial'),
    (CarvingLimits(max_artifacts=1), 1000, 'artifact_analysis_partial'),
    (CarvingLimits(max_archive_members=1), 1000, 'zip_member_count_limit'),
    (CarvingLimits(), 3, 'artifact_analysis_partial'),
    (CarvingLimits(max_expansion_ratio=1), 1000, 'artifact_analysis_partial'),
])
def test_archive_limits_prevent_unbounded_descendants(limits, remaining, reason):
    worker = carver(limits=limits)
    data = archive([('first.js', b'var a = "' + b'x' * 100 + b'";'), ('second.js', b'var b = 1;')],
                   compression=zipfile.ZIP_DEFLATED)
    identifier = admit(worker, data)
    result = worker.finish(remaining)
    assert result['complete'] is False and reason in result['reason_codes']
    assert result['decoded_bytes_used'] <= remaining
    assert len(result['records']) <= limits.max_artifacts
    assert result['records'][0]['id'] == identifier


def test_exact_content_reuses_analysis_but_keeps_both_lineages_and_depth():
    worker = carver()
    body = archive([('one.js', b'var a = 1;'), ('two.js', b'var a = 1;')])
    outer = admit(worker, body)
    result = worker.finish(1000)
    children = [entry for entry in result['records'] if entry['container_id'] == outer]
    assert len(children) == 2 and children[0]['id'] != children[1]['id']
    assert children[1]['reused_from_id'] == children[0]['id']
    assert children[0]['depth'] == children[1]['depth'] == 2
    assert len(result['analyses']) == 2 and result['complete'] is True


def test_cycle_identity_queue_and_retention_validation():
    body = pdf()
    worker = carver(root=sha(body))
    admit(worker, body)
    result = worker.finish(1000)
    assert result['records'][0]['reason_codes'] == ['artifact_ancestor_cycle']
    assert result['analyses'] == {}
    worker = carver(limits=CarvingLimits(max_artifact_bytes=4))
    admit(worker, b'var a = 1;', hint='javascript')
    assert worker.finish(1000)['records'][0]['status'] == 'resource_limit'
    worker = carver()
    with pytest.raises(ValueError, match='artifact_source_identity_mismatch'):
        worker.add(body, parent_id='source', decoded_sha256='f' * 64)
    worker.retain = lambda data: {'sha256': 'f' * 64, 'size_bytes': len(data)}
    with pytest.raises(ValueError, match='artifact_retention_identity_mismatch'):
        admit(worker, body)


@pytest.mark.parametrize(('kind', 'data', 'parameters', 'expected'), [
    ('object_stream', b'9 0 10 4 123 << /S /JavaScript /JS (var a = 1;) >>', {'objects': 2, 'first': 9}, 'observed'),
    ('object_stream', b'9 0 123 garbage', {'objects': 1, 'first': 4}, 'partial'),
    ('object_stream', b'9 0 9 4 123 true', {'objects': 2, 'first': 8}, 'partial'),
    ('object_stream', b'9 50 123', {'objects': 1, 'first': 5}, 'decode_error'),
    ('object_stream', b'9 0 123', {}, 'unsupported'),
    ('xfa_xml', b'<root><script contentType="application/x-javascript">var a = 1;</script></root>', {}, 'observed'),
    ('xfa_xml', b'<!DOCTYPE root [<!ENTITY a "inert">]><root>&a;</root>', {}, 'partial'),
    ('xfa_xml', b'<root><script contentType="application/x-javascript" href="inert">var a = 1;</script></root>', {}, 'partial'),
])
def test_object_and_xml_syntax_stays_inert_with_partial_evidence(kind, data, parameters, expected):
    worker = carver()
    identifier = admit(worker, data, hint=kind, metadata=parameters)
    result = worker.finish(1000)
    assert result['records'][0]['status'] == expected
    if expected in {'observed', 'partial'}:
        assert identifier in result['analyses']
    assert 'var a' not in json.dumps(result)


def test_ast_script_and_xml_budgets_are_shared_and_prior_exhaustion_is_kept():
    worker = carver(code=CodeInspectionLimits(max_scripts=1, max_objects=2))
    admit(worker, b'var a = 1;', hint='javascript', slot=1)
    admit(worker, b'var b = 2;', hint='javascript', slot=2)
    admit(worker, b'<root><one/><two/></root>', hint='xfa_xml', slot=3)
    result = worker.finish(1000)
    assert result['scripts_remaining'] == result['xml_nodes_remaining'] == 0
    assert [item['status'] for item in result['records']] == ['observed', 'resource_limit', 'partial']
    worker = carver()
    admit(worker, b'var a = 1;', hint='javascript')
    result = worker.finish(1000, root_analysis={'budget_usage': {}, 'observations': []},
                           prior_code=[{'errors': ['ast_node_limit']}])
    assert result['records'][0]['status'] == 'resource_limit' and result['ast_nodes_remaining'] == 0


def test_metadata_overflow_retains_last_valid_checkpoint():
    checkpoints = []
    worker = carver(limits=CarvingLimits(max_metadata_bytes=2300), checkpoint=lambda value: checkpoints.append(value))
    admit(worker, archive([('first.js', b'var a = 1;'), ('second.js', b'var b = 2;')]))
    result = worker.finish(1000)
    assert result['complete'] is False and 'artifact_metadata_limit' in result['reason_codes']
    assert checkpoints and result == checkpoints[-1]
    assert all(len(json.dumps(value, separators=(',', ':')).encode()) < 3000 for value in checkpoints)


def test_first_metadata_overflow_has_a_small_explicit_unavailable_summary():
    worker = carver(limits=CarvingLimits(max_metadata_bytes=2048))
    for index in range(8):
        admit(worker, b'var a = ' + str(index).encode() + b';', hint='javascript', slot=index)
    result = worker.finish(1000)
    assert result['records'] == [] and result['omitted_artifacts_lower_bound'] == 8
    assert result['reason_codes'] == ['artifact_metadata_limit']
    assert len(json.dumps(result, separators=(',', ':')).encode()) < 2048


def test_xml_and_utf8_scripts_keep_the_same_normalized_syntax_identity():
    worker = carver()
    text = 'var café = 1;'
    xml = ('<root><script contentType="application/x-javascript">' + text + '</script></root>').encode()
    first = admit(worker, xml, hint='xfa_xml')
    second = admit(worker, text.encode(), hint='javascript_candidate', slot='other')
    result = worker.finish(1000)
    script = result['analyses'][first]['scripts'][0]
    reused = result['analyses'][second]
    assert script['analysis']['decoded_script_sha256'] == reused['decoded_script_sha256'] == sha(text.encode())
    assert reused['reused_from_evidence_id'] == script['id']
    assert result['scripts_remaining'] == worker.code_limits.max_scripts - 1


def test_existing_validated_ast_is_reused_without_new_ast_budget():
    from malpdf.static.js_ast import inspect_js_syntax
    body = b'var a = 1;'
    worker = carver()
    identifier = admit(worker, body, hint='javascript')
    analysis = {'observations': [{'id': 'verified-script', 'kind': 'script', 'source_object_id': 'source',
        'extraction_status': 'complete', 'ast_status': 'complete', 'decoded_validated': True,
        'decoded_sha256': sha(body), 'ast_summary': inspect_js_syntax(body.decode())}],
        'budget_usage': {'ast_nodes_prior': worker.code_limits.max_ast_nodes}}
    result = worker.finish(1000, root_analysis=analysis)
    assert result['ast_nodes_remaining'] == 0
    assert result['analyses'][identifier]['reused_from_evidence_id'] == 'verified-script'
    assert result['records'][0]['status'] == 'observed'


def test_new_artifact_ast_time_is_recorded_separately_from_native_pdf_parsing():
    from malpdf.static.profiling import StageTimings
    timing = StageTimings()
    worker = carver()
    admit(worker,b'var a = 1;',hint='javascript')
    worker.finish(1000,timings=timing)
    assert timing.seconds['js_ast'] > 0
    assert timing.seconds['parse_pdf'] is None


def test_pdf_child_quota_does_not_reset_and_failed_accounting_burns_sibling_budget(monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError('private synthetic parser context')
    monkeypatch.setattr(StaticPDFAnalyzer, 'inspect_snapshot', fail)
    worker = carver(code=CodeInspectionLimits(max_objects=10))
    admit(worker, pdf())
    admit(worker, b'var a = 1;', hint='javascript', slot='sibling')
    result = worker.finish(1000)
    assert result['per_pass_object_allowance_remaining'] == 0
    assert result['decoded_bytes_remaining'] == result['ast_nodes_remaining'] == result['scripts_remaining'] == 0
    assert result['records'][1]['status'] == 'resource_limit'
    assert 'private synthetic' not in json.dumps(result)


def test_empty_and_unknown_inputs_do_not_imply_whole_file_absence():
    worker = carver()
    for index in range(70):
        assert admit(worker, b'inert', slot=index) is None
    result = worker.finish(0)
    assert len(result['unclassified_inputs']) == worker.limits.max_artifacts
    assert result['reason_codes'] == ['unclassified_input_limit'] and result['complete'] is False


@pytest.mark.parametrize('mode', ['missing_end', 'wrong_count', 'zip64', 'multidisk', 'version'])
def test_zip_directory_errors_are_bounded_and_explicit(mode):
    body = bytearray(archive([('inert.js', b'var a = 1;')]))
    end = body.index(b'PK\x05\x06')
    if mode == 'missing_end':
        body = body[:end]
    elif mode == 'wrong_count':
        struct.pack_into('<HH', body, end + 8, 2, 2)
    elif mode == 'zip64':
        struct.pack_into('<I', body, end + 16, 0xffffffff)
    elif mode == 'multidisk':
        struct.pack_into('<H', body, end + 4, 1)
    else:
        struct.pack_into('<H', body, body.index(b'PK\x01\x02') + 6, 127)
    worker = carver()
    admit(worker, bytes(body))
    result = worker.finish(1000)
    assert result['complete'] is False and len(result['records']) == 1
    assert result['records'][0]['status'] in {'partial', 'decode_error', 'unsupported'}


def test_stream_routing_failure_preserves_the_completed_decoder():
    from malpdf.extraction.streams import StreamCollector
    def fail(*args):
        raise ValueError('private routing context')
    stream = DecodedStreamObject()
    stream.set_data(b'var a = 1;')
    collector = StreamCollector('a' * 64, CodeInspectionLimits(), artifact_sink=fail)
    collector.observe(stream, backend='pypdf', source_id='synthetic-source', object_number=8, generation=0, offset='unknown')
    result = collector.finish(1000)
    assert result['records'][0]['status'] == 'observed'
    assert result['records'][0]['decode']['decoded_bytes'] == len(b'var a = 1;')
    assert result['reason_codes'] == ['artifact_routing_failed']
    assert 'private routing' not in json.dumps(result)


def _carving_checkpoint_then_stall(connection, path, boundary, digest, limits, *args):
    import time
    os.setsid()
    data = pdf()
    worker = carver(root=digest)
    admit(worker, b'var a = 1;', hint='javascript', parent_id='original:' + digest)
    carving = worker.finish(1000)
    carving.update(status='partial', complete=False, active_artifact_id='unfinished-sibling')
    from malpdf.extraction.raw import inspect_raw_layout
    layout = inspect_raw_layout(data)
    layout['sha256'] = digest  # Synthetic checkpoint injection, no actual path read.
    connection.send_bytes(json.dumps({'event': 'checkpoint', 'profile': {'status': 'complete', 'errors': [],
        'static': {'input': {'sha256': digest}, 'features': {'JS': 1}}, 'code': None,
        'raw_layout': layout, 'carving': carving}}).encode())
    time.sleep(30)


def test_worker_timeout_keeps_recursive_checkpoint_and_root_primary(tmp_path, monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context = multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing, 'get_context', lambda *args: context)
    monkeypatch.setattr(profile_worker, '_profile_child', _carving_checkpoint_then_stall)
    monkeypatch.setattr(profile_worker, '_worker_count', lambda *args: 1)
    profile = profile_worker.profile_pdf(tmp_path / 'unused.pdf', boundary=tmp_path, digest='a' * 64,
        analysis_version='v9', extraction_profile='deep-static', limits=CodeInspectionLimits(wall_seconds=1, cpu_seconds=1))
    assert profile['status'] == 'timeout' and profile['worker_cleanup_complete']
    assert profile['carving']['worker_failure_codes'] == ['wall_timeout']
    bundle = normalize_profile(profile, 'a' * 64, 'deep-static')
    assert bundle['status'] == 'timeout'
    assert any(record['kind'] == 'artifact' and record['observation_status'] == 'observed'
               for record in bundle['evidence_store']['records'])
    assert next(record for record in bundle['evidence_store']['records'] if record['kind'] == 'primary_checkpoint')['details']['features'] == {'JS': 1}


def test_repaired_child_provenance_is_inherited_in_the_export():
    from malpdf.extraction.raw import inspect_raw_layout
    root, child = pdf(), pdf(action=True)
    worker = carver(root=sha(root))
    identifier = admit(worker, child, parent_id='original:' + sha(root), repaired=True)
    carving = worker.finish(0)  # Layout saved; child analysis is explicitly limited.
    assert carving['records'][0]['status'] == 'resource_limit'
    profile = {'status': 'partial', 'raw_layout': inspect_raw_layout(root), 'carving': carving}
    bundle = normalize_profile(profile, sha(root), 'deep-static')
    child_original = next(record for record in bundle['evidence_store']['records'] if record['evidence_id'] == 'original:' + sha(child))
    assert child_original['is_synthetic_repaired'] is True
    assert any(edge['kind'] == 'artifact_document' and edge['source'] == identifier for edge in bundle['evidence_store']['edges'])


def test_nested_pdf_bundle_namespaces_children_and_only_plans_root_events(tmp_path):
    child = pdf(b'var childFixture = 2;', action=True)
    zipped = archive([('child.pdf', child), ('same.pdf', child), ('inert.js', b'var archiveFixture = 3;')])
    data = pdf(zipped, action=True)
    path = tmp_path / 'synthetic.pdf'
    path.write_bytes(data)
    blobs = tmp_path / 'retained'
    result = extract_pdf(path, boundary=tmp_path, limits=CodeInspectionLimits(wall_seconds=20, cpu_seconds=12),
                         raw_artifact_dir=blobs)
    validate_bundle(result)
    records = result['evidence_store']['records']
    artifacts = [item for item in records if item['kind'] == 'artifact']
    assert len([item for item in artifacts if item['details']['kind'] == 'pdf']) == 2
    child_documents = [item for item in records if item['kind'] == 'document' and item['details'].get('sha256') == sha(child)]
    assert len(child_documents) == 1
    assert any(item['feature_name'].startswith('child:' + sha(child) + ':canonical_') for item in result['feature_store']['records'])
    primaries = [item for item in records if item['kind'] == 'primary_checkpoint']
    root_primary = next(item for item in primaries if item['evidence_id'] == 'primary:' + sha(data))
    assert root_primary['details']['features'] == StaticPDFAnalyzer().inspect(path).features
    plan = plan_triggers(result)
    assert len(plan['events']) == 1
    root_sources = {item['evidence_id'] for item in records if item['kind'] == 'document'
                    and sha(data) in (item['details'].get('sha256'), item['details'].get('raw_sha256'))}
    assert all(event['supporting_ids'][0] in root_sources for event in plan['events'])
    assert all(item['details']['retention']['parent_verification_status'] == 'verified' for item in artifacts)
    assert (blobs / (sha(child) + '.bin')).read_bytes() == child
    assert result['coverage_report']['worker']['worker_cleanup_complete'] is True
    assert path.read_bytes() == data
    assert all(value is False for value in result['safety'].values())
    assert 'archiveFixture' not in json.dumps(result)


def test_carving_exports_reject_root_and_parent_identity_mismatch():
    from malpdf.extraction.raw import inspect_raw_layout
    data = pdf()
    worker = carver(root=sha(data))
    admit(worker, b'var a = 1;', hint='javascript')
    carving = worker.finish(1000)
    profile = {'status': 'partial', 'raw_layout': inspect_raw_layout(data), 'carving': carving}
    with pytest.raises(ValueError, match='artifact_parent_evidence_missing'):
        normalize_profile(profile, sha(data), 'deep-static')
    broken = deepcopy(profile)
    broken['carving']['document_sha256'] = 'c' * 64
    with pytest.raises(ValueError, match='artifact_root_identity_mismatch'):
        normalize_profile(broken, sha(data), 'deep-static')


@pytest.mark.parametrize(('data', 'kind'), [(b'\x89PNG\r\n\x1a\n', 'png'), (b'MZinert', 'pe_candidate'),
    (b'inert', 'unknown'), (b'PK\x05\x06' + b'\0' * 18, 'zip')])
def test_magic_is_a_candidate_not_a_validity_or_maliciousness_claim(data, kind):
    assert artifact_kind(data) == kind
    if kind == 'png':
        worker = carver()
        admit(worker, data)
        assert worker.finish(1000)['records'][0]['status'] == 'unsupported'
