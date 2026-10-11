"""Synthetic byte IPC regression tests, with no external PDF access."""

import base64
import hashlib
import json
import multiprocessing
import os
import time
from dataclasses import replace

import pytest

from malpdf.static.evidence_ipc import EvidenceAccumulator, ParentRawStore, WorkerRawSink
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static import profile_worker


def test_accumulator_rejects_overwrite_and_oversize_without_losing_primary():
    acc = EvidenceAccumulator('a'*64, max_bytes=1024)
    entry = {'id': 'primary', 'status': 'observed', 'backend': 'pypdf'}
    acc.merge({'observations': [entry]})
    for delta, reason in [({'observations': [{**entry, 'status': 'failed'}]}, 'nonmonotonic'),
                           ({'errors': ['x'*2000]}, 'metadata_limit'),
                           ({'document_sha256': 'b'*64}, 'document_mismatch')]:
        with pytest.raises(ValueError, match=reason):
            acc.merge(delta)
        assert acc.value['observations'] == [entry]
    value = acc.interrupted(['wall_timeout'])
    assert value['observations'] == [entry] and value['status'] == 'partial'


def test_accumulator_incremental_size_equals_canonical_size_and_copies_input():
    from malpdf.static.evidence_ipc import encoded
    acc = EvidenceAccumulator('a'*64)
    for index in range(200):
        entry = {'id':str(index),'status':'observed','values':[index]}
        acc.merge({'observations':[entry], 'budget_usage':{'objects':index}})
        entry['values'].append('caller mutation')
        assert acc._bytes == len(encoded(acc.value))
    assert len(acc.value['observations']) == 200
    assert all(len(item['values'])==1 for item in acc.value['observations'])


class Capture:
    def __init__(self): self.messages = []
    def send_bytes(self, payload): self.messages.append(json.loads(payload))


def test_parent_checks_raw_chunks_hash_and_stores_exclusive_blobs(tmp_path):
    raw = b'benign synthetic bytes'*8000
    capture = Capture()
    sink = WorkerRawSink(capture)
    assert sink(raw)['status'] == 'retained'
    count = len(capture.messages)
    assert sink(raw)['status'] == 'retained' and len(capture.messages) == count
    store = ParentRawStore(tmp_path/'raw')
    for message in capture.messages:
        store.accept(message)
    digest = hashlib.sha256(raw).hexdigest()
    assert (tmp_path/'raw'/f'{digest}.bin').read_bytes() == raw
    assert store.used == len(raw) and store.records[0]['status'] == 'verified'
    assert all(len(base64.b64decode(m['data'])) <= 65536 for m in capture.messages if m['event']=='raw_chunk')
    with pytest.raises(FileExistsError): ParentRawStore(tmp_path/'raw')


@pytest.mark.parametrize('mutation', ['hash', 'offset', 'size', 'oversize'])
def test_corrupt_raw_transport_cannot_become_verified(tmp_path, mutation):
    raw = b'benign'
    digest = hashlib.sha256(raw).hexdigest()
    store = ParentRawStore(tmp_path/'raw')
    store.accept({'event':'raw_begin', 'sha256':digest, 'size_bytes':len(raw)})
    chunk = {'event':'raw_chunk', 'sha256':digest, 'offset':0, 'data':base64.b64encode(raw).decode()}
    end = {'event':'raw_end', 'sha256':digest, 'size_bytes':len(raw)}
    if mutation == 'hash': chunk['data'] = base64.b64encode(b'broken').decode()
    elif mutation == 'offset': chunk['offset'] = 1
    elif mutation == 'size': end['size_bytes'] = 5
    else: chunk['data'] = base64.b64encode(b'x'*65537).decode()
    try:
        with pytest.raises(ValueError):
            store.accept(chunk)
            store.accept(end)
        assert store.records == []
    finally: store.close()


def test_raw_total_cap_is_shared_and_refusal_does_not_restart_budget(tmp_path):
    capture = Capture(); sink = WorkerRawSink(capture, max_bytes=6)
    assert sink(b'one')['status']=='retained'
    assert sink(b'two')['status']=='retained'
    assert sink(b'3')['reason_code']=='raw_storage_limit'
    assert sink.used == 6
    store = ParentRawStore(tmp_path/'raw', max_bytes=6)
    for message in capture.messages: store.accept(message)
    with pytest.raises(ValueError, match='storage_limit'):
        store.accept({'event':'raw_begin', 'sha256':'a'*64, 'size_bytes':1})


def _checkpoint_then_failure(connection, path, boundary, digest, limits, *args):
    from malpdf.static.schema import RIT_FEATURES
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'complete', 'errors':[],
        'static':{'input':{'sha256':digest,'size_bytes':100}, 'features':dict.fromkeys(RIT_FEATURES,0),
                  'parser':{'success':True,'structural_complete':True}},
        'code':{'complete':True, 'errors':[]}, 'analysis_v8':{'schema_version':'pdf-evidence-v8',
                  'backends':[{'backend':'pypdf','graph':{'objects':{'pypdf:1:0':{'kind':'dict'}}}}]}}}).encode())
    connection.send_bytes(json.dumps({'event':'evidence_delta', 'delta':{
        'observations':[{'id':'primary', 'kind':'object', 'status':'observed'}]}}).encode())
    WorkerRawSink(connection)(b'benign synthetic raw')
    mode = str(path)
    if 'oversize' in mode:
        connection.send_bytes(b'x'*(6*1024**2+1))
    elif 'timeout' in mode:
        time.sleep(3)
    elif 'signal' in mode:
        os.kill(os.getpid(), 9)
    elif 'spam' in mode:
        payload = json.dumps({'event':'evidence_delta', 'delta':{
            'observations':[{'id':'primary', 'kind':'object', 'status':'observed'}]}}).encode()
        while True:
            connection.send_bytes(payload)
    else:
        connection.close()


@pytest.mark.parametrize('mode', ['exit', 'signal', 'timeout', 'oversize', 'spam'])
def test_later_worker_failure_keeps_primary_delta_and_raw_and_reaps_worker(tmp_path, monkeypatch, mode):
    context = multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing, 'get_context', lambda _: context)
    monkeypatch.setattr(profile_worker, '_worker_count', lambda *args: 1)
    monkeypatch.setattr(profile_worker, '_profile_child', _checkpoint_then_failure)
    result = profile_worker.profile_pdf(tmp_path/f'{mode}.pdf', boundary=tmp_path, digest='a'*64,
        analysis_version='v9', raw_artifact_dir=tmp_path/'raw',
        limits=replace(CodeInspectionLimits(), wall_seconds=1, cpu_seconds=1))
    assert result['status'] in {'worker_error','timeout','resource_limit_or_signal'}
    assert result['primary_status']=='complete' and result['static']['parser']['success']
    assert result['analysis_v8']['backends'][0]['graph']['objects']
    assert result['analysis_v9']['observations'][0]['id']=='primary'
    assert result['raw_stream_storage']['verified_bytes']==len(b'benign synthetic raw')
    assert result['worker_cleanup_complete'] and result['worker_exit_code'] is not None
    if mode == 'spam':
        assert result['status']=='timeout' and result['worker_seconds'] < 2


def test_version_and_raw_storage_validation_precedes_worker_creation(tmp_path):
    with pytest.raises(ValueError, match='Unknown'):
        profile_worker.profile_pdf(tmp_path/'unused.pdf', boundary=tmp_path, digest='a'*64, analysis_version='v10')
    with pytest.raises(ValueError, match='requires v9'):
        profile_worker.profile_pdf(tmp_path/'unused.pdf', boundary=tmp_path, digest='a'*64, raw_artifact_dir=tmp_path/'raw')


def test_generated_pdf_survives_real_v9_worker_transport_and_ast_reuse(tmp_path):
    import io
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, EncodedStreamObject
    import zlib
    writer = PdfWriter(); writer.add_blank_page(72, 72)
    stream = EncodedStreamObject()
    raw = zlib.compress(b'var harmless = 1;')
    stream._data = raw
    stream[NameObject('/Filter')] = NameObject('/FlateDecode')
    writer._root_object[NameObject('/OpenAction')] = DictionaryObject({
        NameObject('/S'):NameObject('/JavaScript'), NameObject('/JS'):writer._add_object(stream)})
    output = io.BytesIO(); writer.write(output)
    data = output.getvalue(); path = tmp_path/'generated.pdf'; path.write_bytes(data)
    profile = profile_worker.profile_pdf(path, boundary=tmp_path, digest=hashlib.sha256(data).hexdigest(),
        analysis_version='v9', raw_artifact_dir=tmp_path/'raw',
        limits=CodeInspectionLimits(wall_seconds=20, cpu_seconds=12))
    assert profile['status'] == 'complete' and profile['worker_cleanup_complete']
    analysis = profile['analysis_v9']
    assert analysis['schema_version']=='pdf-evidence-v9' and analysis['complete']
    assert analysis['witnesses'] and len(analysis['feature_provenance'])==173
    assert profile['code']['script_sources'][0]['ast_summary']
    assert analysis['budget_usage']['ast_nodes_v9'] == 0
    assert (tmp_path/'raw'/f'{hashlib.sha256(raw).hexdigest()}.bin').read_bytes() == raw
