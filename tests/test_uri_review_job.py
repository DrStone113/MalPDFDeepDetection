import hashlib
import io
import json
from pathlib import Path

from pypdf import PdfReader
import pytest

from malpdf.extraction import uri_review_job as review
from malpdf.extraction.normalize import normalize_profile
from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes
from malpdf.static.evidence_v9 import inspect_evidence_v9

FIXTURE = Path(__file__).parent / 'fixtures' / 'real_benign_document.pdf'


def stage(tmp_path, monkeypatch, entries):
    folder = tmp_path / review.INPUT_DIRECTORY
    folder.mkdir(parents=True)
    selection = json.dumps({'schema_version': 1, 'documents': [{'sha256': row['sha256']} for row in entries]}).encode()
    selection_hash = hashlib.sha256(selection).hexdigest()
    path_map = json.dumps({'schema_version': 1, 'selection_sha256': selection_hash, 'entries': entries}).encode()
    (folder / 'review_selection.json').write_bytes(selection)
    (folder / 'path_map.json').write_bytes(path_map)
    monkeypatch.setattr(review, 'SELECTION_SHA256', selection_hash)
    monkeypatch.setattr(review, 'PATH_MAP_SHA256', hashlib.sha256(path_map).hexdigest())
    monkeypatch.setattr(review, 'SAMPLES', len(entries))
    monkeypatch.setattr(review, 'TOTAL_BYTES', sum(row['bytes'] for row in entries))


@pytest.fixture
def entry():
    data = FIXTURE.read_bytes()
    return {'sha256': hashlib.sha256(data).hexdigest(), 'path': 'approved/control.pdf', 'bytes': len(data)}


def test_metadata_prepare_needs_no_lab_raw_tree(tmp_path, monkeypatch, entry):
    stage(tmp_path, monkeypatch, [entry])
    assert review.metadata_rows(tmp_path)[0]['pdf_sha256'] == entry['sha256']
    assert not (tmp_path / 'data/raw').exists()
    with pytest.raises(ValueError, match='manifest_unavailable'):
        review.load_rows(tmp_path)


def test_lab_checks_sealed_size_and_file_kind(tmp_path, monkeypatch, entry):
    stage(tmp_path, monkeypatch, [entry])
    path = tmp_path / 'data/raw' / entry['path']
    path.parent.mkdir(parents=True)
    path.write_bytes(FIXTURE.read_bytes())
    assert review.load_rows(tmp_path) == review.metadata_rows(tmp_path)
    with path.open('ab') as stream:
        stream.write(b' ')
    with pytest.raises(ValueError, match='manifest_unavailable'):
        review.load_rows(tmp_path)


@pytest.mark.parametrize('path', ['../elsewhere.pdf', '/outside.pdf', 'C:/outside.pdf', 'nested\\outside.pdf'])
def test_sealed_manifest_still_rejects_paths_outside_raw(tmp_path, monkeypatch, entry, path):
    stage(tmp_path, monkeypatch, [{**entry, 'path': path}])
    with pytest.raises(ValueError, match='manifest_unavailable'):
        review.metadata_rows(tmp_path)


def test_duplicate_documents_are_rejected(tmp_path, monkeypatch, entry):
    stage(tmp_path, monkeypatch, [entry, {**entry, 'path': 'elsewhere.pdf'}])
    with pytest.raises(ValueError, match='manifest_unavailable'):
        review.metadata_rows(tmp_path)


def test_target_hash_is_read_from_the_same_typed_action_on_the_real_fixture():
    data = FIXTURE.read_bytes()
    reader = PdfReader(io.BytesIO(data))
    expected = set()
    for page in reader.pages:
        for annotation in page.get('/Annots', []):
            action = annotation.get_object().get('/A')
            if action is not None and action.get_object().get('/S') == '/URI':
                value = action.get_object()['/URI'].original_bytes
                expected.add(hashlib.sha256(value).hexdigest())
    assert expected
    static = {'input': {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)},
              'features': {}, 'parser': {'success': True, 'structural_complete': True}, 'errors': []}
    limits = CodeInspectionLimits()
    evidence = inspect_evidence_v9(data, static, _inspect_code_bytes(data, limits), limits, primary_complete=True)
    observed = {item['uri_target_sha256'] for item in evidence['observations']
                if item['kind'] == 'action' and item.get('action_kind') == '/URI'}
    assert observed == expected


def test_completed_fixture_projects_same_action_targets_and_refuses_wrong_job(entry):
    run_id = 'c' * 64
    data = FIXTURE.read_bytes()
    static = {'input': {'sha256': entry['sha256'], 'size_bytes': len(data)}, 'features': {},
              'parser': {'success': True, 'structural_complete': True}, 'errors': []}
    limits = CodeInspectionLimits()
    code = _inspect_code_bytes(data, limits)
    evidence = inspect_evidence_v9(data, static, code, limits, primary_complete=True)
    bundle = normalize_profile({'status': 'complete', 'static': static, 'code': code, 'analysis_v9': evidence,
                                'worker_cleanup_complete': True, 'diagnostic': {'run_id': run_id}},
                               entry['sha256'], 'deep-static')
    observation = review.project_targets(bundle, entry['sha256'], run_id)
    assert observation['sha256'] == entry['sha256']
    assert observation['targets']
    assert all(len(target['target_sha256']) == 64 for target in observation['targets'])
    assert 'https://' not in json.dumps(observation)
    with pytest.raises(ValueError, match='uri_review_bundle_identity'):
        review.project_targets(bundle, entry['sha256'], 'd' * 64)
    for record in bundle['evidence_store']['records']:
        target = record['details'].pop('uri_target_sha256', None)
        if target:
            break
    unhashed = review.project_targets(bundle, entry['sha256'], run_id)
    assert unhashed['actions_without_target'] == 1
    assert target not in {item['target_sha256'] for item in unhashed['targets']}
