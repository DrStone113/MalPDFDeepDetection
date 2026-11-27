from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import stat

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.holdout_fingerprint_job import HEX256, pinned
from malpdf.extraction.triggers import plan_triggers

KIND = 'pdf-uri-review'
SAFEDOCS_KIND = 'pdf-uri-safedocs-review'
INPUT_DIRECTORY = Path('data/processed/uri_review/v1')
RAW_ROOT = Path('data/raw')
SAFEDOCS_RAW_ROOT = RAW_ROOT / 'uri_safedocs_review'
SAFEDOCS_MANIFEST = Path('configs/uri_safedocs_review_20261127.json')
SAFEDOCS_MANIFEST_SHA256 = '03000ea32587e813fc68b854cf7a78303a3db153fdd6397e3ddd2433e6103619'
SAFEDOCS_RECEIPT_SHA256 = '8a1316aaac3c7a2b9730087824945dc202432e94334c5dcddfdcc09ea61db55a'
SAFEDOCS_SAMPLES = 11
SAFEDOCS_TOTAL_BYTES = 4_520_655
SELECTION_SHA256 = '6cffc5934dca25333242018592afbc174504dc6e0c42b156a0fabe9afc05852d'
PATH_MAP_SHA256 = 'a54c9a2da029b20a7b8c93ff43d81629676656318e076df14bd4afcf568b5031'
SAMPLES = 151
TOTAL_BYTES = 31_578_824
MAX_FILE_BYTES = 10 * 1024**2
MAX_TARGETS = 256


def contract(kind=KIND):
    if kind == SAFEDOCS_KIND:
        return {'samples': SAFEDOCS_SAMPLES, 'bytes': SAFEDOCS_TOTAL_BYTES,
                'roster_sha256': SAFEDOCS_MANIFEST_SHA256, 'source_receipt_sha256': SAFEDOCS_RECEIPT_SHA256,
                'purpose': 'static external-action evidence for SafeDocs URI label review',
                'model_evaluation_in_lab': False}
    if kind != KIND:
        raise ValueError('job_mismatch')
    return {'samples': SAMPLES, 'bytes': TOTAL_BYTES, 'selection_sha256': SELECTION_SHA256,
            'path_map_sha256': PATH_MAP_SHA256, 'purpose': 'static external-action evidence for URI label review',
            'model_evaluation_in_lab': False}


def safedocs_rows(source_root):
    if source_root is None:
        raise ValueError('manifest_unavailable')
    manifest = Path(source_root) / SAFEDOCS_MANIFEST
    roster = json.loads(pinned(manifest, manifest.parent, SAFEDOCS_MANIFEST_SHA256, 8192))
    if not isinstance(roster, list) or len(roster) != SAFEDOCS_SAMPLES:
        raise ValueError('manifest_unavailable')
    rows = []
    identities = []
    for item in roster:
        if not isinstance(item, dict) or set(item) != {'sha256', 'bytes'}:
            raise ValueError('manifest_unavailable')
        identity, size = item['sha256'], item['bytes']
        if (not isinstance(identity, str) or not HEX256.fullmatch(identity)
                or type(size) is not int or not 0 < size <= MAX_FILE_BYTES):
            raise ValueError('manifest_unavailable')
        identities.append(identity)
        rows.append({'pdf_sha256': identity, 'pdf_relative_path': (SAFEDOCS_RAW_ROOT / f'{identity}.pdf').as_posix(),
                     'bytes': size})
    if identities != sorted(set(identities)) or sum(row['bytes'] for row in rows) != SAFEDOCS_TOTAL_BYTES:
        raise ValueError('manifest_unavailable')
    return rows


def metadata_rows(root, kind=KIND, *, source_root=None):
    if kind == SAFEDOCS_KIND:
        return safedocs_rows(source_root)
    if kind != KIND:
        raise ValueError('job_mismatch')
    directory = Path(root) / INPUT_DIRECTORY
    selection = json.loads(pinned(directory / 'review_selection.json', directory, SELECTION_SHA256, 128 * 1024))
    path_map = json.loads(pinned(directory / 'path_map.json', directory, PATH_MAP_SHA256, 128 * 1024))
    if (not isinstance(selection, dict) or selection.get('schema_version') != 1
            or not isinstance(selection.get('documents'), list) or not isinstance(path_map, dict)
            or set(path_map) != {'schema_version', 'selection_sha256', 'entries'} or path_map['schema_version'] != 1
            or path_map['selection_sha256'] != SELECTION_SHA256 or not isinstance(path_map['entries'], list)):
        raise ValueError('manifest_unavailable')
    selected = [item.get('sha256') for item in selection['documents'] if isinstance(item, dict)]
    entries = path_map['entries']
    if (len(selection['documents']) != SAMPLES or len(selected) != SAMPLES or len(entries) != SAMPLES
            or not all(isinstance(value, str) and HEX256.fullmatch(value) for value in selected)
            or len(set(selected)) != SAMPLES):
        raise ValueError('manifest_unavailable')
    rows = []
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'sha256', 'path', 'bytes'}:
            raise ValueError('manifest_unavailable')
        identity, path, size = item['sha256'], item['path'], item['bytes']
        if (not isinstance(identity, str) or not HEX256.fullmatch(identity) or type(size) is not int
                or not 0 < size <= MAX_FILE_BYTES or not isinstance(path, str) or len(path) > 512
                or any(char in path for char in ('\\', ':', '\x00'))
                or any(part in ('', '.', '..') for part in path.split('/'))):
            raise ValueError('manifest_unavailable')
        relative = PurePosixPath(RAW_ROOT.as_posix()) / path
        rows.append({'pdf_sha256': identity, 'pdf_relative_path': relative.as_posix(), 'bytes': size})
    if ({row['pdf_sha256'] for row in rows} != set(selected)
            or len({row['pdf_relative_path'] for row in rows}) != SAMPLES
            or sum(row['bytes'] for row in rows) != TOTAL_BYTES):
        raise ValueError('manifest_unavailable')
    return sorted(rows, key=lambda row: row['pdf_sha256'])


def load_rows(data_root, kind=KIND, *, source_root=None):
    data_root = Path(data_root).absolute()
    rows = metadata_rows(data_root, kind, source_root=source_root)
    for row in rows:
        path = data_root / row['pdf_relative_path']
        try:
            info = path.lstat()
            if (path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_size != row['bytes']):
                raise ValueError('manifest_unavailable')
        except (OSError, RuntimeError):
            raise ValueError('manifest_unavailable') from None
    return rows


def project_targets(bundle, expected_sha256, job_id):
    validate_bundle(bundle)
    worker = bundle['coverage_report']['worker']
    diagnostic = worker.get('diagnostic') or {}
    if (bundle['sample_sha256'] != expected_sha256 or diagnostic.get('run_id') != job_id
            or worker['worker_cleanup_complete'] is not True):
        raise ValueError('uri_review_bundle_identity')
    plan = plan_triggers(bundle)
    action_kinds = {'/URI', '/SubmitForm'}
    placed = {action['evidence_id'] for event in plan['events']
              if event.get('source_view') == 'pypdf' and not event['is_synthetic_repaired']
              for action in event['action_chain'] if action['action_kind'] in action_kinds}
    targets = set()
    actions = actions_without_target = 0
    for record in bundle['evidence_store']['records']:
        if (record['backend'] != 'pypdf' or record['kind'] != 'action' or record['observation_status'] != 'observed'
                or record['is_synthetic_repaired']):
            continue
        detail = record['details']
        kind = detail.get('action_kind')
        if kind not in action_kinds:
            continue
        actions += 1
        target = detail.get('uri_target_sha256')
        if isinstance(target, str) and HEX256.fullmatch(target):
            targets.add((kind, target, record['evidence_id'] in placed))
        else:
            actions_without_target += 1
    return {'sha256': expected_sha256, 'status': 'observed_targets' if targets else 'unresolved',
            'actions_observed': actions, 'actions_without_target': actions_without_target,
            'targets_clipped': len(targets) > MAX_TARGETS,
            'targets': [{'action': kind, 'target_sha256': target, 'placement_observed': placement}
                        for kind, target, placement in sorted(targets)[:MAX_TARGETS]]}
