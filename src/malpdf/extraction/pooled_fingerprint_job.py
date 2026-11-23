from __future__ import annotations

from collections import Counter
import json
import stat

from malpdf.extraction.holdout_fingerprint_job import (
    ENGINE_SHA256, HEX256, INPUT_DIRECTORY as HOLDOUT_DIRECTORY, MAX_FILE_BYTES,
    fingerprint_entry, pinned, sealed_engine,
)


INPUT_DIRECTORY = 'data/processed/pooled_fingerprint/v1'
PLAN_SHA256 = 'd910bedcfe3415077189f7c64816b48dcc7a7f7b38d05a13366cfe9601a0e499'
SAMPLES = 20166
TOTAL_BYTES = 19257740191


def contract():
    return {'samples': SAMPLES, 'total_bytes': TOTAL_BYTES, 'manifest_sha256': PLAN_SHA256,
            'engine_sha256': ENGINE_SHA256, 'output': 'holdout_fingerprints.json',
            'hashes': ['sha256', 'sha1', 'tlsh'], 'model_evaluation': False}


def load_inputs(data_root):
    raw = data_root / 'data/raw'
    stage = data_root / INPUT_DIRECTORY
    plan = json.loads(pinned(stage / 'pooled_fingerprint_plan.json', stage, PLAN_SHA256, 8 * 1024**2))
    engine_dir = data_root / HOLDOUT_DIRECTORY
    engine = pinned(engine_dir / 'tlsh_holdout_audit', engine_dir, ENGINE_SHA256, 2 * 1024**2)
    entries = plan['entries']
    if (plan['schema_version'] != 1 or plan['metadata_only'] is not True or len(entries) != SAMPLES
            or plan['total_bytes'] != TOTAL_BYTES or sum(entry['bytes'] for entry in entries) != TOTAL_BYTES
            or len({entry['sha256'] for entry in entries}) != SAMPLES):
        raise ValueError('manifest_unavailable')
    for entry in entries:
        path = raw / entry['path']
        if (not HEX256.fullmatch(entry['sha256']) or not 50 <= entry['bytes'] <= MAX_FILE_BYTES
                or not path.is_relative_to(raw) or path.resolve() != path):
            raise ValueError('manifest_unavailable')
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry['bytes']:
            raise ValueError('manifest_unavailable')
    return raw, entries, {}, engine


def fingerprint_plan(inputs, *, timeout, progress):
    raw, entries, _, engine = inputs
    fingerprints = []
    with sealed_engine(engine) as descriptor:
        for index, entry in enumerate(entries, start=1):
            fingerprints.append(fingerprint_entry(raw, entry, {}, descriptor, timeout=timeout, include_sha1=True))
            if index % 128 == 0 or index == len(entries):
                progress(index)
    counts = Counter(row['status'] for row in fingerprints)
    return {'schema_version': 1, 'inputs': contract(), 'fingerprints': fingerprints,
            'fingerprint_status_counts': dict(counts), 'new_malware_labels': 0}
