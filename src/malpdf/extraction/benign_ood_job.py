from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import stat

from malpdf.extraction.holdout_fingerprint_job import (
    ENGINE_SHA256, HEX256, INPUT_DIRECTORY, fingerprint_entry, pinned, sealed_engine,
)


RAW_ROOT = Path('data/raw/benign_ood/v1')
MANIFEST_SHA256 = 'd4d31cde0d70ad6347d4fd4fb96afafe7d6b148c14dddc943bfba4a1515f844f'
SOURCE_COUNTS = {'irs': 29, 'rfc': 26, 'arxiv': 28}
SAMPLES = sum(SOURCE_COUNTS.values())
TOTAL_BYTES = 101640858
MAX_FILE_BYTES = 12 * 1024**2


def contract():
    return {'samples': SAMPLES, 'source_counts': SOURCE_COUNTS, 'bytes': TOTAL_BYTES,
            'acquisition_sha256': MANIFEST_SHA256, 'engine_sha256': ENGINE_SHA256,
            'purpose': 'external publisher benign controls, static extraction and TLSH',
            'model_evaluation_in_lab': False}


def load_rows(data_root):
    return load_manifest_rows(data_root, RAW_ROOT, MANIFEST_SHA256, SOURCE_COUNTS, TOTAL_BYTES)


def load_manifest_rows(data_root, raw_relative, manifest_sha256, source_counts, total_bytes, *, batched=False):
    directory = data_root / raw_relative
    manifest = json.loads(pinned(directory / 'acquisition.json', directory, manifest_sha256, 1024**2))
    records = manifest['entries']
    expected = sum(source_counts.values())
    if (len(records) != expected or sum(row['bytes'] for row in records) != total_bytes
            or len({row['sha256'] for row in records}) != expected
            or len({row['id'] for row in records}) != expected
            or Counter(row['source'] for row in records) != source_counts):
        raise ValueError('manifest_unavailable')
    rows = []
    for entry in records:
        identity, source, sha = (entry[key] for key in ('id', 'source', 'sha256'))
        relative = Path(identity + '.pdf')
        if batched:
            if not re.fullmatch(r'batch-[0-9]{2}', entry['batch']):
                raise ValueError('manifest_unavailable')
            relative = Path(entry['batch']) / relative
        path = directory / relative
        if (not re.fullmatch(re.escape(source) + r'-[0-9]{3}', identity)
                or not HEX256.fullmatch(sha) or path.resolve() != path
                or not 50 <= entry['bytes'] <= MAX_FILE_BYTES):
            raise ValueError('manifest_unavailable')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != entry['bytes']:
            raise ValueError('manifest_unavailable')
        rows.append({'id': identity, 'source': source, 'pdf_sha256': sha, 'bytes': info.st_size,
                     'pdf_relative_path': (raw_relative / relative).as_posix()})
    return rows


def fingerprint(data_root, row, *, raw_relative=RAW_ROOT):
    engine_dir = data_root / INPUT_DIRECTORY
    engine = pinned(engine_dir / 'tlsh_holdout_audit', engine_dir, ENGINE_SHA256, 2 * 1024**2)
    with sealed_engine(engine) as descriptor:
        return fingerprint_entry(data_root / raw_relative, {'sha256': row['pdf_sha256'],
                                 'path': Path(row['pdf_relative_path']).relative_to(raw_relative).as_posix(),
                                 'bytes': row['bytes']},
                                 {}, descriptor)
