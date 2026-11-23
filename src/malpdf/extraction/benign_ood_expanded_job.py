from __future__ import annotations

from functools import partial
from pathlib import Path

from malpdf.extraction.benign_ood_job import fingerprint as fingerprint_row, load_manifest_rows
from malpdf.extraction.holdout_fingerprint_job import ENGINE_SHA256


RAW_ROOT = Path('data/raw/benign_ood/expanded_v1')
MANIFEST_SHA256 = 'f9fb23c6880d47b03f34d04fe4995542568eba4054d673116466bb72da27ac43'
SOURCE_COUNTS = {'rfc': 149, 'fr': 79, 'nasa': 110, 'court': 41}
SAMPLES = sum(SOURCE_COUNTS.values())
TOTAL_BYTES = 367020435


def contract():
    return {'samples': SAMPLES, 'source_counts': SOURCE_COUNTS, 'bytes': TOTAL_BYTES,
            'acquisition_sha256': MANIFEST_SHA256, 'engine_sha256': ENGINE_SHA256,
            'purpose': 'expanded independent publisher controls, static extraction and TLSH',
            'model_evaluation_in_lab': False}


def load_rows(data_root):
    return load_manifest_rows(data_root, RAW_ROOT, MANIFEST_SHA256, SOURCE_COUNTS, TOTAL_BYTES, batched=True)


fingerprint = partial(fingerprint_row, raw_relative=RAW_ROOT)
