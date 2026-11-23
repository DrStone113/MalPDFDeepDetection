from __future__ import annotations

from functools import partial
from pathlib import Path

from malpdf.extraction.benign_ood_job import fingerprint as fingerprint_row, load_manifest_rows
from malpdf.extraction.holdout_fingerprint_job import ENGINE_SHA256


RAW_ROOT = Path('data/raw/benign_ood/v32_cohort')
MANIFEST_SHA256 = '69dd80240abc8cc2c48da6d1cac143e4dbf86d9b9cfaed9bd85cf9d1179b5371'
SOURCE_COUNTS = {'arxiv': 160, 'court': 16, 'nasa': 98, 'nist': 100, 'pdfjs': 300, 'verapdf': 300}
SAMPLES = sum(SOURCE_COUNTS.values())
TOTAL_BYTES = 493558812


def contract():
    return {'samples': SAMPLES, 'source_counts': SOURCE_COUNTS, 'bytes': TOTAL_BYTES,
            'acquisition_sha256': MANIFEST_SHA256, 'engine_sha256': ENGINE_SHA256,
            'purpose': 'v3.2 multi-source benign supplement (Subset A) plus untouched prospective publisher and hard-benign controls (Subset B)',
            'model_evaluation_in_lab': False}


def load_rows(data_root):
    return load_manifest_rows(data_root, RAW_ROOT, MANIFEST_SHA256, SOURCE_COUNTS, TOTAL_BYTES, batched=True)


fingerprint = partial(fingerprint_row, raw_relative=RAW_ROOT)
