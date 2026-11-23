from __future__ import annotations

from functools import partial
from pathlib import Path

from malpdf.extraction.benign_ood_job import fingerprint as fingerprint_row, load_manifest_rows
from malpdf.extraction.holdout_fingerprint_job import ENGINE_SHA256


RAW_ROOT = Path('data/raw/benign_ood/diverse_v1')
MANIFEST_SHA256 = '971f77b59c55b6e4d9dd68f6e080be84dc72de41cb9e1cbb6eca1f6c661d815b'
SOURCE_COUNTS = {'arxiv': 160, 'irs': 60, 'nasa': 75, 'nist': 82, 'pdfjs': 50, 'verapdf': 50}
SAMPLES = sum(SOURCE_COUNTS.values())
TOTAL_BYTES = 788111236


def contract():
    return {'samples': SAMPLES, 'source_counts': SOURCE_COUNTS, 'bytes': TOTAL_BYTES,
            'acquisition_sha256': MANIFEST_SHA256, 'engine_sha256': ENGINE_SHA256,
            'purpose': 'diverse publisher OOD controls plus hard-benign veraPDF and pdf.js stress, static extraction and TLSH',
            'model_evaluation_in_lab': False}


def load_rows(data_root):
    return load_manifest_rows(data_root, RAW_ROOT, MANIFEST_SHA256, SOURCE_COUNTS, TOTAL_BYTES, batched=True)


fingerprint = partial(fingerprint_row, raw_relative=RAW_ROOT)
