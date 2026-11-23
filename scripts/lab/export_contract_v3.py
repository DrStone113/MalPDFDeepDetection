from __future__ import annotations

from collections import Counter
import gzip
from hashlib import file_digest
import json
from pathlib import Path
import re
import sys

from malpdf.features.contract_v3 import FEATURES, VERSION, project_features


TABLE_SHA256 = 'bda7e59e65052a877ce769e02ecd798ba8ca0328e2ad048a6c888be708ea52ea'


def export(path, output):
    with path.open('rb') as raw:
        if file_digest(raw, 'sha256').hexdigest() != TABLE_SHA256:
            raise ValueError('bulk_table_changed')
    with gzip.open(path, 'rt', encoding='utf-8') as source, gzip.GzipFile(
            fileobj=output, mode='wb', compresslevel=4, mtime=0) as destination:
        def write(row):
            destination.write(json.dumps(row, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n')

        write({'contract': VERSION, 'features': FEATURES, 'table_sha256': TABLE_SHA256})
        seen, counts = set(), Counter()
        for row in map(json.loads, source):
            identity = row['sha256']
            if identity in seen or not re.fullmatch('[a-f0-9]{64}', identity):
                raise ValueError('invalid_bulk_identity')
            seen.add(identity)
            disposition = row['sample_disposition']
            values = [None] * len(FEATURES) if disposition == 'rejected_unverified_cleanup' else project_features(row['features'])
            counts[disposition] += 1
            write([identity, values])
        if len(seen) != 41727:
            raise ValueError('unexpected_bulk_row_count')
        write({'row_count': len(seen), 'dispositions': counts})


if __name__ == '__main__':
    root = Path(json.loads(Path('/etc/malpdf/runner.json').read_text(encoding='utf-8'))['data_root'])
    export(root / 'data/processed/bulk_extract/final/tabular_features_v2.jsonl.gz', sys.stdout.buffer)
