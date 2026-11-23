from __future__ import annotations

import argparse
from collections import Counter
import csv
from decimal import Decimal
from hashlib import sha256
import io
import json
from pathlib import Path

from prepare_holdout_fingerprint_plan import (
    BULK_MANIFEST, BULK_MANIFEST_SHA256, HISTORICAL, HISTORICAL_SHA256, MAX_FILE_BYTES, SHA256,
    metadata_row, pinned_metadata,
)


SPLIT_SHA256 = '9aabb601a2d4081f17fa3e3b1ad30efc3501ca7afeb557d43b1adafcac0ec74d'
SHORT_FILE = 'tlsh_minimum_50_bytes'
MAX_BYTES = 20_000_000_000


def build_plan(root, split_path):
    split = pinned_metadata(split_path, SPLIT_SHA256, 12 * 1024**2).decode('ascii').splitlines()
    if json.loads(split[0])['schema_version'] != 1:
        raise ValueError('unexpected_split_schema')
    pending = {row['sha256'] for row in map(json.loads, split[1:]) if row['role'] == 'pending_fingerprint'}
    if len(pending) != 20169 or not all(SHA256.fullmatch(sha) for sha in pending):
        raise ValueError('unexpected_pending_fingerprint_cohort')
    acquisition = pinned_metadata(root / BULK_MANIFEST, BULK_MANIFEST_SHA256, 24 * 1024**2)
    raw = root / 'data/raw'
    entries, missing = {}, {}
    for row in csv.DictReader(io.StringIO(acquisition.decode('utf-8-sig'))):
        sha = row['sha256']
        if sha not in pending:
            continue
        size = int(row['bytes'])
        if size < 50 or size > MAX_FILE_BYTES:
            reason = SHORT_FILE if size < 50 else 'worker_file_limit_50_mib'
            reservation = {'sha256': sha, 'bytes': size, 'reason': reason}
            if missing.setdefault(sha, reservation) != reservation:
                raise ValueError('conflicting_pending_metadata')
            continue
        entry = metadata_row(raw, raw / 'bulk_20261116' / row['stored_relpath'], sha, size, 'pooled_pending')
        if entries.setdefault(sha, entry) != entry:
            raise ValueError('conflicting_pending_metadata')
    history = pinned_metadata(root / HISTORICAL, HISTORICAL_SHA256, 16 * 1024**2)
    unavailable = pending - entries.keys() - missing.keys()
    for row in csv.DictReader(io.StringIO(history.decode('utf-8-sig'))):
        sha = row['pdf_sha256']
        if sha not in unavailable:
            continue
        size = Decimal(row['bytes']) if row['bytes'] else None
        entry = metadata_row(raw, root / row['pdf_relative_path'], sha, size, 'pooled_pending')
        if entry['bytes'] < 50:
            missing[sha] = {'sha256': sha, 'bytes': entry['bytes'], 'reason': SHORT_FILE}
        else:
            entries[sha] = entry
    if entries.keys() & missing.keys() or pending != entries.keys() | missing.keys():
        raise ValueError('pending_corpus_membership_mismatch')
    total = sum(row['bytes'] for row in entries.values())
    if total > MAX_BYTES:
        raise ValueError('fingerprint_total_byte_limit')
    return {'schema_version': 1, 'metadata_only': True, 'max_file_bytes': MAX_FILE_BYTES,
            'split_sha256': SPLIT_SHA256, 'acquisition_sha256': BULK_MANIFEST_SHA256,
            'historical_manifest_sha256': HISTORICAL_SHA256, 'total_bytes': total,
            'entries': [entries[sha] for sha in sorted(entries)], 'unmeasurable': [missing[sha] for sha in sorted(missing)]}


def main():
    parser = argparse.ArgumentParser(description='Seal a pooled TLSH metadata plan without reading any PDF bytes')
    for name in ('root', 'split', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    plan = build_plan(args.root.resolve(strict=True), args.split)
    payload = (json.dumps(plan, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    with args.out.open('xb') as stream:
        stream.write(payload)
    print(json.dumps({'plan_sha256': sha256(payload).hexdigest(), 'eligible': len(plan['entries']),
                      'total_bytes': plan['total_bytes'], 'metadata_only': True, 'queued': False,
                      'unmeasurable': Counter(item['reason'] for item in plan['unmeasurable'])}, indent=2))


if __name__ == '__main__':
    main()
