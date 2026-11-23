from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import file_digest
from itertools import combinations
import gzip
import json
import math
from pathlib import Path
import re
import struct
import subprocess

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold


ROLES = ('train', 'val_select', 'val_calib', 'test_internal')
TLSH = re.compile(r'T1[0-9A-F]{70}')
FINGERPRINT_REPORT = '30d1ce3f32bc34cdc1e2d4bc0c7a13d6bf442111810d5588f00f49b868476bb1'


def digest(path):
    with path.open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()


def vector_key(values):
    if all(value is None for value in values):
        return None
    numbers = [value or 0.0 for value in values]
    if not all(math.isfinite(value) for value in numbers):
        raise ValueError('nonfinite_table_input')
    return bytes(value is not None for value in values) + struct.pack(f'!{len(numbers)}f', *numbers)


def connected_groups(vectors, measured, representatives):
    size = len(measured)
    if len(representatives) != size or any(not 0 <= root < size for root in representatives):
        raise ValueError('invalid_tls_components')
    if any(representatives[root] != root for root in representatives):
        raise ValueError('invalid_tls_components')
    parents = list(range(len(vectors)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def join(left, right):
        a, b = root(left), root(right)
        parents[max(a, b)] = min(a, b)

    for index, component in zip(measured, representatives, strict=True):
        join(index, measured[component])
    exact = {}
    for index, vector in enumerate(vectors):
        key = vector_key(vector)
        if key is not None:
            join(index, exact.setdefault(key, index))
    return [root(index) for index in range(len(vectors))]


def assign_roles(labels, groups, measured, *, seed):
    eligible = [index for index in sorted(measured) if labels[index] is not None]
    targets = np.asarray([labels[index] for index in eligible])
    labeled_groups = [groups[index] for index in eligible]
    splitter = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=seed)
    role_by_group = {}
    for fold, (_, validation) in enumerate(splitter.split(targets, targets, labeled_groups)):
        role = ROLES[fold + 1] if fold < 3 else 'train'
        for index in validation:
            group = labeled_groups[index]
            if role_by_group.setdefault(group, role) != role:
                raise ValueError('component_crosses_roles')
    roles = []
    for index, (label, group) in enumerate(zip(labels, groups, strict=True)):
        role = role_by_group.get(group, 'train')
        if index not in measured:
            role = 'pending_fingerprint'
        elif label is None and role != 'train':
            role = 'held_out_unlabeled'
        roles.append(role)
    for role in ROLES:
        if {label for label, assigned in zip(labels, roles) if assigned == role and label is not None} != {0, 1}:
            raise ValueError(f'{role}_missing_class')
    return roles


def native(engine, command, header, hashes):
    value = '\n'.join([header, *hashes, ''])
    result = subprocess.run([str(engine.resolve()), *command], input=value, text=True, encoding='ascii',
                            capture_output=True, check=True, timeout=1800)
    return [int(line) for line in result.stdout.splitlines()]


def load_records(pool, view):
    with gzip.open(pool, 'rt', encoding='ascii') as original, view.open(encoding='ascii') as annotated:
        original_header, label_header = json.loads(next(original)), json.loads(next(annotated))
        if (label_header['pool_sha256'] != digest(pool)
                or original_header['features'] != label_header['feature_names']):
            raise ValueError('label_view_pool_mismatch')
        rows, vectors, seen = [], [], set()
        for raw, row in zip(map(json.loads, original), map(json.loads, annotated), strict=True):
            sha, _, _, status, fields, graph = raw
            if (sha in seen or row['sha256'] != sha or row['status'] != status
                    or row['graph_available'] != (graph is not None) or row['label'] not in (0, 1, None)
                    or len(fields) != len(label_header['feature_names'])):
                raise ValueError('label_view_row_mismatch')
            seen.add(sha)
            rows.append(row)
            vectors.append(fields)
    return rows, vectors


def load_fingerprints(path, *, additional=None, additional_sha256=None):
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    if value['report_sha256'] != FINGERPRINT_REPORT or len(value['fingerprints']) != 21559:
        raise ValueError('unexpected_fingerprint_source')
    rows = value['fingerprints']
    if additional is not None:
        from malpdf.extraction.pooled_fingerprint_job import SAMPLES, contract

        if digest(additional) != additional_sha256:
            raise ValueError('additional_fingerprint_digest_mismatch')
        result = json.loads(additional.read_text(encoding='utf-8-sig'))
        if (result['inputs'] != contract() or result['new_malware_labels'] != 0
                or len(result['fingerprints']) != SAMPLES):
            raise ValueError('unexpected_additional_fingerprint_source')
        rows = rows + result['fingerprints']
    fingerprints = {}
    for row in rows:
        sha, state, fingerprint = row['sha256'], row['status'], row['tlsh']
        if (not re.fullmatch('[0-9a-f]{64}', sha) or sha in fingerprints
                or (state == 'measured' and (not isinstance(fingerprint, str) or not TLSH.fullmatch(fingerprint)))
                or (state != 'measured' and fingerprint is not None)):
            raise ValueError('invalid_fingerprint_record')
        fingerprints[sha] = fingerprint
    return fingerprints


def write_json(path, payload):
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Build a grouped research split from verified existing fingerprints')
    for name in ('pool', 'label-view', 'fingerprints', 'engine', 'verification-engine', 'run-directory', 'split-view'):
        parser.add_argument(f'--{name}', type=Path, required=True)
    parser.add_argument('--additional-fingerprints', type=Path)
    parser.add_argument('--additional-report-sha256')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    rows, vectors = load_records(args.pool, args.label_view)
    fingerprints = load_fingerprints(args.fingerprints, additional=args.additional_fingerprints,
                                     additional_sha256=args.additional_report_sha256)
    measured = [i for i, row in enumerate(rows) if fingerprints.get(row['sha256']) is not None]
    hashes = [fingerprints[rows[i]['sha256']] for i in measured]
    labels = [row['label'] for row in rows]
    args.run_directory.mkdir(parents=True, exist_ok=False)
    paths = [args.pool, args.label_view, args.fingerprints, args.engine, args.verification_engine, Path(__file__)]
    if args.additional_fingerprints is not None:
        paths.append(args.additional_fingerprints)
    write_json(args.run_directory / 'locked_methodology.json', {
        'started_utc': datetime.now(timezone.utc).isoformat(), 'seed': args.seed,
        'versions_sha256': {path.name: digest(path) for path in paths},
        'upstream_fingerprint_report_sha256': FINGERPRINT_REPORT,
        'role_fold_counts': dict(zip(ROLES, (7, 1, 1, 1))), 'tlsh_max_distance': 30,
        'exact_vector': 'float32, signed zero normalized, explicit missingness mask',
        'missing_tlsh': 'pending_fingerprint; ineligible for all model fitting and evaluation in this run',
        'ssl': 'measured, label is null, connected group assigned to training only',
    })
    groups = connected_groups(vectors, measured, native(args.engine, ['--components'], str(len(hashes)), hashes))
    roles = assign_roles(labels, groups, set(measured), seed=args.seed)
    by_role = {role: set() for role in ROLES}
    keys = {role: set() for role in ROLES}
    for i in measured:
        if roles[i] in by_role:
            by_role[roles[i]].add(fingerprints[rows[i]['sha256']])
            key = vector_key(vectors[i])
            if key is not None:
                keys[roles[i]].add(key)
    checks = {}
    for left_role, right_role in combinations(ROLES, 2):
        refs, queries = sorted(by_role[left_role]), sorted(by_role[right_role])
        nearest = native(args.verification_engine, [], f'{len(refs)} {len(queries)}', refs + queries)
        if len(nearest) != len(queries) or min(nearest) <= 30 or keys[left_role] & keys[right_role]:
            raise ValueError(f'cross_role_overlap_{left_role}_{right_role}')
        checks[f'{left_role}/{right_role}'] = {'min_tlsh': min(nearest), 'exact_vectors': 0}
    counts, statuses, source_counts = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
    with args.split_view.open('x', encoding='ascii', newline='\n') as out:
        out.write(json.dumps({'schema_version': 1, 'label_view_sha256': digest(args.label_view)}) + '\n')
        for i, (row, role) in enumerate(zip(rows, roles, strict=True)):
            status_group = 'bounded_complete' if row['status'] == 'bounded_complete' else 'degraded_or_unsupported'
            counts[role]['unlabeled' if labels[i] is None else ('benign', 'malicious')[labels[i]]] += 1
            statuses[role][status_group] += 1
            source_counts[role][row['label_source']] += 1
            out.write(json.dumps({'sha256': row['sha256'], 'role': role, 'group': rows[groups[i]]['sha256']},
                                 separators=(',', ':')) + '\n')
    metrics = {'rows': len(rows), 'measured_in_pool': len(measured), 'unmeasured_in_report': sum(
        row['sha256'] in fingerprints and fingerprints[row['sha256']] is None for row in rows),
        'role_label_counts': counts, 'role_status_counts': statuses, 'role_source_counts': source_counts,
        'cross_role_checks': checks, 'split_view_sha256': digest(args.split_view)}
    write_json(args.run_directory / 'metrics.json', metrics)
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
