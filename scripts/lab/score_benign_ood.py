from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from functools import partial
from hashlib import file_digest
import json
from pathlib import Path

import numpy as np
from scipy.stats import beta
import torch

from malpdf.extraction.tlsh import DISTANCE_LIMIT, TLSH_RE, nearest_distances, screen
from malpdf.features.contract_v3 import FEATURES, RobustTransform
from malpdf.models.pdf_transgraph_v3 import PDFTransGraphV3, TransGraphV3Config, load_v3_weights_npz
from scripts.lab.build_clean_splits import ROLES, native
from scripts.lab.export_vapd_retrospective_inputs import GRAPH_KEYS, graph_arrays
from scripts.lab.train_eval_transgraph_v3 import (
    REGIME_B_INDICES, REGIME_B_NAMES, apply_temperature, gather_graph_list_batch, slice_regime_inputs,
)


def digest(path):
    with path.open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()


def read_json(path, expected=None):
    if expected is not None and digest(path) != expected:
        raise ValueError(f'locked_input_changed:{path.name}')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def references(split, reports):
    fingerprints = {}
    for report in reports:
        for row in report['fingerprints']:
            sha, value = row['sha256'], row['tlsh']
            if sha in fingerprints or (value is not None and not TLSH_RE.fullmatch(value)):
                raise ValueError('invalid_pooled_fingerprint_reference')
            fingerprints[sha] = value
    with split.open(encoding='ascii') as stream:
        next(stream)
        roles = {row['sha256']: row['role'] for row in map(json.loads, stream)}
    study = {sha: fingerprints[sha] for sha, role in roles.items() if role in ROLES}
    train = {sha: study[sha] for sha in study if roles[sha] == 'train'}
    if len(study) != 41619 or len(train) != 35537 or None in study.values():
        raise ValueError('incomplete_study_fingerprint_coverage')
    return train, study, roles.keys()


def admit(rows, train, study, exact_pool, nearest, components):
    candidate_hashes = {row['sha256']: row['tlsh'] for row in rows}
    against_train = screen(train, candidate_hashes, nearest)
    against_study = screen(study, candidate_hashes, nearest)
    decisions, eligible = {}, []
    for row in sorted(rows, key=lambda x: (x['source'], x['id'])):
        sha = row['sha256']
        reason = against_study[sha]['disposition']
        if sha in exact_pool:
            reason = 'exact_duplicate'
        decision = {'train_min_tlsh': against_train[sha]['distance'], 'study_min_tlsh': against_study[sha]['distance'],
                    'admission': reason, 'cluster': None, 'representative': False}
        decisions[sha] = decision
        if reason == 'no_near_duplicate_in_reference':
            eligible.append(row)
    if eligible:
        parents = components([row['tlsh'] for row in eligible])
        if len(parents) != len(eligible) or any(not 0 <= i < len(eligible) or parents[i] != i for i in parents):
            raise ValueError('invalid_external_clusters')
        representatives = {}
        for row, parent in zip(eligible, parents, strict=True):
            sha = row['sha256']
            rep = representatives.setdefault(parent, sha)
            decisions[sha].update(cluster=rep, representative=rep == sha)
    return decisions


def interval_summary(flagged, count):
    upper = (float(beta.ppf(0.95, flagged + 1, count - flagged)) if flagged < count else 1.0) if count else None
    return {'false_positives': flagged, 'evaluated': count,
            'fpr': flagged / count if count else None, 'one_sided_95_upper': upper}


def score_rows(rows, cfg, scaler, weights, temperature):
    device = torch.device('cpu')
    model = PDFTransGraphV3(TransGraphV3Config(**read_json(cfg))).eval()
    if (model.config.use_missing_mask or not model.config.enable_graph or not model.config.enable_tab
            or model.config.tab_dim != len(REGIME_B_NAMES)):
        raise ValueError('unexpected_regime_b_model')
    load_v3_weights_npz(model, weights, map_location=device)
    with np.load(scaler, allow_pickle=False) as values:
        transform = RobustTransform(values['center'], values['scale'], values['available'])
    if not rows:
        return []
    observed, missing = transform.transform([row['features'] for row in rows])
    table, _, ast, ast_missing = slice_regime_inputs(observed, missing, 'regime_b')
    graphs = [graph_arrays(dict(zip(GRAPH_KEYS, row['graph'], strict=True), node_feature_dim=23)) for row in rows]
    packed_graphs = gather_graph_list_batch(graphs, device)
    with torch.inference_mode():
        out = model(torch.from_numpy(table), None, torch.from_numpy(ast), torch.from_numpy(ast_missing.astype(np.float32)), *packed_graphs)
    probabilities = apply_temperature(out['logits'].cpu().numpy(), temperature)
    return [{'probability': float(p), 'branch_weights': w.tolist(), 'branch_mask': m.tolist()}
            for p, w, m in zip(probabilities, out['weights'].cpu().numpy(), out['modality_mask'].cpu().numpy(), strict=True)]


def evaluation(export, membership, decisions, thresholds, scorer):
    received = {row['id']: row for row in membership['entries']}
    rows = export['rows']
    if (len(rows) != len(received) or {row['id'] for row in rows} != set(received)
            or export['feature_order'] != list(FEATURES)):
        raise ValueError('exported_cohort_differs_from_intake')
    ready, result_rows = [], []
    for row in rows:
        identity, sha = row['id'], row['sha256']
        expected = received[identity]
        if sha != expected['sha256'] or row['source'] != expected['source']:
            raise ValueError('exported_row_differs_from_intake')
        summary = {key: row[key] for key in ('id', 'sha256', 'source', 'status')}
        summary.update(decisions[sha])
        result_rows.append(summary)
        if summary['admission'] != 'no_near_duplicate_in_reference':
            summary['score_status'] = 'excluded'
        elif row['graph'] is None or row['features'] is None:
            summary['score_status'] = 'incomplete_extraction'
        elif any(row['features'][i] is None for i in REGIME_B_INDICES):
            summary['score_status'] = 'regime_b_feature_missing'
        else:
            summary['score_status'] = 'scored'
            ready.append((row, summary))
    for (_, summary), score in zip(ready, scorer([row for row, _ in ready]), strict=True):
        summary.update(score)
    slices = defaultdict(list)
    for row in result_rows:
        slices['all_candidates'].append(row)
        slices['publisher/' + row['source']].append(row)
        if row['representative']:
            slices['independent_representatives'].append(row)
            slices['representative_publisher/' + row['source']].append(row)
    aggregated = {}
    for name, subset in slices.items():
        scored = [row for row in subset if row['score_status'] == 'scored']
        counts = Counter(row['score_status'] for row in subset)
        aggregated[name] = {'denominator_before_admission': len(subset), 'status_counts': counts,
                            'thresholds': {key: interval_summary(sum(row['probability'] >= cutoff for row in scored), len(scored))
                                           for key, cutoff in thresholds.items()}}
    return {'metrics': aggregated, 'rows': result_rows}


def main():
    parser = argparse.ArgumentParser(description='Score the frozen v3 checkpoint on admitted publisher controls')
    for name in ('lock', 'export', 'membership', 'split', 'holdout', 'pooled', 'weights', 'model-config',
                 'scaler', 'distance-engine', 'component-engine', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    lock = read_json(args.lock)
    for name, expected in lock['input_sha256'].items():
        if digest(getattr(args, name)) != expected:
            raise ValueError(f'locked_input_changed:{name}')
    repository = Path(__file__).resolve().parents[2]
    for name, expected in lock['source_sha256'].items():
        if digest(repository / name) != expected:
            raise ValueError(f'locked_scoring_source_changed:{name}')
    export = read_json(args.export)
    if (export['job_id'] != lock['job_id'] or export['manifest_sha256'] != lock['acquisition_manifest_sha256']
            or export['runner']['status'] not in ('passed', 'partial')
            or not all(export['runner']['preflight'][k] for k in ('guest_network_checked', 'hypervisor_controls_attested'))):
        raise ValueError('offline_export_not_verified')
    torch.set_num_threads(4)
    train, study, pool = references(args.split, [read_json(args.holdout), read_json(args.pooled)])
    nearest = partial(nearest_distances, args.distance_engine)
    decisions = admit(export['rows'], train, study, pool, nearest,
                      lambda hashes: native(args.component_engine, ['--components'], str(len(hashes)), hashes))
    result = evaluation(export, read_json(args.membership), decisions, lock['thresholds'],
                        partial(score_rows, cfg=args.model_config, scaler=args.scaler, weights=args.weights,
                                temperature=lock['temperature']))
    with args.out.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump({'job_id': lock['job_id'], 'locked_methodology_sha256': digest(args.lock),
                   'export_sha256': digest(args.export), 'train_references': len(train), 'study_references': len(study),
                   'tlsh_min_required_exclusive': DISTANCE_LIMIT, **result}, stream, indent=2, allow_nan=False)
        stream.write('\n')


if __name__ == '__main__':
    main()
