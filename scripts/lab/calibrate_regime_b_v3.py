from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path

import numpy as np
import torch

from malpdf.evaluation.binary import classification_metrics_from_confusion_counts
from malpdf.evaluation.operating_point import midpoint_macro_f1
from malpdf.features.contract_v3 import FEATURES, RobustTransform
from malpdf.models.pdf_transgraph_v3 import PDFTransGraphV3, TransGraphV3Config, load_v3_weights_npz
from scripts.lab.score_benign_ood import digest, read_json
from scripts.lab.train_eval_transgraph_v3 import apply_temperature, gather_graph_list_batch, slice_regime_inputs


def load_validation(pool, table, labels, split, benign_supplement=None):
    with split.open(encoding='ascii') as stream:
        next(stream)
        selected = sorted(row['sha256'] for row in map(json.loads, stream) if row['role'] == 'val_calib')
    members = set(selected)
    if len(members) != len(selected):
        raise ValueError('duplicate_calibration_identity')
    with labels.open(encoding='ascii') as stream:
        next(stream)
        targets = {row['sha256']: row['label'] for row in map(json.loads, stream) if row['sha256'] in members}
    with gzip.open(table, 'rt', encoding='ascii') as stream:
        if json.loads(next(stream))['features'] != list(FEATURES):
            raise ValueError('unexpected_calibration_feature_order')
        vectors = {}
        for item in map(json.loads, stream):
            if isinstance(item, list) and item[0] in members:
                vectors[item[0]] = item[1]
    with gzip.open(pool, 'rt', encoding='ascii') as stream:
        next(stream)
        graphs = {row[0]: row[5] for row in map(json.loads, stream) if row[0] in members}
    if (targets.keys() != members or vectors.keys() != members or graphs.keys() != members
            or set(targets.values()) != {0, 1}):
        raise ValueError('incomplete_calibration_cohort')
    out_labels = [targets[sha] for sha in selected]
    out_features = [vectors[sha] for sha in selected]
    out_graphs = [graphs[sha] for sha in selected]
    if benign_supplement is not None:
        supp_rows = read_json(benign_supplement)['rows']
        supp_calib = []
        for row in supp_rows:
            role = row['role']
            if role == 'test_internal' or role not in ('train', 'val_select', 'val_calib'):
                raise ValueError(f'forbidden_supplement_role:{role}')
            if role == 'val_calib':
                supp_calib.append(row)
        for row in sorted(supp_calib, key=lambda r: r['sha256']):
            sha = row['sha256']
            if sha in members:
                raise ValueError('duplicate_calibration_identity')
            if row.get('features') is None or row.get('graph') is None:
                raise ValueError('incomplete_calibration_cohort')
            members.add(sha)
            out_labels.append(0)
            out_features.append(row['features'])
            out_graphs.append(row['graph'])
    return out_labels, out_features, out_graphs


def report_at(labels, probabilities, threshold):
    alerts = probabilities >= threshold
    benign = labels == 0
    counts = {'tn': int((benign & ~alerts).sum()), 'fp': int((benign & alerts).sum()),
              'fn': int((~benign & ~alerts).sum()), 'tp': int((~benign & alerts).sum())}
    scores = classification_metrics_from_confusion_counts(**counts)
    return {'threshold': threshold, **counts, 'f1_macro': scores['f1_macro'],
            'recall': scores['recall_malicious'], 'fpr': counts['fp'] / int(benign.sum())}


def write(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description='Select a prospective Regime B threshold on Val_Calib only')
    for name in ('pool', 'table', 'labels', 'split', 'study-lock', 'weights', 'config', 'scaler', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--benign-supplement', type=Path, default=None)
    parser.add_argument('--max-threshold', type=float, default=1.0)
    parser.add_argument('--model-lock', type=Path, default=None)
    parser.add_argument('--run-metrics', type=Path, default=None)
    args = parser.parse_args()
    if bool(args.model_lock) == bool(args.run_metrics):
        raise ValueError('specify_exactly_one_of_model_lock_or_run_metrics')
    study_lock = read_json(args.study_lock)
    paths = {'pool': args.pool, 'tabular': args.table, 'label_view': args.labels, 'split_view': args.split}
    for name, path in paths.items():
        if digest(path) != study_lock['inputs_sha256'][name]:
            raise ValueError(f'calibration_input_changed:{name}')
    if args.benign_supplement is not None and digest(args.benign_supplement) != study_lock['inputs_sha256'].get('benign_supplement'):
        raise ValueError('calibration_input_changed:benign_supplement')
    rule = 'midpoint of widest contiguous maximum macro F1 interval'
    if args.max_threshold < 1.0:
        rule = f'{rule} within (0, {args.max_threshold:.6g}]'
    lock_meta = {'generated_utc': datetime.now(timezone.utc).isoformat(),
                 'partition': 'val_calib',
                 'threshold_rule': rule,
                 'max_threshold': args.max_threshold,
                 'study_lock_sha256': digest(args.study_lock),
                 'program_sha256': digest(Path(__file__))}
    if args.benign_supplement is not None:
        lock_meta['benign_supplement_sha256'] = digest(args.benign_supplement)
    if args.model_lock is not None:
        model_lock = read_json(args.model_lock)
        for name, path in {'weights': args.weights, 'model_config': args.config, 'scaler': args.scaler}.items():
            if digest(path) != model_lock['input_sha256'][name]:
                raise ValueError(f'calibration_input_changed:{name}')
        temperature = model_lock['temperature']
        baseline_thresholds = model_lock['thresholds']
        lock_meta['model_lock_sha256'] = digest(args.model_lock)
    else:
        run_metrics = read_json(args.run_metrics)
        model_meta = run_metrics['regime_b_primary']['models']['v3_tab_graph_ssl_inv']
        temperature = model_meta['temperature']
        baseline_thresholds = model_meta['thresholds']
        lock_meta['run_metrics_sha256'] = digest(args.run_metrics)
        lock_meta['weights_sha256'] = digest(args.weights)
        lock_meta['model_config_sha256'] = digest(args.config)
        lock_meta['scaler_sha256'] = digest(args.scaler)
    lock_meta['temperature'] = temperature
    args.out.mkdir(parents=True, exist_ok=False)
    write(args.out / 'locked_methodology.json', lock_meta)
    labels, features, graphs = load_validation(args.pool, args.table, args.labels, args.split, benign_supplement=args.benign_supplement)
    supp_calib_count = (
        0 if args.benign_supplement is None
        else sum(1 for row in read_json(args.benign_supplement)['rows'] if row['role'] == 'val_calib')
    )
    torch.set_num_threads(4)
    device = torch.device('cpu')
    model = PDFTransGraphV3(TransGraphV3Config(**read_json(args.config))).eval()
    load_v3_weights_npz(model, args.weights, map_location=device)
    with np.load(args.scaler, allow_pickle=False) as values:
        transformer = RobustTransform(values['center'], values['scale'], values['available'])
    table, _, ast, missing_ast = slice_regime_inputs(*transformer.transform(features), 'regime_b')
    logits = []
    with torch.inference_mode():
        for first in range(0, len(labels), 128):
            batch = slice(first, first + 128)
            packed = gather_graph_list_batch(graphs[batch], device)
            output = model(torch.from_numpy(table[batch]), None, torch.from_numpy(ast[batch]),
                           torch.from_numpy(missing_ast[batch]), *packed)
            logits.extend(output['logits'].numpy().tolist())
    target = np.asarray(labels)
    scores = apply_temperature(logits, temperature)
    point = midpoint_macro_f1(target, scores, max_threshold=args.max_threshold)
    result = {'n': len(labels), 'benign_supplement_val_calib_count': supp_calib_count,
              'max_threshold': args.max_threshold,
              'candidate': point, 'candidate_metrics': report_at(target, scores, point['threshold']),
              'baseline': {key: report_at(target, scores, threshold) for key, threshold in baseline_thresholds.items()},
              'external_used_for_calibration': False, 'test_used_for_calibration': False, 'deployed': False}
    write(args.out / 'metrics.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
