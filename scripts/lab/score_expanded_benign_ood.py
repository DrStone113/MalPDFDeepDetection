from __future__ import annotations

import argparse
from functools import partial
import json
from pathlib import Path

import torch

from malpdf.extraction.tlsh import nearest_distances
from scripts.lab.build_clean_splits import native
from scripts.lab.score_benign_ood import admit, digest, evaluation, read_json, references, score_rows


def main():
    parser = argparse.ArgumentParser(description='Validate the prospective v3 threshold on fresh publisher PDFs')
    for name in ('lock', 'export', 'membership', 'split', 'holdout', 'pooled', 'pilot', 'weights',
                 'model-config', 'scaler', 'distance-engine', 'component-engine', 'out'):
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
    result = read_json(args.export)
    runner = result['runner']
    if (result['job_id'] != lock['job_id'] or result['manifest_sha256'] != lock['acquisition_manifest_sha256']
            or runner['job']['job_id'] != lock['job_id'] or runner['job']['kind'] != 'pdf-benign-ood-expanded'
            or runner['status'] not in ('passed', 'partial')
            or not all(runner['preflight'][key] for key in ('guest_network_checked', 'hypervisor_controls_attested'))):
        raise ValueError('offline_export_not_verified')
    torch.set_num_threads(4)
    train, study, pool = references(args.split, [read_json(args.holdout), read_json(args.pooled)])
    pilot = {row['sha256']: row['tlsh'] for row in read_json(args.pilot)['rows']}
    if len(pilot) != 83 or None in pilot.values():
        raise ValueError('incomplete_previous_publisher_reference')
    nearest = partial(nearest_distances, args.distance_engine)
    decisions = admit(result['rows'], train, study | pilot, pool | pilot.keys(), nearest,
                      lambda hashes: native(args.component_engine, ['--components'], str(len(hashes)), hashes))
    report = evaluation(result, read_json(args.membership), decisions, lock['thresholds'],
                        partial(score_rows, cfg=args.model_config, scaler=args.scaler, weights=args.weights,
                                temperature=lock['temperature']))
    independent = report['metrics'].get('independent_representatives', {})
    primary = independent.get('thresholds', {}).get('prospective', {})
    upper = primary.get('one_sided_95_upper')
    complete = bool(independent) and primary.get('evaluated') == independent['denominator_before_admission']
    qualified = complete and upper is not None and upper <= lock['decision_target_fpr']
    with args.out.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump({'job_id': lock['job_id'], 'locked_methodology_sha256': digest(args.lock),
                   'export_sha256': digest(args.export), 'train_references': len(train), 'study_references': len(study),
                   'pilot_references': len(pilot), 'representative_scoring_complete': complete,
                   'primary_threshold_qualified': qualified, **report},
                  stream, indent=2, allow_nan=False)
        stream.write('\n')


if __name__ == '__main__':
    main()
