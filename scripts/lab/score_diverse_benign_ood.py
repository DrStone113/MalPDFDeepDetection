from __future__ import annotations

import argparse
from functools import partial
import json
from pathlib import Path

import torch

from malpdf.extraction.tlsh import TLSH_RE, nearest_distances
from malpdf.features.contract_v3 import FEATURES
from scripts.lab.build_clean_splits import native
from scripts.lab.score_benign_ood import admit, digest, evaluation, read_json, references, score_rows

TRACK_B_SOURCES = frozenset({'arxiv', 'irs', 'nist', 'nasa'})
TRACK_C1_SOURCES = frozenset({'verapdf', 'pdfjs'})
IDX = {name: i for i, name in enumerate(FEATURES)}


def partition_by_track(entries: list[dict], rows: list[dict]) -> dict[str, tuple[list[dict], list[dict]]]:
    groups = {'prospective_diverse_publishers': TRACK_B_SOURCES, 'hard_benign_stress': TRACK_C1_SOURCES}
    out = {}
    for track, allowed in groups.items():
        t_entries = [e for e in entries if e['source'] in allowed]
        t_rows = [r for r in rows if r['source'] in allowed]
        out[track] = (t_entries, t_rows)
    if sum(len(v[0]) for v in out.values()) != len(entries) or sum(len(v[1]) for v in out.values()) != len(rows):
        raise ValueError('unexpected_diverse_ood_source')
    return out


def active_feature_slices(export_rows: list[dict], eval_rows: list[dict], prospective_thr: float) -> dict[str, dict]:
    feat_by_id = {r['id']: r.get('features') for r in export_rows}
    slices = {
        'has_acroform': lambda f, st: f is not None and (f[IDX['lexical_AcroForm']] or 0) > 0,
        'has_js': lambda f, st: f is not None and ((f[IDX['lexical_JS']] or 0) + (f[IDX['lexical_JavaScript']] or 0)) > 0,
        'has_aa_or_openaction': lambda f, st: f is not None and ((f[IDX['lexical_AA']] or 0) + (f[IDX['lexical_OpenAction']] or 0)) > 0,
        'has_embedded_file': lambda f, st: f is not None and (f[IDX['lexical_EmbeddedFile']] or 0) > 0,
        'has_jbig2': lambda f, st: f is not None and (f[IDX['lexical_JBIG2Decode']] or 0) > 0,
        'has_objstm': lambda f, st: f is not None and (f[IDX['lexical_ObjStm']] or 0) > 0,
        'has_encrypt': lambda f, st: f is not None and (f[IDX['lexical_Encrypt']] or 0) > 0,
        'has_uri': lambda f, st: f is not None and (f[IDX['lexical_URI']] or 0) > 0,
        'degraded_status': lambda f, st: st != 'bounded_complete',
    }
    scored = [r for r in eval_rows if r.get('score_status') == 'scored']
    out = {}
    for s_name, pred in slices.items():
        sub = [r for r in scored if pred(feat_by_id.get(r['id']), r['status'])]
        probs = [r['probability'] for r in sub]
        out[s_name] = {
            'count': len(sub),
            'fp_prospective': sum(p >= prospective_thr for p in probs),
            'max_prob': max(probs) if probs else None,
        }
    return out


def score_diverse_export(
    *,
    export_doc: dict,
    membership: dict,
    train_refs: dict,
    study_refs: dict,
    exact_pool: set[str],
    thresholds: dict[str, float],
    decision_target_fpr: float,
    distance_exec: Path,
    component_exec: Path,
    model_config: Path,
    scaler: Path,
    weights: Path,
    temperature: float,
) -> dict:
    nearest = partial(nearest_distances, distance_exec)
    comp = lambda hashes: native(component_exec, ['--components'], str(len(hashes)), hashes)
    scorer = partial(score_rows, cfg=model_config, scaler=scaler, weights=weights, temperature=temperature)
    partitioned = partition_by_track(membership['entries'], export_doc['rows'])

    tracks = {}
    for track_name, (t_entries, t_rows) in partitioned.items():
        decisions = admit(t_rows, train_refs, study_refs, exact_pool, nearest, comp)
        t_export = {**export_doc, 'rows': t_rows}
        t_member = {**membership, 'entries': t_entries}
        report = evaluation(t_export, t_member, decisions, thresholds, scorer)
        report['active_feature_slices'] = active_feature_slices(t_rows, report['rows'], thresholds['prospective'])
        tracks[track_name] = report

    pub = tracks['prospective_diverse_publishers']
    ind = pub['metrics'].get('independent_representatives', {})
    prim = ind.get('thresholds', {}).get('prospective', {})
    upper = prim.get('one_sided_95_upper')
    complete = bool(ind) and prim.get('evaluated') == ind['denominator_before_admission']
    qualified = complete and upper is not None and upper <= decision_target_fpr
    return {
        'representative_scoring_complete': complete,
        'primary_threshold_qualified': qualified,
        'tracks': tracks,
    }


def main():
    parser = argparse.ArgumentParser(description='Score diverse publisher OOD and hard-benign export')
    for name in ('lock', 'export', 'membership', 'split', 'holdout', 'pooled', 'pilot', 'expanded',
                 'weights', 'model-config', 'scaler', 'distance-engine', 'component-engine', 'out'):
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
            or runner['job']['job_id'] != lock['job_id'] or runner['job']['kind'] != 'pdf-benign-ood-diverse'
            or runner['status'] not in ('passed', 'partial')
            or not all(runner['preflight'][key] for key in ('guest_network_checked', 'hypervisor_controls_attested'))):
        raise ValueError('offline_diverse_export_not_verified')

    torch.set_num_threads(4)
    train, study, pool = references(args.split, [read_json(args.holdout), read_json(args.pooled)])
    pilot_rows = read_json(args.pilot)['rows']
    pilot = {row['sha256']: row['tlsh'] for row in pilot_rows}
    if len(pilot) != 83 or None in pilot.values():
        raise ValueError('incomplete_previous_publisher_reference')
    exp_rows = read_json(args.expanded)['rows']
    expanded_tls = {row['sha256']: row['tlsh'] for row in exp_rows if row.get('tlsh') is not None}
    if len(expanded_tls) < 360:
        raise ValueError('incomplete_expanded_publisher_reference')
    expanded_shas = {row['sha256'] for row in exp_rows}

    scored = score_diverse_export(
        export_doc=result,
        membership=read_json(args.membership),
        train_refs=train,
        study_refs=study | pilot | expanded_tls,
        exact_pool=set(pool) | pilot.keys() | expanded_shas,
        thresholds=lock['thresholds'],
        decision_target_fpr=lock['decision_target_fpr'],
        distance_exec=args.distance_engine,
        component_exec=args.component_engine,
        model_config=args.model_config,
        scaler=args.scaler,
        weights=args.weights,
        temperature=lock['temperature'],
    )
    payload = {
        'job_id': lock['job_id'],
        'locked_methodology_sha256': digest(args.lock),
        'export_sha256': digest(args.export),
        'train_references': len(train),
        'study_references': len(study),
        'prior_ood_references': len(pilot) + len(expanded_tls),
        **scored,
    }
    with args.out.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(payload, stream, indent=2, allow_nan=False)
        stream.write('\n')


if __name__ == '__main__':
    main()
