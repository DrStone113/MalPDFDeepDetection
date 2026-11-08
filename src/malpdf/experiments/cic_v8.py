"""Private v7 audit and same-identity v8 evaluation; never reread baseline PDFs."""

from collections import Counter
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from malpdf.inference.evidence_policy import evidence_decision, POLICY_ID
from malpdf.provenance.research_runs import write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes

V7_RUN = 'run_20261010T154029301301Z_20cf4e14ac84'


def locked_v8_design():
    return {'schema': 'pdf-evidence-v8', 'policy': POLICY_ID, 'threshold': 0.5,
        'fitting': 'fixed RF budget from baseline config; Train only; median+missing indicators; no selection',
        'calibration': 'not fitted: small exposed development subset, no calibration claim',
        'completeness': 'primary completeness retained; independent recovery stays partial; latest reachable catalog only',
        'recovery': 'one independent read-only MuPDF view; shared explicit decoded-byte/AST allowance; no QPDF installed',
        'budgets': 'baseline CPU/RAM/wall/file caps; per-traversal object/depth caps; native implicit decoding only OS-capped',
        'benchmark_attempts': 1, 'deployment': False, 'test_access': False,
        'acceptance': 'all64 same identities/labels/splits; unexplained P0/P1/P2 changes block release; final technical evidence review required'}


def baseline_evidence_checksums(root):
    """Seal saved evidence at preparation without reading a PDF or exposing IDs."""
    specifications = {}
    for folder, names in [('reports/experiments/cic_static_profile', ['run_summary.json','locked_methodology.json']),
                          ('artifacts/cic_static_profile', ['per_file.jsonl','development_predictions.json','observed_development_predictions.json'])]:
        for name in names:
            relative = Path(folder)/V7_RUN/name
            content = read_bounded_bytes(root/relative,boundary=root/relative.parts[0],max_bytes=32*1024**2)
            specifications[str(relative)] = hashlib.sha256(content).hexdigest()
    return specifications


def _attempt_path(root, prepared_run):
    import re
    if not re.fullmatch(r'run_[A-Za-z0-9_-]{1,100}', prepared_run):
        raise ValueError('Unsafe prepared-run identity')
    path = root/'artifacts/cic_static_prepare'/prepared_run/'v8_attempt.json'
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('Unsafe v8 attempt path')
    return path


def v8_attempt_outcome(root, prepared_run):
    """Read saved aggregate outcome only; never release or replace a claim."""
    path = _attempt_path(root, prepared_run)
    if not path.exists():
        return None
    marker = _json(root, path.relative_to(root))
    if marker['prepared_run'] != prepared_run:
        raise ValueError('V8 attempt identity mismatch')


    directory = root/'reports/experiments/cic_static_profile'
    profile_run = marker.get('profile_run')
    if profile_run is not None:
        import re
        if not re.fullmatch(r'run_[A-Za-z0-9_-]{1,100}', profile_run):
            raise ValueError('Unsafe saved profile-run identity')
        lock_paths = [directory/profile_run/'locked_methodology.json']
    else:
        lock_paths = sorted(directory.glob('run_*/locked_methodology.json'))
    candidates = []
    for lock_path in lock_paths:
        if not lock_path.exists():
            continue
        lock = _json(root, lock_path.relative_to(root))
        if lock.get('prepared_run') == prepared_run:
            candidates.append(lock_path.parent)
        elif profile_run is not None:
            raise ValueError('V8 attempt profile methodology mismatch')
    if len(candidates) > 1:
        raise ValueError('Ambiguous saved V8 attempts; inspect immutable reports')
    result = {'prepared_run': prepared_run, 'status': 'claimed_without_final_outcome',
              'report_path': None, 'recorded': None, 'planned': None, 'error_code': None}
    if not candidates:
        return result
    report = candidates[0]
    if marker.get('profile_run') not in (None, report.name):
        raise ValueError('V8 attempt profile mismatch')
    summary_path = report/'run_summary.json'
    if not summary_path.exists():
        return result
    summary = _json(root, summary_path.relative_to(root))
    result.update(status=summary['status'], report_path=str(summary_path.relative_to(root)))
    pipeline_path = report/'pipeline_summary.json'
    if pipeline_path.exists():
        cold = _json(root, pipeline_path.relative_to(root))['cold']
        result.update(recorded=cold['recorded'], planned=cold['planned'])
    error_path = Path('artifacts/cic_static_profile')/report.name/'error.json'
    if (root/error_path).exists():
        error = _json(root, error_path)
        if error.get('message', '').startswith('Insufficient available RAM for the isolated parser budget'):
            result['error_code'] = 'insufficient_parser_ram'
    return result


def claim_v8_attempt(root, prepared_run, *, profile_run=None):
    """Atomic one-attempt claim after offline preflight; interrupted claims stay."""
    import re
    from datetime import datetime, timezone
    path = _attempt_path(root, prepared_run)
    if profile_run is not None and not re.fullmatch(r'run_[A-Za-z0-9_-]{1,100}', profile_run):
        raise ValueError('Unsafe profile-run identity')
    try:
        write_json(path,{'prepared_run':prepared_run,'claimed_at_utc':datetime.now(timezone.utc).isoformat(),
                        'profile_run': profile_run,
                        'policy':'one final benchmark attempt; preserve failures/interruptions; no automatic rerun'})
    except FileExistsError as error:
        raise ValueError('V8 benchmark already attempted; inspect saved outcome instead of rerunning') from error


def _json(root, relative):
    path = root / relative
    content = read_bounded_bytes(path, boundary=root / relative.parts[0], max_bytes=32*1024**2)
    return json.loads(content)


def baseline_records(root):
    report = Path('reports/experiments/cic_static_profile') / V7_RUN
    summary, lock = (_json(root, report / name) for name in ['run_summary.json', 'locked_methodology.json'])
    if summary['status'] != 'completed' or lock['seed'] != 42 or lock['test_access'] is not False:
        raise ValueError('Invalid sealed v7 baseline')
    relative = Path('artifacts/cic_static_profile') / V7_RUN
    content = read_bounded_bytes(root/relative/'per_file.jsonl', boundary=root/'artifacts', max_bytes=32*1024**2)
    rows = [json.loads(line) for line in content.decode().splitlines() if line.strip()]
    cold = [r for r in rows if r['cache_mode']=='cold']
    if (len(cold) != 64 or len({r['pdf_sha256'] for r in cold}) != 64 or
            Counter((r['split'], int(r['Label'])) for r in cold) != {('train',0):16,('train',1):16,('validation',0):16,('validation',1):16}):
        raise ValueError('Baseline64 identities/labels/partitions invalid')
    predictions = _json(root, relative/'development_predictions.json')
    if len(predictions['sample_ids']) != len(set(predictions['sample_ids'])):
        raise ValueError('Duplicate baseline prediction identity')
    scores = predictions['predictions']['C1_rit_plus_structure_ast']
    if len(scores) != len(predictions['sample_ids']) or not all(type(p) in (int,float) and math.isfinite(p) and 0<=p<=1 for p in scores):
        raise ValueError('Invalid baseline C1 scores')
    lookup = dict(zip(predictions['sample_ids'], scores))
    if not set(lookup) <= {r['sample_id'] for r in cold if r['split']=='validation'}:
        raise ValueError('Baseline predictions not from saved development rows')
    return cold, lookup, lock


def failure_inventory(records, scores):
    inventory = []
    for row in records:
        code, static = row.get('code') or {}, row.get('static') or {}
        probability = scores.get(row['sample_id'])
        predicted = None if probability is None else int(probability>=0.5)
        errors = []
        for backend, diagnostic in [('pypdf_structure', static.get('parser',{}).get('diagnostics')),
                                    ('pypdf_code', code.get('parser_diagnostics'))]:
            if diagnostic:
                for failure in diagnostic.get('failures', []):
                    errors.append({**failure, 'backend': backend})
        inventory.append({'sha256':row['pdf_sha256'], 'sample_id':row['sample_id'], 'Label':int(row['Label']),
            'partition':row['split'], 'status':row['status'], 'failure_stage':row.get('last_stage'),
            'error_codes':row['errors'], 'reasons':row.get('reasons', []), 'backend_failures':errors,
            'recovery_attempted': bool((code.get('parser_diagnostics') or {}).get('recovery_attempt')),
            'timeout_reason':next((e for e in row['errors'] if 'timeout' in e or 'signal' in e), None),
            'structural_complete':static.get('parser',{}).get('structural_complete'),
            'script_extraction_complete':code.get('script_extraction_complete'), 'ast_complete':code.get('ast_complete'),
            'c1_probability':probability, 'c1_predicted_label':predicted,
            'c1_outcome': 'not_evaluated_train' if row['split']=='train' else 'Inconclusive' if predicted is None else
                'TP' if predicted==1 and int(row['Label'])==1 else 'FP' if predicted==1 else 'FN' if int(row['Label'])==1 else 'TN',
            'diagnostic_certainty':'observed backend failure only; no irrecoverability or malware-causality claim'})
    return inventory


def audit_v7(run):
    records, scores, lock = baseline_records(run.root)
    inventory = failure_inventory(records, scores)
    write_json(run.artifacts/'failure_inventory.json', inventory)
    counts = Counter(r['status'] for r in records)
    codes = {status:dict(Counter(e for r in records if r['status']==status for e in r['errors'])) for status in counts}
    result = {'baseline_run':V7_RUN, 'rows':64, 'status_counts':dict(counts), 'errors_overlapping_by_status':codes,
              'c1_outcomes':dict(Counter(r['c1_outcome'] for r in inventory if r['partition']=='validation')),
              'inventory_path':str((run.artifacts/'failure_inventory.json').relative_to(run.root)),
              'dataset_subset_sha256':lock['subset_sha256'], 'pdf_access':False,
              'certainty':'14 missing-startxref structural failures; 4 unclassified exceptions; actual cause/irrecoverability remains unverified'}
    write_json(run.report/'failure_analysis.json', result)
    (run.report/'failure_analysis.md').write_text(
        '# Saved v7 failure audit\n\n64 saved inputs; no PDFs reopened.\n\n'
        '23 complete, 23 partial, 18 structural parser errors. Fourteen structural open failures report '
        '`startxref_missing`; four are unclassified. Partial errors include unavailable references, invalid '
        'stream data, encrypted inputs, and object/AST/XML caps. Counts overlap. These saved failures do not '
        'establish that a PDF is irrecoverable or that a parser bug caused them. Synthetic fixtures reproduce '
        'the error categories without copying untrusted sample bytes.\n\n'
        'The private inventory retains all64 SHA-256 identities, labels, partitions, component coverage, '
        'backend failures and baseline C1 TP/FP/FN/TN/abstention. Token presence and parser failure are '
        'not malware ground truth.\n', encoding='utf-8')
    return result


def v8_feature_values(row):
    from malpdf.experiments.cic_static_accuracy import profile_feature_values, PROFILE_VARIANTS
    values = profile_feature_values(row, PROFILE_VARIANTS[2])
    values = {name: None if value == -1 else value for name,value in values.items()}
    evidence = row.get('analysis_v8') or {}
    names = ['action_'+s for s in ['JavaScript','Launch','URI','SubmitForm','GoToR','GoToE','ImportData']]
    names += ['embedded_'+s for s in ['pdf','pe','elf','zip','png','jpeg','other']]
    for name in names:
        facts = [f for f in evidence.get('features',[]) if f['name']==name and f['status'] in {'observed','absent_after_complete_check'}]


        selected = next((f for f in facts if f['source']=='pypdf'), facts[0] if facts else None)
        values['v8_'+name] = None if selected is None else selected['value']

    from malpdf.static.js_ast import CALL_NAMES
    for backend in ('pypdf','MuPDF'):
        view = next((b.get('code') for b in evidence.get('backends',[]) if b['backend']==backend), None) or {}
        observed = view.get('observed') or {}
        ast = observed.get('ast') or {}
        for name in ('node_count','max_depth','loops','computed_members'):
            values[f'v8_{backend}_ast_{name}'] = ast.get(name)
        for name in sorted(CALL_NAMES):
            values[f'v8_{backend}_call_{name}'] = None if not ast else ast.get('named_calls',{}).get(name,0)
        values[f'v8_{backend}_scripts_parsed'] = view.get('scripts_parsed')
        values[f'v8_{backend}_scripts_found'] = observed.get('scripts_found')
    return values


def fit_c1_v8(records, config):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import make_pipeline
    from malpdf.experiments.cic_static_accuracy import profile_input_available
    if not records or any(r['split'] not in {'train','validation'} or r['cache_mode']!='cold' for r in records):
        raise ValueError('C1v8 requires cold Train/development only')
    if len({r['sample_id'] for r in records}) != len(records):
        raise ValueError('Duplicate C1v8 input identity')
    set_random_seed(42)
    known = np.array([profile_input_available(r, config['limits']['max_file_bytes']) for r in records])
    train = known & np.array([r['split']=='train' for r in records])
    dev = known & np.array([r['split']=='validation' for r in records])
    labels = np.array([int(r['Label']) for r in records])
    if not set(labels) <= {0,1}:
        raise ValueError('C1v8 requires binary malicious=1 labels')
    if set(labels[train]) != {0,1}:
        raise ValueError('Insufficient C1v8 Train classes')
    features = pd.DataFrame([v8_feature_values(r) for r in records], dtype=float)
    vectors = [tuple(None if np.isnan(v) else float(v) for v in r) for r in features.to_numpy()]
    if {v for v,m in zip(vectors,train) if m} & {v for v,m in zip(vectors,dev) if m}:
        raise ValueError('C1v8 feature-equivalent groups cross locked partitions')
    if np.isinf(features.to_numpy()).any():
        raise ValueError('Non-finite C1v8 features')
    model = make_pipeline(SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True),
        RandomForestClassifier(**config['rf'],random_state=42,n_jobs=1))
    model.fit(features.loc[train],labels[train])
    probabilities = model.predict_proba(features.loc[dev])[:,1] if dev.any() else []
    scores = dict(zip((r['sample_id'] for r,m in zip(records,dev) if m),map(float,probabilities)))
    decisions = [{**evidence_decision(scores.get(r['sample_id']),r.get('analysis_v8'),input_available=bool(m)),
                  'sample_id':r['sample_id'],'sha256':r['pdf_sha256'],'Label':int(r['Label'])}
                 for r,m in zip(records,known) if r['split']=='validation']
    return model, decisions, list(features.columns), int(train.sum())


def decision_metrics(decisions):
    from malpdf.evaluation.selective import calibration_metrics
    selected = [d for d in decisions if d['predicted_label'] is not None]
    planned = Counter(d['Label'] for d in decisions)
    counts = Counter(d['Label'] for d in selected)
    tp = sum(d['Label']==1 and d['predicted_label']==1 for d in selected)
    fp = sum(d['Label']==0 and d['predicted_label']==1 for d in selected)
    ratio = lambda a,b: a/b if b else None
    return {'planned':len(decisions),'classified':len(selected),'inconclusive':len(decisions)-len(selected),
        'coverage':ratio(len(selected),len(decisions)), 'malicious_coverage':ratio(counts[1],planned[1]),
        'benign_coverage':ratio(counts[0],planned[0]),'true_positives':tp,'false_positives':fp,
        'conditional_recall':ratio(tp,counts[1]),'conditional_fpr':ratio(fp,counts[0]),
        'end_to_end_detected_fraction':ratio(tp,planned[1]),'end_to_end_false_positive_fraction':ratio(fp,planned[0]),
        'quarantine_malicious_fraction':ratio(sum(d['Label']==1 and d['operational_action']=='quarantine' for d in decisions),planned[1]),
        'quarantine_benign_fraction':ratio(sum(d['Label']==0 and d['operational_action']=='quarantine' for d in decisions),planned[0]),
        'abstention_policy':'unscored label, operational quarantine; no benign imputation; detection fractions do not count abstentions as detections',
        'metrics_classified':calibration_metrics([d['Label'] for d in selected], [d['malicious_probability'] for d in selected],threshold=0.5) if selected else None}


def compare_v8_run(run, records, lock):
    import joblib
    if lock.get('baseline_run') != V7_RUN:
        write_json(run.report/'v7_v8_comparison.json',{'status':'unavailable','reason':'v8 acceptance requires the fixed completed v7 baseline'})
        return
    old, old_scores, baseline_lock = baseline_records(run.root)
    new = [r for r in records if r['cache_mode']=='cold']
    indexed = {r['sample_id']:r for r in new}
    if len(indexed)!=64 or len(new)!=64 or lock['subset_sha256']!=baseline_lock['subset_sha256']:
        raise ValueError('V8 must retain all64 sealed v7 inputs')
    for r in old:
        n=indexed.get(r['sample_id'])
        if n is None or any(str(r[k])!=str(n[k]) for k in ['pdf_sha256','Label','split']):
            raise ValueError('V7/v8 PDF identity/label/partition mismatch')
    model, decisions, features, train_count = fit_c1_v8(new,lock['configuration'])
    metric=decision_metrics(decisions)
    write_json(run.report/'c1_v8_comparison.json',{'status':'completed','model':metric,'policy':POLICY_ID,
        'calibration':'not fitted; fixed uncalibrated pilot, small exposed Validation; no probability-calibration claim',
        'threshold_selection':False,'deployment':False})
    joblib.dump(model,run.artifacts/'C1_v8.joblib')
    write_json(run.report/'C1_v8_manifest.json',{'model_id':'c1-v8-fixed-rf-evidence-v1','feature_order':features,
        'train_rows':train_count,'seed':42,'threshold':0.5,'policy':POLICY_ID,'configuration':lock['configuration']['rf'],
        'preprocessing':'Train-only median imputation and missing indicators','deployment':False,
        'artifact_path':str((run.artifacts/'C1_v8.joblib').relative_to(run.root)),
        'artifact_sha256':hashlib.sha256((run.artifacts/'C1_v8.joblib').read_bytes()).hexdigest(),
        'code_commit':run.state['code_commit'],'dataset_manifest_hash':lock['subset_sha256'],
        'config_hash':hashlib.sha256(json.dumps(lock['configuration'],sort_keys=True).encode()).hexdigest(),
        'backend_versions':lock['fingerprint']['backends'], 'calibration_fitted':False})
    if metric['metrics_classified'] is not None:
        run.state['metrics']['C1_v8_evidence/cic_development_classified']=metric['metrics_classified']
    write_json(run.artifacts/'c1_v8_decisions.json',decisions)
    paired=[]
    decision_lookup={d['sample_id']:d for d in decisions}
    for o in old:
        n=indexed[o['sample_id']]; evidence=n.get('analysis_v8') or {}; d=decision_lookup.get(o['sample_id'])
        paired.append({'sha256':o['pdf_sha256'],'sample_id':o['sample_id'],'Label':int(o['Label']),'partition':o['split'],
            'v7_status':o['status'],'v8_status':evidence.get('status','unavailable'),'v7_c1_probability':old_scores.get(o['sample_id']),
            'v8_c1_decision':None if d is None else d['decision'],'recovery_attempted':evidence.get('recovery_attempted'),
            'recovery_success':evidence.get('recovery_success'),'backend_conflicts':evidence.get('conflicts',[]),
            'v7_errors':o['errors'],'v8_primary_errors':n.get('primary_errors',n['errors']),
            'v8_backend_errors':[b.get('error_code') for b in evidence.get('backends',[]) if b.get('error_code')],
            'primary_measurements_changed': (o.get('static') or {}).get('features')!=(n.get('static') or {}).get('features'),
            'v8_reasons':None if d is None else d['reasons']})
    write_json(run.artifacts/'v7_v8_per_sample.json',paired)
    write_json(run.artifacts/'failure_inventory.json',failure_inventory(new,{
        d['sample_id']:d['malicious_probability'] for d in decisions if d['predicted_label'] is not None}))
    error_analysis=[]
    for p in paired:
        if p['partition']!='validation':
            continue
        d=decision_lookup[p['sample_id']]
        old_label=None if p['v7_c1_probability'] is None else int(p['v7_c1_probability']>=0.5)
        outcome=lambda label: 'Inconclusive' if label is None else 'TP' if label==1 and p['Label']==1 else 'FP' if label==1 else 'FN' if p['Label']==1 else 'TN'
        evidence=indexed[p['sample_id']].get('analysis_v8') or {}
        error_analysis.append({**p,'v7_outcome':outcome(old_label),'v8_outcome':outcome(d['predicted_label']),
            'v8_probability':d['malicious_probability'],'explanation_evidence_ids':d['evidence_ids'],
            'backend_component_summary':[{'backend':b['backend'],'status':b['status'],
                'graph_errors':(b.get('graph') or {}).get('errors'),
                'action_counts':(b.get('graph') or {}).get('action_counts'),
                'script_sources':(b.get('code') or {}).get('script_sources')} for b in evidence.get('backends',[])],
            'interpretation':'prediction transition on exposed development; no causal attribution or tuning'})
    write_json(run.artifacts/'c1_error_analysis.json',error_analysis)
    old_predictions=_json(run.root,Path('artifacts/cic_static_profile')/V7_RUN/'observed_development_predictions.json')
    new_predictions=_json(run.root,run.artifacts.relative_to(run.root)/'observed_development_predictions.json')
    regression=[]
    for variant in old_predictions['probabilities']:
        a=dict(zip(old_predictions['sample_ids'],old_predictions['probabilities'][variant]))
        if variant not in new_predictions['probabilities']:
            regression.append({'variant':variant,'reason':'model_unavailable'})
            continue
        b=dict(zip(new_predictions['sample_ids'],new_predictions['probabilities'][variant]))
        if a.keys()!=b.keys():
            regression.append({'variant':variant,'reason':'eligibility_changed'})
        for identity in sorted(a.keys() & b.keys()):
            if int(a[identity]>=0.5)!=int(b[identity]>=0.5):
                regression.append({'variant':variant,'sample_id':identity,'before':int(a[identity]>=0.5),
                    'after':int(b[identity]>=0.5),'resolution':'requires per-file evidence review; no automatic acceptance'})
    write_json(run.artifacts/'p0_p1_p2_prediction_changes.json',regression)
    statuses=Counter(p['v8_status'] for p in paired)
    from malpdf.experiments.cic_static_benchmark import distribution
    parser_comparison={'samples':64,'before':dict(Counter(p['v7_status'] for p in paired)),
        'after':dict(statuses),'transitions':dict(Counter(p['v7_status']+' -> '+p['v8_status'] for p in paired)),
        'recovery_attempted':sum(bool(p['recovery_attempted']) for p in paired),
        'recovery_success_partial':sum(bool(p['recovery_success']) and p['v8_status']=='partial' for p in paired),
        'backend_disagreement_files':sum(bool(p['backend_conflicts']) for p in paired),
        'scope':'reopened/recovered remains partial; never redefine old complete to meet targets'}
    write_json(run.report/'parser_comparison.json',parser_comparison)
    resource_comparison={name:{'before':distribution([r.get(name) for r in old]),
                              'after':distribution([r.get(name) for r in new])}
                         for name in ('total_seconds','worker_seconds','peak_rss_bytes','peak_family_rss_sampled_bytes')}
    resource_comparison['scope']='cold application passes; OS cache/host load uncontrolled; RSS of whole process, not extractor-only'
    write_json(run.report/'resource_usage.json',resource_comparison)
    write_json(run.report/'c1_error_summary.json',{
        'before':dict(Counter(p['v7_outcome'] for p in error_analysis)),
        'after':dict(Counter(p['v8_outcome'] for p in error_analysis)),
        'transitions':dict(Counter(p['v7_outcome']+' -> '+p['v8_outcome'] for p in error_analysis)),
        'private_analysis_path':str((run.artifacts/'c1_error_analysis.json').relative_to(run.root)),
        'retuning':False})
    unavailable=sum(statuses[s] for s in ('unavailable','resource_limited','parser_error'))
    unsafe=any((r.get('analysis_v8') or {}).get('original_bytes_changed') is not False or
               (r.get('analysis_v8') or {}).get('active_content_executed') is not False for r in new)
    acceptance = 'blocked' if regression or unsafe else 'technical_review_required'
    comparison={'status':'completed_measurement','acceptance':acceptance,
        'baseline':V7_RUN,'paired_samples':64,'status_counts':dict(statuses),
        'recovery_attempted':sum(bool(p['recovery_attempted']) for p in paired),
        'recovery_success_partial':sum(bool(p['recovery_success']) and p['v8_status']=='partial' for p in paired),
        'backend_disagreement_files':sum(bool(p['backend_conflicts']) for p in paired),
        'p0_p1_p2_prediction_changes':len(regression),'c1':metric,
        'unavailable_or_unrecovered':unavailable, 'safety_evidence_incomplete':unsafe,
        'research_targets':{'complete_ge_32':statuses['complete']>=32,'unrecovered_parser_errors_le_9':unavailable<=9,
                            'c1_classified_ge_18':metric['classified']>=18},
        'private_per_sample_path':str((run.artifacts/'v7_v8_per_sample.json').relative_to(run.root)),
        'scope':'fixed exposed Train/dev cohort only; no Test, threshold/model selection or deployment; targets are not release claims'}
    write_json(run.report/'v7_v8_comparison.json',comparison)
    run.state['v8_acceptance']=comparison['acceptance']
    run.state['v8_results']=comparison
    (run.report/'validation_report.md').write_text(
        '# Final v8 offline measurement\n\n'
        f"Paired samples: 64. Status counts: {dict(statuses)}. C1 classified: {metric['classified']}/32. "
        f"Conditional recall: {metric['conditional_recall']}; conditional FPR: {metric['conditional_fpr']}. "
        f"End-to-end detected fraction: {metric['end_to_end_detected_fraction']}; "
        f"end-to-end false-positive fraction: {metric['end_to_end_false_positive_fraction']}.\n\n"
        f"P0/P1/P2 changes requiring review: {len(regression)}. Acceptance: {comparison['acceptance']}. "
        'This completed measurement is not a completed v8 release. Technical review must reconcile all changes, '
        'resource failures and safety evidence with the saved unit/security validation. No independent Test '
        'or calibration/overall accuracy improvement claim. Quarantined abstentions are not true detections. '
        'See run_summary.json for the generating revision, metrics and evidence paths.\n',encoding='utf-8')
