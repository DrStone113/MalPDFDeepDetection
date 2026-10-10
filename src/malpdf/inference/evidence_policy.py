"""Fixed LAB-only C1 v8 abstention policy; no deployment threshold selection."""

import math

POLICY_ID = 'c1-v8-fixed-evidence-abstention-v1'


def evidence_decision(probability, analysis, *, input_available):
    """An incomplete negative never becomes benign; conflicts always abstain.

    Partial positives need contextual evidence in addition to the fixed ML
    score. Token occurrence, parser failure and missingness alone cannot decide.
    Every abstention is operationally quarantined, without inventing a label.
    """
    reasons, ids = [], []
    resource_codes = set()
    if not input_available:
        reasons.append('verified_input_unavailable')
    if type(probability) not in (int, float) or not math.isfinite(probability) or not 0 <= probability <= 1:
        reasons.append('model_score_unavailable')
    if not analysis or analysis.get('schema_version') != 'pdf-evidence-v8':
        reasons.append('v8_evidence_unavailable')
    elif analysis.get('conflicts'):
        reasons.append('backend_conflict')
    elif analysis.get('status') in {'resource_limited', 'parser_error'}:
        reasons.append('analysis_unavailable_or_resource_limited')
    elif analysis.get('status') not in {'complete','partial'}:
        reasons.append('analysis_unavailable')
    if analysis:
        codes = list(analysis.get('primary_errors',[])) + list(analysis.get('errors',[]))
        for backend in analysis.get('backends',[]):
            codes.extend((backend.get('graph') or {}).get('errors',[]))
            codes.extend((backend.get('code') or {}).get('errors',[]))
        resource_codes = {code for code in codes if code.endswith('_limit')}
        if analysis.get('resource_limits_reached'):
            resource_codes.add('static_resource_limit')
        if resource_codes:
            reasons.append('analysis_resource_limited')
    complete = bool(analysis and analysis.get('status') == 'complete')
    if not reasons and not complete:
        contextual = False
        for backend in analysis.get('backends', []):
            graph = backend.get('graph') or {}
            script = backend.get('code') or {}
            has_ast = any(s.get('ast_status') == 'complete' for s in script.get('script_sources', []))
            has_action = any(a['kind'] == '/JavaScript' for a in graph.get('actions', []))
            linked_payload = any(e.get('magic') in {'pe', 'elf'} for e in graph.get('embedded', [])) and any(
                a['kind'] in {'/Launch', '/GoToE'} for a in graph.get('actions', []))
            # This is evidence availability, not a rule declaring JS or an
            # attachment malicious. A separately fitted positive ML score is
            # still required. Co-occurrence does not prove actual execution.
            contextual |= (has_ast and has_action) or linked_payload
        if probability < 0.5:
            reasons.append('incomplete_negative')
        elif not contextual:
            reasons.append('contextual_evidence_unavailable')
    for feature in (analysis or {}).get('features', []):
        if feature.get('status') == 'observed':
            ids.extend(feature.get('evidence_ids', []))
    label = None if reasons else int(probability >= 0.5)
    return {'policy': POLICY_ID, 'decision': 'Inconclusive' if label is None else 'Malicious' if label else 'Benign',
            'predicted_label': label, 'malicious_probability': probability if not 'model_score_unavailable' in reasons else None,
            'threshold': 0.5, 'reasons': reasons, 'evidence_ids': sorted(set(ids)),
            'resource_error_codes': sorted(resource_codes),
            'explanation_scope': 'observed context supporting eligibility; not causal attribution or proof of execution',
            'operational_action': 'allow' if label == 0 else 'quarantine', 'deployment': False}
