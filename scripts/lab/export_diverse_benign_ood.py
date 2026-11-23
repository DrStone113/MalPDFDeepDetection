from __future__ import annotations

import argparse
import json
from pathlib import Path

from lab_contract import parse_json
import lab_jobs as jobs
import lab_runner as runner


def bundle_identity_verified(bundle, expected_sha):
    observed = bundle.get('sample_sha256')
    if observed == expected_sha:
        return True
    if observed is None and bundle['status'] in ('partial', 'resource_limit', 'unsupported', 'timeout', 'not_run'):
        return False
    raise ValueError('offline_diverse_bundle_identity_changed')


def export(job_id):
    job = jobs.load_job(job_id)
    report = jobs.read_result(job_id)
    if (job['kind'] != jobs.BENIGN_OOD_DIVERSE_KIND or report['status'] not in ('passed', 'partial')
            or not all(report['preflight'][key] for key in ('guest_network_checked', 'hypervisor_controls_attested'))):
        raise ValueError('offline_diverse_result_unavailable')
    runner.source_imports(job)
    from malpdf.extraction import benign_ood_diverse_job as cohort
    from malpdf.extraction.graph_projection_v2 import project_graph_bundle_v2
    from malpdf.extraction.quality_gate import finish_sample_quality_v2, prepare_sample_quality_v2
    from malpdf.extraction.tlsh import TLSH_RE
    from malpdf.features.contract_v3 import FEATURES, project_features

    directory = jobs.job_directory(job_id)
    selection = parse_json(jobs.side.bounded_read(directory / 'selection.json', 4 * 1024**2))
    rows = cohort.load_rows(Path(jobs.config()['data_root']))
    if (selection['job_id'] != job_id or selection['rows'] != rows or len(rows) != cohort.SAMPLES
            or selection['selection_sha256'] != jobs.sha(jobs.encoded(rows))):
        raise ValueError('offline_diverse_selection_changed')
    results = []
    for index, row in enumerate(rows):
        sha = row['pdf_sha256']
        fingerprint_path = directory / f'benign_tls.{index}.json'
        bundle_path = directory / 'private_bundles' / f'{index:04d}.json'
        value = {'id': row['id'], 'source': row['source'], 'sha256': sha, 'tlsh': None,
                 'status': 'not_run', 'features': None, 'graph': None}
        if fingerprint_path.is_file():
            fingerprint = parse_json(jobs.side.bounded_read(fingerprint_path, 1024))
            if fingerprint['sha256'] != sha:
                raise ValueError('offline_diverse_fingerprint_changed')
            if fingerprint['status'] == 'measured' and TLSH_RE.fullmatch(fingerprint['tlsh']):
                value['tlsh'] = fingerprint['tlsh']
        if bundle_path.is_file():
            bundle = parse_json(jobs.side.bounded_read(bundle_path, jobs.pdf_bundle_limit(job['kind']) + 1024))
            value['status'] = bundle['status']
            if bundle_identity_verified(bundle, sha):
                facts = prepare_sample_quality_v2(bundle, sha)
                if facts.get('rejected') is None:
                    projection = project_graph_bundle_v2(bundle, sha)
                    gate = finish_sample_quality_v2(facts, sha, projection)
                    if gate['gnn_message_passing_eligible']:
                        value['features'] = project_features(projection['features'])
                        value['graph'] = [projection['graph'][name] for name in ('node_features', 'node_types', 'edge_src', 'edge_dst', 'edge_rel')]
        results.append(value)
    return {'schema_version': 1, 'job_id': job_id, 'manifest_sha256': cohort.MANIFEST_SHA256,
            'feature_order': FEATURES, 'runner': report, 'rows': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export numeric fields after diverse OOD + hard-benign offline run')
    parser.add_argument('job_id')
    print(json.dumps(export(parser.parse_args().job_id), separators=(',', ':'), allow_nan=False))
