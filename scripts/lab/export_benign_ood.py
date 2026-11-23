from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from lab_contract import parse_json
import lab_jobs as jobs
import lab_runner as runner


def export(job_id):
    job = jobs.load_job(job_id)
    status = jobs.read_result(job_id)
    if (job['kind'] != jobs.BENIGN_OOD_KIND or status['status'] not in ('passed', 'partial')
            or not all(status['preflight'][key] for key in ('guest_network_checked', 'hypervisor_controls_attested'))):
        raise ValueError('offline_benign_result_unavailable')
    runner.source_imports(job)
    from malpdf.extraction.benign_ood_job import MANIFEST_SHA256, SAMPLES, load_rows
    from malpdf.extraction.graph_projection_v2 import project_graph_bundle_v2
    from malpdf.extraction.quality_gate import finish_sample_quality_v2, prepare_sample_quality_v2
    from malpdf.extraction.tlsh import TLSH_RE
    from malpdf.features.contract_v3 import FEATURES, project_features

    directory = jobs.job_directory(job_id)
    selection = parse_json(jobs.side.bounded_read(directory / 'selection.json', 4 * 1024**2))
    rows = load_rows(Path(jobs.config()['data_root']))
    if (selection['job_id'] != job_id or selection['rows'] != rows or len(rows) != SAMPLES
            or selection['selection_sha256'] != jobs.sha(jobs.encoded(rows))):
        raise ValueError('offline_benign_selection_changed')
    results = []
    for index, row in enumerate(rows):
        sha = row['pdf_sha256']
        fp_path = directory / f'benign_tls.{index}.json'
        bundle_path = directory / 'private_bundles' / f'{index:04d}.json'
        result = {'sha256': sha, 'source': row['source'], 'id': row['id'], 'tlsh': None,
                  'status': 'not_run', 'features': None, 'graph': None}
        if fp_path.is_file():
            fingerprint = parse_json(jobs.side.bounded_read(fp_path, 1024))
            if fingerprint['sha256'] != sha:
                raise ValueError('offline_benign_fingerprint_changed')
            if fingerprint['status'] == 'measured' and TLSH_RE.fullmatch(fingerprint['tlsh']):
                result['tlsh'] = fingerprint['tlsh']
        if bundle_path.is_file():
            bundle = parse_json(jobs.side.bounded_read(bundle_path, jobs.pdf_bundle_limit(job['kind']) + 1024))
            facts = prepare_sample_quality_v2(bundle, sha)
            projection = project_graph_bundle_v2(bundle, sha)
            gate = finish_sample_quality_v2(facts, sha, projection)
            result['status'] = projection['status']
            if gate['gnn_message_passing_eligible']:
                result['features'] = project_features(projection['features'])
                graph = projection['graph']
                result['graph'] = [graph[name] for name in ('node_features', 'node_types', 'edge_src', 'edge_dst', 'edge_rel')]
        results.append(result)
    return {'schema_version': 1, 'job_id': job_id, 'manifest_sha256': MANIFEST_SHA256,
            'feature_order': FEATURES, 'runner': status, 'rows': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export only the numeric fields of the approved offline publisher job')
    parser.add_argument('job_id')
    args = parser.parse_args()
    json.dump(export(args.job_id), sys.stdout, separators=(',', ':'), allow_nan=False)
    print()
