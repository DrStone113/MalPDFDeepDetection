from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys

from lab_contract import parse_json
import lab_jobs as jobs
import lab_side as side


def export_review(job_id):
    if sys.platform != 'linux':
        raise ValueError('runtime_unavailable')
    job = jobs.load_job(job_id)
    if job['kind'] != jobs.URI_REVIEW_KIND or job['mode'] != 'offline':
        raise ValueError('job_mismatch')
    metadata = side.verify_release(job['commit'], job['manifest_sha256'])
    jobs.verify_helpers(metadata)
    sys.path.insert(0, str(side.RELEASES / job['commit'] / 'src'))
    from malpdf.extraction import uri_review_job

    directory = jobs.job_directory(job_id)
    rows = uri_review_job.metadata_rows(Path(jobs.config()['data_root']))
    selection = parse_json(side.bounded_read(directory / 'selection.json', 4 * 1024**2))
    if selection != {'job_id': job_id, 'rows': rows, 'selection_sha256': jobs.sha(jobs.encoded(rows))}:
        raise ValueError('manifest_unavailable')
    result = jobs.validate_result(parse_json(side.bounded_read(directory / 'result.json', 1024**2)), job)
    if result['status'] not in {'passed', 'partial', 'failed', 'interrupted'}:
        raise ValueError('report_invalid')
    outputs = directory / 'private_bundles'
    records = []
    for index, row in enumerate(rows):
        identity = row['pdf_sha256']
        bundle_path = outputs / f'{index:04d}.json'
        record = {'sha256': identity, 'status': 'missing', 'actions_observed': None,
                  'actions_without_target': None, 'targets_clipped': False, 'targets': []}
        if bundle_path.exists():
            try:
                payload = side.bounded_read(jobs.trusted_path(bundle_path), jobs.pdf_bundle_limit(job['kind']))
                record = uri_review_job.project_targets(parse_json(payload), identity, job_id)
            except (OSError, ValueError, TypeError, KeyError):
                record['status'] = 'invalid'
        records.append(record)
    return {'schema_version': 1, 'job_id': job_id, 'selection_sha256': selection['selection_sha256'],
            'cohort': uri_review_job.contract(), 'records': records,
            'status_counts': dict(Counter(record['status'] for record in records))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('job_id')
    args = parser.parse_args()
    report = jobs.encoded(export_review(args.job_id))
    if len(report) > 8 * 1024**2:
        raise ValueError('report_invalid')
    sys.stdout.buffer.write(report + b'\n')


if __name__ == '__main__':
    main()
