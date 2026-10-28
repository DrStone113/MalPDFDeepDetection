"""Prepare reviewed offline source and operator setup without reading PDFs."""

from datetime import datetime, timezone
import json
from pathlib import Path
import re

import gateway_contract as contract
import gateway_snapshot as snapshot
import lab_jobs as jobs
import lab_vmware as vmware
import labctl as ctl
import setup_runner as installer
from lab_contract import parse_json, text_failure, validate_public_key


def bootstrap():
    contents = {}
    for name in ctl.BOOTSTRAP_FILES:
        path = ctl.REPO / ('src/malpdf/static/lab_guard.py' if name == 'lab_guard.py' else 'scripts/lab/' + name)
        payload = jobs.side.bounded_read(jobs.trusted_path(path), 2 * 1024**2).replace(b'\r\n', b'\n')
        if text_failure(payload, 'scripts/lab/' + name):
            raise ValueError('bootstrap_rejected')
        contents[name] = payload
    public = jobs.side.bounded_read(jobs.trusted_path(ctl.PUBLIC_KEY), 1024)
    contents['id_ed25519_malpdf_audit.pub'] = (validate_public_key(public) + '\n').encode('ascii')
    metadata = {'schema_version': 1, 'commit': ctl.revision(), 'source_kind': 'reviewed_worktree_bootstrap',
        'files': [{'path': name, 'size': len(payload), 'sha256': contract.sha(payload)} for name, payload in sorted(contents.items())]}
    identity = contract.sha(contract.encoded(metadata))
    folder = jobs.trusted_path(ctl.OUT / 'offline-bootstrap' / identity)
    folder.mkdir(parents=True, exist_ok=True)
    if {path.name for path in folder.iterdir()} - {*contents, 'manifest.json'}:
        raise ValueError('bootstrap_rejected')
    for name, payload in {**contents, 'manifest.json': contract.encoded(metadata) + b'\n'}.items():
        path = jobs.trusted_path(folder / name)
        if path.exists():
            if jobs.side.bounded_read(path, 2 * 1024**2) != payload:
                raise ValueError('bootstrap_rejected')
        else:
            with path.open('xb') as output:
                output.write(payload)
    return {'bootstrap': str(folder), 'manifest_id': identity, 'files': len(contents) + 1,
            'remote_changes': False, 'pdf_execution': False}


def verified_files(value):
    identity = value['manifest_id']
    if not isinstance(identity, str) or not contract.HEX.fullmatch(identity):
        raise ValueError('bootstrap_rejected')
    folder = jobs.trusted_path(Path(value['bootstrap']))
    if folder != ctl.OUT / 'offline-bootstrap' / identity:
        raise ValueError('bootstrap_rejected')
    metadata = parse_json(jobs.side.bounded_read(jobs.trusted_path(folder / 'manifest.json'), 32768))
    if contract.sha(contract.encoded(metadata)) != identity:
        raise ValueError('bootstrap_rejected')
    _, payloads = installer.validate_bootstrap(folder)
    validate_public_key(payloads['id_ed25519_malpdf_audit.pub'])
    for name, payload in payloads.items():
        if not name.endswith('.pub') and text_failure(payload, 'scripts/lab/' + name):
            raise ValueError('bootstrap_rejected')
    return [folder / name for name in sorted({*installer.FILES, 'manifest.json'})]


def make_job(commit, manifest, metadata, kind):
    manifest_sha = contract.sha(jobs.side.bounded_read(manifest, 512 * 1024))
    attempt = contract.sha(contract.encoded({'manifest_sha256': manifest_sha, 'kind': kind, 'mode': 'offline'}))[:32]
    return jobs.make_job(commit, metadata['archive_sha256'], manifest_sha,
                         mode='offline', kind=kind, attempt=attempt)


def cohort_contract(kind='pdf-static'):
    if kind == 'pdf-static-cve':
        from lab_runner import cve_contract
        return cve_contract()
    if kind == 'pdf-static-cic-full':
        from lab_runner import cic_full_contract
        return cic_full_contract()
    if kind != 'pdf-static':
        raise ValueError('job_mismatch')
    import yaml
    source = jobs.side.bounded_read(jobs.trusted_path(ctl.REPO / 'configs/cic_static_benchmark.yaml'), 65536)
    value = yaml.safe_load(source)
    if not isinstance(value, dict) or type(value.get('seed')) is not int or value['seed'] != 42 or type(value.get('samples_per_partition')) is not int or value['samples_per_partition'] != 32:
        raise ValueError('manifest_unavailable')
    manifests = {}
    for key in ('split_manifest', 'source_manifest', 'normalization_manifest'):
        item = value.get(key)
        if not isinstance(item, dict) or set(item) != {'path', 'sha256'} or not isinstance(item['path'], str) or not re.fullmatch(r'data/processed/[A-Za-z0-9_./-]{1,220}\.csv', item['path']) or any(part in ('', '.', '..') for part in item['path'].split('/')) or not isinstance(item['sha256'], str) or not contract.HEX.fullmatch(item['sha256']):
            raise ValueError('manifest_unavailable')
        manifests[key] = item
    return {'config_sha256': contract.sha(source.replace(b'\r\n', b'\n')), 'seed': 42,
        'train': 32, 'validation': 32, 'test': 0, 'samples': 64, 'manifests': manifests}


def prepare(kind='pdf-static'):
    if kind not in jobs.KINDS:
        raise ValueError('job_mismatch')
    commit, archive, manifest, metadata = snapshot.prepare(normalize=True)
    job = make_job(commit, manifest, metadata, kind)
    setup = bootstrap()
    verified_files(setup)
    plan = {'api': 1, 'job': job, 'source_kind': 'validated_lf_normalized_worktree_snapshot',
        'source_files': len(metadata['files']), 'cohort': cohort_contract(kind) if kind in jobs.PDF_KINDS else None,
        'source_archive': str(archive), 'source_manifest': str(manifest),
        'bootstrap_manifest_id': setup['manifest_id'],
        'lab_output_directory': '/var/lib/malpdf/jobs/' + job['job_id'],
        'release_policy': 'existing same-base offline release must match the exact manifest; otherwise stop for a separately reviewed source version',
        'real_pdf_approved': False, 'lab_execution': 'not_run', 'export_approved': False,
        'recovery': 'keep VM offline; preserve claims, private results and backups; operator-reviewed recovery only'}
    folder = jobs.trusted_path(ctl.OUT / 'offline-plans' / job['job_id'])
    folder.mkdir(parents=True, exist_ok=True)
    jobs.immutable(folder / 'proposal.json', plan)
    isolation = vmware.isolation()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    jobs.immutable(folder / ('host-isolation-' + stamp + '.json'), isolation)
    return {'plan': str(folder / 'proposal.json'), 'job_id': job['job_id'], 'source_files': len(metadata['files']),
        'source_manifest_sha256': job['manifest_sha256'], 'source_archive_sha256': job['archive_sha256'],
        'bootstrap': setup, 'cohort': plan['cohort'], 'limits': job['limits'],
        'host_isolation': isolation, 'pdf_execution': False, 'remote_changes': False, 'ready_for_real_pdf': False}
