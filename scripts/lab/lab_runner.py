"""Installed LAB console and bounded operator transport, with no network changes."""

import argparse
from contextlib import redirect_stdout
import csv
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
import tempfile

import lab_jobs as jobs
import lab_side as side
from lab_contract import MAX_REPORT, parse_json

CVE_NAMES = ('bank_statment.pdf', 'link_URI.pdf', 'rce_foxit.pdf', 'url2_invoice_template.pdf', 'xss_popup.pdf')
CVE_MANIFEST = {'path': 'data/processed/source_preparation/run_20261001T133833267219Z_3efd81e782c1/cve_t4pdf/source_pdf_manifest.csv',
                'sha256': '3dd3412cfdd277b3b14ff198db807679557b3b32bcb20af8b2f2770610eea4aa'}


def cve_contract():
    return {'cohort': 'cve-t4pdf-5', 'samples': 5, 'seed': 42, 'test': 0,
        'boundary': 'data/raw/cve_t4pdf', 'manifests': {'source_manifest': dict(CVE_MANIFEST)},
        'filenames': list(CVE_NAMES), 'selection': 'all five named raw files; hashes from the pinned prepared-copy manifest',
        'labels': 'historical user-assigned labels; no accuracy evaluation'}


def cic_full_contract():
    manifests = {
        'split_manifest': {'path': 'data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv',
                           'sha256': 'e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643'},
        'source_manifest': {'path': 'data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv',
                            'sha256': 'd74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b'},
        'normalization_manifest': {'path': 'data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv',
                                   'sha256': 'c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f'},
    }
    return {'cohort': 'cic-full-1452', 'samples': 1452, 'seed': 42,
            'train': 870, 'validation': 291, 'test': 291,
            'boundary': 'data/raw/cic_pdf', 'manifests': manifests,
            'selection': 'all 1452 CIC samples partitioned under Protocol G; train 870, validation 291, test 291'}


def cve_rows(data_root):
    manifest = jobs.trusted_path(data_root / CVE_MANIFEST['path'])
    try:
        payload = side.bounded_read(manifest, 65536)
    except OSError:
        raise ValueError('manifest_unavailable') from None
    if jobs.sha(payload) != CVE_MANIFEST['sha256']:
        raise ValueError('manifest_unavailable')
    try:
        reader = csv.DictReader(io.StringIO(payload.decode('utf-8', 'strict')), strict=True)
        fields = reader.fieldnames
        rows = list(reader)
    except (csv.Error, UnicodeError):
        raise ValueError('manifest_unavailable') from None
    if fields != ['sample_id', 'Label', 'pdf_relative_path', 'pdf_sha256', 'label_source']:
        raise ValueError('manifest_unavailable')
    if len(rows) != len(CVE_NAMES):
        raise ValueError('manifest_unavailable')
    indexed = {}
    for row in rows:
        if set(row) != set(fields) or any(not isinstance(value, str) for value in row.values()):
            raise ValueError('manifest_unavailable')
        name = row['sample_id'].removeprefix('cve_t4pdf:')
        expected = {'sample_id': 'cve_t4pdf:' + name, 'Label': '1',
            'pdf_relative_path': Path(CVE_MANIFEST['path']).parent.as_posix() + '/' + name}
        if name not in CVE_NAMES or name in indexed or any(row[key] != value for key, value in expected.items()):
            raise ValueError('manifest_unavailable')
        if not jobs.HEX.fullmatch(row['pdf_sha256']) or not 1 <= len(row['label_source']) <= 256 or any(not 32 <= ord(character) < 127 for character in row['label_source']):
            raise ValueError('manifest_unavailable')
        indexed[name] = {**row, 'manifest_pdf_relative_path': row['pdf_relative_path'],
            'pdf_relative_path': 'data/raw/cve_t4pdf/' + name}
    if len({row['pdf_sha256'] for row in indexed.values()}) != len(CVE_NAMES):
        raise ValueError('manifest_unavailable')
    for row in indexed.values():
        path = jobs.trusted_path(data_root / row['pdf_relative_path'])
        try:
            info = path.stat(follow_symlinks=False)
        except OSError:
            raise ValueError('manifest_unavailable') from None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= jobs.policy('pdf-static-cve')['file_max_bytes']:
            raise ValueError('manifest_unavailable')
    return [indexed[name] for name in CVE_NAMES]


def read_frame(stream, limit):
    header = stream.read(4)
    if len(header) != 4:
        raise ValueError('manifest_unavailable')
    length = int.from_bytes(header, 'big')
    if not 0 < length <= limit:
        raise ValueError('manifest_unavailable')
    payload = stream.read(length)
    if len(payload) != length:
        raise ValueError('manifest_unavailable')
    return payload


def receive(stream, expected_id):
    jobs.config()
    jobs.preflight('host-only')
    job = jobs.validate_job(parse_json(read_frame(stream, MAX_REPORT)))
    if job['job_id'] != expected_id:
        raise ValueError('job_mismatch')
    manifest = read_frame(stream, 512 * 1024)
    archive = read_frame(stream, 40 * 1024 * 1024)
    if stream.read(1) or jobs.sha(manifest) != job['manifest_sha256'] or jobs.sha(archive) != job['archive_sha256']:
        raise ValueError('release_mismatch')
    metadata = parse_json(manifest)
    if metadata.get('commit') != job['commit'] or metadata.get('archive_sha256') != job['archive_sha256']:
        raise ValueError('release_mismatch')
    jobs.verify_helpers(metadata)
    side.INBOX.mkdir(parents=True, exist_ok=True)
    jobs.trusted_path(side.INBOX)
    for suffix, payload in (('.json', manifest), ('.tar', archive)):
        path = jobs.trusted_path(side.INBOX / (job['commit'] + suffix))
        if path.exists():
            if side.bounded_read(path, 40 * 1024 * 1024) != payload:
                raise ValueError('release_mismatch')
        else:
            with path.open('xb') as output:
                output.write(payload)
    if not (side.RELEASES / job['commit']).exists():
        with redirect_stdout(io.StringIO()):
            side.install(job['commit'])
    side.verify_release(job['commit'], job['manifest_sha256'])
    directory = jobs.save_job(job)
    if (directory / 'result.json').exists():
        return jobs.read_result(job['job_id'])
    if (directory / 'claim.json').exists():
        raise ValueError('already_claimed')
    if (directory / 'queued.json').exists():
        return jobs.read_result(job['job_id'])
    if job['mode'] == 'offline':
        if job['kind'] in jobs.PDF_KINDS:
            pdf_prepare(job, directory)
        value = jobs.result(job, 'queued')
        jobs.immutable(directory / 'queued.json', value)
        return jobs.read_result(job['job_id'])
    return jobs.execute(job)


def source_imports(job):
    metadata = side.verify_release(job['commit'], job['manifest_sha256'])
    jobs.verify_helpers(metadata)
    source = side.RELEASES / job['commit']
    sys.path.insert(0, str(source / 'src'))
    return source


def pdf_prepare(job, directory):
    cfg = jobs.config()
    import subprocess
    command = [cfg['python'], '-Es', '-B', str(Path(__file__).resolve()), 'pdf-prepare', job['job_id']]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
            start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(directory),
                'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1', 'MKL_NUM_THREADS': '1'})
        try:
            code = process.wait(timeout=60)
        except BaseException:
            jobs.stop_worker(process)
            raise
        if code:
            stdout.seek(0)
            raw = stdout.read(4097)
            try:
                value = parse_json(raw) if len(raw) <= 4096 else None
            except ValueError:
                value = None
            if isinstance(value, dict) and set(value) == {'status', 'reason'} and value['status'] == 'blocked' and isinstance(value['reason'], str) and value['reason'] in jobs.REASONS:
                raise ValueError(value['reason'])
            raise ValueError('worker_failed')


def pdf_metadata(job):
    source = source_imports(job)
    cfg = jobs.config()
    import tomllib
    import importlib.metadata
    from check_local import dependency_versions
    try:
        dependency_versions(tomllib.loads((source / 'pyproject.toml').read_text(encoding='utf-8')))
    except (importlib.metadata.PackageNotFoundError, ImportError, ValueError):
        raise ValueError('dependency_mismatch') from None
    import yaml
    data_root = Path(cfg['data_root'])
    if job['kind'] == 'pdf-static-cve':
        return source, data_root, cve_rows(data_root)
    if job['kind'] == 'pdf-static-cic-full':
        from malpdf.experiments.cic_static_benchmark import checked_table, select_corpus, verify_label_provenance
        cohort = yaml.safe_load((source / 'configs/cic_static_benchmark.yaml').read_text(encoding='utf-8'))
        tables = {key: checked_table(data_root, cohort[key]) for key in ('split_manifest', 'source_manifest', 'normalization_manifest')}
        rows = select_corpus(tables['split_manifest'], tables['source_manifest'], 42)
        verify_label_provenance(rows, tables['normalization_manifest'])
        if len(rows) != 1452:
            raise ValueError('manifest_unavailable')
        return source, data_root, rows
    from malpdf.experiments.cic_static_benchmark import checked_table, select_subset, verify_label_provenance
    cohort = yaml.safe_load((source / 'configs/cic_static_benchmark.yaml').read_text(encoding='utf-8'))
    tables = {key: checked_table(data_root, cohort[key]) for key in ('split_manifest', 'source_manifest', 'normalization_manifest')}
    rows = select_subset(tables['split_manifest'], tables['source_manifest'], 32, 42)
    verify_label_provenance(rows, tables['normalization_manifest'])
    if len(rows) != 64 or any(row['split'] not in ('train', 'validation') for row in rows):
        raise ValueError('manifest_unavailable')
    return source, data_root, rows


def worker_limits(*, prepare=False, wall_seconds=1800):
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for name, amount in ((resource.RLIMIT_CPU, 60 if prepare else min(1700, wall_seconds - 10)), (resource.RLIMIT_AS, 2 * 1024**3),
                         (resource.RLIMIT_FSIZE, 8 * 1024**2), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 2048)):
        resource.setrlimit(name, (amount, amount))


def pdf_worker(job_id, *, prepare=False, shard=0, count=1):
    if sys.platform != 'linux':
        raise ValueError('runtime_unavailable')
    job = jobs.load_job(job_id)
    if job['kind'] not in jobs.PDF_KINDS or job['mode'] != 'offline':
        raise ValueError('job_mismatch')
    if not prepare:
        jobs.preflight('offline', attested=True)
        claim = parse_json(side.bounded_read(jobs.job_directory(job_id) / 'claim.json', 4096))
        if claim.get('job_id') != job_id or claim.get('hypervisor_controls_attested') is not True or claim.get('parent_pid') != os.getppid():
            raise ValueError('approval_required')
    worker_limits(prepare=prepare, wall_seconds=job['limits']['wall_seconds'])
    source, data_root, rows = pdf_metadata(job)
    if len(rows) != job['limits']['samples']:
        raise ValueError('manifest_unavailable')
    directory = jobs.job_directory(job_id)
    selection = {'job_id': job_id, 'rows': rows, 'selection_sha256': jobs.sha(jobs.encoded(rows))}
    if prepare:
        jobs.immutable(directory / 'selection.json', selection)
        return
    stored = parse_json(side.bounded_read(directory / 'selection.json', 512 * 1024))
    if stored != selection:
        raise ValueError('manifest_unavailable')
    if not 0 <= shard < count <= job['limits']['workers']:
        raise ValueError('job_mismatch')
    rows = [(index, row) for index, row in enumerate(rows) if index % count == shard]
    from malpdf.extraction.orchestrator import extract_pdf
    from malpdf.extraction.arlington_model import load_model
    from malpdf.extraction.jobs import require_extraction_lab
    from malpdf.static.code_inspector import CodeInspectionLimits, _worker_count
    require_extraction_lab(True, repository_root=data_root)
    file_wall = min(60, int(job['limits'].get('file_wall_seconds', 60)))
    file_cpu = min(file_wall, int(job['limits'].get('file_cpu_seconds', 45)))
    limits = CodeInspectionLimits(wall_seconds=file_wall, cpu_seconds=file_cpu)
    _worker_count(1, limits)
    if parse_json(side.bounded_read(data_root / 'configs/arlington.lock.json', 2 * 1024**2)) != parse_json(side.bounded_read(source / 'configs/arlington.lock.json', 2 * 1024**2)):
        raise ValueError('manifest_unavailable')
    catalog = load_model(data_root)
    started = time.monotonic()
    summary = dict.fromkeys(('planned', 'completed', 'observed', 'bounded_complete', 'partial', 'failed', 'primary_available', 'timeout', 'elapsed_ms', 'peak_rss_bytes'), 0)
    summary['planned'] = job['limits']['samples']
    summary['shard'], summary['shards'] = shard, count
    statuses = {}
    outputs = directory / 'private_bundles'
    outputs.mkdir(mode=0o700, exist_ok=True)
    total = 0
    os.environ['MALPDF_LAB_ISOLATED'] = '1'
    for index, row in rows:
        if time.monotonic() - started > job['limits']['wall_seconds'] - 25:
            break
        require_extraction_lab(True, repository_root=data_root)
        boundary = 'data/raw/cve_t4pdf' if job['kind'] == 'pdf-static-cve' else 'data/raw/cic_pdf'
        bundle = extract_pdf(data_root / row['pdf_relative_path'], boundary=data_root / boundary,
            expected_sha256=row['pdf_sha256'], limits=limits, arlington_catalog=catalog)
        payload = jobs.encoded(bundle)
        if len(payload) > 8 * 1024**2 or total + len(payload) > job['limits']['output_bytes']:
            break
        with (outputs / f'{index:04d}.json').open('xb') as output:
            output.write(payload)
        total += len(payload)
        summary['completed'] += 1
        summary['bounded_complete'] += (bundle['status'] == 'bounded_complete')
        summary['observed' if bundle['status'] in ('observed', 'bounded_complete') else 'partial' if bundle['status'] == 'partial' else 'failed'] += 1
        statuses[bundle['status']] = statuses.get(bundle['status'], 0) + 1
        summary['primary_available'] += any(item['kind'] == 'primary_checkpoint' for item in bundle['evidence_store']['records'])
        worker = bundle['coverage_report']['worker']
        summary['timeout'] += bundle['status'] == 'timeout'
        summary['peak_rss_bytes'] = max(summary['peak_rss_bytes'], worker.get('peak_rss_bytes') or 0)
        if worker.get('worker_cleanup_complete') is not True:
            break
    summary['elapsed_ms'] = int((time.monotonic() - started) * 1000)
    jobs.immutable(directory / f'pdf_summary.{shard}.json', {**summary, 'status_counts': statuses})


def historical(job_id):
    directory = jobs.job_directory(job_id)
    value = parse_json(side.bounded_read(directory / 'job.json', MAX_REPORT))
    fields = {'schema_version', 'api', 'commit', 'archive_sha256', 'manifest_sha256', 'mode', 'kind', 'limits', 'job_id', 'attempt'}
    if not isinstance(value, dict) or set(value) != fields or value.get('job_id') != job_id or value.get('kind') not in jobs.PDF_KINDS:
        raise ValueError('job_mismatch')
    limits = value.get('limits')
    if not isinstance(limits, dict) or type(limits.get('samples')) is not int or not 1 <= limits['samples'] <= 4096:
        raise ValueError('job_mismatch')
    return directory, value


def bundle_view(directory, index):
    path = directory / 'private_bundles' / f'{index:04d}.json'
    try:
        value = parse_json(side.bounded_read(path, 8 * 1024**2 + 1024))
    except OSError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get('status'), str) or value['status'] not in jobs.PDF_STATUSES:
        raise ValueError('report_invalid')
    return value['status'], jobs.sha(jobs.encoded(value.get('feature_store')))


def selection_id(directory):
    try:
        value = parse_json(side.bounded_read(directory / 'selection.json', 512 * 1024))
    except OSError:
        return None
    return value.get('selection_sha256') if isinstance(value, dict) else None


def compare(left_id, right_id):
    left, left_job = historical(left_id)
    right, right_job = historical(right_id)
    samples = left_job['limits']['samples']
    if samples != right_job['limits']['samples']:
        raise ValueError('job_mismatch')
    identical = status_mismatch = feature_mismatch = missing = 0
    first_mismatch = None
    for index in range(samples):
        one, two = bundle_view(left, index), bundle_view(right, index)
        if one is not None and two is not None and one == two:
            identical += 1
            continue
        if one is None or two is None:
            missing += 1
        else:
            status_mismatch += one[0] != two[0]
            feature_mismatch += one[1] != two[1]
        if first_mismatch is None:
            first_mismatch = index
    selection = selection_id(left)
    return {'compared': samples, 'identical': identical, 'status_mismatch': status_mismatch,
            'feature_mismatch': feature_mismatch, 'missing_bundles': missing,
            'first_mismatch_index': first_mismatch,
            'same_selection': selection is not None and selection == selection_id(right),
            'same_commit': left_job['commit'] == right_job['commit']}


def historical_report(job_id):
    directory, _ = historical(job_id)
    path = directory / 'result.json'
    if not path.is_file():
        return {'job_id': job_id, 'status': 'interrupted', 'reason': 'already_claimed', 'pdf_summary': None}
    value = parse_json(side.bounded_read(path, MAX_REPORT))
    fields = {'schema_version', 'job', 'status', 'reason', 'checks', 'pdf_summary', 'preflight', 'generated_utc'}
    if (not isinstance(value, dict) or set(value) != fields
            or value.get('status') not in ('queued', 'running', 'passed', 'partial', 'failed', 'blocked', 'interrupted')
            or value.get('reason') is not None and value['reason'] not in jobs.REASONS):
        raise ValueError('report_invalid')
    summary = value['pdf_summary']
    if summary is not None:
        current = isinstance(summary, dict) and set(summary) - {'bounded_complete'} == jobs.SUMMARY_FIELDS and jobs.summary_valid(summary)
        if not current and not jobs.legacy_summary_valid(summary):
            raise ValueError('report_invalid')
    return {'job_id': job_id, 'status': value['status'], 'reason': value['reason'], 'pdf_summary': summary}


def choose(items):
    if not items:
        raise ValueError('manifest_unavailable')
    for index, job in enumerate(items, 1):
        print(f"{index}. {job['kind']} | {job['mode']} | {job['job_id'][:12]}")
    if len(items) == 1:
        return items[0]
    answer = input('Chon job [1]: ').strip() or '1'
    if not answer.isdecimal() or not 1 <= int(answer) <= len(items):
        raise ValueError('job_mismatch')
    return items[int(answer) - 1]


def console_preflight():
    return {'credentials': jobs.credential_reasons(Path(jobs.config()['data_root'])),
            'pending_jobs': len(jobs.pending()), 'network_changed': False}


def console_run():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('approval_required')
    job = choose(jobs.pending())
    print('Job: ' + job['job_id'] + ' | kind: ' + job['kind'])
    if job['kind'] == 'pdf-static-cve':
        print(json.dumps(cve_contract(), sort_keys=True))
    if job['kind'] == 'pdf-static-cic-full':
        print(json.dumps(cic_full_contract(), sort_keys=True))
    print(json.dumps({'limits': job['limits'], 'lab_output_directory': str(jobs.job_directory(job['job_id']))}, sort_keys=True))
    print('Xac nhan snapshot/recovery, tat clipboard/drag-drop/shared folders, khong credentials; NIC da ngat.')
    print('PDF/blob/ket qua chi luu tai LAB. Khong tu ket noi lai Windows.')
    if input('Chay job da duyet? [y/N]: ').strip().lower() != 'y':
        raise ValueError('approval_required')
    try:
        print('Bat dau chay job ' + job['job_id'][:12] + '...')
        with jobs.execution_limits(job['kind']):
            value = jobs.execute(job, attested=True)
    except ValueError as error:
        if str(error) != 'credential_present':
            raise
        print(json.dumps({'status': 'blocked', 'reason': 'credential_present',
                          'credentials': jobs.credential_reasons(Path(jobs.config()['data_root']))}, sort_keys=True))
        return
    print(json.dumps(value, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('status', 'preflight', 'run', 'report', 'compare', 'menu', 'receive', 'pdf-worker', 'pdf-prepare'))
    parser.add_argument('job_id', nargs='?')
    parser.add_argument('other', nargs='?')
    parser.add_argument('--shard', type=int, default=0)
    parser.add_argument('--of', type=int, default=1)
    args = parser.parse_args()
    old_handlers = {}
    old_timer = None
    timer_started = time.monotonic()
    if sys.platform == 'linux':
        def cancelled(*unused):
            raise KeyboardInterrupt
        for name in (signal.SIGTERM, signal.SIGHUP):
            old_handlers[name] = signal.getsignal(name)
            signal.signal(name, cancelled)
        old_timer = signal.getitimer(signal.ITIMER_REAL)
    try:
        if args.command in ('pdf-worker', 'pdf-prepare'):
            pdf_worker(args.job_id, prepare=args.command == 'pdf-prepare', shard=args.shard, count=args.of)
        elif args.command == 'receive':
            if sys.platform != 'linux':
                raise ValueError('runtime_unavailable')
            signal.alarm(240)
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 2 * 1024**3))
            resource.setrlimit(resource.RLIMIT_CPU, (180, 1800))
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            resource.setrlimit(resource.RLIMIT_NPROC, (2048, 2048))
            with jobs.execution_limits('synthetic'):
                value = receive(sys.stdin.buffer, args.job_id)
            print(json.dumps(value, sort_keys=True))
        elif args.command == 'status':
            print(json.dumps({'runner': jobs.probe(), 'pending_jobs': len(jobs.pending()), 'network_changed': False}))
        elif args.command == 'preflight':
            print(json.dumps(console_preflight(), sort_keys=True))
        elif args.command == 'run':
            console_run()
        elif args.command == 'report':
            if args.job_id:
                try:
                    job = jobs.load_job(args.job_id)
                except ValueError as error:
                    if str(error) != 'job_mismatch':
                        raise
                    print(json.dumps(historical_report(args.job_id), sort_keys=True))
                else:
                    print(json.dumps(jobs.read_result(job['job_id']), sort_keys=True))
            else:
                print(json.dumps(jobs.read_result(choose(jobs.catalog())['job_id']), sort_keys=True))
        elif args.command == 'compare':
            if not args.job_id or not args.other:
                raise ValueError('job_mismatch')
            print(json.dumps(compare(args.job_id, args.other), sort_keys=True))
        else:
            while True:
                print('MalPDF LAB Runner\n1. Kiem tra truoc khi chay\n2. Run approved job\n3. Report\n0. Exit')
                answer = input('> ').strip()
                if answer == '0':
                    break
                if answer == '1':
                    print(json.dumps({**console_preflight(), 'runner': jobs.probe()}, sort_keys=True))
                elif answer == '2':
                    try:
                        console_run()
                    except (OSError, ValueError) as error:
                        print('Blocked: ' + (str(error) if str(error) in jobs.REASONS else 'worker_failed'))
                elif answer == '3':
                    items = jobs.catalog()
                    print(json.dumps(jobs.read_result(choose(items)['job_id']), sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({'status': 'interrupted', 'reason': 'already_claimed'}))
        return 130
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        import errno
        reason = str(error) if str(error) in jobs.REASONS else 'resource_unavailable' if isinstance(error, OSError) and error.errno in (errno.EAGAIN, errno.ENOMEM, errno.EMFILE, errno.ENOSPC) else 'worker_failed'
        print(json.dumps({'status': 'blocked', 'reason': reason}))
        return 2
    finally:
        for name, handler in old_handlers.items():
            signal.signal(name, handler)
        if old_timer is not None:
            remaining = max(0.001, old_timer[0] - (time.monotonic() - timer_started)) if old_timer[0] else 0
            signal.setitimer(signal.ITIMER_REAL, remaining, old_timer[1])


if __name__ == '__main__':
    raise SystemExit(main())
