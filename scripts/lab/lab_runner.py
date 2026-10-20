"""Installed LAB console and bounded operator transport, with no network changes."""

import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import sys
import time
import tempfile

import lab_jobs as jobs
import lab_side as side
from lab_contract import MAX_REPORT, parse_json


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
        if job['kind'] == 'pdf-static':
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
        raise ValueError('dependency_mismatch')


def pdf_metadata(job):
    source = source_imports(job)
    cfg = jobs.config()
    import tomllib
    from check_local import dependency_versions
    dependency_versions(tomllib.loads((source / 'pyproject.toml').read_text(encoding='utf-8')))
    import yaml
    from malpdf.experiments.cic_static_benchmark import checked_table, select_subset, verify_label_provenance
    cohort = yaml.safe_load((source / 'configs/cic_static_benchmark.yaml').read_text(encoding='utf-8'))
    data_root = Path(cfg['data_root'])
    tables = {key: checked_table(data_root, cohort[key]) for key in ('split_manifest', 'source_manifest', 'normalization_manifest')}
    rows = select_subset(tables['split_manifest'], tables['source_manifest'], 32, 42)
    verify_label_provenance(rows, tables['normalization_manifest'])
    if len(rows) != 64 or any(row['split'] not in ('train', 'validation') for row in rows):
        raise ValueError('manifest_unavailable')
    return source, data_root, rows


def worker_limits(*, prepare=False):
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for name, amount in ((resource.RLIMIT_CPU, 60 if prepare else 1700), (resource.RLIMIT_AS, 2 * 1024**3),
                         (resource.RLIMIT_FSIZE, 8 * 1024**2), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 64)):
        resource.setrlimit(name, (amount, amount))


def pdf_worker(job_id, *, prepare=False):
    if sys.platform != 'linux':
        raise ValueError('runtime_unavailable')
    job = jobs.load_job(job_id)
    if job['kind'] != 'pdf-static' or job['mode'] != 'offline':
        raise ValueError('job_mismatch')
    if not prepare:
        jobs.preflight('offline', attested=True)
        claim = parse_json(side.bounded_read(jobs.job_directory(job_id) / 'claim.json', 4096))
        if claim.get('job_id') != job_id or claim.get('hypervisor_controls_attested') is not True or claim.get('parent_pid') != os.getppid():
            raise ValueError('approval_required')
    worker_limits(prepare=prepare)
    source, data_root, rows = pdf_metadata(job)
    directory = jobs.job_directory(job_id)
    selection = {'job_id': job_id, 'rows': rows, 'selection_sha256': jobs.sha(jobs.encoded(rows))}
    if prepare:
        jobs.immutable(directory / 'selection.json', selection)
        return
    stored = parse_json(side.bounded_read(directory / 'selection.json', 512 * 1024))
    if stored != selection:
        raise ValueError('manifest_unavailable')
    from malpdf.extraction.orchestrator import extract_pdf
    from malpdf.extraction.arlington_model import load_model
    from malpdf.extraction.jobs import extraction_lab_state
    from malpdf.static.code_inspector import CodeInspectionLimits, _worker_count
    state = extraction_lab_state(repository_root=data_root)
    if state['known_credentials_present'] or state['agent_forwarding_present']:
        raise ValueError('network_blocked')
    limits = CodeInspectionLimits(wall_seconds=20, cpu_seconds=12)
    _worker_count(1, limits)
    if parse_json(side.bounded_read(data_root / 'configs/arlington.lock.json', 2 * 1024**2)) != parse_json(side.bounded_read(source / 'configs/arlington.lock.json', 2 * 1024**2)):
        raise ValueError('manifest_unavailable')
    catalog = load_model(data_root)
    started = time.monotonic()
    summary = dict.fromkeys(('planned', 'completed', 'observed', 'partial', 'failed', 'primary_available', 'timeout', 'elapsed_ms', 'peak_rss_bytes'), 0)
    summary['planned'] = 64
    outputs = directory / 'private_bundles'
    outputs.mkdir(mode=0o700)
    total = 0
    os.environ['MALPDF_LAB_ISOLATED'] = '1'
    for index, row in enumerate(rows):
        if time.monotonic() - started > jobs.LIMITS['wall_seconds'] - 25:
            break
        bundle = extract_pdf(data_root / row['pdf_relative_path'], boundary=data_root / 'data/raw/cic_pdf',
            expected_sha256=row['pdf_sha256'], limits=limits, arlington_catalog=catalog)
        payload = jobs.encoded(bundle)
        if len(payload) > 8 * 1024**2 or total + len(payload) > jobs.LIMITS['output_bytes']:
            break
        with (outputs / f'{index:04d}.json').open('xb') as output:
            output.write(payload)
        total += len(payload)
        summary['completed'] += 1
        summary['observed' if bundle['status'] == 'observed' else 'partial' if bundle['status'] == 'partial' else 'failed'] += 1
        summary['primary_available'] += any(item['kind'] == 'primary_checkpoint' for item in bundle['evidence_store']['records'])
        worker = bundle['coverage_report']['worker']
        summary['timeout'] += bundle['status'] == 'timeout'
        summary['peak_rss_bytes'] = max(summary['peak_rss_bytes'], worker.get('peak_rss_bytes') or 0)
        if worker.get('worker_cleanup_complete') is not True:
            break
    summary['elapsed_ms'] = int((time.monotonic() - started) * 1000)
    jobs.immutable(directory / 'pdf_summary.json', summary)


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


def console_run():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('approval_required')
    job = choose(jobs.pending())
    print('Xac nhan snapshot/recovery, tat clipboard/drag-drop/shared folders, khong credentials; NIC da ngat.')
    print('PDF/blob/ket qua chi luu tai LAB. Khong tu ket noi lai Windows.')
    if input('Chay job da duyet? [y/N]: ').strip().lower() != 'y':
        raise ValueError('approval_required')
    with jobs.execution_limits(job['kind']):
        value = jobs.execute(job, attested=True)
    print(json.dumps(value, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('status', 'run', 'report', 'menu', 'receive', 'pdf-worker', 'pdf-prepare'))
    parser.add_argument('job_id', nargs='?')
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
            pdf_worker(args.job_id, prepare=args.command == 'pdf-prepare')
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
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            with jobs.execution_limits('synthetic'):
                value = receive(sys.stdin.buffer, args.job_id)
            print(json.dumps(value, sort_keys=True))
        elif args.command == 'status':
            print(json.dumps({'runner': jobs.probe(), 'pending_jobs': len(jobs.pending()), 'network_changed': False}))
        elif args.command == 'run':
            console_run()
        elif args.command == 'report':
            items = jobs.catalog()
            job = jobs.load_job(args.job_id) if args.job_id else choose(items)
            print(json.dumps(jobs.read_result(job['job_id']), sort_keys=True))
        else:
            while True:
                print('MalPDF LAB Runner\n1. Status\n2. Run approved job\n3. Report\n0. Exit')
                answer = input('> ').strip()
                if answer == '0':
                    break
                if answer == '1':
                    print(json.dumps({'runner': jobs.probe(), 'pending_jobs': len(jobs.pending())}))
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
