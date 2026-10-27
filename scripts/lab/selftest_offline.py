"""Synthetic offline preparation and fixed host-metadata admission regressions."""

from contextlib import redirect_stdout
import base64
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gateway_client as client
import gateway_contract as contract
import gateway_snapshot as snapshot
import gateway_transfer as transfer
import lab_jobs as jobs
import lab_runner as runner
import lab_vmware as vmware
import lab_windows as windows
import offline_prepare as offline
import setup_runner as installer

HERE = Path(__file__).resolve().parent


class OfflineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='malpdf-offline-preparation-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / 'source'
        self.repo.mkdir()
        for name in offline.ctl.BOOTSTRAP_FILES:
            source = HERE.parents[1] / 'src/malpdf/static/lab_guard.py' if name == 'lab_guard.py' else HERE / name
            target = self.repo / ('src/malpdf/static/lab_guard.py' if name == 'lab_guard.py' else 'scripts/lab/' + name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        target = self.repo / 'configs/cic_static_benchmark.yaml'
        target.parent.mkdir()
        target.write_bytes((HERE.parents[1] / 'configs/cic_static_benchmark.yaml').read_bytes())
        self.public = self.base / 'audit.pub'
        key = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))
        self.public.write_bytes(b'ssh-ed25519 ' + base64.b64encode(key) + b' synthetic-audit\n')
        for module, attributes in ((offline.ctl, {'REPO': self.repo, 'OUT': self.base / 'packages', 'PUBLIC_KEY': self.public}),
                (client, {'STATE': self.base / 'gateway'}), (windows, {'STATE': self.base / 'workflow'})):
            for name, value in attributes.items():
                handle = patch.object(module, name, value)
                handle.start()
                self.addCleanup(handle.stop)
        for module, name, options in ((offline.ctl, 'revision', {'return_value': 'a' * 40}),
                (offline.ctl, 'audit_request', {'side_effect': AssertionError('Unexpected LAB audit transport')}),
                (client, 'exchange', {'side_effect': AssertionError('Unexpected runner transport')})):
            handle = patch.object(module, name, **options)
            handle.start()
            self.addCleanup(handle.stop)

    def package(self):
        with patch.object(snapshot, 'source_contents', return_value=[('src/malpdf/inert.py', b'value = 1\r\n')]):
            return snapshot.prepare(normalize=True)

    def test_bootstrap_is_exact_hashed_lf_source_and_existing_public_key_only(self):
        value = offline.bootstrap()
        files = offline.verified_files(value)
        self.assertEqual(len(files), 12)
        self.assertEqual({path.name for path in files}, {*installer.FILES, 'manifest.json'})
        metadata, payloads = installer.validate_bootstrap(Path(value['bootstrap']))
        self.assertEqual(metadata['source_kind'], 'reviewed_worktree_bootstrap')
        self.assertFalse(value['remote_changes'])
        self.assertFalse(value['pdf_execution'])
        self.assertTrue(all(b'\r\n' not in blob for blob in payloads.values()))
        self.assertFalse(any(path.name.endswith(('.pdf', '.tar')) for path in files))

    def test_bootstrap_rejects_modified_extra_or_misidentified_files(self):
        value = offline.bootstrap()
        folder = Path(value['bootstrap'])
        target = folder / 'setup_runner.sh'
        payload = target.read_bytes()
        target.write_bytes(payload + b'changed\n')
        with self.assertRaises(ValueError):
            offline.verified_files(value)
        target.write_bytes(payload)
        extra = folder / 'unexpected.json'
        extra.write_bytes(b'{}')
        with self.assertRaises(ValueError):
            offline.verified_files(value)
        extra.unlink()
        with self.assertRaises(ValueError):
            offline.verified_files({**value, 'manifest_id': '../escape'})
        with self.assertRaises(ValueError):
            offline.verified_files({**value, 'bootstrap': str(self.base)})

    def test_installer_rejects_duplicate_json_keys_before_any_privileged_action(self):
        value = offline.bootstrap()
        folder = Path(value['bootstrap'])
        target = folder / 'manifest.json'
        raw = target.read_bytes()
        target.write_bytes(raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'))
        with self.assertRaises(ValueError):
            installer.validate_bootstrap(folder)

    def test_unsafe_bootstrap_source_is_rejected_without_copy_or_remote_access(self):
        target = self.repo / 'scripts/lab/check_local.py'
        target.write_bytes(b'MZinert test marker')
        with self.assertRaisesRegex(ValueError, 'bootstrap_rejected'):
            offline.bootstrap()

    def test_shared_gateway_helper_drift_is_refused(self):
        _, payloads = installer.validate_bootstrap(Path(offline.bootstrap()['bootstrap']))
        policy = {name: contract.sha(payloads[name]) for name in installer.HELPERS if name != 'check_local.py'}
        installer.compatible_helpers(payloads, {'policy': policy})
        for name in policy:
            changed = {**payloads, name: payloads[name] + b'\n'}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'gateway_upgrade_required'):
                installer.compatible_helpers(changed, {'policy': policy})

    def test_installer_root_guard_runs_before_bootstrap_or_filesystem_changes(self):
        with patch.object(installer.sys, 'platform', 'win32'), patch.object(installer, 'validate_bootstrap') as validate, self.assertRaisesRegex(ValueError, 'operator_console_root_required'):
            installer.preflight()
        validate.assert_not_called()

    def test_installer_check_is_read_only_and_errors_do_not_expose_private_details(self):
        with patch.object(installer, 'preflight', return_value=({}, {}, {}, None, {})), patch.object(installer, 'install') as install, redirect_stdout(io.StringIO()):
            self.assertEqual(installer.main(['--check']), 0)
        install.assert_not_called()
        output = io.StringIO()
        with patch.object(installer, 'preflight', side_effect=ValueError('private canary')), patch.object(installer, 'install') as install, redirect_stdout(output):
            self.assertEqual(installer.main(['--install']), 2)
        install.assert_not_called()
        self.assertNotIn('canary', output.getvalue())

    def test_repeated_install_preserves_gateway_proof_keys_helpers_and_existing_jobs(self):
        root = self.base / 'installation'
        library, etc, state = root / 'lib', root / 'etc', root / 'jobs'
        cli, desktop = root / 'bin/lab', root / 'applications/lab.desktop'
        for path in (library, etc, state, cli.parent, desktop.parent, root / 'inbox', root / 'releases'):
            path.mkdir(parents=True, exist_ok=True)
        _, payloads = installer.validate_bootstrap(Path(offline.bootstrap()['bootstrap']))
        policy = {name: contract.sha(payloads[name]) for name in installer.HELPERS if name != 'check_local.py'}
        config = {'policy': policy}
        protected = {library / name: payloads[name] for name in policy}
        protected.update({etc / 'gateway-verified.json': b'preserved proof', etc / 'authorized_keys': b'preserved key', state / 'existing.claim': b'preserved claim'})
        for path, payload in protected.items():
            path.write_bytes(payload)
        candidate = {'schema_version': 1, 'data_root': '/home/remnux/MalPDFDeepDetection', 'python': '/usr/bin/python3', 'uid': 12345}
        original = tempfile.mkdtemp
        backups = []
        def backup(**unused):
            directory = original(prefix='backup-', dir=self.base)
            backups.append(Path(directory))
            return directory
        with patch.multiple(installer, LIB=library, ETC=etc, JOBS=state, CLI=cli, DESKTOP=desktop, INBOX=root / 'inbox', RELEASES=root / 'releases'), patch.object(installer.tempfile, 'mkdtemp', side_effect=backup), patch.object(installer.os, 'chown', create=True), patch.object(installer.os, 'fchown', create=True), patch.object(installer.os, 'fchmod', create=True), patch.object(installer, 'state_directory'), patch.object(installer, 'live_gateway', return_value=config), redirect_stdout(io.StringIO()):
            for unused in range(2):
                installer.install(payloads, config, SimpleNamespace(pw_uid=12345, pw_gid=12345), candidate)
        self.assertEqual(len(backups), 2)
        self.assertTrue(all(path.is_dir() for path in backups))
        for path, payload in protected.items():
            self.assertEqual(path.read_bytes(), payload)
        self.assertEqual(json.loads((etc / 'runner.json').read_bytes()), candidate)
        self.assertIn(b'lab_runner.py', cli.read_bytes())
        self.assertEqual((library / 'check_local.py').read_bytes(), payloads['check_local.py'])

    def test_installer_root_file_rejects_foreign_writable_linked_or_special_entries(self):
        target = self.base / 'root-helper.py'
        target.write_bytes(b'value = 1\n')
        for info in (SimpleNamespace(st_mode=installer.stat.S_IFREG | 0o644, st_nlink=1, st_size=10, st_uid=12345),
                SimpleNamespace(st_mode=installer.stat.S_IFREG | 0o664, st_nlink=1, st_size=10, st_uid=0),
                SimpleNamespace(st_mode=installer.stat.S_IFREG | 0o644, st_nlink=2, st_size=10, st_uid=0),
                SimpleNamespace(st_mode=installer.stat.S_IFIFO | 0o644, st_nlink=1, st_size=10, st_uid=0)):
            with patch.object(installer.os, 'fstat', return_value=info), self.assertRaisesRegex(ValueError, 'unsafe_file'):
                installer.read(target, 1024, root=True)

    def test_private_job_directory_rejects_foreign_group_and_readable_permissions(self):
        account = SimpleNamespace(pw_uid=12345, pw_gid=12345)
        target = self.base / 'jobs'
        target.mkdir()
        for uid, gid, mode in ((12346, 12345, 0o700), (12345, 12346, 0o700), (12345, 12345, 0o750), (12345, 12345, 0o755)):
            info = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=installer.stat.S_IFDIR | mode)
            with patch.object(installer, 'safe'), patch.object(Path, 'stat', return_value=info), self.assertRaisesRegex(ValueError, 'existing_state_requires_review'):
                installer.state_directory(target, account, private=True)

    def test_normalized_snapshot_hashes_are_stable_and_source_is_not_modified(self):
        raw = b'value = 1\r\n'
        with patch.object(snapshot, 'source_contents', return_value=[('src/malpdf/inert.py', raw)]):
            commit, archive, manifest, metadata = snapshot.prepare(normalize=True)
            repeated = snapshot.prepare(normalize=True)
            different = snapshot.prepare()
        self.assertEqual(archive, repeated[1])
        self.assertNotEqual(archive.parent, different[1].parent)
        with tarfile.open(archive, 'r:') as source:
            self.assertEqual(source.extractfile('src/malpdf/inert.py').read(), b'value = 1\n')
        self.assertEqual(raw, b'value = 1\r\n')
        self.assertEqual(commit, 'a' * 40)

    def test_offline_job_identity_is_deterministic_and_bound_to_source_and_profile(self):
        commit, archive, manifest, metadata = self.package()
        first = offline.make_job(commit, manifest, metadata, 'pdf-static')
        self.assertEqual(first, offline.make_job(commit, manifest, metadata, 'pdf-static'))
        self.assertNotEqual(first['job_id'], offline.make_job(commit, manifest, metadata, 'syntax')['job_id'])
        self.assertEqual(first['mode'], 'offline')
        self.assertEqual(first['limits']['samples'], 64)

    def test_cohort_contract_is_metadata_only_and_excludes_test(self):
        value = offline.cohort_contract()
        self.assertEqual((value['train'], value['validation'], value['test'], value['seed']), (32, 32, 0, 42))
        target = self.repo / 'configs/cic_static_benchmark.yaml'
        target.write_text(target.read_text().replace('samples_per_partition: 32', 'samples_per_partition: 33'))
        with self.assertRaisesRegex(ValueError, 'manifest_unavailable'):
            offline.cohort_contract()

    def cve_fixture(self):
        root = self.base / 'lab-data'
        rows = []
        for index, name in enumerate(runner.CVE_NAMES):
            path = root / 'data/raw/cve_t4pdf' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'reviewed inert metadata fixture')
            rows.append({'sample_id': 'cve_t4pdf:' + name, 'Label': '1',
                'pdf_relative_path': Path(runner.CVE_MANIFEST['path']).parent.as_posix() + '/' + name,
                'pdf_sha256': jobs.sha(str(index).encode()), 'label_source': 'synthetic_user_assignment'})
        return root, rows

    def write_cve_manifest(self, root, rows, fields=None):
        fields = fields or ['sample_id', 'Label', 'pdf_relative_path', 'pdf_sha256', 'label_source']
        stream = io.StringIO(newline='')
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
        payload = stream.getvalue().encode()
        path = root / runner.CVE_MANIFEST['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return {**runner.CVE_MANIFEST, 'sha256': jobs.sha(payload)}

    def test_cve_metadata_reads_only_the_pinned_csv_and_stats_five_explicit_raw_paths(self):
        root, rows = self.cve_fixture()
        spec = self.write_cve_manifest(root, list(reversed(rows)))
        original = jobs.side.bounded_read
        def metadata_only(path, limit):
            self.assertEqual(path, root / spec['path'])
            return original(path, limit)
        with patch.object(runner, 'CVE_MANIFEST', spec), patch.object(jobs.side, 'bounded_read', side_effect=metadata_only) as read:
            selected = runner.cve_rows(root)
        self.assertEqual(read.call_count, 1)
        self.assertEqual([row['sample_id'] for row in selected], [row['sample_id'] for row in rows])
        self.assertEqual([row['pdf_relative_path'] for row in selected], ['data/raw/cve_t4pdf/' + name for name in runner.CVE_NAMES])
        self.assertEqual([row['manifest_pdf_relative_path'] for row in selected], [row['pdf_relative_path'] for row in rows])
        self.assertEqual([row['pdf_sha256'] for row in selected], [row['pdf_sha256'] for row in rows])

    def test_cve_metadata_refuses_hash_changes_before_raw_file_metadata(self):
        root, rows = self.cve_fixture()
        self.write_cve_manifest(root, rows)
        with patch.object(Path, 'stat', side_effect=AssertionError('No raw stat before manifest integrity')), self.assertRaisesRegex(ValueError, 'manifest_unavailable'):
            with patch.object(jobs, 'trusted_path', side_effect=lambda path: path):
                runner.cve_rows(root)

    def test_cve_manifest_rejects_missing_duplicate_traversal_wrong_hash_and_extra_rows(self):
        root, rows = self.cve_fixture()
        candidates = [rows[:-1], rows + [rows[0]], [rows[0], rows[0], *rows[2:]]]
        for name, value in (('sample_id', 'cve_t4pdf:../escape.pdf'), ('pdf_relative_path', 'data/raw/cve_t4pdf/bank_statment.pdf'), ('pdf_sha256', 'not-a-hash'), ('Label', '0'), ('label_source', 'bad\nfield'), ('pdf_sha256', rows[1]['pdf_sha256'])):
            candidates.append([{**rows[0], name: value}, *rows[1:]])
        for candidate in candidates:
            with self.subTest(candidate=candidates.index(candidate)):
                spec = self.write_cve_manifest(root, candidate)
                with patch.object(runner, 'CVE_MANIFEST', spec), self.assertRaisesRegex(ValueError, 'manifest_unavailable'):
                    runner.cve_rows(root)
        spec = self.write_cve_manifest(root, rows, list(reversed(rows[0])))
        with patch.object(runner, 'CVE_MANIFEST', spec), self.assertRaisesRegex(ValueError, 'manifest_unavailable'):
            runner.cve_rows(root)

    def test_cve_metadata_refuses_missing_oversized_and_hardlinked_raw_files(self):
        root, rows = self.cve_fixture()
        spec = self.write_cve_manifest(root, rows)
        target = root / 'data/raw/cve_t4pdf' / runner.CVE_NAMES[0]
        with patch.object(runner, 'CVE_MANIFEST', spec):
            target.unlink()
            with self.assertRaisesRegex(ValueError, 'manifest_unavailable'):
                runner.cve_rows(root)
            with target.open('wb') as stream:
                stream.truncate(jobs.LIMITS['file_max_bytes'] + 1)
            with self.assertRaisesRegex(ValueError, 'manifest_unavailable'):
                runner.cve_rows(root)
            target.write_bytes(b'inert')
            os.link(target, target.with_suffix('.linked'))
            with self.assertRaisesRegex(ValueError, 'manifest_unavailable'):
                runner.cve_rows(root)

    def test_cve_profile_cannot_use_connected_mode_or_the_synthetic_gateway(self):
        with self.assertRaisesRegex(ValueError, 'job_mismatch'):
            jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, kind='pdf-static-cve')
        with self.assertRaisesRegex(ValueError, 'job_mismatch'):
            contract.make_job('a' * 40, 'b' * 64, 'c' * 64, 'pdf-static-cve', 'd' * 64)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(windows.main(['test', '--kind', 'pdf-static-cve']), 3)
        self.assertEqual(contract.PROFILES, {'syntax', 'synthetic'})

    def test_cve_summary_is_bound_to_five_samples_and_its_own_time_budget(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline', kind='pdf-static-cve')
        self.assertEqual((job['limits']['samples'], job['limits']['wall_seconds'], job['limits']['output_bytes']), (5, 180, 40 * 1024**2))
        environment = {'mode': 'offline', 'guest_network_checked': True, 'stdlib_dependencies_checked': True, 'hypervisor_controls_attested': True}
        summary = {'planned': 5, 'completed': 5, 'observed': 4, 'partial': 1, 'failed': 0, 'primary_available': 5, 'timeout': 0, 'elapsed_ms': 2000, 'peak_rss_bytes': 1024,
                   'status_counts': {'observed': 4, 'partial': 1}}
        jobs.result(job, 'partial', summary=summary, environment=environment)
        with self.assertRaisesRegex(ValueError, 'report_invalid'):
            jobs.result(job, 'passed', summary=summary, environment=environment)
        for change in ({'planned': 64}, {'completed': 6}, {'elapsed_ms': 180001}, {'timeout': 6},
                       {'status_counts': {'observed': 4, 'partial': 1, 'private': 0}},
                       {'status_counts': {'observed': 4, 'partial': 1, 'encrypted': 1}}):
            with self.assertRaisesRegex(ValueError, 'report_invalid'):
                jobs.result(job, 'partial', summary={**summary, **change}, environment=environment)
        jobs.result(job, 'passed', summary={**summary, 'observed': 5, 'partial': 0, 'status_counts': {'observed': 5}}, environment=environment)

    def test_merged_shard_summary_carries_the_reviewed_status_histogram(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline', kind='pdf-static')
        directory = self.base / 'merge'
        directory.mkdir()
        shards = ({'completed': 40, 'observed': 30, 'partial': 2, 'failed': 8, 'primary_available': 40, 'timeout': 1,
                   'elapsed_ms': 100, 'peak_rss_bytes': 5,
                   'status_counts': {'decode_error': 3, 'encrypted': 5, 'observed': 30, 'partial': 2}},
                  {'completed': 24, 'observed': 20, 'partial': 1, 'failed': 3, 'primary_available': 24, 'timeout': 0,
                   'elapsed_ms': 120, 'peak_rss_bytes': 7,
                   'status_counts': {'observed': 20, 'partial': 1, 'resource_limit': 2, 'unsupported': 1}})
        for index, shard in enumerate(shards):
            (directory / f'pdf_summary.{index}.json').write_bytes(
                jobs.encoded({'planned': 64, 'shard': index, 'shards': 2, **shard}))
        summary = jobs.merge_summary(job, directory, 2)
        self.assertEqual({name: summary[name] for name in ('completed', 'observed', 'partial', 'failed', 'primary_available', 'timeout')},
                         {'completed': 64, 'observed': 50, 'partial': 3, 'failed': 11, 'primary_available': 64, 'timeout': 1})
        self.assertEqual(summary['status_counts'], {'decode_error': 3, 'encrypted': 5, 'observed': 50,
                                                    'partial': 3, 'resource_limit': 2, 'unsupported': 1})
        self.assertEqual((summary['elapsed_ms'], summary['peak_rss_bytes']), (120, 7))
        self.assertEqual(json.loads((directory / 'pdf_summary.json').read_bytes()), summary)
        self.assertFalse((directory / 'status_counts.json').exists())
        environment = {'mode': 'offline', 'guest_network_checked': True,
                       'stdlib_dependencies_checked': True, 'hypervisor_controls_attested': True}
        jobs.result(job, 'partial', summary=summary, environment=environment)
        for change in ({'status_counts': {'observed': 40, 'partial': 2, 'private': 8}},
                       {'status_counts': {'observed': 40, 'partial': 2, 'encrypted': 7}},
                       {'observed': 41, 'failed': 7},
                       {'shard': 1}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'report_invalid'):
                broken = {**shards[0], **change}
                (directory / 'pdf_summary.0.json').write_bytes(
                    jobs.encoded({'planned': 64, 'shard': 0, 'shards': 2, **broken}))
                jobs.merge_summary(job, directory, 2)

    def test_console_compare_and_historical_report_read_stale_policy_jobs(self):
        root = self.base / 'jobs'
        root.mkdir()
        limits = {'wall_seconds': 1800, 'file_wall_seconds': 20, 'file_cpu_seconds': 12,
                  'file_memory_bytes': 1073741824, 'file_max_bytes': 10485760,
                  'samples': 2, 'workers': 1, 'output_bytes': 536870912}
        left = {'schema_version': 1, 'api': 1, 'commit': 'a' * 40, 'archive_sha256': 'b' * 64,
                'manifest_sha256': 'c' * 64, 'mode': 'offline', 'kind': 'pdf-static',
                'limits': limits, 'job_id': 'd' * 64, 'attempt': 'e' * 32}
        right = {**left, 'limits': {**limits, 'workers': 5}, 'job_id': 'f' * 64}
        for job, bundles in ((left, ({'status': 'observed', 'feature_store': {'records': [1]}},
                                     {'status': 'observed', 'feature_store': {'records': [2]}})),
                             (right, ({'status': 'observed', 'feature_store': {'records': [1]}},
                                      {'status': 'partial', 'feature_store': {'records': [3]}}))):
            directory = root / job['job_id']
            (directory / 'private_bundles').mkdir(parents=True)
            (directory / 'job.json').write_bytes(jobs.encoded(job))
            (directory / 'selection.json').write_bytes(jobs.encoded({'job_id': job['job_id'], 'rows': [], 'selection_sha256': '1' * 64}))
            for index, bundle in enumerate(bundles):
                (directory / 'private_bundles' / f'{index:04d}.json').write_bytes(jobs.encoded(bundle))
        legacy = {'planned': 2, 'completed': 1, 'observed': 1, 'partial': 0, 'failed': 0,
                  'primary_available': 1, 'timeout': 0, 'elapsed_ms': 10, 'peak_rss_bytes': 20}
        (root / left['job_id'] / 'result.json').write_bytes(jobs.encoded({'schema_version': 1,
            'job': left, 'status': 'partial', 'reason': None, 'checks': [], 'pdf_summary': legacy,
            'preflight': {'mode': 'offline', 'guest_network_checked': True,
                          'stdlib_dependencies_checked': True, 'hypervisor_controls_attested': True},
            'generated_utc': '2026-10-27T00:00:00Z'}))
        with patch.object(jobs, 'JOBS', root):
            value = runner.compare(left['job_id'], right['job_id'])
            self.assertEqual(value, {'compared': 2, 'identical': 1, 'status_mismatch': 1, 'feature_mismatch': 1,
                                     'missing_bundles': 0, 'first_mismatch_index': 1,
                                     'same_selection': True, 'same_commit': True})
            (root / right['job_id'] / 'private_bundles/0001.json').unlink()
            value = runner.compare(left['job_id'], right['job_id'])
            self.assertEqual((value['identical'], value['missing_bundles'], value['first_mismatch_index']), (1, 1, 1))
            self.assertEqual(runner.historical_report(left['job_id'])['pdf_summary'], legacy)
            with self.assertRaisesRegex(ValueError, 'report_invalid'):
                (root / left['job_id'] / 'result.json').write_bytes(jobs.encoded({'schema_version': 1,
                    'job': left, 'status': 'partial', 'reason': None, 'checks': [], 'pdf_summary': {**legacy, 'completed': 2},
                    'preflight': {'mode': 'offline', 'guest_network_checked': True,
                                  'stdlib_dependencies_checked': True, 'hypervisor_controls_attested': True},
                    'generated_utc': '2026-10-27T00:00:00Z'}))
                runner.historical_report(left['job_id'])
            with self.assertRaisesRegex(ValueError, 'job_mismatch'):
                runner.compare(left['job_id'], left['job_id'] + '0')

    def test_console_preflight_lists_credential_reasons(self):
        with patch.object(jobs, 'config', return_value={'data_root': '/home/synthetic/MalPDFDeepDetection'}), patch.object(jobs, 'credential_reasons', return_value=['env:SSH_AUTH_SOCK']), patch.object(jobs, 'pending', return_value=[{'job_id': 'a' * 64}]):
            self.assertEqual(runner.console_preflight(),
                             {'credentials': ['env:SSH_AUTH_SOCK'], 'pending_jobs': 1, 'network_changed': False})

    def test_cve_worker_requires_console_claim_and_refuses_windows_before_metadata(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline', kind='pdf-static-cve')
        with patch.object(jobs, 'JOBS', self.base / 'jobs'):
            jobs.save_job(job)
            with patch.object(runner.sys, 'platform', 'win32'), patch.object(runner, 'pdf_metadata') as metadata, self.assertRaisesRegex(ValueError, 'runtime_unavailable'):
                runner.pdf_worker(job['job_id'], prepare=True)
            metadata.assert_not_called()
            with patch.object(runner.sys, 'platform', 'linux'), patch.object(jobs, 'preflight'), patch.object(runner, 'pdf_metadata') as metadata, self.assertRaises((OSError, ValueError)):
                runner.pdf_worker(job['job_id'])
            metadata.assert_not_called()

    def test_cve_worker_reuses_static_extraction_with_exact_paths_hashes_and_five_row_summary(self):
        root, rows = self.cve_fixture()
        spec = self.write_cve_manifest(root, rows)
        with patch.object(runner, 'CVE_MANIFEST', spec):
            selected = runner.cve_rows(root)
        source = self.repo
        for base in (source, root):
            lock = base / 'configs/arlington.lock.json'
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_bytes(b'{}')
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline', kind='pdf-static-cve')
        calls = []
        checks = []
        def extract(path, **kwargs):
            calls.append((path, kwargs))
            return {'status': 'partial' if len(calls) == 1 else 'observed',
                'evidence_store': {'records': [{'kind': 'primary_checkpoint'}]},
                'coverage_report': {'worker': {'peak_rss_bytes': 1024, 'worker_cleanup_complete': True}}}
        modules = {'malpdf.extraction.orchestrator': SimpleNamespace(extract_pdf=extract),
            'malpdf.extraction.arlington_model': SimpleNamespace(load_model=lambda path: 'synthetic-catalog'),
            'malpdf.extraction.jobs': SimpleNamespace(require_extraction_lab=lambda attested, **kwargs: checks.append((attested, kwargs))),
            'malpdf.static.code_inspector': SimpleNamespace(CodeInspectionLimits=lambda **kwargs: kwargs, _worker_count=lambda *args: None)}
        with patch.object(jobs, 'JOBS', self.base / 'jobs'), patch.object(runner.sys, 'platform', 'linux'), patch.object(jobs, 'preflight'), patch.object(runner, 'worker_limits') as limits, patch.object(runner, 'pdf_metadata', return_value=(source, root, selected)), patch.dict(sys.modules, modules), patch.dict(os.environ):
            directory = jobs.save_job(job)
            runner.pdf_worker(job['job_id'], prepare=True)
            self.assertEqual(calls, [])
            self.assertFalse((directory / 'private_bundles').exists())
            jobs.immutable(directory / 'claim.json', {'job_id': job['job_id'], 'parent_pid': os.getppid(), 'hypervisor_controls_attested': True})
            runner.pdf_worker(job['job_id'])
        self.assertEqual(limits.call_args_list[0].kwargs, {'prepare': True, 'wall_seconds': 180})
        self.assertEqual(limits.call_args_list[1].kwargs, {'prepare': False, 'wall_seconds': 180})
        self.assertEqual(len(calls), 5)
        self.assertEqual(len(checks), 6)
        self.assertTrue(all(attested is True and kwargs == {'repository_root': root} for attested, kwargs in checks))
        for (path, kwargs), row in zip(calls, selected):
            self.assertEqual(path, root / row['pdf_relative_path'])
            self.assertEqual(kwargs['boundary'], root / 'data/raw/cve_t4pdf')
            self.assertEqual(kwargs['expected_sha256'], row['pdf_sha256'])
            self.assertEqual(kwargs['limits'], {'wall_seconds': 20, 'cpu_seconds': 12})
            self.assertEqual(kwargs['arlington_catalog'], 'synthetic-catalog')
        summary = json.loads((directory / 'pdf_summary.0.json').read_bytes())
        self.assertEqual((summary['planned'], summary['completed'], summary['observed'], summary['partial']), (5, 5, 4, 1))
        self.assertEqual((summary['shard'], summary['shards']), (0, 1))
        self.assertEqual(summary['status_counts'], {'observed': 4, 'partial': 1})
        self.assertEqual(len(list((directory / 'private_bundles').iterdir())), 5)

    def test_pdf_preparation_returns_only_fixed_failure_reasons_from_private_worker_output(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline', kind='pdf-static-cve')
        for value, expected in (({'status': 'blocked', 'reason': 'manifest_unavailable'}, 'manifest_unavailable'), ({'status': 'blocked', 'reason': 'private untrusted text'}, 'worker_failed'), ({'status': 'blocked', 'reason': 'manifest_unavailable', 'raw_log': 'private'}, 'worker_failed')):
            def start(command, **kwargs):
                kwargs['stdout'].write(jobs.encoded(value))
                return SimpleNamespace(wait=lambda timeout: 2)
            with patch.object(jobs, 'config', return_value={'python': '/usr/bin/python3'}), patch.object(subprocess, 'Popen', side_effect=start), self.assertRaisesRegex(ValueError, expected):
                runner.pdf_prepare(job, self.base)

    def test_cve_proposal_is_metadata_only_and_never_substitutes_the_cic_cohort(self):
        package = self.package()
        with patch.object(offline.snapshot, 'prepare', return_value=package), patch.object(offline.vmware, 'isolation', return_value={'ready_for_real_pdf': False}):
            value = offline.prepare('pdf-static-cve')
        self.assertEqual(value['cohort']['cohort'], 'cve-t4pdf-5')
        self.assertEqual(value['cohort']['samples'], 5)
        self.assertEqual(value['cohort']['boundary'], 'data/raw/cve_t4pdf')
        self.assertEqual(value['limits']['samples'], 5)
        self.assertFalse(value['ready_for_real_pdf'])
        plan = json.loads(Path(value['plan']).read_bytes())
        self.assertFalse(plan['real_pdf_approved'])
        self.assertFalse(plan['export_approved'])

    def test_preparation_records_an_unapproved_plan_without_lab_execution(self):
        package = self.package()
        with patch.object(offline.snapshot, 'prepare', return_value=package), patch.object(offline.vmware, 'isolation', return_value={'ready_for_real_pdf': False}):
            value = offline.prepare()
            repeated = offline.prepare()
        self.assertEqual(value['job_id'], repeated['job_id'])
        self.assertFalse(value['ready_for_real_pdf'])
        self.assertFalse(value['pdf_execution'])
        self.assertFalse(value['remote_changes'])
        plan = json.loads(Path(value['plan']).read_bytes())
        self.assertFalse(plan['real_pdf_approved'])
        self.assertFalse(plan['export_approved'])
        self.assertEqual(plan['lab_execution'], 'not_run')
        self.assertEqual(plan['cohort']['test'], 0)

    def test_offline_setup_and_prepare_facades_do_not_enter_the_operator_transport(self):
        with patch.object(offline, 'bootstrap', return_value={'remote_changes': False}), patch.object(offline, 'prepare', return_value={'pdf_execution': False}), patch.object(windows, 'exchange') as exchange, redirect_stdout(io.StringIO()):
            self.assertEqual(windows.main(['setup', '--mode', 'offline']), 0)
            self.assertEqual(windows.main(['prepare', '--mode', 'offline', '--kind', 'pdf-static']), 0)
        exchange.assert_not_called()

    def test_offline_copy_uses_its_fixed_parent_and_rejects_noninteractive_use(self):
        value = offline.bootstrap()
        files = transfer.verified_files(value, offline=True)
        self.assertEqual(len(files), 12)
        command = transfer.create_directory(value['manifest_id'], offline=True)
        self.assertIn('/home/remnux/malpdf-offline-bootstrap/' + value['manifest_id'], command)
        self.assertNotIn('/home/remnux/malpdf-gateway-bootstrap/', command)
        with patch.object(transfer.sys.stdin, 'isatty', return_value=False), patch.object(offline, 'bootstrap') as prepare, patch.object(transfer.subprocess, 'run') as run, self.assertRaises(ValueError):
            transfer.transfer(offline=True)
        prepare.assert_not_called()
        run.assert_not_called()

    def test_operator_offline_copy_sends_only_the_verified_installer_and_never_executes_it(self):
        ssh = self.base / 'ssh.exe'
        ssh.touch()
        ssh.with_name('scp.exe').touch()
        value = offline.bootstrap()
        with patch.object(transfer.sys, 'platform', 'win32'), patch.object(transfer.sys.stdin, 'isatty', return_value=True), patch.object(transfer.sys.stdout, 'isatty', return_value=True), patch.object(client.ctl, 'SSH', str(ssh)), patch('builtins.input', return_value='y'), patch.object(transfer.subprocess, 'run') as run, redirect_stdout(io.StringIO()) as output:
            with patch.object(transfer.sys.stdout, 'isatty', return_value=True):
                self.assertEqual(transfer.transfer(offline=True), 0)
        self.assertEqual(run.call_count, 2)
        scp = run.call_args_list[1].args[0]
        self.assertEqual(scp[-1], client.ctl.ADMIN + ':/home/remnux/malpdf-offline-bootstrap/' + value['manifest_id'] + '/')
        self.assertEqual(scp[1 + len(client.ctl.SCP_SECURITY):-1], list(map(str, offline.verified_files(value))))
        self.assertNotIn('sudo', run.call_args_list[0].args[0][-1])
        self.assertIn('sudo sh setup_runner.sh --check', output.getvalue())
        self.assertNotIn('--allow-synthetic', output.getvalue())

    def test_offline_pdf_proposal_keeps_the_actual_human_gate_before_transport(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        package = self.package()
        status = {'schema_version': 2, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate',
            'runner': {'api': 1, 'installed': True, 'host_only_ready': True, 'offline_guest_ready': False, 'reason': None}}
        with patch.object(windows.sys, 'stdin', Terminal()), redirect_stdout(Terminal()), patch.object(windows.ctl, 'clean_repo', side_effect=AssertionError('Unrelated work must not be committed')), patch.object(windows.ctl, 'run'), patch.object(windows.ctl, 'audit_request', return_value=(0, contract.encoded(status))), patch.object(snapshot, 'prepare', return_value=package), patch('builtins.input', return_value='n'), patch.object(windows, 'exchange') as exchange, self.assertRaisesRegex(ValueError, 'approval_required'):
            windows.test(mode='offline', kind='pdf-static')
        exchange.assert_not_called()
        self.assertFalse((windows.STATE / 'last.json').exists())

    def test_offline_source_drift_after_human_approval_prevents_admin_transfer(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        package = self.package()
        status = {'schema_version': 2, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate',
            'runner': {'api': 1, 'installed': True, 'host_only_ready': True, 'offline_guest_ready': False, 'reason': None}}
        def approve(unused):
            package[2].write_bytes(package[2].read_bytes() + b'\n')
            return 'y'
        with patch.object(windows.sys, 'stdin', Terminal()), redirect_stdout(Terminal()), patch.object(windows.ctl, 'clean_repo', side_effect=AssertionError('Unrelated work must not be committed')), patch.object(windows.ctl, 'run'), patch.object(windows.ctl, 'audit_request', return_value=(0, contract.encoded(status))), patch.object(snapshot, 'prepare', return_value=package), patch('builtins.input', side_effect=approve), patch.object(windows, 'exchange') as exchange, self.assertRaisesRegex(ValueError, 'release_mismatch'):
            windows.test(mode='offline', kind='pdf-static')
        exchange.assert_not_called()

    def vmx(self):
        return b'ethernet0.present = "TRUE"\nethernet0.connectionType = "hostonly"\nisolation.tools.copy.disable = "TRUE"\nisolation.tools.paste.disable = "TRUE"\nisolation.tools.dnd.disable = "TRUE"\nisolation.tools.hgfs.disable = "TRUE"\n'

    def test_explicit_configuration_controls_are_metadata_not_runtime_attestation(self):
        value = vmware.configuration_isolation(self.vmx())
        self.assertEqual(value['network_configuration'], 'host_only')
        self.assertEqual(value['copy_paste'], 'disabled')
        self.assertEqual(value['drag_drop'], 'disabled')
        self.assertEqual(value['shared_folders'], 'disabled')
        self.assertNotIn('ready_for_real_pdf', value)

    def test_missing_disabled_or_conflicting_controls_never_pass_as_disabled(self):
        value = vmware.configuration_isolation(b'ethernet0.present = "TRUE"\nethernet0.connectionType = "hostonly"\n')
        self.assertEqual(value['copy_paste'], 'unverified')
        self.assertEqual(value['shared_folders'], 'unverified')
        value = vmware.configuration_isolation(self.vmx().replace(b'copy.disable = "TRUE"', b'copy.disable = "FALSE"'))
        self.assertEqual(value['copy_paste'], 'enabled')
        value = vmware.configuration_isolation(self.vmx() + b'sharedFolder0.enabled = "TRUE"\n')
        self.assertEqual(value['shared_folders'], 'enabled')

    def test_multiple_nat_unknown_or_duplicate_adapter_configuration_is_not_host_only(self):
        for raw in (self.vmx().replace(b'"hostonly"', b'"nat"'), self.vmx() + b'ethernet1.present = "TRUE"\n',
                self.vmx().replace(b'present = "TRUE"', b'present = "unknown"')):
            self.assertEqual(vmware.configuration_isolation(raw)['network_configuration'], 'unverified')
        for raw in (self.vmx() + b'ethernet0.present = "FALSE"\n', b'x' * 1048577, b'\xff'):
            with self.assertRaises(ValueError):
                vmware.configuration_isolation(raw)

    def test_isolation_reads_fixed_inventory_only_and_redacts_snapshot_names_and_host_paths(self):
        vmx = self.base / 'Remnux.vmx'
        vmx.write_bytes(self.vmx() + b'sharedFolder0.hostPath = "private canary"\n')
        binary = self.base / 'vmrun.exe'
        binary.touch()
        replies = ['Total running VMs: 1\n' + str(vmx), 'Total snapshots: 1\nprivate canary']
        with patch.multiple(vmware, VMX=vmx, VMRUNS=(binary,)), patch.object(vmware.sys, 'platform', 'win32'), patch.object(vmware, 'query', side_effect=replies) as query:
            value = vmware.isolation()
        self.assertEqual([call.args[1] for call in query.call_args_list], ['list', 'snapshots'])
        self.assertEqual(value['snapshot_count'], 1)
        self.assertTrue(value['vm_running'])
        self.assertFalse(value['ready_for_real_pdf'])
        self.assertIsNone(value['runtime_nics_disconnected'])
        self.assertFalse(value['guest_controls_verified'])
        self.assertNotIn('canary', json.dumps(value))
        self.assertNotIn(str(vmx), json.dumps(value))

    def test_snapshot_inventory_missing_or_malformed_remains_unverified(self):
        vmx = self.base / 'Remnux.vmx'
        vmx.write_bytes(self.vmx())
        binary = self.base / 'vmrun.exe'
        binary.touch()
        for reply, expected in [('Total snapshots: 0', 0), ('Total snapshots: 1', None), ('private canary', None)]:
            with patch.multiple(vmware, VMX=vmx, VMRUNS=(binary,)), patch.object(vmware.sys, 'platform', 'win32'), patch.object(vmware, 'query', side_effect=['Total running VMs: 0', reply]):
                value = vmware.isolation()
            self.assertEqual(value['snapshot_count'], expected)
            self.assertFalse(value['ready_for_real_pdf'])

    def test_snapshot_query_has_fixed_read_only_arguments(self):
        with patch.object(vmware.subprocess, 'run', return_value=subprocess.CompletedProcess('vmrun', 0, stdout=b'Total snapshots: 0\n')) as run:
            vmware.query(vmware.VMRUNS[0], 'snapshots')
        self.assertEqual(run.call_args.args[0], [str(vmware.VMRUNS[0]), '-T', 'ws', 'listSnapshots', str(vmware.VMX)])
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
        self.assertNotIn('shell', run.call_args.kwargs)
