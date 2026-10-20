"""Synthetic workflow failures and mocked LAB execution; never read corpus inputs."""

from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import ast
import re
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lab_contract as contract
import lab_jobs as jobs
import lab_runner as runner
import lab_side as side
import lab_windows as windows


class Terminal(io.StringIO):
    def isatty(self):
        return True


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='malpdf-workflow-tests-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        for module, attributes in ((jobs, {'JOBS': self.base / 'jobs'}),
            (side, {'INBOX': self.base / 'inbox', 'RELEASES': self.base / 'releases', 'REPORTS': self.base / 'reports'}),
            (windows, {'STATE': self.base / 'windows'})):
            for key, value in attributes.items():
                handle = patch.object(module, key, value)
                handle.start()
                self.addCleanup(handle.stop)
        self.job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64)

    def environment(self, mode='host-only'):
        return {'mode': mode, 'guest_network_checked': True, 'stdlib_dependencies_checked': True,
                'hypervisor_controls_attested': mode == 'offline'}

    def checks(self, job=None):
        job = job or self.job
        return [side.make_report(job['commit'], kind, 1, 0, 0, []) for kind in ('ast_syntax', 'synthetic_security')]

    def release(self, *, mode='offline', kind='syntax'):
        from selftest import write_archive
        side.INBOX.mkdir(exist_ok=True)
        commit = 'a' * 40
        archive = side.INBOX / (commit + '.tar')
        files = [('src/malpdf/inert.py', b'value=42\n')]
        for name in ('lab_contract.py', 'lab_readonly.py', 'lab_side.py', 'lab_jobs.py', 'lab_runner.py', 'check_local.py'):
            files.append(('scripts/lab/' + name, (HERE / name).read_bytes()))
        guard = HERE.parents[1] / 'src/malpdf/static/lab_guard.py'
        files.append(('src/malpdf/static/lab_guard.py', guard.read_bytes()))
        entries = write_archive(archive, files)
        meta = {'schema_version': 1, 'commit': commit, 'archive_sha256': jobs.sha(archive.read_bytes()), 'files': entries}
        manifest = side.INBOX / (commit + '.json')
        manifest.write_bytes(jobs.encoded(meta))
        job = jobs.make_job(commit, meta['archive_sha256'], jobs.sha(manifest.read_bytes()), mode=mode, kind=kind)
        return job, archive, manifest

    def installed(self, **options):
        job, archive, manifest = self.release(**options)
        with redirect_stdout(io.StringIO()):
            side.install(job['commit'])
        return job

    def test_job_identity_is_bound_to_all_fields(self):
        self.assertEqual(jobs.validate_job(self.job), self.job)
        for key, value in (('commit', 'd' * 40), ('kind', 'syntax'), ('mode', 'offline'), ('schema_version', True), ('limits', {**jobs.LIMITS, 'workers': 2}), ('attempt', '../escape')):
            altered = copy.deepcopy(self.job)
            altered[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                jobs.validate_job(altered)

    def test_pdf_cannot_be_a_connected_job(self):
        with self.assertRaises(ValueError):
            jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, kind='pdf-static')

    def test_new_approval_has_distinct_job_id_and_fixed_plan_is_repeatable(self):
        other = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64)
        self.assertNotEqual(other['job_id'], self.job['job_id'])
        same = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, attempt=self.job['attempt'])
        self.assertEqual(same, self.job)

    def test_reports_reject_raw_fields_and_false_passes(self):
        good = jobs.result(self.job, 'passed', checks=self.checks(), environment=self.environment())
        for change in (lambda value: value.update(raw_log='private canary'),
                       lambda value: value.update(checks=[]),
                       lambda value: value['preflight'].update(guest_network_checked=False),
                       lambda value: value['checks'][0].update(commit='e' * 40),
                       lambda value: value.update(generated_utc='not a time'),
                       lambda value: value.update(checks=list(reversed(value['checks'])))):
            altered = copy.deepcopy(good)
            change(altered)
            with self.assertRaises(ValueError):
                jobs.validate_result(altered, self.job)

    def test_pdf_summary_preserves_denominators_and_requires_offline_attestation(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, kind='pdf-static', mode='offline')
        summary = {'planned': 64, 'completed': 63, 'observed': 1, 'partial': 60, 'failed': 2,
            'primary_available': 63, 'timeout': 1, 'elapsed_ms': 1000, 'peak_rss_bytes': 123456}
        value = jobs.result(job, 'partial', summary=summary, environment=self.environment('offline'))
        with self.assertRaises(ValueError):
            jobs.validate_result({**value, 'status': 'passed'}, job)
        value['preflight']['hypervisor_controls_attested'] = False
        with self.assertRaises(ValueError):
            jobs.validate_result(value, job)

    def test_status_old_and_new_schemas_are_separate(self):
        old = {'schema_version': 1, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate'}
        contract.validate_status(old)
        new = {**old, 'schema_version': 2, 'runner': {'api': 1, 'installed': True, 'host_only_ready': True, 'offline_guest_ready': False, 'reason': None}}
        contract.validate_status(new)
        new['runner']['raw_path'] = 'private'
        with self.assertRaises(ValueError):
            contract.validate_status(new)

    def test_missing_manifest_fails_without_installing_release(self):
        with self.assertRaises((ValueError, OSError)):
            side.verify_release('a' * 40, 'c' * 64)
        self.assertFalse(side.RELEASES.exists())

    def test_modified_release_cannot_execute(self):
        job = self.installed()
        (side.RELEASES / job['commit'] / 'src/malpdf/inert.py').write_text('value=43\n')
        with self.assertRaises(ValueError):
            side.verify_release(job['commit'], job['manifest_sha256'])

    def test_release_rejects_extra_files_and_wrong_revision(self):
        job = self.installed()
        with self.assertRaises(ValueError):
            side.verify_release('d' * 40, job['manifest_sha256'])
        (side.RELEASES / job['commit'] / 'src/extra.py').write_text('pass\n')
        with self.assertRaises(ValueError):
            side.verify_release(job['commit'], job['manifest_sha256'])

    def test_receiver_queues_offline_job_without_running_it(self):
        job, archive, manifest = self.release()
        data = windows.packet(job, archive, manifest)
        with patch.object(jobs, 'config'), patch.object(jobs, 'preflight'), patch.object(jobs, 'execute') as execute:
            value = runner.receive(io.BytesIO(data), job['job_id'])
            repeated = runner.receive(io.BytesIO(data), job['job_id'])
        self.assertEqual(value['status'], 'queued')
        self.assertEqual(value, repeated)
        execute.assert_not_called()
        self.assertEqual(jobs.pending(), [job])

    def test_receiver_rejects_checksum_corruption_and_oversized_frames(self):
        job, archive, manifest = self.release()
        payload = windows.packet(job, archive, manifest)
        for data in (payload[:-1], payload + b'X', b'\xff' * 4):
            with patch.object(jobs, 'config'), patch.object(jobs, 'preflight'), self.assertRaises(ValueError):
                runner.receive(io.BytesIO(data), job['job_id'])
        self.assertFalse(side.RELEASES.exists())

    def test_network_refusal_precedes_remote_writes(self):
        with patch.object(jobs, 'config'), patch.object(jobs, 'preflight', side_effect=ValueError('network_blocked')):
            with self.assertRaises(ValueError):
                runner.receive(io.BytesIO(b''), self.job['job_id'])
        self.assertFalse(side.INBOX.exists())

    def test_pdf_queue_prepares_metadata_without_executing_pdf(self):
        job, archive, manifest = self.release(kind='pdf-static')
        with patch.object(jobs, 'config'), patch.object(jobs, 'preflight'), patch.object(runner, 'pdf_prepare') as prepare, patch.object(jobs, 'pdf_task') as run:
            value = runner.receive(io.BytesIO(windows.packet(job, archive, manifest)), job['job_id'])
        prepare.assert_called_once()
        run.assert_not_called()
        self.assertEqual(value['status'], 'queued')

    def test_execute_uses_existing_checks_and_completed_job_is_idempotent(self):
        job = self.installed(mode='host-only', kind='synthetic')
        checks = self.checks(job)
        with patch.object(jobs, 'config', return_value={}), patch.object(jobs, 'preflight', return_value=self.environment()), patch.object(side, 'syntax', return_value=checks[0]) as syntax, patch.object(side, 'synthetic', return_value=checks[1]) as synthetic:
            first = jobs.execute(job)
            second = jobs.execute(job)
        self.assertEqual(first, second)
        self.assertEqual(first['status'], 'passed')
        syntax.assert_called_once()
        synthetic.assert_called_once()

    def test_claimed_job_never_restarts_after_interruption(self):
        job = self.installed()
        directory = jobs.save_job(job)
        (directory / 'claim.json').write_text(job['job_id'])
        with patch.object(jobs, 'config', return_value={}), patch.object(side, 'syntax') as syntax:
            with self.assertRaisesRegex(ValueError, 'already_claimed'):
                jobs.execute(job, attested=True)
        syntax.assert_not_called()

    def test_worker_failure_is_redacted_and_preserved(self):
        job = self.installed(mode='host-only')
        with patch.object(jobs, 'config', return_value={}), patch.object(jobs, 'preflight', return_value=self.environment()), patch.object(side, 'syntax', side_effect=ValueError('private PDF canary')):
            value = jobs.execute(job)
        self.assertEqual(value['reason'], 'worker_failed')
        self.assertNotIn('canary', json.dumps(value))
        self.assertEqual(jobs.read_result(job['job_id']), value)

    def test_offline_gate_is_checked_before_claim(self):
        job = self.installed()
        with patch.object(jobs, 'config', return_value={}), patch.object(jobs, 'preflight', side_effect=ValueError('network_blocked')):
            with self.assertRaises(ValueError):
                jobs.execute(job)
        self.assertFalse((jobs.job_directory(job['job_id']) / 'claim.json').exists())

    def test_known_credential_presence_blocks_pdf_before_worker(self):
        (self.base / '.codex').mkdir()
        (self.base / '.codex/auth.json').write_text('never read me')
        with patch.object(Path, 'home', return_value=self.base), self.assertRaisesRegex(ValueError, 'credential_present'):
            jobs.check_credentials(self.base / 'data')

    def test_job_ids_cannot_be_paths_or_shell_fragments(self):
        for value in ('../outside', 'a' * 64 + ';id', 'A' * 64, None):
            with self.assertRaises(ValueError):
                jobs.job_directory(value)

    def test_windows_tests_require_an_operator_terminal(self):
        with patch.object(windows.sys, 'stdin', io.StringIO()), patch.object(windows.ctl, 'prepare') as prepare, self.assertRaises(ValueError):
            windows.test(mode='host-only', kind='synthetic')
        prepare.assert_not_called()

    def client_context(self, callback):
        job, archive, manifest = self.release(mode='host-only', kind='synthetic')
        status = {'schema_version': 2, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate',
            'runner': {'api': 1, 'installed': True, 'host_only_ready': True, 'offline_guest_ready': False, 'reason': None}}
        with patch.object(windows.sys, 'stdin', Terminal()), redirect_stdout(Terminal()), patch.object(windows.ctl, 'clean_repo'), patch.object(windows.ctl, 'run'), patch.object(windows.ctl, 'prepare', return_value=(job['commit'], archive, manifest)), patch.object(windows.ctl, 'audit_request', return_value=(0, jobs.encoded(status))), patch.object(windows.ctl, 'revision', return_value=job['commit']):
            return callback()

    def test_declining_batch_makes_no_ssh_write(self):
        def check():
            with patch('builtins.input', return_value='n'), patch.object(windows, 'exchange') as exchange, self.assertRaises(ValueError):
                windows.test(mode='host-only', kind='synthetic')
            exchange.assert_not_called()
        self.client_context(check)

    def test_ssh_loss_keeps_pending_job_and_never_retries(self):
        def check():
            with patch('builtins.input', return_value='y'), patch.object(windows, 'exchange', side_effect=ValueError('ssh_unavailable')) as exchange, self.assertRaises(ValueError):
                windows.test(mode='host-only', kind='synthetic')
            exchange.assert_called_once()
            self.assertEqual(windows.local_job()['kind'], 'synthetic')
        self.client_context(check)

    def test_release_drift_after_approval_blocks_transport(self):
        def check():
            with patch('builtins.input', return_value='y'), patch.object(windows.ctl, 'revision', return_value='d' * 40), patch.object(windows, 'exchange') as exchange, self.assertRaises(ValueError):
                windows.test(mode='host-only', kind='synthetic')
            exchange.assert_not_called()
        self.client_context(check)

    def test_ssh_output_is_bounded_and_never_prints_remote_text(self):
        with patch.object(windows.sys, 'stdin', Terminal()), redirect_stdout(Terminal()), patch.object(windows.ctl, 'SSH', sys.executable), patch.object(windows.ctl, 'ADMIN_SECURITY', ['-c', "import os; os.write(1,b'x'*100000)"]), self.assertRaises(ValueError):
            windows.exchange('fixed-command')

    def test_remote_fixed_error_is_preserved_without_untrusted_diagnostics(self):
        program = "import json,sys; print(json.dumps({'status':'blocked','reason':'release_mismatch'})); sys.exit(2)"
        with patch.object(windows.sys, 'stdin', Terminal()), redirect_stdout(Terminal()), patch.object(windows.ctl, 'SSH', sys.executable), patch.object(windows.ctl, 'ADMIN_SECURITY', ['-c', program]), self.assertRaisesRegex(ValueError, 'release_mismatch'):
            windows.exchange('fixed-command')

    def test_safe_local_report_does_not_contact_ssh(self):
        value = jobs.result(self.job, 'passed', checks=self.checks(), environment=self.environment())
        windows.save_pending(self.job)
        windows.save_result(value, self.job)
        with redirect_stdout(io.StringIO()), patch.object(windows, 'exchange') as exchange:
            self.assertEqual(windows.main(['report']), 0)
        exchange.assert_not_called()

    def test_offline_report_refresh_never_contacts_vm(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline', kind='pdf-static')
        windows.save_pending(job)
        with redirect_stdout(io.StringIO()), patch.object(windows, 'exchange') as exchange:
            self.assertEqual(windows.main(['report', '--refresh']), 2)
        exchange.assert_not_called()

    def test_pdf_worker_requires_console_claim_before_source_import(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline', kind='pdf-static')
        jobs.save_job(job)
        with patch.object(sys, 'platform', 'linux'), patch.object(jobs, 'preflight'), patch.object(runner, 'source_imports') as imports, self.assertRaises((OSError, ValueError)):
            runner.pdf_worker(job['job_id'])
        imports.assert_not_called()

    def test_ipv6_default_route_is_not_host_only(self):
        addresses = [{'ifname': 'ens33', 'flags': ['UP'], 'addr_info': [{'family': 'inet', 'local': '192.168.217.10', 'prefixlen': 24}]}]
        with patch.object(jobs, 'ip_json', side_effect=[addresses, [], [{'dst': 'default', 'dev': 'ens33'}]]), self.assertRaisesRegex(ValueError, 'network_blocked'):
            jobs.host_only_network()

    def test_console_menu_has_no_network_reconnect_action(self):
        with patch.object(sys, 'argv', ['lab', 'menu']), patch('builtins.input', return_value='0'), redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(), 0)

    def test_console_run_refuses_noninteractive_call(self):
        with patch.object(sys, 'stdin', io.StringIO()), self.assertRaises(ValueError):
            runner.console_run()

    def test_pdf_worker_refuses_windows_before_source_or_sample_access(self):
        with patch.object(sys, 'platform', 'win32'), patch.object(runner, 'source_imports') as imports, self.assertRaises(ValueError):
            runner.pdf_worker(self.job['job_id'])
        imports.assert_not_called()

    def test_fixed_network_policy_rejects_default_and_extra_adapters(self):
        addresses = [{'ifname': 'lo', 'flags': ['UP']}, {'ifname': 'ens33', 'flags': ['UP'], 'addr_info': [{'family': 'inet', 'local': '192.168.217.10', 'prefixlen': 24}]}]
        safe = [{'dst': '192.168.217.0/24', 'dev': 'ens33'}, {'dst': '127.0.0.0/8', 'dev': 'lo'}]
        with patch.object(jobs, 'ip_json', side_effect=[addresses, safe, []]):
            jobs.host_only_network()
        for routes in ([{'dst': 'default', 'gateway': '192.168.217.1', 'dev': 'ens33'}], [{'dst': '192.168.217.0/8', 'dev': 'ens33'}], [{'dst': '::/0', 'dev': 'ens33'}]):
            with patch.object(jobs, 'ip_json', side_effect=[addresses, routes]), self.assertRaisesRegex(ValueError, 'network_blocked'):
                jobs.host_only_network()
        with patch.object(jobs, 'ip_json', return_value=addresses + [addresses[-1]]), self.assertRaises(ValueError):
            jobs.host_only_network()

    def test_status_probe_reports_unknown_without_claiming_vm_isolation(self):
        with patch.object(jobs, 'preflight', side_effect=ValueError('network_blocked')):
            value = jobs.probe()
        self.assertFalse(value['host_only_ready'])
        self.assertFalse(value['offline_guest_ready'])

    def test_interrupted_claim_does_not_look_like_an_unstarted_queue(self):
        job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, mode='offline')
        directory = jobs.save_job(job)
        jobs.immutable(directory / 'queued.json', jobs.result(job, 'queued'))
        jobs.immutable(directory / 'claim.json', {'job_id': job['job_id'], 'parent_pid': 12345,
            'start_ticks': 123, 'generated_utc': '2026-10-19T00:00:00Z', 'hypervisor_controls_attested': True})
        with patch.object(jobs, 'process_identity', return_value=None):
            report = jobs.read_result(job['job_id'])
        self.assertEqual(report['status'], 'interrupted')
        self.assertEqual(report['reason'], 'already_claimed')

    def test_resource_limits_are_restored_even_when_a_task_raises(self):
        limits = {index: (999999, -1) for index in range(5)}
        original = limits.copy()
        fake_resource = types.SimpleNamespace(RLIMIT_AS=0, RLIMIT_CPU=1, RLIMIT_FSIZE=2,
            RLIMIT_NOFILE=3, RLIMIT_NPROC=4, RLIM_INFINITY=-1, RUSAGE_SELF=0,
            getrusage=lambda _: types.SimpleNamespace(ru_utime=0.1, ru_stime=0.1),
            getrlimit=lambda key: limits[key], setrlimit=lambda key, value: limits.update({key: value}))
        handlers = {14: 'original_alarm', 24: 'original_cpu'}
        timers = []
        fake_signal = types.SimpleNamespace(SIGALRM=14, SIGXCPU=24, ITIMER_REAL=0,
            getsignal=lambda key: handlers[key], signal=lambda key, value: handlers.update({key: value}),
            getitimer=lambda _: (0, 0), setitimer=lambda *args: timers.append(args))
        with patch.dict(sys.modules, {'resource': fake_resource, 'signal': fake_signal}):
            with self.assertRaisesRegex(ValueError, 'synthetic task failure'):
                with jobs.execution_limits('syntax'):
                    self.assertNotEqual(limits, original)
                    raise ValueError('synthetic task failure')
        self.assertEqual(limits, original)
        self.assertEqual(handlers, {14: 'original_alarm', 24: 'original_cpu'})
        self.assertEqual(timers[-1][1:], (0, 0))

    def test_installer_preflight_and_embedded_python_are_reviewable_without_root(self):
        source = (HERE / 'setup_runner.sh').read_text(encoding='utf-8')
        snippets = re.findall(r"<<'PY'\r?\n(.*?)\r?\nPY", source, re.S)
        self.assertEqual(len(snippets), 2)
        for snippet in snippets:
            ast.parse(snippet)
        self.assertLess(source.index('if [ "$ACTION" = --check ]'), source.index('install -d'))
        self.assertIn('/usr/bin/python3 -Es -B -', source)
        self.assertIn('/usr/bin/python3 -Es -B -', (HERE / 'setup_readonly.sh').read_text(encoding='utf-8'))

    def test_different_installed_helper_version_blocks_before_upload(self):
        job, archive, manifest = self.release()
        metadata = json.loads(manifest.read_bytes())
        entry = next(item for item in metadata['files'] if item['path'] == 'scripts/lab/lab_jobs.py')
        entry['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'setup_required'):
            jobs.verify_helpers(metadata)


def main():
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(WorkflowTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
