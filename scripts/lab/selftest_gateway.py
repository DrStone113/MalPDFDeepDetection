"""Generated source-only gateway failures and bounded, mocked transport checks."""

from contextlib import redirect_stdout
from datetime import datetime, timedelta
import copy
import base64
import errno
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gateway_client as client
import gateway_contract as contract
import gateway_snapshot as snapshot
import gateway_transfer as transfer
import lab_gateway as gate
import lab_jobs as jobs
import lab_side as side
import lab_windows as windows
import setup_gateway as setup
from lab_contract import parse_json, validate_status


class GatewayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='malpdf-gateway-tests-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        for module, name, value in [(gate, 'ROOT', self.base), (client, 'STATE', self.base / 'client')]:
            handle = patch.object(module, name, value)
            handle.start()
            self.addCleanup(handle.stop)
        for name in ('uploads', 'worker', 'reports', 'queued', 'requests'):
            (self.base / name).mkdir()
        self.job = contract.make_job('a' * 40, 'b' * 64, 'c' * 64, 'syntax', 'd' * 64)
        self.capability = {'api': 1, 'installed': True, 'verified': True, 'profiles': ['syntax', 'synthetic'], 'policy_sha256': 'd' * 64, 'reason': None}

    def package(self, profile='syntax', *, bad=False):
        from selftest import write_archive
        archive = self.base / 'safe.tar'
        entries = write_archive(archive, [('src/inert.py', b'value=42\n' if not bad else b'value=\n')])
        metadata = {'schema_version': 1, 'commit': 'a' * 40, 'archive_sha256': contract.sha(archive.read_bytes()), 'files': entries}
        manifest = contract.encoded(metadata)
        job = contract.make_job('a' * 40, contract.sha(manifest), metadata['archive_sha256'], profile, 'd' * 64)
        pieces = [contract.encoded(job), manifest, archive.read_bytes()]
        return job, b''.join(len(value).to_bytes(4, 'big') + value for value in pieces)

    def receive(self, job, data):
        cfg = {'runner_uid': 12345, 'profiles': ['syntax', 'synthetic'], 'policy_sha256': 'd' * 64}
        with patch.object(gate, 'config', return_value=cfg), patch.object(gate, 'verified'), patch.object(gate, 'submission_lock'), patch.object(gate.os, 'getuid', return_value=12345, create=True), patch.object(jobs, 'preflight'):
            return gate.receive(io.BytesIO(data), job['profile'], job['job_id'])

    def test_fixed_commands_reject_shell_subsystem_pdf_and_unsafe_arguments(self):
        for value in ('', 'id', 'sftp', 'submit-pdf ' + 'a' * 64, 'submit-syntax ../escape', 'submit-syntax ' + 'a' * 64 + ';id', 'submit-syntax ' + 'a' * 64 + '\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.command(value)
        self.assertEqual(gate.command('submit-syntax ' + 'a' * 64), ('syntax', 'a' * 64))

    def test_job_binds_snapshot_profile_policy_and_resource_caps(self):
        for key, value in [('profile', 'pdf-static'), ('base_commit', 'b' * 40), ('limits', {**contract.LIMITS, 'tasks': 100}), ('policy_sha256', 'e' * 64), ('source_kind', 'git_commit_only')]:
            changed = copy.deepcopy(self.job)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.validate_job(changed)

    def test_closed_reports_reject_raw_strings_and_false_pass(self):
        value = contract.result(self.job, 'passed', syntax={'passed': 1, 'failed': 0})
        for update in ({'raw_log': 'canary'}, {'syntax': None}, {'syntax': {'passed': True, 'failed': 0}}, {'reason': 'arbitrary text'}):
            with self.assertRaises(ValueError):
                contract.validate_result({**value, **update}, self.job)

    def test_legacy_status_never_claims_gateway_ready(self):
        legacy = {'schema_version': 1, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate'}
        with patch.object(client.ctl, 'audit_request', return_value=(0, contract.encoded(legacy))), patch.object(client, 'exchange') as exchange:
            with self.assertRaisesRegex(ValueError, 'setup_required'):
                client.readiness()
        exchange.assert_not_called()

    def test_status_v3_stays_closed_and_backwards_compatible(self):
        runner = {'api': 1, 'installed': True, 'host_only_ready': True, 'offline_guest_ready': False, 'reason': None}
        value = {'schema_version': 3, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate', 'runner': runner, 'gateway': self.capability}
        validate_status(value)
        with self.assertRaises(ValueError):
            validate_status({**value, 'raw_log': 'canary'})

    def test_unapproved_harness_is_not_a_synthetic_capability(self):
        value = {**self.capability, 'verified': False}
        with self.assertRaises(ValueError):
            contract.validate_capability(value)

    def test_receiver_installs_source_without_running_any_source(self):
        job, data = self.package()
        with patch.object(gate, 'work') as work, patch.object(gate, 'synthetic') as synthetic:
            result = self.receive(job, data)
        self.assertEqual(result, gate.acknowledge(job))
        work.assert_not_called()
        synthetic.assert_not_called()
        self.assertEqual(gate.audit(job['job_id'])['status'], 'queued')

    def test_duplicate_submission_keeps_original_queued_timestamp(self):
        job, data = self.package()
        self.receive(job, data)
        original = (self.base / 'queued' / (job['job_id'] + '.json')).read_bytes()
        with patch.object(contract, 'result', side_effect=AssertionError('Do not regenerate queued timestamps')):
            self.receive(job, data)
        self.assertEqual((self.base / 'queued' / (job['job_id'] + '.json')).read_bytes(), original)

    def test_checksum_mismatch_has_no_accepted_job(self):
        job, data = self.package()
        with self.assertRaises(ValueError):
            self.receive(job, data[:-1] + b'X')
        self.assertFalse(list((self.base / 'requests').iterdir()))

    def test_runtime_permission_is_checked_before_any_upload(self):
        with patch.object(gate, 'config', return_value={}), patch.object(gate, 'verified', side_effect=ValueError('gateway_not_verified')):
            with self.assertRaises(ValueError):
                gate.receive(io.BytesIO(b''), 'syntax', self.job['job_id'])
        self.assertFalse(list((self.base / 'uploads').iterdir()))

    def test_busy_submission_lock_refuses_without_reading_payload(self):
        cfg = {'runner_uid': 12345, 'profiles': ['syntax'], 'policy_sha256': 'd' * 64}
        with patch.object(gate, 'config', return_value=cfg), patch.object(gate, 'verified'), patch.object(gate.os, 'getuid', return_value=12345, create=True), patch.object(gate, 'submission_lock', side_effect=ValueError('resource_unavailable')), patch.object(gate, 'receive_locked') as receive:
            with self.assertRaisesRegex(ValueError, 'resource_unavailable'):
                gate.receive(io.BytesIO(b''), 'syntax', self.job['job_id'])
        receive.assert_not_called()

    def test_pinned_synthetic_profile_cannot_be_enabled_by_submitted_source(self):
        job, data = self.package('synthetic')
        with patch.object(gate, 'config', return_value={'runner_uid': 123, 'profiles': ['syntax']}), patch.object(gate, 'verified'), patch.object(gate.os, 'getuid', return_value=123, create=True):
            with self.assertRaisesRegex(ValueError, 'profile_not_approved'):
                gate.receive(io.BytesIO(data), 'synthetic', job['job_id'])

    def worker(self):
        cfg = {'worker_uid': 123, 'profiles': ['syntax', 'synthetic'], 'policy_sha256': 'd' * 64}
        with patch.object(gate, 'config', return_value=cfg), patch.object(gate, 'verified'), patch.object(gate, 'containment'), patch.object(gate, 'paths', return_value=(self.base / 'uploads', self.base / 'worker', self.base / 'reports')):
            gate.work()

    def test_syntax_worker_only_parses_and_preserves_claims(self):
        job, data = self.package()
        self.receive(job, data)
        with patch.object(gate, 'synthetic') as synthetic:
            self.worker()
            self.worker()
        self.assertEqual(gate.audit(job['job_id'])['status'], 'passed')
        self.assertEqual(len(list((self.base / 'worker').iterdir())), 1)
        synthetic.assert_not_called()

    def test_upgrade_keeps_claimed_jobs_without_blocking_new_policy(self):
        job, data = self.package()
        self.receive(job, data)
        self.worker()
        previous = (self.base / 'reports' / (job['job_id'] + '.json')).read_bytes()
        with patch.object(gate, 'config', return_value={'worker_uid': 123, 'profiles': ['syntax'], 'policy_sha256': 'e' * 64}), patch.object(gate, 'verified'), patch.object(gate, 'containment'), patch.object(gate, 'paths', return_value=(self.base / 'uploads', self.base / 'worker', self.base / 'reports')), patch.object(gate.ast, 'parse') as parse:
            self.assertIsNone(gate.work())
        parse.assert_not_called()
        self.assertEqual((self.base / 'reports' / (job['job_id'] + '.json')).read_bytes(), previous)

    def test_unclaimed_old_policy_is_rejected_once_and_next_job_can_run(self):
        job, data = self.package()
        self.receive(job, data)
        cfg = {'worker_uid': 123, 'profiles': ['syntax'], 'policy_sha256': 'e' * 64}
        with patch.object(gate, 'config', return_value=cfg), patch.object(gate, 'verified'), patch.object(gate, 'containment'), patch.object(gate, 'paths', return_value=(self.base / 'uploads', self.base / 'worker', self.base / 'reports')), patch.object(gate.side, 'verify_release') as verify, patch.object(gate.ast, 'parse') as parse:
            result = gate.work()
            self.assertIsNone(gate.work())
        verify.assert_not_called()
        parse.assert_not_called()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['reason'], 'profile_not_approved')
        self.assertEqual(gate.audit(job['job_id'])['job'], job)
        current = contract.make_job(job['base_commit'], job['manifest_sha256'], job['archive_sha256'], 'syntax', cfg['policy_sha256'])
        jobs.immutable(self.base / 'requests' / (current['job_id'] + '.json'), current)
        jobs.immutable(self.base / 'queued' / (current['job_id'] + '.json'), contract.result(current, 'queued'))
        with patch.object(gate, 'config', return_value=cfg), patch.object(gate, 'verified'), patch.object(gate, 'containment'), patch.object(gate, 'paths', return_value=(self.base / 'uploads', self.base / 'worker', self.base / 'reports')):
            self.assertEqual(gate.work()['status'], 'passed')
        self.assertEqual(gate.audit(current['job_id'])['status'], 'passed')

    def test_direct_gateway_client_cli_emits_help(self):
        result = subprocess.run([sys.executable, '-B', str(HERE / 'gateway_client.py'), '--help'],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'doctor', result.stdout)
        self.assertIn(b'verify', result.stdout)

    def configuration(self):
        policy = {name: 'a' * 64 for name in gate.HELPERS}
        return {'api': 1, 'runner_uid': 12345, 'worker_uid': 12346, 'profiles': ['syntax'],
                'policy': policy, 'policy_sha256': contract.sha(contract.encoded(policy)),
                'units': {name: 'b' * 64 for name in gate.UNIT_NAMES}, 'sshd_sha256': 'c' * 64}

    def test_config_rejects_malformed_metadata_before_trusting_helper_hashes(self):
        for key, value in [('api', True), ('policy', []), ('units', []), ('units', {'../other': 'b' * 64}),
                           ('runner_uid', True), ('worker_uid', 12345), ('sshd_sha256', '../private'),
                           ('policy_sha256', None), ('profiles', ['synthetic'])]:
            cfg = {**self.configuration(), key: value}
            with self.subTest(key=key), patch.object(gate.sys, 'platform', 'linux'), patch.object(gate, 'root_json', return_value=cfg), patch.object(gate, 'policy_hashes') as hashes, self.assertRaises(ValueError):
                gate.config()
            hashes.assert_not_called()

    def test_policy_hash_binds_every_helper_and_configuration_digest(self):
        cfg = self.configuration()
        gate.verify_policy(cfg, cfg['policy'])
        for changed in [{**cfg['policy'], 'lab_gateway.py': 'd' * 64}, {**cfg['policy'], 'unexpected.py': 'a' * 64}]:
            with self.assertRaisesRegex(ValueError, 'gateway_not_verified'):
                gate.verify_policy(cfg, changed)
        with self.assertRaises(ValueError):
            gate.verify_policy({**cfg, 'policy_sha256': 'e' * 64}, cfg['policy'])

    def test_proof_requires_typed_flags_and_current_configuration(self):
        cfg = self.configuration()
        proof = {'api': 1, 'verified': True, 'policy_sha256': cfg['policy_sha256'], 'profiles': cfg['profiles'],
                 'units': cfg['units'], 'sshd_sha256': cfg['sshd_sha256']}
        with patch.object(gate, 'root_json', return_value=proof):
            gate.verified(cfg)
        for update in [{'api': True}, {'verified': 1}, {'policy_sha256': 'e' * 64}, {'profiles': ['syntax', 'synthetic']}, {'units': {}}, {'raw_log': 'private canary'}]:
            with patch.object(gate, 'root_json', return_value={**proof, **update}), self.assertRaises(ValueError):
                gate.verified(cfg)

    def test_syntax_error_returns_only_aggregate_counts(self):
        job, data = self.package(bad=True)
        self.receive(job, data)
        self.worker()
        value = gate.audit(job['job_id'])
        self.assertEqual(value['status'], 'failed')
        self.assertEqual(value['syntax'], {'passed': 0, 'failed': 1})
        self.assertNotIn('inert.py', json.dumps(value))

    def test_claimed_job_is_not_restarted_after_worker_interruption(self):
        job, data = self.package()
        self.receive(job, data)
        (self.base / 'worker' / (job['job_id'] + '.claim')).write_text('claimed')
        with patch.object(gate.ast, 'parse') as parse:
            self.worker()
        parse.assert_not_called()

    def test_worker_diagnostic_is_redacted(self):
        job, data = self.package('synthetic')
        self.receive(job, data)
        with patch.object(gate, 'synthetic', side_effect=ValueError('private canary')):
            self.worker()
        value = gate.audit(job['job_id'])
        self.assertEqual(value['reason'], 'worker_failed')
        self.assertNotIn('canary', json.dumps(value))

    def test_audit_job_id_cannot_name_other_paths(self):
        for value in ('../escape', 'a' * 64 + ';id', 'A' * 64):
            with self.assertRaises(ValueError):
                gate.audit(value)

    def test_test_command_never_falls_back_to_admin_ssh(self):
        with patch.object(client, 'readiness', side_effect=ValueError('setup_required')), patch.object(windows, 'exchange') as admin, patch.object(client, 'ensure_key') as key, redirect_stdout(io.StringIO()):
            self.assertEqual(windows.main(['test', '--mode', 'syntax']), 3)
        admin.assert_not_called()
        key.assert_not_called()

    def test_negative_remote_shell_or_forwarding_success_blocks_readiness(self):
        runner = {'api': 1, 'installed': True, 'host_only_ready': True, 'offline_guest_ready': False, 'reason': None}
        status = {'schema_version': 3, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate', 'runner': runner, 'gateway': self.capability}
        for replies in ([ (0, contract.encoded(self.capability)), (0, b'unsafe') ], [(0, contract.encoded(self.capability)), *[(2, b'')] * 5, (0, b'')]):
            with patch.object(client.ctl, 'audit_request', return_value=(0, contract.encoded(status))), patch.object(client, 'expected_policy', return_value='d' * 64), patch.object(client, 'exchange', side_effect=replies):
                with self.assertRaisesRegex(ValueError, 'gateway_not_verified'):
                    client.readiness()

    def test_connection_loss_preserves_job_and_does_not_retry(self):
        job, data = self.package()
        manifest = self.base / 'manifest.json'
        archive = self.base / 'safe.tar'
        metadata = {'archive_sha256': job['archive_sha256']}
        with gate.release(job):
            pass
        from lab_runner import read_frame
        stream = io.BytesIO(data)
        read_frame(stream, 16384)
        manifest.write_bytes(read_frame(stream, 512 * 1024))
        with patch.object(client, 'readiness', return_value=self.capability), patch.object(client.ctl, 'run'), patch.object(snapshot, 'prepare', return_value=(job['base_commit'], archive, manifest, metadata)), patch.object(client, 'exchange', side_effect=ValueError('ssh_unavailable')) as exchange:
            with self.assertRaises(ValueError):
                client.test('syntax')
        exchange.assert_called_once()
        self.assertEqual(client.read_job()['job_id'], job['job_id'])
        with patch.object(client, 'readiness', return_value=self.capability), patch.object(client.ctl, 'run'), patch.object(snapshot, 'prepare', return_value=(job['base_commit'], archive, manifest, metadata)), patch.object(client, 'fetch', return_value=contract.result(job, 'running')), patch.object(client, 'exchange') as exchange:
            client.test('syntax')
        exchange.assert_not_called()

    def test_cached_report_never_calls_ssh(self):
        client.remember(self.job)
        jobs.immutable(client.STATE / self.job['job_id'] / 'passed.json', contract.result(self.job, 'passed', syntax={'passed': 1, 'failed': 0}))
        with patch.object(client.ctl, 'audit_request') as audit, redirect_stdout(io.StringIO()):
            self.assertEqual(client.main(['report']), 0)
        audit.assert_not_called()

    def test_snapshot_preserves_git_and_refuses_pdf_content(self):
        (self.base / 'src').mkdir()
        path = self.base / 'src/safe.py'
        path.write_bytes(b'value=42\n')
        with patch.object(snapshot.ctl, 'REPO', self.base), patch.object(snapshot.ctl, 'run'), patch.object(snapshot.ctl, 'git', return_value=b'src/safe.py\0data/raw/not-read.pdf\0'):
            self.assertEqual(snapshot.source_contents(), [('src/safe.py', b'value=42\n')])
            path.write_bytes(b'%PDF-1.7\n')
            with self.assertRaises(ValueError):
                snapshot.source_contents()

    def test_installer_check_refuses_windows_before_mutation(self):
        with patch.object(setup.sys, 'platform', 'win32'), patch.object(setup, 'install') as install:
            with self.assertRaises(ValueError):
                setup.preflight()
        install.assert_not_called()

    def test_installer_sudo_policy_failure_stops_install_and_names_readonly_check(self):
        error = subprocess.CalledProcessError(1, ['/usr/sbin/visudo', '-c'], output=b'private policy canary', stderr=b'private path canary')
        for action in ('--check', '--install'):
            output = io.StringIO()
            with self.subTest(action=action), patch.object(setup, 'preflight', side_effect=error), patch.object(setup, 'install') as install, redirect_stdout(output):
                self.assertEqual(setup.main([action]), 2)
            install.assert_not_called()
            self.assertIn('[preflight/sudo_policy_invalid]', output.getvalue())
            self.assertIn('sudo /usr/sbin/visudo -c', output.getvalue())
            self.assertNotIn('canary', output.getvalue())

    def test_installer_diagnostics_classify_failures_without_returning_raw_data(self):
        for error, expected in [
            (ValueError('bootstrap_rejected'), 'bootstrap_rejected'),
            (ValueError('unsupported_python'), 'unsupported_python'),
            (ValueError('private canary'), 'validation_failed'),
            (FileNotFoundError(2, 'private canary', '/home/malpdf-audit/.ssh/authorized_keys'), 'audit_key_missing'),
            (FileNotFoundError(2, 'private canary', '/private/path'), 'required_file_missing'),
            (PermissionError('private canary'), 'permission_denied'),
            (subprocess.TimeoutExpired('private canary', 30), 'command_timeout'),
            (subprocess.CalledProcessError(1, ['private canary']), 'command_failed'),
        ]:
            with self.subTest(expected=expected):
                self.assertEqual(setup.failure_reason(error), expected)

    def test_installer_successful_check_never_installs_and_install_failure_names_stage(self):
        output = io.StringIO()
        with patch.object(setup, 'preflight', return_value=({}, 'inert')), patch.object(setup, 'install') as install, redirect_stdout(output):
            self.assertEqual(setup.main(['--check']), 0)
        install.assert_not_called()
        with patch.object(setup, 'preflight', return_value=({}, 'inert')), patch.object(setup, 'install', side_effect=ValueError('private canary')), redirect_stdout(output):
            self.assertEqual(setup.main(['--install']), 2)
        self.assertIn('[installation/validation_failed]', output.getvalue())
        self.assertNotIn('canary', output.getvalue())

    def test_installer_command_failures_identify_the_check_without_leaking_stderr(self):
        for command, expected in [
            (['/usr/sbin/sshd', '-t'], 'sshd_config_invalid'),
            (['/usr/sbin/sshd', '-T', '-C', 'private canary'], 'sshd_policy_mismatch'),
            (['/usr/bin/systemd-analyze', 'verify', 'private canary'], 'systemd_unit_invalid'),
            (['/usr/bin/systemctl', 'daemon-reload'], 'systemd_reload_failed'),
            (['/usr/bin/systemctl', 'start', 'malpdf-gateway-probe.service'], 'containment_probe_failed'),
            (['/usr/bin/systemctl', 'reload', 'ssh'], 'ssh_reload_failed'),
            (['/usr/bin/systemctl', 'enable', '--now', 'malpdf-gateway.timer'], 'timer_enable_failed'),
        ]:
            error = subprocess.CalledProcessError(1, command, stderr=b'private canary')
            output = io.StringIO()
            with self.subTest(expected=expected), patch.object(setup, 'preflight', return_value=({}, 'inert')), patch.object(setup, 'install', side_effect=error), redirect_stdout(output):
                self.assertEqual(setup.main(['--install']), 2)
            self.assertIn('[installation/' + expected + ']', output.getvalue())
            self.assertNotIn('canary', output.getvalue())

    def test_worker_units_separate_source_data_network_and_resource_limits(self):
        text = setup.service('worker')
        for required in ('User=malpdf-worker', 'RootDirectory=/var/lib/malpdf-gateway/runtime', 'PrivateNetwork=yes', 'ProtectSystem=strict', 'NoNewPrivileges=yes', 'MemoryMax=512M', 'TasksMax=32', 'LimitCPU=60', 'TimeoutStartSec=90', 'StandardOutput=null', 'SystemCallFilter=~@mount'):
            self.assertIn(required, text)
        self.assertNotIn('/home/remnux', text)
        self.assertIn('ForceCommand /usr/bin/python3 -Es -B', setup.sshd_text())
        self.assertIn('DisableForwarding yes', setup.sshd_text())

    def test_network_denial_returns_errno_to_the_probe_while_other_filters_remain_fatal(self):
        for action in ('probe', 'worker'):
            text = setup.service(action)
            rules = [line.partition('=')[2] for line in text.splitlines() if line.startswith('SystemCallFilter=')]
            self.assertEqual(len(rules), 1)
            self.assertTrue(rules[0].startswith('~'))
            self.assertEqual(set(rules[0][1:].split()), {
                '@mount', '@privileged', '@debug', '@raw-io', '@reboot', '@swap', '@network-io:EPERM'})
            self.assertFalse(any(line.startswith('SystemCallErrorNumber=') for line in text.splitlines()))
            self.assertIn('RestrictAddressFamilies=AF_UNIX', text)
            self.assertIn('PrivateNetwork=yes', text)

    def test_probe_records_expected_network_denial_and_rejects_unrelated_socket_errors(self):
        cfg = {'worker_uid': 12345, 'policy_sha256': 'd' * 64}
        for code in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT, errno.EIO, errno.EMFILE):
            with self.subTest(code=code), patch.object(gate, 'config', return_value=cfg), patch.object(gate.os, 'getuid', return_value=12345, create=True), patch.object(gate, 'host_paths_hidden'), patch.object(gate, 'rlimit_checks'), patch.object(gate, 'cgroup_limits'), patch.object(gate.socket, 'socket', side_effect=OSError(code, 'private canary')) as create_socket, patch.object(gate.os, 'open', side_effect=OSError(errno.EROFS, 'private canary')), patch.object(gate.diagnostics, 'write_latest') as write:
                passed = code in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT)
                self.assertEqual(gate.run_probe(), 0 if passed else 1)
            records = [call.args[1] for call in write.call_args_list]
            self.assertEqual(len(records), 2 if passed else 1)
            gate.diagnostics.validate_run(records[-1])
            self.assertEqual(records[-1]['status'], 'passed' if passed else 'failed')
            self.assertEqual(records[-1]['reason'], None if passed else 'containment_network_failed')
            if passed:
                self.assertEqual([call.args[0] for call in create_socket.call_args_list], [gate.socket.AF_INET, gate.socket.AF_INET6])
                self.assertTrue(records[0]['checks']['network_denied'])
            self.assertNotIn('canary', json.dumps(records))

    def test_failed_local_checks_block_snapshot_and_submission_without_requesting_reinstall(self):
        failure = subprocess.CalledProcessError(1, ['local-check'], output=b'private canary')
        with patch.object(client, 'readiness', return_value={'profiles': ['synthetic']}), patch.object(client.ctl, 'run', side_effect=failure), patch.object(client.snapshot, 'prepare') as prepare, patch.object(client, 'exchange') as exchange, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(client.main(['test', '--profile', 'synthetic']), 3)
        prepare.assert_not_called()
        exchange.assert_not_called()
        value = json.loads(output.getvalue())
        self.assertEqual(value['reason'], 'local_checks_failed')
        self.assertIn('check_local.py', value['action'])
        self.assertNotIn('one-time gateway setup', value['action'])
        self.assertNotIn('canary', output.getvalue())

    def test_operator_pinned_lexer_harness_passes_reviewed_synthetic_cases(self):
        source = self.base / 'candidate'
        for name in ('src/malpdf/extraction/raw_syntax.py', 'src/malpdf/static/execution.py'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((HERE.parents[1] / name).read_bytes())
        for name in ('src/malpdf/__init__.py', 'src/malpdf/static/__init__.py', 'src/malpdf/extraction/__init__.py', 'tests/test_trap.py'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"raise AssertionError('Candidate initializers and test files must not run')\n")
        result = subprocess.run([sys.executable, '-B', str(HERE / 'gateway_harness.py'), str(source)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=True)
        self.assertEqual(parse_json(result.stdout), {'passed': 6, 'failed': 0})

    def test_bootstrap_contains_only_pinned_helpers_and_separate_public_key(self):
        public = b'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32)))
        with patch.object(client, 'ensure_key', return_value=public), patch.object(client.ctl, 'OUT', self.base / 'packages'), patch.object(client.ctl, 'revision', return_value='a' * 40):
            result = client.setup()
        folder = Path(result['bootstrap'])
        metadata = parse_json((folder / 'manifest.json').read_bytes())
        self.assertEqual(result['files'], 14)
        self.assertEqual(result['manifest_id'], contract.sha(contract.encoded(metadata)))
        self.assertFalse(result['remote_changes'])
        self.assertNotIn('id_ed25519_malpdf_runner', {path.name for path in folder.iterdir()})
        for item in metadata['files']:
            self.assertEqual(contract.sha((folder / item['path']).read_bytes()), item['sha256'])

    def test_kernel_cgroup_limits_reject_unlimited_or_weakened_caps(self):
        values = {'memory.max': '536870912', 'memory.swap.max': '0', 'pids.max': '32', 'cpu.max': '50000 100000'}
        folder = self.base / 'limits'
        folder.mkdir()
        for name, value in values.items():
            (folder / name).write_text(value)
        gate.cgroup_limits(folder)
        for name, value in [('memory.max', 'max'), ('memory.swap.max', '1024'), ('pids.max', '33'), ('cpu.max', '100000 100000')]:
            (folder / name).write_text(value)
            with self.assertRaises(ValueError):
                gate.cgroup_limits(folder)
            (folder / name).write_text(values[name])

    def test_inaccessible_systemd_placeholders_count_as_hidden_without_reading(self):
        checked = []
        def denied(path, flags):
            checked.append(path)
            raise OSError(errno.EACCES if path == '/root' else errno.ENOENT, 'private canary')
        with patch.object(gate.os, 'open', side_effect=denied), patch.object(gate.os, 'read') as read, patch.object(gate.os, 'close') as close:
            gate.host_paths_hidden()
        self.assertIn('/root', checked)
        read.assert_not_called()
        close.assert_not_called()

    def test_every_readable_host_path_fails_even_when_empty_and_is_closed_without_read(self):
        paths = ('/home/remnux', '/root', '/etc/passwd', '/run/ssh-agent', '/mnt/hgfs')
        for exposed in paths:
            def opened(path, flags):
                if path == exposed:
                    return 17
                raise OSError(errno.ENOENT, 'private canary')
            with self.subTest(path=exposed), patch.object(gate.os, 'open', side_effect=opened), patch.object(gate.os, 'read') as read, patch.object(gate.os, 'close') as close, self.assertRaisesRegex(gate.ContainmentFailure, 'containment_paths_failed'):
                gate.host_paths_hidden()
            read.assert_not_called()
            close.assert_called_once_with(17)

    def test_host_path_unexpected_errors_and_symlinks_fail_closed(self):
        for code in (errno.EIO, errno.ELOOP, errno.ENFILE, errno.ENOTDIR):
            with self.subTest(code=code), patch.object(gate.os, 'open', side_effect=OSError(code, 'private canary')), self.assertRaisesRegex(gate.ContainmentFailure, 'containment_paths_failed') as error:
                gate.host_paths_hidden()
            self.assertNotIn('canary', str(error.exception))

    def rlimit_module(self):
        limits = {'as': (536870912, 536870912), 'cpu': (60, 60), 'files': (64, 64),
                  'tasks': (32, 32), 'bytes': (1048576, 1048576), 'core': (0, 0)}
        resource = SimpleNamespace(RLIMIT_AS='as', RLIMIT_CPU='cpu', RLIMIT_NOFILE='files',
            RLIMIT_NPROC='tasks', RLIMIT_FSIZE='bytes', RLIMIT_CORE='core', RLIM_INFINITY=-1,
            getrlimit=lambda name: limits[name])
        return resource, limits

    def test_rlimits_require_finite_soft_and_hard_limits_including_negative_infinity(self):
        resource, limits = self.rlimit_module()
        with patch.dict(sys.modules, {'resource': resource}):
            gate.rlimit_checks()
            for name in limits:
                original = limits[name]
                for candidate in ((-1, -1), (original[0], -1), (-1, original[1])):
                    limits[name] = candidate
                    with self.subTest(name=name, candidate=candidate), self.assertRaisesRegex(gate.ContainmentFailure, 'containment_rlimits_failed'):
                        gate.rlimit_checks()
                limits[name] = original

    def test_rlimits_reject_raised_hard_caps_unbounded_output_and_core_dumps(self):
        resource, limits = self.rlimit_module()
        with patch.dict(sys.modules, {'resource': resource}):
            for name in limits:
                original = limits[name]
                for candidate in ((original[0], original[1] + 1), (True, original[1])):
                    limits[name] = candidate
                    with self.subTest(name=name, candidate=candidate), self.assertRaises(gate.ContainmentFailure):
                        gate.rlimit_checks()
                limits[name] = original

    def test_cgroup_failures_are_specific_bounded_and_never_accept_zero_or_unlimited(self):
        values = {'memory.max': '536870912', 'memory.swap.max': '0', 'pids.max': '32', 'cpu.max': '50000 100000'}
        folder = self.base / 'cgroup'
        folder.mkdir()
        for name, value in values.items():
            (folder / name).write_text(value)
        cases = [('memory.max', '0', 'memory'), ('memory.max', 'max', 'memory'),
                 ('memory.swap.max', '1', 'swap'), ('pids.max', 'max', 'tasks'),
                 ('pids.max', '0', 'tasks'), ('cpu.max', 'max 100000', 'cpu'), ('cpu.max', '0 100000', 'cpu')]
        for name, value, part in cases:
            (folder / name).write_text(value)
            with self.subTest(name=name, value=value), self.assertRaisesRegex(gate.ContainmentFailure, 'containment_cgroup_' + part + '_failed'):
                gate.cgroup_limits(folder)
            (folder / name).write_text(values[name])
        for payload in (b'x' * 129, b'\xff'):
            (folder / 'memory.max').write_bytes(payload)
            with self.assertRaisesRegex(gate.ContainmentFailure, 'containment_cgroup_unavailable'):
                gate.cgroup_limits(folder)

    def test_full_containment_still_requires_socket_denial_and_readonly_source(self):
        def denied_socket(*args):
            raise OSError(errno.EPERM, 'private canary')
        with patch.object(gate.os, 'getuid', return_value=12345, create=True), patch.object(gate, 'host_paths_hidden'), patch.object(gate, 'rlimit_checks'), patch.object(gate, 'cgroup_limits'), patch.object(gate.socket, 'socket', side_effect=denied_socket), patch.object(gate.os, 'open', side_effect=OSError(errno.EROFS, 'private canary')):
            result = gate.containment({'worker_uid': 12345, 'policy_sha256': 'd' * 64})
        self.assertTrue(all(result['checks'].values()))
        for code in (errno.ENOENT, errno.EIO):
            with patch.object(gate.os, 'getuid', return_value=12345, create=True), patch.object(gate, 'host_paths_hidden'), patch.object(gate, 'rlimit_checks'), patch.object(gate, 'cgroup_limits'), patch.object(gate.socket, 'socket', side_effect=denied_socket), patch.object(gate.os, 'open', side_effect=OSError(code, 'private canary')), self.assertRaisesRegex(gate.ContainmentFailure, 'containment_source_failed'):
                gate.containment({'worker_uid': 12345, 'policy_sha256': 'd' * 64})

    def test_root_worker_and_open_network_fail_before_any_job(self):
        for uid in (0, 12346):
            with patch.object(gate.os, 'getuid', return_value=uid, create=True), patch.object(gate, 'host_paths_hidden') as paths, self.assertRaisesRegex(gate.ContainmentFailure, 'containment_uid_failed'):
                gate.containment({'worker_uid': 12345})
            paths.assert_not_called()
        from unittest.mock import MagicMock
        opened = MagicMock()
        with patch.object(gate.os, 'getuid', return_value=12345, create=True), patch.object(gate, 'host_paths_hidden'), patch.object(gate, 'rlimit_checks'), patch.object(gate, 'cgroup_limits'), patch.object(gate.socket, 'socket', return_value=opened), patch.object(gate.os, 'open') as source, self.assertRaisesRegex(gate.ContainmentFailure, 'containment_network_failed'):
            gate.containment({'worker_uid': 12345})
        opened.close.assert_called_once()
        source.assert_not_called()

    def transfer_bootstrap(self):
        for module, name, value in [(client.ctl, 'OUT', self.base / 'packages'), (client.ctl, 'SSH', str(self.base / 'ssh.exe')),
                                    (transfer.sys, 'platform', 'win32')]:
            handle = patch.object(module, name, value)
            handle.start()
            self.addCleanup(handle.stop)
        for name in ('ssh.exe', 'scp.exe'):
            (self.base / name).write_bytes(b'inert test placeholder')
        public = b'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32)))
        with patch.object(client, 'ensure_key', return_value=public), patch.object(client.ctl, 'revision', return_value='a' * 40):
            return client.setup()

    def test_installer_copy_refuses_noninteractive_before_preparation_or_ssh(self):
        with patch.object(transfer.sys, 'platform', 'win32'), patch.object(transfer.sys.stdin, 'isatty', return_value=False), patch.object(client, 'setup') as prepare, patch.object(transfer.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'operator_terminal_required'):
                transfer.transfer()
        prepare.assert_not_called()
        run.assert_not_called()

    def test_installer_copy_rejects_modified_or_extra_files(self):
        value = self.transfer_bootstrap()
        folder = Path(value['bootstrap'])
        self.assertEqual(len(transfer.verified_files(value)), 14)
        target = folder / 'setup_gateway.sh'
        original = target.read_bytes()
        target.write_bytes(original + b'changed\n')
        with self.assertRaises(ValueError):
            transfer.verified_files(value)
        target.write_bytes(original)
        (folder / 'unexpected.txt').write_bytes(b'inert')
        with self.assertRaises(ValueError):
            transfer.verified_files(value)

    def test_installer_copy_rejects_manifest_and_destination_injection(self):
        value = self.transfer_bootstrap()
        for identity in ('../escape', 'a' * 64 + ';id', 'a' * 64 + '\n'):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                transfer.create_directory(identity)
            with self.assertRaises(ValueError):
                transfer.verified_files({**value, 'manifest_id': identity})
        manifest = Path(value['bootstrap']) / 'manifest.json'
        metadata = parse_json(manifest.read_bytes())
        metadata['files'][0]['path'] = '../outside'
        manifest.write_bytes(contract.encoded(metadata))
        with self.assertRaises(ValueError):
            transfer.verified_files(value)

    def test_installer_copy_requires_human_confirmation(self):
        value = self.transfer_bootstrap()
        with patch.object(transfer.sys.stdin, 'isatty', return_value=True), patch.object(transfer.sys.stdout, 'isatty', return_value=True), patch.object(client, 'setup', return_value=value), patch('builtins.input', return_value='n'), patch.object(transfer.subprocess, 'run') as run, patch('builtins.print'):
            with self.assertRaisesRegex(ValueError, 'copy_cancelled'):
                transfer.transfer()
        run.assert_not_called()

    def test_installer_copy_rechecks_files_after_confirmation(self):
        value = self.transfer_bootstrap()
        def approve(prompt):
            (Path(value['bootstrap']) / 'setup_gateway.sh').write_bytes(b'changed\n')
            return 'y'
        with patch.object(transfer.sys.stdin, 'isatty', return_value=True), patch.object(transfer.sys.stdout, 'isatty', return_value=True), patch.object(client, 'setup', return_value=value), patch('builtins.input', side_effect=approve), patch.object(transfer.subprocess, 'run') as run, patch('builtins.print'):
            with self.assertRaises(ValueError):
                transfer.transfer()
        run.assert_not_called()

    def test_installer_copy_stops_on_existing_target_or_connection_failure(self):
        value = self.transfer_bootstrap()
        with patch.object(transfer.sys.stdin, 'isatty', return_value=True), patch.object(transfer.sys.stdout, 'isatty', return_value=True), patch.object(client, 'setup', return_value=value), patch('builtins.input', return_value='y'), patch.object(transfer.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'ssh')) as run, patch('builtins.print'):
            with self.assertRaises(transfer.CopyFailure) as error:
                transfer.transfer()
        self.assertEqual(error.exception.phase, 'directory_preparation')
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0][-1]
        self.assertIn('mkdir -m 700 ' + transfer.REMOTE_PARENT + '/' + value['manifest_id'], command)
        self.assertNotIn('mkdir -p', command)

    def test_installer_copy_uses_fixed_host_native_auth_and_only_verified_files(self):
        value = self.transfer_bootstrap()
        with patch.object(transfer.sys.stdin, 'isatty', return_value=True), patch.object(transfer.sys.stdout, 'isatty', return_value=True), patch.object(client, 'setup', return_value=value), patch('builtins.input', return_value='y'), patch.object(transfer.subprocess, 'run') as run, patch('builtins.print'):
            self.assertEqual(transfer.transfer(), 0)
        self.assertEqual(run.call_count, 2)
        ssh, scp = run.call_args_list
        self.assertEqual(ssh.args[0][-2], client.ctl.ADMIN)
        self.assertNotIn('sudo', ssh.args[0][-1])
        self.assertNotIn('--install', ssh.args[0][-1])
        expected_files = list(map(str, transfer.verified_files(value)))
        self.assertEqual(scp.args[0][1 + len(client.ctl.SCP_SECURITY):-1], expected_files)
        self.assertEqual(scp.args[0][-1], client.ctl.ADMIN + ':' + transfer.REMOTE_PARENT + '/' + value['manifest_id'] + '/')
        for call in (ssh, scp):
            self.assertIn('StrictHostKeyChecking=yes', call.args[0])
            self.assertIn('PreferredAuthentications=password', call.args[0])
            self.assertNotIn('shell', call.kwargs)
            self.assertNotIn('input', call.kwargs)
            self.assertEqual(call.kwargs['env']['SSH_ASKPASS_REQUIRE'], 'never')
            self.assertEqual(call.kwargs['timeout'], 180)

    def test_installer_copy_does_not_retry_or_delete_after_partial_scp(self):
        value = self.transfer_bootstrap()
        with patch.object(transfer.sys.stdin, 'isatty', return_value=True), patch.object(transfer.sys.stdout, 'isatty', return_value=True), patch.object(client, 'setup', return_value=value), patch('builtins.input', return_value='y'), patch.object(transfer.subprocess, 'run', side_effect=[subprocess.CompletedProcess('ssh', 0), subprocess.CalledProcessError(1, 'scp')]) as run, patch('builtins.print'):
            self.assertEqual(transfer.main(), 2)
        self.assertEqual(run.call_count, 2)

    def test_authentication_denial_reports_directory_stage_without_copy_or_raw_errors(self):
        value = self.transfer_bootstrap()
        output = io.StringIO()
        with redirect_stdout(output), patch.object(transfer.sys.stdin, 'isatty', return_value=True), patch.object(transfer.sys.stdout, 'isatty', return_value=True), patch.object(client, 'setup', return_value=value), patch('builtins.input', return_value='y'), patch.object(transfer.subprocess, 'run', side_effect=subprocess.CalledProcessError(255, 'ssh', stderr=b'private canary')) as run:
            self.assertEqual(transfer.main(), 2)
        self.assertEqual(run.call_count, 1)
        self.assertIn('[directory_preparation/command_failed] (exit 255)', output.getvalue())
        self.assertIn('Source file copy was not attempted', output.getvalue())
        self.assertNotIn('canary', output.getvalue())
        self.assertNotIn('Use a separate operator PowerShell terminal', output.getvalue())

    def test_transfer_failures_preserve_stage_without_automatic_retry(self):
        for phase in ('directory_preparation', 'file_copy'):
            for error, reason in [(subprocess.TimeoutExpired('private canary', 180), 'command_timeout'),
                                  (OSError('private canary'), 'client_unavailable')]:
                with self.subTest(phase=phase, reason=reason), patch.object(transfer.subprocess, 'run', side_effect=error) as run, self.assertRaises(transfer.CopyFailure) as caught:
                    transfer.operator_command(['reviewed-client'], {}, phase)
                self.assertEqual(caught.exception.phase, phase)
                self.assertEqual(str(caught.exception), reason)
                self.assertEqual(run.call_count, 1)

    def test_scp_failure_is_distinct_from_directory_creation_failure(self):
        output = io.StringIO()
        with patch.object(transfer, 'transfer', side_effect=transfer.CopyFailure('file_copy', 'command_failed', 255)), redirect_stdout(output):
            self.assertEqual(transfer.main(), 2)
        self.assertIn('[file_copy/command_failed] (exit 255)', output.getvalue())
        self.assertNotIn('Source file copy was not attempted', output.getvalue())


if __name__ == '__main__':
    unittest.main()
