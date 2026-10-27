"""Generated metadata and mocked transport checks for the read-only doctor."""

from contextlib import contextmanager, redirect_stdout
import base64
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import gateway_client as client
import gateway_contract as contract
import lab_diagnostics as diagnostic
import lab_gateway as gateway
import lab_readonly as readonly
import lab_windows as windows
import lab_vmware as vmware
import setup_gateway as setup


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='malpdf-doctor-tests-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        handle = patch.object(client, 'STATE', self.base / 'client')
        handle.start()
        self.addCleanup(handle.stop)
        handle = patch.object(client, 'host_metadata', return_value=None)
        handle.start()
        self.addCleanup(handle.stop)
        handle = patch.object(client, 'expected_policy', return_value='d' * 64)
        handle.start()
        self.addCleanup(handle.stop)

    def report(self):
        units = {name: {**diagnostic.unit_unknown(), 'load': 'loaded', 'active': 'inactive',
                       'sub': 'dead', 'unit_file': 'static', 'result': 'success',
                       'exit_code': 1, 'exit_status': 0, 'started': False, 'finished': False}
                 for name in diagnostic.UNITS}
        units[diagnostic.UNITS[2]].update(active='active', sub='waiting', unit_file='enabled')
        return {'api': 1, 'generated_utc': diagnostic.stamp(),
                'gateway': {'api': 1, 'installed': True, 'verified': True, 'profiles': ['syntax', 'synthetic'],
                            'policy_sha256': 'd' * 64, 'reason': None},
                'systemd': 'ok', 'units': units, 'installation': None, 'probe': None,
                'worker': None, 'last_job': None, 'record_errors': []}

    def configuration_report(self):
        return {**self.report(), 'api': 2, 'configuration_checks': {name: 'passed' for name in diagnostic.CONFIG_CHECKS}}

    def test_configuration_diagnostics_distinguish_missing_permissions_hashes_and_proof(self):
        for target, name, error, state in [('load_config', 'configuration', FileNotFoundError('private canary'), 'missing'),
                ('policy_hashes', 'helpers', gateway.UnsafeInstallation(), 'unsafe'),
                ('verify_policy', 'policy', ValueError('gateway_not_verified'), 'mismatch'),
                ('verify_units', 'units', PermissionError('private canary'), 'unreadable'),
                ('verify_sshd', 'sshd', ValueError('private canary'), 'invalid'),
                ('verified', 'proof', FileNotFoundError('private canary'), 'missing')]:
            with self.subTest(target=target), patch.multiple(gateway, load_config=MagicMock(return_value={}),
                    policy_hashes=MagicMock(return_value={}), verify_policy=MagicMock(), verify_units=MagicMock(),
                    verify_sshd=MagicMock(), verified=MagicMock()):
                getattr(gateway, target).side_effect = error
                result = gateway.configuration_checks()
            self.assertEqual(result[name], state)
            self.assertNotIn('canary', json.dumps(result))
            if name == 'configuration':
                self.assertEqual(result['policy'], 'not_checked')
                self.assertEqual(result['proof'], 'not_checked')

    def test_configuration_schema_is_closed_and_partial_checks_cannot_claim_readiness(self):
        value = self.configuration_report()
        self.assertEqual(diagnostic.classify(value), ('ready', 'waiting_for_timer'))
        for name in diagnostic.CONFIG_CHECKS:
            for state in diagnostic.CHECK_STATES - {'passed'}:
                changed = copy.deepcopy(value)
                changed['configuration_checks'][name] = state
                self.assertEqual(diagnostic.classify(changed), ('not_ready', name + '_' + state))
        for update in [{'unexpected': 'passed'}, {'policy': True}, {'policy': 'private canary'}]:
            changed = copy.deepcopy(value)
            changed['configuration_checks'].update(update)
            with self.assertRaises(ValueError):
                diagnostic.validate_report(changed)

    def test_root_metadata_rejects_writable_foreign_linked_or_nonregular_files_before_read(self):
        for metadata in [SimpleNamespace(st_uid=1001, st_mode=gateway.stat.S_IFREG | 0o644, st_nlink=1),
                         SimpleNamespace(st_uid=0, st_mode=gateway.stat.S_IFREG | 0o664, st_nlink=1),
                         SimpleNamespace(st_uid=0, st_mode=gateway.stat.S_IFREG | 0o644, st_nlink=2),
                         SimpleNamespace(st_uid=0, st_mode=gateway.stat.S_IFDIR | 0o755, st_nlink=1)]:
            with patch.object(gateway.jobs, 'trusted_path'), patch.object(Path, 'stat', return_value=metadata), patch.object(gateway.side, 'bounded_read') as read, self.assertRaises(gateway.UnsafeInstallation):
                gateway.root_json(self.base / 'inert.json')
            read.assert_not_called()
        with patch.object(gateway.jobs, 'trusted_path', side_effect=ValueError('private canary')), self.assertRaises(gateway.UnsafeInstallation) as error:
            gateway.root_file(self.base / 'inert.json')
        self.assertNotIn('canary', str(error.exception))

    def test_doctor_legacy_status_is_read_only_evidence_without_invented_configuration(self):
        status = {'schema_version': 3, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate',
                  'runner': {'api': 1, 'installed': False, 'host_only_ready': True, 'offline_guest_ready': False, 'reason': None},
                  'gateway': {**self.report()['gateway'], 'installed': False, 'verified': False, 'profiles': [], 'policy_sha256': None, 'reason': 'gateway_not_verified'}}
        with patch.object(client.ctl, 'audit_request', side_effect=[(2, b''), (0, contract.encoded(status))]) as audit, patch.object(client, 'exchange') as runner:
            value = client.doctor()
        self.assertEqual([call.args[0] for call in audit.call_args_list], ['diagnose gateway', 'status'])
        runner.assert_not_called()
        self.assertEqual(value['reason'], 'diagnostics_upgrade_required')
        self.assertEqual(value['audit_status'], status)
        self.assertIsNone(value['diagnostics'])

    def test_doctor_rejects_mismatched_or_unavailable_local_policy(self):
        for error, reason in [(None, 'local_policy_mismatch'), (OSError('private canary'), 'local_policy_unavailable')]:
            with patch.object(client.ctl, 'audit_request', return_value=(0, contract.encoded(self.configuration_report()))), patch.object(client, 'expected_policy', return_value='e' * 64, side_effect=error):
                value = client.doctor()
            self.assertEqual(value['status'], 'not_ready')
            self.assertEqual(value['reason'], reason)
            self.assertNotIn('canary', json.dumps(value))

    def job_result(self, status='passed'):
        job = contract.make_job('a' * 40, 'b' * 64, 'c' * 64, 'syntax', 'd' * 64)
        return contract.result(job, status, syntax={'passed': 1, 'failed': 0} if status == 'passed' else None)

    def raw_units(self):
        return '\n\n'.join('\n'.join([
            'Id=' + name, 'LoadState=loaded', 'ActiveState=inactive', 'SubState=dead',
            'UnitFileState=static', 'Result=success', 'ExecMainCode=1', 'ExecMainStatus=0',
            'ExecMainStartTimestampMonotonic=0', 'ExecMainExitTimestampMonotonic=0',
            'LastTriggerUSecMonotonic=0']) for name in diagnostic.UNITS).encode()

    def test_closed_schema_rejects_raw_logs_extra_fields_booleans_and_wrong_units(self):
        value = self.report()
        diagnostic.validate_report(value)
        for mutate in [lambda v: v.update(raw_log='private canary'),
                       lambda v: v['units'][diagnostic.UNITS[0]].update(exit_status=True),
                       lambda v: v['units'].update({'arbitrary.service': diagnostic.unit_unknown()}),
                       lambda v: v['units'][diagnostic.UNITS[0]].update(sub='private canary'),
                       lambda v: v.update(record_errors=['private canary']),
                       lambda v: v.update(api=True)]:
            candidate = copy.deepcopy(value)
            mutate(candidate)
            with self.assertRaises(ValueError):
                diagnostic.validate_report(candidate)

    def test_property_parser_normalizes_untrusted_strings_and_rejects_duplicate_or_extra_fields(self):
        raw = self.raw_units()
        value = diagnostic.parse_units(raw.replace(b'ActiveState=inactive', b'ActiveState=private canary', 1))
        self.assertEqual(value[diagnostic.UNITS[0]]['active'], 'unknown')
        self.assertNotIn('canary', json.dumps(value))
        for changed in (raw + b'\nDescription=private canary', raw.replace(b'Result=success', b'Result=success\nResult=success', 1),
                        raw.replace(b'ExecMainStatus=0', b'ExecMainStatus=999', 1), raw.replace(b'Id=malpdf-gateway.service', b'Id=arbitrary.service')):
            with self.assertRaises(ValueError):
                diagnostic.parse_units(changed)

    def test_collector_invokes_only_fixed_show_and_caps_output(self):
        for raw, expected in [(self.raw_units(), 'ok'), (b'x' * (diagnostic.MAX_REPORT + 1), 'oversize')]:
            process = MagicMock()
            process.__enter__.return_value = process
            process.stdout = io.BytesIO(raw)
            process.wait.return_value = 0
            with patch.object(diagnostic.subprocess, 'Popen', return_value=process) as popen:
                state, output = diagnostic.query_systemd()
            self.assertEqual(state, expected)
            self.assertLessEqual(len(output), diagnostic.MAX_REPORT)
            command = popen.call_args.args[0]
            self.assertEqual(command[0], '/usr/bin/systemctl')
            self.assertEqual(command[-3:], list(diagnostic.UNITS))
            self.assertIn('show', command)
            self.assertNotIn('sudo', command)
            self.assertNotIn('start', command)
            self.assertNotIn('shell', popen.call_args.kwargs)
            if expected == 'oversize':
                process.kill.assert_called_once()

    def test_timer_trigger_accepts_bounded_systemd_timespans_and_exports_only_a_boolean(self):
        for text, expected in [('0', False), ('0s', False), ('1us', True), ('1ms', True),
                ('15.123ms', True), ('1.234567s', True), ('2h 17min 4.123456s', True),
                ('1y 1month 1w 1d 1h 1min 1s', True), ('18446744073709551615', True)]:
            blocks = self.raw_units().split(b'\n\n')
            blocks[-1] = blocks[-1].replace(b'LastTriggerUSecMonotonic=0', b'LastTriggerUSecMonotonic=' + text.encode())
            with self.subTest(text=text):
                units = diagnostic.parse_units(b'\n\n'.join(blocks))
                self.assertIs(units[diagnostic.UNITS[2]]['timer_triggered'], expected)
                diagnostic.validate_report({**self.report(), 'units': units})
                self.assertNotIn(json.dumps(text), json.dumps(units))

    def test_timer_trigger_rejects_unknown_units_injection_unlimited_overflow_and_fractional_microseconds(self):
        for text in ('infinity', '-1s', '1s;id', 'private canary', '1.5h', '1.1us', '1.000001ms',
                '1s 1min', '1s 1s', '1s  1ms', '1.1234567s', '18446744073709551616',
                '18446744073709551615s', '1' * 129 + 's'):
            raw = self.raw_units().replace(b'LastTriggerUSecMonotonic=0', b'LastTriggerUSecMonotonic=' + text.encode())
            with self.subTest(text=text), self.assertRaises(ValueError):
                diagnostic.parse_units(raw)
        raw = self.raw_units().replace(b'ExecMainStartTimestampMonotonic=0', b'ExecMainStartTimestampMonotonic=1s')
        with self.assertRaises(ValueError):
            diagnostic.parse_units(raw)

    def test_triggered_timer_remains_readable_after_successful_installation(self):
        blocks = self.raw_units().split(b'\n\n')
        blocks[-1] = blocks[-1].replace(b'ActiveState=inactive', b'ActiveState=active').replace(b'SubState=dead', b'SubState=waiting').replace(b'UnitFileState=static', b'UnitFileState=enabled').replace(b'LastTriggerUSecMonotonic=0', b'LastTriggerUSecMonotonic=2h 17min 4.123456s')
        value = self.configuration_report()
        with patch.object(gateway, 'capability', return_value=value['gateway']), patch.object(gateway, 'configuration_checks', return_value=value['configuration_checks']), patch.object(diagnostic, 'query_systemd', return_value=('ok', b'\n\n'.join(blocks))), patch.object(diagnostic, 'read_record', side_effect=FileNotFoundError):
            report = diagnostic.collect()
        self.assertEqual(report['systemd'], 'ok')
        self.assertIs(report['units'][diagnostic.UNITS[2]]['timer_triggered'], True)
        self.assertEqual(diagnostic.classify(report), ('ready', 'waiting_for_timer'))

    def test_collector_timeout_stops_only_its_query_process(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.stdout = io.BytesIO(b'')
        process.wait.side_effect = [subprocess.TimeoutExpired('systemctl', 4), 0]
        with patch.object(diagnostic.subprocess, 'Popen', return_value=process):
            self.assertEqual(diagnostic.query_systemd(), ('timeout', b''))
        process.kill.assert_called_once()

    def test_collect_discards_private_error_text_and_never_walks_corpus(self):
        value = self.report()
        with patch.object(gateway, 'capability', return_value=value['gateway']), patch.object(diagnostic, 'query_systemd', return_value=('ok', b'Description=private canary')), patch.object(diagnostic, 'read_record', side_effect=FileNotFoundError) as read:
            result = diagnostic.collect()
        self.assertEqual(result['systemd'], 'invalid')
        self.assertNotIn('canary', json.dumps(result))
        self.assertEqual(len(read.call_args_list), 5)
        self.assertTrue(all('data/raw' not in str(call.args[0]) for call in read.call_args_list))

    def test_oneshot_dead_is_not_failure_or_proof_of_tests_passed(self):
        value = self.report()
        self.assertEqual(diagnostic.classify(value), ('ready', 'waiting_for_timer'))
        value['units'][diagnostic.UNITS[0]].update(started=True, finished=True)
        self.assertEqual(diagnostic.classify(value), ('ready', 'ready_idle'))
        value['last_job'] = self.job_result()
        self.assertEqual(diagnostic.classify(value), ('ready', 'last_job_passed'))

    def test_classifies_service_failure_timer_off_and_incomplete_installation(self):
        value = self.report()
        value['units'][diagnostic.UNITS[0]].update(active='failed', result='exit-code', exit_status=226, started=True)
        self.assertEqual(diagnostic.classify(value), ('failed', 'service_failed'))
        value = self.report()
        value['units'][diagnostic.UNITS[2]].update(active='inactive', sub='dead')
        self.assertEqual(diagnostic.classify(value), ('not_ready', 'timer_inactive'))
        value = self.report()
        value['installation'] = {'api': 1, 'status': 'failed', 'phase': 'unit_validation', 'reason': 'systemd_unit_invalid',
                                 'policy_sha256': 'd' * 64, 'generated_utc': diagnostic.stamp()}
        self.assertEqual(diagnostic.classify(value), ('not_ready', 'systemd_unit_invalid'))

    def test_failed_native_probe_is_not_hidden_by_deliberately_cleared_proof(self):
        value = self.configuration_report()
        value['configuration_checks']['proof'] = 'mismatch'
        value['gateway'].update(verified=False, profiles=[], reason='gateway_not_verified')
        value['installation'] = {'api': 1, 'status': 'failed', 'phase': 'containment',
            'reason': 'containment_probe_failed', 'policy_sha256': 'd' * 64, 'generated_utc': diagnostic.stamp()}
        self.assertEqual(diagnostic.classify(value), ('not_ready', 'containment_probe_failed'))
        value['probe'] = {'api': 1, 'status': 'failed', 'phase': 'containment',
            'reason': 'containment_cgroup_cpu_failed', 'policy_sha256': 'd' * 64,
            'job_id': None, 'generated_utc': diagnostic.stamp()}
        self.assertEqual(diagnostic.classify(value), ('not_ready', 'containment_cgroup_cpu_failed'))
        value['probe']['policy_sha256'] = 'e' * 64
        self.assertEqual(diagnostic.classify(value), ('not_ready', 'containment_probe_failed'))

    def test_probe_and_worker_return_only_fixed_containment_reasons(self):
        for reason in diagnostic.CONTAINMENT_REASONS:
            with self.subTest(reason=reason), patch.object(gateway, 'config', return_value={'policy_sha256': 'd' * 64}), patch.object(gateway, 'containment', side_effect=gateway.ContainmentFailure(reason)), patch.object(diagnostic, 'write_latest') as write:
                self.assertEqual(gateway.run_probe(), 1)
            record = write.call_args.args[1]
            diagnostic.validate_run(record)
            self.assertEqual(record['reason'], reason)
            self.assertEqual(record['phase'], 'containment')
            with patch.object(gateway, 'work', side_effect=gateway.ContainmentFailure(reason)), patch.object(diagnostic, 'write_latest') as write:
                self.assertEqual(gateway.run_worker(), 1)
            record = write.call_args.args[1]
            diagnostic.validate_run(record)
            self.assertEqual(record['reason'], reason)
            self.assertEqual(record['phase'], 'containment')
        self.assertEqual(str(gateway.ContainmentFailure('private canary')), 'containment_failed')

    def test_failed_or_pending_job_is_never_reported_as_a_pass(self):
        for status, expected in [('queued', ('pending', 'job_pending')), ('running', ('pending', 'job_pending')),
                                 ('failed', ('failed', 'job_failed')), ('interrupted', ('failed', 'job_failed'))]:
            value = self.report()
            value['last_job'] = self.job_result(status)
            self.assertEqual(diagnostic.classify(value), expected)

    def test_exact_audit_command_only_and_filtered_response(self):
        value = self.report()
        for command in ('diagnose gateway;', 'diagnose gateway extra', 'diagnose other', 'diagnose gateway\n', 'systemctl status ssh', 'diagnose gateway ../escape'):
            with patch.dict(readonly.os.environ, {'SSH_ORIGINAL_COMMAND': command}), patch.object(diagnostic, 'collect') as collect:
                self.assertEqual(readonly.main(), 2)
            collect.assert_not_called()
        output = io.StringIO()
        with patch.dict(readonly.os.environ, {'SSH_ORIGINAL_COMMAND': 'diagnose gateway'}), patch.object(diagnostic, 'collect', return_value=value), redirect_stdout(output):
            self.assertEqual(readonly.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), value)

    def test_doctor_uses_audit_only_saves_receipt_and_never_requests_credentials(self):
        with patch.object(client.ctl, 'audit_request', return_value=(0, contract.encoded(self.report()))) as audit, patch.object(client, 'exchange') as runner, patch.object(windows, 'exchange') as admin, patch.object(client, 'ensure_key') as key:
            value = client.doctor()
        self.assertEqual(value['status'], 'ready')
        audit.assert_called_once_with('diagnose gateway')
        runner.assert_not_called()
        admin.assert_not_called()
        key.assert_not_called()
        self.assertTrue(value['cache_saved'])
        self.assertEqual(len(list((client.STATE / 'doctor').glob('*.json'))), 1)

    def test_legacy_offline_and_invalid_diagnostics_have_no_fallback(self):
        for reply, reason in [((2, b''), 'diagnostics_upgrade_required'), ((255, b''), 'lab_unreachable'),
                              ((3, b''), 'diagnostics_unavailable'), ((0, b'{"private canary":1}'), 'diagnostics_invalid')]:
            with patch.object(client.ctl, 'audit_request', return_value=reply), patch.object(client, 'exchange') as runner, patch.object(windows, 'exchange') as admin:
                value = client.doctor()
            self.assertEqual(value['reason'], reason)
            self.assertIsNone(value['diagnostics'])
            self.assertNotIn('canary', json.dumps(value))
            runner.assert_not_called()
            admin.assert_not_called()

    def test_facade_doctor_cannot_select_the_operator_write_workflow(self):
        output = io.StringIO()
        with patch.object(client.ctl, 'audit_request', return_value=(2, b'')), patch.object(windows, 'exchange') as admin, redirect_stdout(output):
            self.assertEqual(windows.main(['doctor', '--operator']), 3)
        admin.assert_not_called()

    def test_probe_failure_writes_only_a_structured_record_without_raw_exception(self):
        with patch.object(gateway, 'config', side_effect=ValueError('private canary')), patch.object(diagnostic, 'write_latest') as write:
            self.assertEqual(gateway.run_probe(), 1)
        self.assertEqual(len(write.call_args_list), 1)
        value = write.call_args.args[1]
        diagnostic.validate_run(value)
        self.assertEqual(value['reason'], 'configuration_failed')
        self.assertNotIn('canary', json.dumps(value))

    def test_signalled_install_probe_takes_priority_over_an_old_record_and_revoked_proof(self):
        for result, code in [('signal', 2), ('core-dump', 3)]:
            for policy in ('d' * 64, 'e' * 64):
                value = self.configuration_report()
                value['configuration_checks']['proof'] = 'mismatch'
                value['gateway'].update(verified=False, profiles=[], reason='gateway_not_verified')
                value['installation'] = {'api': 1, 'status': 'failed', 'phase': 'containment',
                    'reason': 'containment_probe_failed', 'policy_sha256': 'd' * 64, 'generated_utc': diagnostic.stamp()}
                value['probe'] = {'api': 1, 'status': 'failed', 'phase': 'containment',
                    'reason': 'containment_paths_failed', 'policy_sha256': policy, 'job_id': None, 'generated_utc': diagnostic.stamp()}
                value['units'][diagnostic.UNITS[1]].update(active='failed', sub='failed', result=result,
                    exit_code=code, exit_status=31, started=True, finished=True)
                with self.subTest(result=result, policy=policy):
                    self.assertEqual(diagnostic.classify(value), ('not_ready', 'containment_probe_signalled'))
                value['installation']['phase'] = 'unit_validation'
                value['installation']['reason'] = 'systemd_unit_invalid'
                self.assertEqual(diagnostic.classify(value), ('not_ready', 'systemd_unit_invalid'))

    def test_worker_failure_is_recorded_without_rerunning_a_job(self):
        with patch.object(gateway, 'work', side_effect=ValueError('private canary')) as work, patch.object(diagnostic, 'write_latest') as write:
            self.assertEqual(gateway.run_worker(), 1)
        work.assert_called_once()
        value = write.call_args.args[1]
        diagnostic.validate_run(value)
        self.assertEqual(value['reason'], 'worker_failed')
        self.assertNotIn('canary', json.dumps(value))

    def test_atomic_latest_result_preserves_existing_record_on_invalid_input(self):
        target = self.base / 'last-job.json'
        value = self.job_result()
        diagnostic.write_latest(target, value, diagnostic.validate_job_result)
        before = target.read_bytes()
        with self.assertRaises(ValueError):
            diagnostic.write_latest(target, {**value, 'raw_log': 'private canary'}, diagnostic.validate_job_result)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(list(self.base.glob('metadata-*')), [])

    def test_installation_checkpoint_is_bounded_and_has_no_raw_paths(self):
        with patch.object(setup, 'write') as write:
            setup.record_installation(self.base, 'unit_validation', 'failed', 'd' * 64, 'systemd_unit_invalid')
        self.assertEqual(write.call_count, 2)
        value = json.loads(write.call_args_list[0].args[1])
        diagnostic.validate_installation(value)
        self.assertNotIn(str(self.base), json.dumps(value))
        self.assertTrue(set(setup.FAILURE_HINTS) <= diagnostic.INSTALL_REASONS)

    def test_latest_pointer_does_not_hide_new_queue_or_replace_completed_state(self):
        (self.base / 'reports').mkdir()
        (self.base / 'queued').mkdir()
        value = self.report()
        completed = self.job_result()
        queued = contract.result(completed['job'], 'queued')
        queued['generated_utc'] = completed['generated_utc']
        diagnostic.write_latest(self.base / 'reports/last-job.json', completed, diagnostic.validate_job_result)
        diagnostic.write_latest(self.base / 'queued/last-job.json', queued, diagnostic.validate_job_result)
        with patch.object(diagnostic, 'ROOT', self.base), patch.object(diagnostic, 'INSTALLATION', self.base / 'missing.json'), patch.object(gateway, 'capability', return_value=value['gateway']), patch.object(diagnostic, 'query_systemd', return_value=('ok', self.raw_units())):
            self.assertEqual(diagnostic.collect()['last_job']['status'], 'passed')
            other = contract.make_job('a' * 40, 'e' * 64, 'c' * 64, 'syntax', 'd' * 64)
            queued = contract.result(other, 'queued')
            queued['generated_utc'] = completed['generated_utc']
            diagnostic.write_latest(self.base / 'queued/last-job.json', queued, diagnostic.validate_job_result)
            self.assertEqual(diagnostic.collect()['last_job']['job']['job_id'], other['job_id'])

    def test_audit_rejects_invalid_collector_output_before_printing(self):
        output = io.StringIO()
        with patch.dict(readonly.os.environ, {'SSH_ORIGINAL_COMMAND': 'diagnose gateway'}), patch.object(diagnostic, 'collect', return_value={'raw_log': 'private canary'}), redirect_stdout(output):
            self.assertEqual(readonly.main(), 3)
        self.assertEqual(output.getvalue(), '')

    def test_worker_success_uses_nested_job_identity_in_health_record(self):
        result = self.job_result()
        with patch.object(gateway, 'work', return_value=result), patch.object(diagnostic, 'write_latest') as write:
            self.assertEqual(gateway.run_worker(), 0)
        value = write.call_args.args[1]
        diagnostic.validate_run(value)
        self.assertEqual(value['status'], 'passed')
        self.assertEqual(value['job_id'], result['job']['job_id'])

    def test_explicit_offline_mode_never_attempts_ssh_or_imports_old_results(self):
        output = io.StringIO()
        with patch.object(client.ctl, 'audit_request') as audit, redirect_stdout(output):
            self.assertEqual(windows.main(['doctor', '--mode', 'offline']), 3)
        audit.assert_not_called()
        value = json.loads(output.getvalue())
        self.assertEqual(value['reason'], 'offline_result_requires_review')
        self.assertIsNone(value['diagnostics'])

    def test_status_transport_failure_does_not_claim_worker_execution(self):
        output = io.StringIO()
        with patch.object(client.ctl, 'audit_request', return_value=(255, b'private canary')) as audit, redirect_stdout(output):
            self.assertEqual(windows.main(['status']), 2)
        audit.assert_called_once_with('status')
        value = json.loads(output.getvalue())
        self.assertEqual(value['reason'], 'ssh_unavailable')
        self.assertNotIn('canary', output.getvalue())

    def test_status_transport_timeout_and_limits_are_redacted_without_retry(self):
        for error in [OSError('private canary'), subprocess.TimeoutExpired('private canary', 1), ValueError('private canary')]:
            output = io.StringIO()
            with self.subTest(error=type(error).__name__), patch.object(client.ctl, 'audit_request', side_effect=error) as audit, redirect_stdout(output):
                self.assertEqual(windows.main(['status']), 2)
            audit.assert_called_once_with('status')
            self.assertEqual(json.loads(output.getvalue())['reason'], 'ssh_unavailable')
            self.assertNotIn('canary', output.getvalue())

    def test_status_invalid_remote_data_is_distinct_from_transport_failure(self):
        for payload in [b'private canary', b'{"role":"private canary"}', b'\xff', b'[]']:
            output = io.StringIO()
            with self.subTest(payload=payload), patch.object(client.ctl, 'audit_request', return_value=(0, payload)) as audit, redirect_stdout(output):
                self.assertEqual(windows.main(['status']), 2)
            audit.assert_called_once_with('status')
            self.assertEqual(json.loads(output.getvalue())['reason'], 'audit_response_invalid')
            self.assertNotIn('canary', output.getvalue())

    def test_status_success_retains_the_closed_audit_schema(self):
        value = {'schema_version': 1, 'role': 'malpdf-audit', 'connection': 'read-only-command-gate'}
        output = io.StringIO()
        with patch.object(client.ctl, 'audit_request', return_value=(0, json.dumps(value).encode())) as audit, redirect_stdout(output):
            self.assertEqual(windows.main(['status']), 0)
        audit.assert_called_once_with('status')
        self.assertEqual(json.loads(output.getvalue()), value)

    def test_doctor_uses_vmware_metadata_only_after_audit_transport_loss(self):
        metadata = {'vm_running': True, 'tools': 'running', 'guest_ipv4': '192.168.217.10',
                    'expected_ipv4': '192.168.217.10', 'address_matches': True, 'reason': None}
        with patch.object(client.ctl, 'audit_request', return_value=(255, b'')), patch.object(client, 'host_metadata', return_value=metadata) as host:
            value = client.doctor()
        host.assert_called_once_with()
        self.assertEqual(value['host_vmware'], metadata)
        self.assertEqual(value['reason'], 'lab_unreachable')
        self.assertEqual(value['status'], 'not_ready')

    def test_doctor_offline_or_working_audit_never_queries_vmware(self):
        for offline, reply in [(True, (255, b'')), (False, (0, contract.encoded(self.report()))), (False, (2, b''))]:
            with self.subTest(offline=offline, code=reply[0]), patch.object(client.ctl, 'audit_request', return_value=reply), patch.object(client, 'host_metadata') as host:
                self.assertIsNone(client.doctor(offline=offline)['host_vmware'])
            host.assert_not_called()

    def vmware_context(self, replies):
        binary = self.base / 'vmrun.exe'
        binary.touch()
        return patch.multiple(vmware, VMRUNS=(binary,)), patch.object(vmware.sys, 'platform', 'win32'), patch.object(vmware, 'query', side_effect=replies)

    def test_vmware_reads_only_known_running_guest_and_fixed_metadata(self):
        paths, platform, commands = self.vmware_context(['Total running VMs: 1\n' + str(vmware.VMX), 'running', '192.168.217.10'])
        with paths, platform, commands as query:
            value = vmware.collect()
        self.assertTrue(value['vm_running'])
        self.assertTrue(value['address_matches'])
        self.assertEqual(value['tools'], 'running')
        self.assertEqual([call.args[1] for call in query.call_args_list], ['list', 'tools', 'address'])
        self.assertNotIn(str(vmware.VMX), json.dumps(value))

    def test_vmware_never_starts_a_stopped_guest_or_selects_another_guest(self):
        for listing in ['Total running VMs: 0', 'Total running VMs: 1\nC:/Other/Guest.vmx']:
            paths, platform, commands = self.vmware_context([listing])
            with paths, platform, commands as query:
                value = vmware.collect()
            self.assertEqual(value['reason'], 'vm_not_running')
            self.assertFalse(value['vm_running'])
            self.assertEqual(query.call_count, 1)

    def test_vmware_malformed_or_failed_inventory_never_reaches_guest_queries(self):
        for listing in [None, 'private canary', 'Total running VMs: 1', 'Total running VMs: 0\n' + str(vmware.VMX)]:
            paths, platform, commands = self.vmware_context([listing])
            with paths, platform, commands as query:
                value = vmware.collect()
            self.assertEqual(value['reason'], 'vmware_metadata_unavailable')
            self.assertEqual(query.call_count, 1)
            self.assertNotIn('canary', json.dumps(value))

    def test_vmware_tools_without_running_state_do_not_trigger_address_queries(self):
        for tools in [None, 'installed', 'not_installed', 'private canary']:
            paths, platform, commands = self.vmware_context(['Total running VMs: 1\n' + str(vmware.VMX), tools])
            with paths, platform, commands as query:
                value = vmware.collect()
            self.assertEqual(value['reason'], 'guest_ip_unavailable')
            self.assertEqual(query.call_count, 2)
            self.assertNotIn('canary', json.dumps(value))

    def test_vmware_ip_mismatch_is_reported_without_changing_endpoint(self):
        paths, platform, commands = self.vmware_context(['Total running VMs: 1\n' + str(vmware.VMX), 'running', '192.168.217.11'])
        with paths, platform, commands:
            value = vmware.collect()
        self.assertEqual(value['reason'], 'guest_ip_mismatch')
        self.assertEqual(value['expected_ipv4'], '192.168.217.10')
        self.assertFalse(value['address_matches'])

    def test_vmware_untrusted_ip_text_never_enters_doctor_results(self):
        for address in [None, 'private canary', '192.168.217.10\nprivate canary', '127.0.0.1', '0.0.0.0', '::1', '224.0.0.1']:
            paths, platform, commands = self.vmware_context(['Total running VMs: 1\n' + str(vmware.VMX), 'running', address])
            with paths, platform, commands:
                value = vmware.collect()
            self.assertIsNone(value['guest_ipv4'])
            self.assertEqual(value['reason'], 'guest_ip_unavailable')
            self.assertNotIn('canary', json.dumps(value))

    def test_vmware_unavailable_platform_or_binary_never_queries_guest(self):
        for platform, paths in [('linux', ()), ('win32', ())]:
            with patch.object(vmware.sys, 'platform', platform), patch.object(vmware, 'VMRUNS', paths), patch.object(vmware, 'query') as query:
                self.assertEqual(vmware.collect()['reason'], 'vmware_metadata_unavailable')
            query.assert_not_called()

    def test_vmware_query_has_fixed_arguments_timeout_and_no_credentials(self):
        with patch.object(vmware.subprocess, 'run', return_value=subprocess.CompletedProcess('vmrun', 0, stdout=b'running\r\n')) as run:
            self.assertEqual(vmware.query(vmware.VMRUNS[0], 'tools'), 'running')
        self.assertEqual(run.call_args.args[0], [str(vmware.VMRUNS[0]), '-T', 'ws', 'checkToolsState', str(vmware.VMX)])
        self.assertEqual(run.call_args.kwargs['timeout'], 3)
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertNotIn('input', run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
        with patch.object(vmware.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'vmware_action_rejected'):
            vmware.query(vmware.VMRUNS[0], 'runProgramInGuest')
        run.assert_not_called()

    def test_vmware_query_discards_errors_oversize_and_invalid_encoding(self):
        for reply in [subprocess.CompletedProcess('vmrun', 1, stdout=b'private canary'),
                      subprocess.CompletedProcess('vmrun', 0, stdout=b'x' * 4097),
                      subprocess.CompletedProcess('vmrun', 0, stdout=b'\xff')]:
            with patch.object(vmware.subprocess, 'run', return_value=reply):
                self.assertIsNone(vmware.query(vmware.VMRUNS[0], 'list'))
        with patch.object(vmware.subprocess, 'run', side_effect=subprocess.TimeoutExpired('private canary', 3)):
            self.assertIsNone(vmware.query(vmware.VMRUNS[0], 'list'))

    @contextmanager
    def sshd_fixture(self, previous=b'Match User previous\n    PermitTTY no\n'):
        with tempfile.TemporaryDirectory(prefix='sshd-', dir=self.base) as temporary:
            folder = Path(temporary)
            dropin = folder / 'runner.conf'
            backup = folder / 'backup'
            backup.mkdir()
            if previous is not None:
                dropin.write_bytes(previous)
            original_stat = Path.stat
            def metadata(path, **options):
                value = original_stat(path, **options)
                if path == dropin:
                    return SimpleNamespace(st_uid=0, st_gid=17, st_mode=setup.stat.S_IFREG | 0o640, st_size=value.st_size)
                return value
            with patch.object(setup, 'DROPIN', dropin), patch.object(setup.os, 'chown', create=True), patch.object(Path, 'stat', new=metadata):
                yield dropin, backup

    def test_sshd_match_uses_only_supported_keywords_and_still_requires_environment_denial(self):
        supported = {'authenticationmethods', 'pubkeyauthentication', 'pubkeyacceptedalgorithms',
            'passwordauthentication', 'kbdinteractiveauthentication', 'authorizedkeysfile',
            'authorizedkeyscommand', 'forcecommand', 'disableforwarding', 'allowtcpforwarding',
            'allowstreamlocalforwarding', 'allowagentforwarding', 'x11forwarding', 'permittunnel',
            'permittty', 'permituserrc', 'maxsessions'}
        lines = setup.sshd_text().splitlines()
        self.assertEqual(lines[0], 'Match User malpdf-runner')
        self.assertEqual(lines[-1], 'Match all')
        self.assertTrue({line.split()[0].lower() for line in lines[1:-1]} <= supported)
        self.assertNotIn('PermitUserEnvironment', setup.sshd_text())
        self.assertIn('permituserenvironment no', setup.sshd_required())

    def test_sshd_valid_candidate_is_checked_without_starting_or_reloading_service(self):
        with self.sshd_fixture() as (dropin, backup):
            previous = dropin.read_bytes()
            replies = [subprocess.CompletedProcess('sshd', 0),
                       subprocess.CompletedProcess('sshd', 0, stdout='\n'.join(setup.sshd_required()).encode())]
            with patch.object(setup, 'run', side_effect=replies) as run, patch.object(setup, 'replace_sshd', wraps=setup.replace_sshd) as replace:
                phases = []
                setup.configure_sshd(backup, phases.append)
            self.assertEqual(phases, ['sshd_syntax', 'sshd_policy'])
            self.assertEqual(dropin.read_bytes(), setup.sshd_text().encode())
            self.assertEqual((backup / 'sshd.previous').read_bytes(), previous)
            self.assertFalse((backup / 'sshd.rejected').exists())
            self.assertEqual(replace.call_count, 1)
            self.assertEqual(run.call_args_list[0].args[0], ['/usr/sbin/sshd', '-t'])
            self.assertEqual(run.call_args_list[1].args[0][:3], ['/usr/sbin/sshd', '-T', '-C'])

    def test_sshd_syntax_failure_restores_previous_or_removes_only_new_candidate(self):
        for previous in (b'Match User previous\n    PermitTTY no\n', None):
            with self.subTest(existing=previous is not None), self.sshd_fixture(previous) as (dropin, backup):
                error = subprocess.CalledProcessError(255, ['/usr/sbin/sshd', '-t'])
                with patch.object(setup, 'run', side_effect=error) as run, patch.object(setup, 'replace_sshd', wraps=setup.replace_sshd) as replace:
                    with self.assertRaises(subprocess.CalledProcessError):
                        setup.configure_sshd(backup, lambda phase: None)
                run.assert_called_once_with(['/usr/sbin/sshd', '-t'])
                self.assertEqual((backup / 'sshd.rejected').read_bytes(), setup.sshd_text().encode())
                if previous is None:
                    self.assertFalse(dropin.exists())
                else:
                    self.assertEqual(dropin.read_bytes(), previous)
                    self.assertEqual(replace.call_args.args, (previous, 0o640, 17))

    def test_sshd_policy_failure_keeps_environment_and_forwarding_guards(self):
        for omitted, replacement in [('permituserenvironment no', 'permituserenvironment yes'),
                                      ('disableforwarding yes', 'disableforwarding no')]:
            with self.subTest(omitted=omitted), self.sshd_fixture() as (dropin, backup):
                previous = dropin.read_bytes()
                effective = [line for line in setup.sshd_required() if line != omitted] + [replacement]
                replies = [subprocess.CompletedProcess('sshd', 0), subprocess.CompletedProcess('sshd', 0, stdout='\n'.join(effective).encode())]
                with patch.object(setup, 'run', side_effect=replies), self.assertRaisesRegex(ValueError, 'sshd_policy_mismatch'):
                    setup.configure_sshd(backup, lambda phase: None)
                self.assertEqual(dropin.read_bytes(), previous)
                self.assertTrue((backup / 'sshd.rejected').is_file())

    def test_sshd_interrupted_validation_restores_previous_configuration(self):
        with self.sshd_fixture() as (dropin, backup):
            previous = dropin.read_bytes()
            with patch.object(setup, 'run', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                setup.configure_sshd(backup, lambda phase: None)
            self.assertEqual(dropin.read_bytes(), previous)
            self.assertTrue((backup / 'sshd.rejected').is_file())

    def test_sshd_rollback_refuses_to_overwrite_concurrent_operator_changes(self):
        with self.sshd_fixture() as (dropin, backup):
            def fail(arguments):
                dropin.write_bytes(b'operator change\n')
                raise subprocess.CalledProcessError(255, arguments)
            with patch.object(setup, 'run', side_effect=fail), self.assertRaisesRegex(ValueError, 'sshd_restore_failed'):
                setup.configure_sshd(backup, lambda phase: None)
            self.assertEqual(dropin.read_bytes(), b'operator change\n')
            self.assertTrue((backup / 'sshd.previous').is_file())

    def test_sshd_rollback_failure_retains_both_operator_backup_and_rejected_candidate(self):
        with self.sshd_fixture() as (dropin, backup):
            previous = dropin.read_bytes()
            replace = setup.replace_sshd
            def replace_or_fail(payload, *metadata):
                if metadata:
                    raise OSError('private canary')
                replace(payload)
            with patch.object(setup, 'run', side_effect=subprocess.CalledProcessError(255, ['/usr/sbin/sshd', '-t'])), patch.object(setup, 'replace_sshd', side_effect=replace_or_fail), self.assertRaisesRegex(ValueError, 'sshd_restore_failed') as caught:
                setup.configure_sshd(backup, lambda phase: None)
            self.assertEqual((backup / 'sshd.previous').read_bytes(), previous)
            self.assertEqual((backup / 'sshd.rejected').read_bytes(), setup.sshd_text().encode())
            self.assertNotIn('canary', str(caught.exception))

    def test_sshd_atomic_replacement_failure_preserves_existing_file_and_cleans_own_temp(self):
        with self.sshd_fixture() as (dropin, backup):
            previous = dropin.read_bytes()
            with patch.object(setup.os, 'replace', side_effect=OSError('synthetic replacement failure')), self.assertRaises(OSError):
                setup.replace_sshd(b'candidate\n')
            self.assertEqual(dropin.read_bytes(), previous)
            self.assertEqual(list(dropin.parent.glob('.malpdf-runner-*')), [])

    def prepare_sshd(self, backup):
        replies = [subprocess.CompletedProcess('sshd', 0),
                   subprocess.CompletedProcess('sshd', 0, stdout='\n'.join(setup.sshd_required()).encode())]
        with patch.object(setup, 'run', side_effect=replies):
            return setup.configure_sshd(backup, lambda phase: None)

    def test_sshd_generated_policy_preserves_all_runner_restrictions(self):
        fields = {name.lower(): value for name, value in (line.strip().split(None, 1) for line in setup.sshd_text().splitlines()[1:-1])}
        expected = {'authenticationmethods': 'publickey', 'pubkeyauthentication': 'yes',
            'pubkeyacceptedalgorithms': 'ssh-ed25519', 'passwordauthentication': 'no',
            'kbdinteractiveauthentication': 'no', 'authorizedkeyscommand': 'none',
            'authorizedkeysfile': '/var/lib/malpdf-gateway/runner-home/.ssh/authorized_keys',
            'forcecommand': '/usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_gateway.py',
            'disableforwarding': 'yes', 'allowtcpforwarding': 'no', 'allowstreamlocalforwarding': 'no',
            'allowagentforwarding': 'no', 'x11forwarding': 'no', 'permittunnel': 'no',
            'permittty': 'no', 'permituserrc': 'no', 'maxsessions': '1'}
        self.assertEqual(fields, expected)

    def test_sshd_activation_rechecks_syntax_and_effective_policy_before_reload(self):
        with self.sshd_fixture() as (dropin, backup):
            previous, candidate = self.prepare_sshd(backup)
            replies = [subprocess.CompletedProcess('sshd', 0),
                       subprocess.CompletedProcess('sshd', 0, stdout='\n'.join(setup.sshd_required()).encode()),
                       subprocess.CompletedProcess('systemctl', 0)]
            with patch.object(setup, 'run', side_effect=replies) as run:
                setup.activate_sshd(backup, previous, candidate)
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                ['/usr/sbin/sshd', '-t'],
                ['/usr/sbin/sshd', '-T', '-C', 'user=malpdf-runner,addr=192.168.217.1,host=192.168.217.1,laddr=192.168.217.10,lport=22'],
                ['/usr/bin/systemctl', 'reload', 'ssh']])
            self.assertEqual(dropin.read_bytes(), candidate)

    def test_sshd_activation_syntax_failure_restores_without_reloading(self):
        errors = [subprocess.CalledProcessError(255, ['/usr/sbin/sshd', '-t']),
                  subprocess.TimeoutExpired(['/usr/sbin/sshd', '-t'], 30), FileNotFoundError('synthetic missing sshd')]
        for content in (b'Match User previous\n    PermitTTY no\n', None):
            for error in errors:
                with self.subTest(existing=content is not None, error=type(error).__name__), self.sshd_fixture(content) as (dropin, backup):
                    previous, candidate = self.prepare_sshd(backup)
                    with patch.object(setup, 'run', side_effect=error) as run, self.assertRaises(type(error)):
                        setup.activate_sshd(backup, previous, candidate)
                    run.assert_called_once_with(['/usr/sbin/sshd', '-t'])
                    self.assertEqual((backup / 'sshd.rejected').read_bytes(), candidate)
                    self.assertEqual(dropin.read_bytes() if dropin.exists() else None, content)

    def test_sshd_activation_rejects_weakened_environment_or_session_policy(self):
        for omitted, replacement in [('permituserenvironment no', 'permituserenvironment yes'),
                                      ('maxsessions 1', 'maxsessions 10')]:
            with self.subTest(omitted=omitted), self.sshd_fixture() as (dropin, backup):
                content = dropin.read_bytes()
                previous, candidate = self.prepare_sshd(backup)
                effective = [line for line in setup.sshd_required() if line != omitted] + [replacement]
                replies = [subprocess.CompletedProcess('sshd', 0), subprocess.CompletedProcess('sshd', 0, stdout='\n'.join(effective).encode())]
                with patch.object(setup, 'run', side_effect=replies) as run, self.assertRaisesRegex(ValueError, 'sshd_policy_mismatch'):
                    setup.activate_sshd(backup, previous, candidate)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(dropin.read_bytes(), content)

    def test_sshd_failed_reload_restores_previous_file_mode_and_group(self):
        with self.sshd_fixture() as (dropin, backup):
            content = dropin.read_bytes()
            previous, candidate = self.prepare_sshd(backup)
            error = subprocess.CalledProcessError(1, ['/usr/bin/systemctl', 'reload', 'ssh'])
            replies = [subprocess.CompletedProcess('sshd', 0),
                       subprocess.CompletedProcess('sshd', 0, stdout='\n'.join(setup.sshd_required()).encode()), error]
            with patch.object(setup, 'run', side_effect=replies), patch.object(setup, 'replace_sshd', wraps=setup.replace_sshd) as replace, self.assertRaises(subprocess.CalledProcessError) as caught:
                setup.activate_sshd(backup, previous, candidate)
            self.assertEqual(setup.failure_reason(caught.exception), 'ssh_reload_failed')
            self.assertEqual(dropin.read_bytes(), content)
            self.assertEqual(replace.call_args.args, (content, 0o640, 17))
            self.assertEqual((backup / 'sshd.rejected').read_bytes(), candidate)

    def test_sshd_activation_preserves_changes_made_before_or_during_validation(self):
        for timing in ('before', 'during'):
            with self.subTest(timing=timing), self.sshd_fixture() as (dropin, backup):
                previous, candidate = self.prepare_sshd(backup)
                if timing == 'before':
                    dropin.write_bytes(b'operator change\n')
                def command(arguments):
                    if '-T' in arguments:
                        dropin.write_bytes(b'operator change\n')
                        return subprocess.CompletedProcess(arguments, 0, stdout='\n'.join(setup.sshd_required()).encode())
                    return subprocess.CompletedProcess(arguments, 0)
                with patch.object(setup, 'run', side_effect=command) as run, self.assertRaisesRegex(ValueError, 'sshd_restore_failed'):
                    setup.activate_sshd(backup, previous, candidate)
                self.assertEqual(run.call_count, 0 if timing == 'before' else 2)
                self.assertEqual(dropin.read_bytes(), b'operator change\n')

    def test_sshd_interrupted_activation_restores_previous_file(self):
        with self.sshd_fixture() as (dropin, backup):
            content = dropin.read_bytes()
            previous, candidate = self.prepare_sshd(backup)
            with patch.object(setup, 'run', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                setup.activate_sshd(backup, previous, candidate)
            self.assertEqual(dropin.read_bytes(), content)

    def test_sshd_invalid_existing_configuration_blocks_installer_before_writes(self):
        public = b'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32)))
        with patch.object(client, 'ensure_key', return_value=public), patch.object(client.ctl, 'OUT', self.base / 'packages'), patch.object(client.ctl, 'revision', return_value='a' * 40):
            source = Path(client.setup()['bootstrap'])
        original_read = Path.read_text
        def text(path, *args, **kwargs):
            if path == Path('/etc/ssh/sshd_config'):
                return 'Include /etc/ssh/sshd_config.d/*.conf\n'
            if path == Path('/home/malpdf-audit/.ssh/authorized_keys'):
                return 'ssh-ed25519 distinct-audit-public-key'
            return original_read(path, *args, **kwargs)
        accounts = SimpleNamespace(getpwnam=MagicMock())
        groups = SimpleNamespace(getgrnam=MagicMock())
        replies = [subprocess.CompletedProcess('visudo', 0), subprocess.CalledProcessError(255, ['/usr/sbin/sshd', '-t'])]
        output = io.StringIO()
        with patch.dict(setup.sys.modules, {'pwd': accounts, 'grp': groups}), patch.object(setup.sys, 'platform', 'linux'), patch.object(setup.sys, 'path', setup.sys.path.copy()), patch.object(setup.os, 'getuid', return_value=0, create=True), patch.object(setup, 'SOURCE', source), patch.object(Path, 'read_text', new=text), patch.object(setup, 'run', side_effect=replies) as run, patch.object(setup, 'install') as install, patch.object(setup, 'write') as write, redirect_stdout(output):
            self.assertEqual(setup.main(['--install']), 2)
        install.assert_not_called()
        write.assert_not_called()
        accounts.getpwnam.assert_called_once_with('malpdf-audit')
        self.assertEqual([call.args[0] for call in run.call_args_list], [['/usr/sbin/visudo', '-c'], ['/usr/sbin/sshd', '-t']])
        self.assertIn('[preflight/sshd_config_invalid]', output.getvalue())

    def account(self, name):
        return SimpleNamespace(pw_uid=12345, pw_dir=str(setup.BASE / ('runner-home' if name == 'malpdf-runner' else 'worker-home')),
                               pw_shell='/bin/sh' if name == 'malpdf-runner' else '/usr/sbin/nologin')

    def test_account_guard_identifies_process_without_reading_sudo_listing(self):
        for name, expected in [('malpdf-runner', 'runner_process_present'), ('malpdf-worker', 'worker_process_present')]:
            replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 0)]
            with self.subTest(name=name), patch.object(setup, 'run', side_effect=replies) as run, self.assertRaisesRegex(ValueError, expected):
                setup.check_account(name, self.account(name))
            self.assertEqual(run.call_count, 2)

    def test_account_guard_identifies_sudo_review_without_returning_policy_text(self):
        for name, expected in [('malpdf-runner', 'runner_sudo_listing_allowed'), ('malpdf-worker', 'worker_sudo_listing_allowed')]:
            replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 1),
                       subprocess.CompletedProcess('sudo', 0, stdout=f'User {name} may run the following commands on remnux:\n    (root) /private/policy/canary\n'.encode(), stderr=b'')]
            with self.subTest(name=name), patch.object(setup, 'run', side_effect=replies), self.assertRaisesRegex(ValueError, expected) as caught:
                setup.check_account(name, self.account(name))
            self.assertNotIn('canary', str(caught.exception))

    def test_account_guard_rejects_unknown_process_and_sudo_exit_codes(self):
        name = 'malpdf-runner'
        for process, privilege, expected in [(2, 1, 'account_process_check_failed'), (1, 2, 'account_sudo_check_failed')]:
            replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', process),
                       subprocess.CompletedProcess('sudo', privilege)]
            with patch.object(setup, 'run', side_effect=replies), self.assertRaisesRegex(ValueError, expected):
                setup.check_account(name, self.account(name))

    def test_account_guard_accepts_only_clear_no_process_and_denied_sudo_results(self):
        name = 'malpdf-worker'
        replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 1),
                   subprocess.CompletedProcess('sudo', 1, stdout=f'User {name} is not allowed to run sudo on remnux.\n'.encode(), stderr=b'')]
        with patch.object(setup, 'run', side_effect=replies) as run:
            setup.check_account(name, self.account(name))
        self.assertEqual(run.call_count, 3)

    def test_root_sudo_listing_can_succeed_while_target_has_no_grants(self):
        for name in ('malpdf-runner', 'malpdf-worker'):
            replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 1),
                       subprocess.CompletedProcess('sudo', 0, stdout=f'User {name} is not allowed to run sudo on remnux.\n'.encode(), stderr=b'')]
            with self.subTest(name=name), patch.object(setup, 'run', side_effect=replies) as run:
                setup.check_account(name, self.account(name))
            self.assertEqual(run.call_args.args[0], ['/usr/bin/sudo', '-n', '-l', '-U', name])
            self.assertEqual(run.call_args.kwargs, {'check': False, 'env': {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}})

    def test_sudo_denial_requires_known_status_and_explicit_policy_result(self):
        name = 'malpdf-runner'
        denial = f'User {name} is not allowed to run sudo on remnux.\n'.encode()
        for status, output in [(0, b''), (1, b''), (1, b'sudo: policy plugin failed\n'), (2, denial), (-9, denial)]:
            replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 1),
                       subprocess.CompletedProcess('sudo', status, stdout=output, stderr=b'')]
            with self.subTest(status=status, output=output), patch.object(setup, 'run', side_effect=replies), self.assertRaisesRegex(ValueError, 'account_sudo_check_failed'):
                setup.check_account(name, self.account(name))

    def test_sudo_denial_rejects_wrong_subject_and_unknown_localized_output(self):
        name = 'malpdf-runner'
        for output in [b'User malpdf-worker is not allowed to run sudo on remnux.\n', b'Utilisateur malpdf-runner non autorise.\n',
                       b'User malpdf-runner is not allowed to run sudo on remnux;canary.\n']:
            replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 1),
                       subprocess.CompletedProcess('sudo', 0, stdout=output, stderr=b'')]
            with self.subTest(output=output), patch.object(setup, 'run', side_effect=replies), self.assertRaisesRegex(ValueError, 'account_sudo_check_failed'):
                setup.check_account(name, self.account(name))

    def test_sudo_denial_rejects_extra_output_and_oversized_policy(self):
        name = 'malpdf-runner'
        denial = f'User {name} is not allowed to run sudo on remnux.\n'.encode()
        for output in [b'private canary\n' + denial, denial + b'    (ALL) ALL\n', denial + b'\n', b'x' * 16385]:
            replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 1),
                       subprocess.CompletedProcess('sudo', 0, stdout=output, stderr=b'')]
            with self.subTest(size=len(output)), patch.object(setup, 'run', side_effect=replies), self.assertRaisesRegex(ValueError, 'account_sudo_check_failed') as caught:
                setup.check_account(name, self.account(name))
            self.assertNotIn('canary', str(caught.exception))

    def test_sudo_denial_does_not_hide_stderr_errors_or_warnings(self):
        name = 'malpdf-worker'
        replies = [subprocess.CompletedProcess('id', 0, stdout=name.encode()), subprocess.CompletedProcess('pgrep', 1),
                   subprocess.CompletedProcess('sudo', 0, stdout=f'User {name} is not allowed to run sudo on remnux.\n'.encode(), stderr=b'sudo: private canary\n')]
        with patch.object(setup, 'run', side_effect=replies), self.assertRaisesRegex(ValueError, 'account_sudo_check_failed') as caught:
            setup.check_account(name, self.account(name))
        self.assertNotIn('canary', str(caught.exception))

    def test_new_account_is_checked_before_home_or_key_installation(self):
        accounts = {}
        def lookup(name):
            return accounts[name]
        def command(arguments, **kwargs):
            if arguments[0] == '/usr/sbin/useradd':
                accounts[arguments[-1]] = self.account(arguments[-1])
            return subprocess.CompletedProcess(arguments, 0)
        with patch.dict(setup.sys.modules, {'pwd': SimpleNamespace(getpwnam=lookup)}), patch.object(setup, 'run', side_effect=command) as run, patch.object(setup, 'check_account', side_effect=ValueError('runner_sudo_listing_allowed')) as check, patch.object(setup, 'directory') as directory:
            with self.assertRaisesRegex(ValueError, 'runner_sudo_listing_allowed'):
                setup.configure_accounts()
        check.assert_called_once_with('malpdf-runner', accounts['malpdf-runner'])
        directory.assert_not_called()
        self.assertEqual(run.call_args_list[-1].args[0], ['/usr/sbin/usermod', '--lock', 'malpdf-runner'])

    def test_unknown_account_cannot_expand_fixed_account_checks(self):
        with patch.object(setup, 'run') as run, self.assertRaises(ValueError):
            setup.check_account('arbitrary', self.account('malpdf-worker'))
        run.assert_not_called()

    @contextmanager
    def installation_fixture(self):
        etc = self.base / 'etc'
        root = self.base / 'gateway'
        units = self.base / 'units'
        library = self.base / 'libexec'
        for folder in (etc, root, units, library, root / 'reports', root / 'worker', root / 'requests'):
            folder.mkdir(parents=True, exist_ok=True)
        cfg = {'policy_sha256': 'd' * 64, 'profiles': ['syntax'], 'units': {name: 'a' * 64 for name in setup.UNITS}, 'sshd_sha256': 'b' * 64}
        backups = []
        resets = []
        def backup(**kwargs):
            folder = self.base / ('backup-' + str(len(backups)))
            folder.mkdir()
            backups.append(folder)
            return str(folder)
        def configure(key, allow_synthetic):
            resets.append(json.loads((etc / 'gateway-verified.json').read_bytes()))
            setup.write(etc / 'gateway.json', contract.encoded(cfg))
            for name in setup.UNITS:
                setup.write(units / name, 'reviewed unit\n')
            return cfg
        def command(arguments, **kwargs):
            if arguments[:2] == ['/usr/bin/systemctl', 'start']:
                proof = {'api': 1, 'policy_sha256': cfg['policy_sha256'], 'checks': {
                    'nonroot': True, 'network_denied': True, 'source_readonly': True,
                    'host_data_hidden': True, 'resource_limits': True}}
                (root / 'reports/probe.json').write_bytes(contract.encoded(proof))
            code = 2 if arguments[0] == '/usr/sbin/runuser' else 1 if arguments[0] == '/usr/bin/pgrep' else 0
            return subprocess.CompletedProcess(arguments, code, stdout=b'', stderr=b'')
        with patch.multiple(setup, ETC=etc, BASE=root, UNIT_DIR=units, LIB=library, DROPIN=etc / 'runner.conf'), patch.object(setup.tempfile, 'mkdtemp', side_effect=backup), patch.object(setup.os, 'chown', create=True), patch.object(setup, 'configure_gateway', side_effect=configure) as configure_mock, patch.object(setup, 'configure_sshd', return_value=(None, b'candidate')), patch.object(setup, 'activate_sshd'), patch.object(setup, 'run', side_effect=command) as run, redirect_stdout(io.StringIO()):
            yield SimpleNamespace(etc=etc, root=root, backups=backups, resets=resets, cfg=cfg, configure=configure_mock, run=run)

    def test_repeated_install_preserves_evidence_and_rechecks_before_publishing_proof(self):
        with self.installation_fixture() as fixture:
            evidence = [fixture.root / 'reports/old-job.json', fixture.root / 'worker/old-job.claim', fixture.root / 'requests/old-job.json']
            for path in evidence:
                path.write_bytes(b'preserved evidence\n')
            audit = self.base / 'audit-authorized_keys'
            audit.write_bytes(b'preserved audit key\n')
            setup.install('reviewed public key', False)
            first = (fixture.etc / 'gateway-verified.json').read_bytes()
            setup.install('reviewed public key', False)
            self.assertEqual((fixture.etc / 'gateway-verified.json').read_bytes(), first)
            self.assertEqual(fixture.resets, [{}, {}])
            self.assertEqual(len(fixture.backups), 2)
            for path in evidence:
                self.assertEqual(path.read_bytes(), b'preserved evidence\n')
            self.assertEqual(audit.read_bytes(), b'preserved audit key\n')
            self.assertEqual(json.loads((fixture.etc / 'gateway-installation.json').read_bytes())['status'], 'passed')
            self.assertEqual(sum(call.args[0][:2] == ['/usr/bin/systemctl', 'start'] for call in fixture.run.call_args_list), 2)

    def test_configuration_failure_clears_previous_proof_and_records_the_early_failure(self):
        with self.installation_fixture() as fixture:
            (fixture.etc / 'gateway-verified.json').write_text('{"verified":true}')
            fixture.configure.side_effect = ValueError('existing_account_requires_review')
            with self.assertRaisesRegex(ValueError, 'existing_account_requires_review'):
                setup.install('reviewed public key', False)
            self.assertEqual(json.loads((fixture.etc / 'gateway-verified.json').read_bytes()), {})
            record = json.loads((fixture.etc / 'gateway-installation.json').read_bytes())
            diagnostic.validate_installation(record)
            self.assertEqual((record['status'], record['phase'], record['reason']), ('failed', 'configuration', 'existing_account_requires_review'))
            self.assertIsNone(record['policy_sha256'])
            self.assertFalse(any(call.args[0][:2] == ['/usr/bin/systemctl', 'enable'] for call in fixture.run.call_args_list))

    def test_failed_reinstallation_probe_never_restores_old_verified_flag_or_enables_timer(self):
        with self.installation_fixture() as fixture:
            (fixture.etc / 'gateway-verified.json').write_text('{"verified":true}')
            original = fixture.run.side_effect
            def fail_probe(arguments, **kwargs):
                if arguments[:2] == ['/usr/bin/systemctl', 'start']:
                    raise subprocess.CalledProcessError(1, arguments, stderr=b'private canary')
                return original(arguments, **kwargs)
            fixture.run.side_effect = fail_probe
            with self.assertRaises(subprocess.CalledProcessError):
                setup.install('reviewed public key', False)
            self.assertEqual(json.loads((fixture.etc / 'gateway-verified.json').read_bytes()), {})
            record = json.loads((fixture.etc / 'gateway-installation.json').read_bytes())
            self.assertEqual((record['status'], record['phase'], record['reason']), ('failed', 'containment', 'containment_probe_failed'))
            self.assertNotIn('canary', json.dumps(record))
            self.assertFalse(any(call.args[0][:2] == ['/usr/bin/systemctl', 'enable'] for call in fixture.run.call_args_list))


if __name__ == '__main__':
    unittest.main()
