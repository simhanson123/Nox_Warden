"""Keep authority smoke failures useful after private fixture cleanup, without secrets."""
import contextlib
import copy
from contextlib import ExitStack
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('authority_smoke', Path(__file__).with_name('smoke_authority_review.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

PRIVATE = 'private-key-assertion-path-marker'
VALID = b'AUTHORITY_STARTUP stage=ui_assets code=AUTHORITY_UI_ASSETS_REJECTED\n'
READY = (b'Authority review is listening on its configured loopback origin. '
         b'No signer or host enforcement is enabled.\n')


class DiagnosticsTests(unittest.TestCase):
    def retain(self, contents):
        report = {}
        with tempfile.TemporaryDirectory(prefix=PRIVATE) as temporary:
            path = Path(temporary) / 'service.log'
            path.write_bytes(contents)
            smoke.retain_service_diagnostic(report, path)
        self.assertNotIn(PRIVATE, json.dumps(report))
        return report

    def invoke(self, run):
        with tempfile.TemporaryDirectory(prefix=PRIVATE) as temporary:
            output = Path(temporary) / 'report.json'
            stdout = io.StringIO()
            arguments = ['smoke', '--service-binary', PRIVATE, '--fixture-binary', PRIVATE,
                         '--report', str(output)]
            with patch.object(smoke, 'run', run), patch.object(sys, 'argv', arguments), contextlib.redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as result:
                    smoke.main()
            report = json.loads(output.read_text())
            self.assertNotIn(PRIVATE, stdout.getvalue() + output.read_text())
            self.assertLess(len(stdout.getvalue()), 350)
            return result.exception.code, report, stdout.getvalue()

    @staticmethod
    def complete(_args, report):
        report.update(stage='complete', service_log_status='ready', service_ready_count=2,
                      checks=[{'name': 'fixture integration completed', 'passed': True}])

    def test_all_exact_startup_pairs_are_preserved(self):
        self.assertEqual(len(smoke.STARTUP_DIAGNOSTICS), 11)
        for stage, code in smoke.STARTUP_DIAGNOSTICS.items():
            for ending in (b'', b'\n'):
                with self.subTest(stage=stage, ending=ending):
                    report = self.retain(f'AUTHORITY_STARTUP stage={stage} code={code}'.encode() + ending)
                    self.assertEqual(report, {'service_log_status': 'startup_failure',
                                              'service_ready_count': 0,
                                              'startup_failure': {'stage': stage, 'code': code}})

    def test_invalid_malicious_multiline_and_oversized_logs_are_not_salvaged(self):
        for contents in (
            b'AUTHORITY_STARTUP stage=ui_assets code=AUTHORITY_DATABASE_REJECTED\n',
            b'AUTHORITY_STARTUP stage=' + PRIVATE.encode() + b' code=AUTHORITY_UI_ASSETS_REJECTED\n',
            b'AUTHORITY_STARTUP stage=ui_assets code=' + PRIVATE.encode() + b'\n',
            PRIVATE.encode() + VALID, VALID + PRIVATE.encode(),
            VALID + VALID, b'\n' + VALID, VALID + b'\n',
            VALID.replace(b'\n', b'\r\n'), VALID + b'\xff\x00',
            b'thread main panicked at ' + PRIVATE.encode(),
            VALID + b'x' * smoke.SERVICE_LOG_LIMIT,
            b'x' * smoke.SERVICE_LOG_LIMIT + VALID,
            READY * 3, READY * 2 + VALID, READY + VALID + VALID,
            VALID + READY, READY + PRIVATE.encode() + VALID,
            PRIVATE.encode() + READY * 2, READY * 2 + PRIVATE.encode(),
            READY * 2 + b'thread main panicked at ' + PRIVATE.encode(),
            READY.rstrip(b'\n') + READY,
        ):
            with self.subTest(length=len(contents)):
                self.assertEqual(self.retain(contents), {'service_log_status': 'unrecognized'})

    def test_reads_are_bounded_and_missing_logs_do_not_count_as_empty(self):
        path = MagicMock()
        source = path.open.return_value.__enter__.return_value
        source.read.return_value = b'x' * (smoke.SERVICE_LOG_LIMIT + 1)
        report = {}
        smoke.retain_service_diagnostic(report, path)
        source.read.assert_called_once_with(smoke.SERVICE_LOG_LIMIT + 1)
        self.assertEqual(report, {'service_log_status': 'unrecognized'})
        path.open.side_effect = OSError(PRIVATE)
        smoke.retain_service_diagnostic(report, path)
        self.assertEqual(report, {'service_log_status': 'unavailable'})
        self.assertEqual(self.retain(b''), {'service_log_status': 'empty'})

    def test_startup_failure_survives_child_shutdown_and_temporary_cleanup(self):
        removed = []

        def fail(_args, report):
            report['stage'] = 'service_ready'
            with tempfile.TemporaryDirectory(prefix=PRIVATE) as temporary, ExitStack() as cleanup:
                path = Path(temporary) / 'service.log'
                removed.append(Path(temporary))
                cleanup.callback(smoke.retain_service_diagnostic, report, path)
                # Simulate the child's final diagnostic becoming available only
                # during shutdown, before the retention callback runs.
                cleanup.callback(path.write_bytes, VALID)
                raise smoke.CheckFailed(PRIVATE)

        code, report, stdout = self.invoke(fail)
        self.assertEqual(code, 1)
        self.assertFalse(report['passed'])
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['failure_stage'], 'service_ready')
        self.assertEqual(report['failure'], 'AUTHORITY_SMOKE_SERVICE_FAILED')
        self.assertEqual(report['startup_failure'], {'stage': 'ui_assets', 'code': 'AUTHORITY_UI_ASSETS_REJECTED'})
        self.assertIn('startup_stage=ui_assets startup_code=AUTHORITY_UI_ASSETS_REJECTED', stdout)
        self.assertTrue(all(not path.exists() for path in removed))

    def test_exceptions_and_unknown_stages_use_only_closed_values(self):
        class BrowserError(Exception):
            pass
        BrowserError.__module__ = 'playwright._impl._errors'
        for error, expected in (
            (smoke.CheckFailed, 'AUTHORITY_SMOKE_CHECK_FAILED'),
            (AssertionError, 'AUTHORITY_SMOKE_ASSERTION_FAILED'),
            (TimeoutError, 'AUTHORITY_SMOKE_BROWSER_TIMEOUT'),
            (BrowserError, 'AUTHORITY_SMOKE_BROWSER_FAILED'),
            (ImportError, 'AUTHORITY_SMOKE_BROWSER_TOOLS_MISSING'),
            (OSError, 'AUTHORITY_SMOKE_PROCESS_OR_IO_FAILED'),
            (subprocess.SubprocessError, 'AUTHORITY_SMOKE_PROCESS_OR_IO_FAILED'),
            (RuntimeError, 'AUTHORITY_SMOKE_UNEXPECTED_ERROR'),
        ):
            with self.subTest(error=error):
                def fail(_args, report):
                    report['stage'] = PRIVATE
                    raise error(PRIVATE)
                code, report, _ = self.invoke(fail)
                self.assertEqual(code, 1)
                self.assertEqual(report['failure_stage'], 'initialization')
                self.assertEqual(report['failure'], expected)

    def test_startup_panic_or_missing_log_cannot_be_reported_as_pass(self):
        for contents in (VALID, b'thread main panicked at ' + PRIVATE.encode(), None):
            with self.subTest(contents=contents):
                def incomplete(_args, report):
                    self.complete(_args, report)
                    if contents is None:
                        report['service_log_status'] = 'unavailable'
                    else:
                        report.update(self.retain(contents))
                code, report, stdout = self.invoke(incomplete)
                self.assertEqual(code, 1)
                self.assertFalse(report['passed'])
                self.assertEqual(report['status'], 'FAIL')
                self.assertTrue(stdout.startswith('FAIL:'))

    def test_incomplete_or_failed_check_evidence_is_not_a_pass(self):
        for fields in ({}, {'stage': 'complete', 'service_log_status': 'empty'},
                       {'stage': 'complete', 'service_log_status': 'empty',
                        'checks': [{'name': 'failed check', 'passed': False}]}):
            with self.subTest(fields=fields):
                code, report, _ = self.invoke(lambda _args, report: report.update(fields))
                self.assertEqual(code, 1)
                self.assertFalse(report['passed'])

    def test_success_requires_completed_checks_and_exactly_two_ready_lines(self):
        def complete(_args, report):
            self.complete(_args, report)
            report.update(self.retain(READY * 2))
        code, report, stdout = self.invoke(complete)
        self.assertEqual(code, 0)
        self.assertTrue(report['passed'])
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['service_ready_count'], 2)
        self.assertTrue(stdout.startswith('PASS:'))

    def test_restart_and_second_listener_failure_preserve_the_exact_diagnostic(self):
        listener = b'AUTHORITY_STARTUP stage=listener code=AUTHORITY_LISTENER_STOPPED\n'
        for contents, ready, stage, code in (
            (READY + VALID, 1, 'ui_assets', 'AUTHORITY_UI_ASSETS_REJECTED'),
            (READY * 2 + listener, 2, 'listener', 'AUTHORITY_LISTENER_STOPPED'),
        ):
            with self.subTest(stage=stage):
                def fail(_args, report):
                    self.complete(_args, report)
                    report.update(self.retain(contents))
                exit_code, report, stdout = self.invoke(fail)
                self.assertEqual(exit_code, 1)
                self.assertFalse(report['passed'])
                self.assertEqual(report['status'], 'FAIL')
                self.assertEqual(report['failure'], 'AUTHORITY_SMOKE_SERVICE_FAILED')
                self.assertEqual(report['service_ready_count'], ready)
                self.assertEqual(report['startup_failure'], {'stage': stage, 'code': code})
                self.assertTrue(stdout.startswith('FAIL:'))

    def test_missing_ready_line_cannot_pass_even_when_browser_checks_finished(self):
        for contents in (b'', READY):
            with self.subTest(ready_lines=contents.count(READY)):
                def incomplete(_args, report):
                    self.complete(_args, report)
                    report.update(self.retain(contents))
                code, report, stdout = self.invoke(incomplete)
                self.assertEqual(code, 1)
                self.assertFalse(report['passed'])
                self.assertEqual(report['failure'], 'AUTHORITY_SMOKE_SERVICE_DIAGNOSTIC_UNAVAILABLE')
                self.assertTrue(stdout.startswith('FAIL:'))

    def test_early_browser_timeout_category_survives_incomplete_planned_restart(self):
        def fail(_args, report):
            report['stage'] = 'browser_checks'
            report.update(self.retain(READY))
            raise TimeoutError(PRIVATE)

        code, report, _ = self.invoke(fail)
        self.assertEqual(code, 1)
        self.assertFalse(report['passed'])
        self.assertEqual(report['service_ready_count'], 1)
        self.assertEqual(report['failure'], 'AUTHORITY_SMOKE_SERVICE_DIAGNOSTIC_UNAVAILABLE')
        self.assertEqual(report['primary_failure'], 'AUTHORITY_SMOKE_BROWSER_TIMEOUT')

    def test_report_write_failure_has_no_pass_or_private_path(self):
        stdout = io.StringIO()
        with patch.object(smoke, 'run', self.complete), patch.object(sys, 'argv', [
                'smoke', '--service-binary', PRIVATE, '--fixture-binary', PRIVATE]), \
                patch.object(Path, 'write_text', side_effect=OSError(PRIVATE)), contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as result:
                smoke.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(stdout.getvalue(), 'FAIL: stage=report_write code=AUTHORITY_SMOKE_REPORT_WRITE_FAILED\n')

    def test_exited_service_is_not_ready_even_with_zero_exit_code(self):
        for code in (0, 1, -11):
            with self.subTest(code=code):
                process = MagicMock()
                process.poll.return_value = code
                with patch.object(smoke.urllib.request, 'urlopen') as opened:
                    with self.assertRaises(smoke.CheckFailed):
                        smoke.wait_ready(process)
                opened.assert_not_called()

    def test_http_success_cannot_hide_service_exit_during_readiness(self):
        process = MagicMock()
        process.poll.side_effect = [None, 1, 1]
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with patch.object(smoke.urllib.request, 'urlopen', return_value=response):
            with self.assertRaises(smoke.CheckFailed):
                smoke.wait_ready(process)


class ReadinessContractsTests(unittest.TestCase):
    @staticmethod
    def detail():
        return {'plan_hash': 'sha256:' + 'a' * 64,
                'plan': {'org_id': 'org', 'project_id': 'project', 'target_id': 'target', 'plan_id': 'plan',
                         'authority_epoch': '1', 'valid_until': '2026-11-06T01:00:00Z'}}

    def legacy(self):
        detail = self.detail()
        return {'schema_version': 'fw.signing-readiness/v2',
                **{key: detail['plan'][key] for key in ('org_id', 'project_id', 'target_id', 'plan_id')},
                'plan_hash': detail['plan_hash'], 'checked_at': '2026-11-06T00:00:00Z',
                'valid_until': '2026-11-06T00:00:30Z', 'signing_allowed': False, 'dispatch_allowed': False,
                'reasons': ['PROTECTED_BOOTSTRAP_REQUIRED', 'BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED',
                            'PROTECTED_SIGNER_UNAVAILABLE', 'APPROVAL_SET_MISSING',
                            'QUOTA_CONFIGURATION_MISSING', 'TARGET_GENERATION_UNINITIALIZED'],
                'approval_set_hash': None, 'quota_configured': False, 'target_generation': None,
                'latest_intent': None, 'quota_scope': None, 'quota_root_id': None,
                'latest_dispatch_unknown_seen': None}

    def canonical(self):
        value = self.legacy()
        value.update(schema_version='fw.signing-readiness/v3', bootstrap_authorization_hash=None,
                     target_bootstrap=None,
                     reasons=['BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED', 'POLICY_SIGNER_KEY_REQUIRED',
                              'PROTECTED_SIGNER_UNAVAILABLE', 'BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED',
                              'BOOTSTRAP_AUTHORIZATION_REQUIRED', 'TARGET_EPOCH_CONFIRMATION_REQUIRED',
                              'APPROVAL_SET_MISSING', 'QUOTA_CONFIGURATION_MISSING', 'TARGET_GENERATION_UNINITIALIZED'])
        return value

    def confirmed(self):
        value = self.canonical()
        value['bootstrap_authorization_hash'] = 'sha256:' + 'b' * 64
        value['reasons'] = [reason for reason in value['reasons'] if reason not in
                            ('BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED', 'BOOTSTRAP_AUTHORIZATION_REQUIRED', 'TARGET_EPOCH_CONFIRMATION_REQUIRED')]
        value['target_bootstrap'] = {'state': 'target_confirmed_pending_qualification', 'target_id': 'target',
            'confirmation_revision': '1', 'accepted_epoch': '1', 'highest_generation': '0',
            'confirmation_hash': 'sha256:' + 'c' * 64, 'observed_at': '2026-11-05T23:59:55Z',
            'admitted_at': '2026-11-05T23:59:58Z', 'valid_until': '2026-11-06T00:00:30Z',
            'current_confirmation_eligibility': True, 'current_for_plan': True,
            'signing_allowed': False, 'dispatch_allowed': False}
        return value

    def test_legacy_v2_fixture_helper_keeps_its_versioned_shape(self):
        value = self.legacy()
        self.assertTrue(smoke.signing_readiness_matches_fixture(value, self.detail()))
        self.assertFalse(smoke.signing_readiness_matches_fixture(self.canonical(), self.detail()))
        self.assertFalse(smoke.signing_readiness_v3_matches_fixture(value, self.detail()))
        for field in ('quota_scope', 'quota_root_id', 'latest_dispatch_unknown_seen'):
            wrong = copy.deepcopy(value)
            del wrong[field]
            self.assertFalse(smoke.signing_readiness_matches_fixture(wrong, self.detail()))

    def test_v3_human_quorum_does_not_create_fixture_bootstrap_or_target_authority(self):
        value = self.canonical()
        self.assertTrue(smoke.signing_readiness_v3_matches_fixture(value, self.detail()))
        value['approval_set_hash'] = 'sha256:' + 'd' * 64
        value['reasons'].remove('APPROVAL_SET_MISSING')
        self.assertTrue(smoke.signing_readiness_v3_matches_fixture(value, self.detail()))
        self.assertIsNone(value['bootstrap_authorization_hash'])
        self.assertIsNone(value['target_bootstrap'])
        self.assertFalse(smoke.signing_readiness_v3_matches_fixture(self.confirmed(), self.detail()))

    def test_v3_current_target_and_expired_accepted_history_are_distinct(self):
        current = self.confirmed()
        self.assertTrue(smoke.signing_readiness_v3_matches_profile(current, self.detail()))
        history = copy.deepcopy(current)
        history['target_bootstrap'].update(current_for_plan=False, current_confirmation_eligibility=False,
                                           valid_until='2026-11-05T23:59:59Z')
        history['reasons'].append('TARGET_EPOCH_CONFIRMATION_REQUIRED')
        self.assertTrue(smoke.signing_readiness_v3_matches_profile(history, self.detail()))
        self.assertEqual(history['target_bootstrap']['accepted_epoch'], '1')
        self.assertFalse(smoke.signing_readiness_v3_matches_fixture(history, self.detail()))

    def test_v3_missing_duplicate_or_legacy_blockers_cannot_pass(self):
        for missing in ('BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED', 'POLICY_SIGNER_KEY_REQUIRED',
                        'PROTECTED_SIGNER_UNAVAILABLE', 'BOOTSTRAP_AUTHORIZATION_REQUIRED', 'TARGET_EPOCH_CONFIRMATION_REQUIRED',
                        'APPROVAL_SET_MISSING', 'QUOTA_CONFIGURATION_MISSING', 'TARGET_GENERATION_UNINITIALIZED'):
            with self.subTest(missing=missing):
                value = self.canonical()
                value['reasons'].remove(missing)
                self.assertFalse(smoke.signing_readiness_v3_matches_fixture(value, self.detail()))
        for extra in ('PROTECTED_BOOTSTRAP_REQUIRED', 'BUILD_IDENTITY_UNVERIFIED', 'BUILD_IDENTITY_REQUIRED'):
            value = self.canonical()
            value['reasons'].append(extra)
            self.assertFalse(smoke.signing_readiness_v3_matches_fixture(value, self.detail()))
        value = self.canonical()
        value['bootstrap_authorization_hash'] = 'sha256:' + 'b' * 64
        self.assertFalse(smoke.signing_readiness_v3_matches_profile(value, self.detail()))

    def test_v3_contradictory_target_claims_or_private_fields_are_rejected(self):
        for field, invalid in [('accepted_epoch', '2'), ('highest_generation', '1'), ('confirmation_revision', '0'),
                               ('target_id', 'another-target'), ('current_confirmation_eligibility', False),
                               ('dispatch_allowed', True), ('raw_assertion', PRIVATE)]:
            with self.subTest(field=field):
                value = self.confirmed()
                value['target_bootstrap'][field] = invalid
                self.assertFalse(smoke.signing_readiness_v3_matches_profile(value, self.detail()))
        for invalid in ('2026-11-05T23:59:58Z', '2026-11-05T23:59:57Z'):
            value = self.confirmed()
            value['target_bootstrap'].update(current_for_plan=False, current_confirmation_eligibility=False, valid_until=invalid)
            value['reasons'].append('TARGET_EPOCH_CONFIRMATION_REQUIRED')
            self.assertFalse(smoke.signing_readiness_v3_matches_profile(value, self.detail()))
        value = self.confirmed()
        value['target_bootstrap']['valid_until'] = '2026-11-06T00:00:20Z'
        self.assertFalse(smoke.signing_readiness_v3_matches_profile(value, self.detail()))

    def test_v3_unknown_shape_binding_permissions_and_unbounded_times_fail(self):
        for field, invalid in [('schema_version', 'fw.signing-readiness/v2'), ('project_id', 'another-project'),
                               ('plan_hash', 'sha256:' + 'f' * 64), ('signing_allowed', True), ('dispatch_allowed', 0),
                               ('private_key', PRIVATE), ('checked_at', '2026-02-31T00:00:00Z'),
                               ('valid_until', '2026-11-06T00:01:01Z')]:
            with self.subTest(field=field):
                value = self.canonical()
                value[field] = invalid
                self.assertFalse(smoke.signing_readiness_v3_matches_fixture(value, self.detail()))
        for field in ('bootstrap_authorization_hash', 'target_bootstrap'):
            value = self.canonical()
            del value[field]
            self.assertFalse(smoke.signing_readiness_v3_matches_fixture(value, self.detail()))


if __name__ == '__main__':
    unittest.main()
