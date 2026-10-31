"""Failure artifacts must locate a phase without retaining browser/operator inputs."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('catalogue_smoke', Path(__file__).with_name('smoke_catalogue_navigation.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class DiagnosticsTests(unittest.TestCase):
    def invoke(self, exception, stage='asset_save_confirmation'):
        private = 'private-key-assertion-input-marker'
        with tempfile.TemporaryDirectory(prefix=private) as temporary:
            output = Path(temporary) / 'private-report.json'
            def fail(_args, report):
                report['stage'] = stage
                raise exception(private)
            stdout = io.StringIO()
            with patch.object(smoke, 'run', fail), patch.object(sys, 'argv', ['smoke', '--controller-binary', private, '--report', str(output)]), contextlib.redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as result:
                    smoke.main()
            self.assertEqual(result.exception.code, 1)
            report = json.loads(output.read_text())
            self.assertNotIn(private, stdout.getvalue() + output.read_text())
            self.assertLess(len(stdout.getvalue()), 200)
            self.assertFalse(report['passed'])
            return report

    def test_assertions_are_sanitized_and_located(self):
        report = self.invoke(AssertionError)
        self.assertEqual(report.get('failure_stage'), 'asset_save_confirmation')
        self.assertEqual(report['failure'], 'CATALOGUE_ASSERTION_FAILED')

    def test_check_failure_does_not_echo_input(self):
        report = self.invoke(smoke.CheckFailed)
        self.assertEqual(report['failure'], 'CATALOGUE_CHECK_FAILED')

    def test_browser_errors_are_a_closed_category(self):
        class Error(Exception):
            pass
        Error.__module__ = 'playwright._impl._errors'
        report = self.invoke(Error)
        self.assertEqual(report['failure'], 'CATALOGUE_BROWSER_FAILED')

    def test_report_write_errors_do_not_print_private_paths(self):
        stdout = io.StringIO()
        with patch.object(smoke, 'run', lambda _args, _report: None), patch.object(sys, 'argv', ['smoke', '--controller-binary', 'unused']), patch.object(Path, 'write_text', side_effect=OSError('private-output-marker')), contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as result:
                smoke.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(stdout.getvalue(), 'FAIL: stage=report_write code=CATALOGUE_REPORT_WRITE_FAILED\n')

    def test_io_and_unknown_phase_are_bounded(self):
        report = self.invoke(OSError, stage='private-key-assertion-input-marker')
        self.assertEqual(report.get('failure_stage'), 'initialization')
        self.assertEqual(report['failure'], 'CATALOGUE_PROCESS_OR_IO_FAILED')

    def test_browser_timeout_is_not_misreported_as_assertion(self):
        class TimeoutError(Exception):
            pass
        report = self.invoke(TimeoutError)
        self.assertEqual(report['failure'], 'CATALOGUE_BROWSER_TIMEOUT')


if __name__ == '__main__':
    unittest.main()
