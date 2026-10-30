"""Signed lifecycle runner failure handling; these tests do not invoke Docker."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('signed_lab_runner', ROOT / 'scripts/signed-linux-lab.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class SignedOutcomes(unittest.TestCase):
    def exercise(self, execution=None, cleanup=None, startup=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'native/linux/Dockerfile.lab',
                     'native/linux/signed_lifecycle.py', 'scripts/signed-linux-lab.py',
                     'target/debug/fw_linux_executor', 'target/debug/fw_signed_lab_fixture']
            for crate in ('fw_linux_executor', 'fw_backend_linux', 'fw_authority', 'fw_executor',
                          'fw_contracts', 'fw_domain', 'fw_planner', 'fw_testlab'):
                paths.extend(['crates/' + crate + '/Cargo.toml', 'crates/' + crate + '/src/lib.rs'])
            for name in paths:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'fixture')
            report = root / 'report.json'
            def process(command, **kwargs):
                if 'info' in command and startup:
                    raise OSError('synthetic daemon unavailable')
                if 'inspect' in command:
                    data = b'sha256:fixture\n'
                elif 'rev-parse' in command:
                    data = b'fixture-commit\n'
                elif 'run' in command:
                    data = b'a' * 64 + b'\n'
                elif '/lab/signed_lifecycle.py' in command:
                    if isinstance(execution, BaseException):
                        raise execution
                    code, data = execution or (0, json.dumps({'status': 'PASS', 'packet_tests_executed': 7}))
                    return subprocess.CompletedProcess(command, code, data, '')
                elif 'rm' in command:
                    if isinstance(cleanup, BaseException):
                        raise cleanup
                    return subprocess.CompletedProcess(command, cleanup or 0, b'', b'')
                else:
                    data = b''
                return subprocess.CompletedProcess(command, 0, data, b'')
            with patch.object(runner, 'ROOT', root), patch.object(runner.subprocess, 'run', side_effect=process), \
                 patch.object(sys, 'argv', ['signed-linux-lab.py', '--skip-image-build', '--report', str(report)]), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = runner.main()
            return code, json.loads(report.read_text())

    def test_unavailable_startup_is_not_run(self):
        code, result = self.exercise(startup=True)
        self.assertEqual((code, result['status'], result['packet_tests_executed']), (2, 'NOT_RUN', 0))

    def test_timeout_after_start_is_failure_with_unknown_count(self):
        code, result = self.exercise(execution=subprocess.TimeoutExpired('fixture', 240))
        self.assertEqual((code, result['status']), (1, 'FAIL'))
        self.assertIsNone(result['packet_tests_executed'])
        self.assertTrue(result['container_removed'])

    def test_malformed_report_cannot_pass(self):
        code, result = self.exercise(execution=(0, 'not JSON'))
        self.assertEqual((code, result['status']), (1, 'FAIL'))
        self.assertTrue(result['container_removed'])

    def test_mismatched_exit_preserves_known_packet_count(self):
        code, result = self.exercise(execution=(1, json.dumps({'status': 'PASS', 'packet_tests_executed': 7})))
        self.assertEqual((code, result['status'], result['packet_tests_executed']), (1, 'FAIL', 7))

    def test_cleanup_failure_overrides_success(self):
        for failure in (1, OSError('unavailable'), subprocess.TimeoutExpired('cleanup', 30)):
            with self.subTest(kind=type(failure).__name__):
                code, result = self.exercise(cleanup=failure)
                self.assertEqual((code, result['status'], result['packet_tests_executed']), (1, 'FAIL', 7))
                self.assertFalse(result['container_removed'])
                self.assertIn('cleanup_error', result)


if __name__ == '__main__':
    unittest.main()
