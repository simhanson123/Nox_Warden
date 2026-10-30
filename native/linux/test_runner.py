"""Regression tests for trustworthy smoke-runner outcomes; no Docker calls."""
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
spec = importlib.util.spec_from_file_location('linux_lab_runner', ROOT/'scripts/linux-lab.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Outcomes(unittest.TestCase):
    def test_startup_unavailable_is_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)/'report.json'
            with patch.object(sys,'argv',['linux-lab.py','--report',str(report)]), patch.object(runner,'execute',side_effect=RuntimeError('Docker unavailable')), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 2)
            result = json.loads(report.read_text())
            self.assertEqual(result['status'], 'NOT_RUN')
            self.assertEqual(result['packet_tests_executed'], 0)

    def run_after_start(self, execution):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ['crates/fw_backend_linux/src/lib.rs','crates/fw_backend_linux/src/readback.rs','crates/fw_backend_linux/src/portable.rs','crates/fw_backend_linux/src/bin/fw_compile_lab.rs','crates/fw_backend_linux/Cargo.toml','crates/fw_domain/src/lib.rs','crates/fw_contracts/src/lib.rs','native/linux/packet_lab.py','native/linux/Dockerfile.lab','Cargo.toml','Cargo.lock','rust-toolchain.toml','target/debug/fw_compile_lab','crates/fw_testlab/src/main.rs','scripts/linux-lab.py']:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
            report=root/'report.json'
            def execute(args, **_):
                if 'inspect' in args: return 'sha256:fixture\n'
                if 'rev-parse' in args: return 'fixture-commit\n'
                if 'status' in args: return ''
                if 'run' in args: return 'a'*64+'\n'
                return ''
            def process(args, **kwargs):
                if '/lab/packet_lab.py' in args:
                    if isinstance(execution,BaseException): raise execution
                    return subprocess.CompletedProcess(args, execution[0], execution[1], '')
                return subprocess.CompletedProcess(args, 0, b'' if 'input' in kwargs else '', b'' if 'input' in kwargs else '')
            with patch.object(runner,'ROOT',root),patch.object(runner,'__file__',str(root/'scripts/linux-lab.py')),patch.object(runner,'execute',side_effect=execute),patch.object(runner.subprocess,'run',side_effect=process),patch.object(sys,'argv',['linux-lab.py','--skip-image-build','--report',str(report)]),contextlib.redirect_stdout(io.StringIO()):
                code=runner.main()
            return code,json.loads(report.read_text())

    def test_transport_timeout_after_start_is_failure_with_unknown_count(self):
        code,result=self.run_after_start(subprocess.TimeoutExpired('docker exec',90))
        self.assertEqual(code,1)
        self.assertEqual(result['status'],'FAIL')
        self.assertIsNone(result['packet_tests_executed'])
        self.assertTrue(result['container_removed'])

    def test_malformed_report_after_start_cannot_return_zero(self):
        code,result=self.run_after_start((0,'not JSON'))
        self.assertEqual(code,1)
        self.assertEqual(result['status'],'FAIL')
        self.assertTrue(result['container_removed'])

    def test_mismatched_result_and_exit_code_cannot_pass(self):
        code,result=self.run_after_start((1,json.dumps({'status':'PASS','packet_tests_executed':40})))
        self.assertEqual(code,1)
        self.assertEqual(result['status'],'FAIL')


if __name__ == '__main__':
    unittest.main()
