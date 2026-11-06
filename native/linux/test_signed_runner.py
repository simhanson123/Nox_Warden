"""Signed lifecycle runner failure handling; these tests do not invoke Docker."""
import contextlib
import copy
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


def core_report():
    digest = 'sha256:' + '1' * 64
    captures = [{'artifact_role': role, 'reference_source': 'separate-trusted-lab-input',
                 'reference_revision': '1', **{field: digest for field in
                    ('reference_pin_hash', 'references_hash', 'expected_artifact_hash', 'submitted_artifact_hash',
                     'compilation_hash', 'challenge_hash', 'proof_hash', 'readback_hash', 'observed_state_hash')}}
                for role in ('baseline', 'candidate')]
    return {'schema_version': 'fw.core-access-linux-lab/v1', 'status': 'PASS',
            'packet_tests_executed': 7, 'capture_count': 2, 'native_captures': captures,
            'original_lease_window': {'expires_at_unix': 160},
            'original_expiry_boundary_observations': [
                {'kind': 'positive', 'original_expires_at_unix': 160, 'target_unix': 152,
                 'started_at_unix': 152.01, 'finished_at_unix': 152.05,
                 'actual_elapsed_monotonic_seconds': .04,
                 'conservative_binding_deduction_seconds': 6, 'packet_sampling_margin_seconds': 2,
                 'clock_uncertainty_seconds': 1, 'elapsed_seconds': 0, 'commit_budget_seconds': 5,
                 'binding_wall_time_unix': 100, 'binding_monotonic_millis': 1000,
                 'sample_observed_at_unix': 152, 'sample_started_monotonic_millis': 53010,
                 'sample_finished_monotonic_millis': 53040,
                 'initial_timeout_seconds': 54, 'nft_representation_tolerance_seconds': 1,
                 'monotonic_sampling_tolerance_millis': 1,
                 'minimum_remaining_seconds': 1, 'maximum_remaining_seconds': 7,
                 'actual_remaining_seconds': {'token': 2}},
                {'kind': 'negative', 'original_expires_at_unix': 160, 'sampled_at_unix': 161.01,
                 'core_tokens_absent': True, 'new_and_established_tcp_blocked': True}]}


class SignedOutcomes(unittest.TestCase):
    def exercise(self, execution=None, cleanup=None, startup=False, profile='legacy'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'native/linux/Dockerfile.lab',
                     'native/linux/signed_lifecycle.py', 'scripts/signed-linux-lab.py',
                     'target/debug/fw_linux_executor', 'target/debug/fw_signed_lab_fixture']
            if profile == 'core-access':
                paths.extend(['native/linux/core_access_lifecycle.py', 'scripts/core-access-linux-lab.py'])
            for crate in ('fw_linux_executor', 'fw_backend_linux', 'fw_authority', 'fw_executor',
                          'fw_contracts', 'fw_domain', 'fw_planner', 'fw_testlab',
                          'fw_native_evidence', 'fw_target_evidence'):
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
                elif '/lab/signed_lifecycle.py' in command or '/lab/core_access_lifecycle.py' in command:
                    if isinstance(execution, BaseException):
                        raise execution
                    schema = 'fw.core-access-linux-lab/v1' if profile == 'core-access' else 'fw.signed-linux-lab/v1'
                    report = (core_report() if profile == 'core-access' else
                              {'schema_version': schema, 'status': 'PASS', 'packet_tests_executed': 7})
                    code, data = execution or (0, json.dumps(report))
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
                code = runner.main(profile=profile)
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

    def test_core_profile_keeps_separate_schema_and_capture_count(self):
        code, result = self.exercise(profile='core-access')
        self.assertEqual((code, result['schema_version'], result['capture_count']),
                         (0, 'fw.core-access-linux-lab/v1', 2))

    def test_core_profile_rejects_legacy_or_missing_capture_report(self):
        for report in ({'schema_version': 'fw.signed-linux-lab/v1', 'status': 'PASS', 'packet_tests_executed': 7},
                       {'schema_version': 'fw.core-access-linux-lab/v1', 'status': 'PASS', 'packet_tests_executed': 7, 'capture_count': 1}):
            with self.subTest(report=report):
                code, result = self.exercise(profile='core-access', execution=(0, json.dumps(report)))
                self.assertEqual((code, result['status'], result['packet_tests_executed']), (1, 'FAIL', 7))

    def test_old_pass_or_missing_pin_and_positive_boundary_cannot_satisfy_core_profile(self):
        mutations = (
            lambda value: value.pop('original_expiry_boundary_observations'),
            lambda value: value['native_captures'][0].pop('reference_pin_hash'),
            lambda value: value['native_captures'][1].update(submitted_artifact_hash='sha256:' + '2' * 64),
            lambda value: value['original_expiry_boundary_observations'][0].update(minimum_remaining_seconds=0),
            lambda value: value['original_expiry_boundary_observations'][0].update(finished_at_unix=161),
            lambda value: value['original_expiry_boundary_observations'][1].update(sampled_at_unix=159),
        )
        for mutate in mutations:
            report = copy.deepcopy(core_report())
            mutate(report)
            with self.assertRaises(runner.StageFailure):
                runner.validate_core_evidence(report)

    def test_core_boundary_requires_the_exact_original_end_minus_eight_target_and_six_second_deduction(self):
        mutations = (
            lambda value: value.pop('target_unix'),
            lambda value: value.update(target_unix=100, started_at_unix=100.01, finished_at_unix=100.05),
            lambda value: value.update(target_unix=151),
            lambda value: value.update(target_unix=152.0),
            lambda value: value.update(conservative_binding_deduction_seconds=5),
            lambda value: value.pop('conservative_binding_deduction_seconds'),
            lambda value: value.update(packet_sampling_margin_seconds=3),
        )
        for mutate in mutations:
            report = copy.deepcopy(core_report())
            mutate(report['original_expiry_boundary_observations'][0])
            with self.subTest(mutate=mutate), self.assertRaises(runner.StageFailure):
                runner.validate_core_evidence(report)

    def test_core_boundary_independently_pins_executor_constants_and_clock_relationship(self):
        mutations = (
            {'clock_uncertainty_seconds': 10}, {'elapsed_seconds': 15}, {'commit_budget_seconds': 20},
            {'clock_uncertainty_seconds': True}, {'elapsed_seconds': 0.0}, {'commit_budget_seconds': 5.0},
            {'sample_observed_at_unix': 150}, {'sample_observed_at_unix': 154},
            {'sample_started_monotonic_millis': 999},
            {'sample_finished_monotonic_millis': 53009},
            {'minimum_remaining_seconds': 2}, {'maximum_remaining_seconds': 8},
            {'initial_timeout_seconds': 53}, {'monotonic_sampling_tolerance_millis': 0},
            {'actual_remaining_seconds': {'token': 0}}, {'actual_remaining_seconds': {'token': 8}},
            {'actual_remaining_seconds': {'token': True}},
            {'started_at_unix': float('nan')}, {'actual_elapsed_monotonic_seconds': float('inf')},
        )
        for changed in mutations:
            report = copy.deepcopy(core_report())
            report['original_expiry_boundary_observations'][0].update(changed)
            with self.subTest(changed=changed), self.assertRaises(runner.StageFailure):
                runner.validate_core_evidence(report)

    def test_core_boundary_missing_clock_fields_are_stage_failures(self):
        for field in ('clock_uncertainty_seconds', 'elapsed_seconds', 'commit_budget_seconds',
                      'binding_wall_time_unix', 'binding_monotonic_millis', 'sample_observed_at_unix',
                      'sample_started_monotonic_millis', 'sample_finished_monotonic_millis',
                      'started_at_unix', 'finished_at_unix', 'actual_elapsed_monotonic_seconds'):
            report = copy.deepcopy(core_report())
            report['original_expiry_boundary_observations'][0].pop(field)
            with self.subTest(field=field), self.assertRaises(runner.StageFailure):
                runner.validate_core_evidence(report)


if __name__ == '__main__':
    unittest.main()
