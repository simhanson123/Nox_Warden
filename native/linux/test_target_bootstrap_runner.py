"""Outer report contract regressions; no container, process or packet execution."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/target-bootstrap-linux-lab.py'
SPEC = importlib.util.spec_from_file_location('target_bootstrap_outer_contract', SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def report():
    # Independent wire fixture for initial confirmation plus real rotation.
    # Its values are never presented as results of native observations.
    return {'schema_version': 'fw.target-bootstrap-linux-lab/v1', 'status': 'PASS',
            'checks': 3, 'check_names': ['initial target confirmation', 'fresh owner rotation', 'expired history'],
            'packet_tests_executed': 6, 'probe_tests_executed': 8,
            'setup_operator_commands_executed': 18, 'target_operator_commands_executed': 9,
            'operator_commands_executed': 27, 'target_confirmations_accepted': 2,
            'negative_service_preflight_verified': True,
            'production_signing_allowed': False, 'production_dispatch_allowed': False,
            'dispatch_allowed': False, 'production_supported': False,
            'observations': {'initial_confirmation_hash': 'sha256:' + 'a' * 64,
                             'rotation_confirmation_hash': 'sha256:' + 'b' * 64}}


class TargetBootstrapReportContract(unittest.TestCase):
    def rejects(self, value, code=0):
        with self.assertRaises(RUNNER.StageFailure):
            RUNNER.validate_report(value, code)

    def test_complete_report_and_partial_failure_preserve_observed_counts(self):
        value = report()
        before = copy.deepcopy(value)
        self.assertIsNone(RUNNER.validate_report(value, 0))
        self.assertEqual(value, before)
        value.update(status='FAIL', checks=1, check_names=['initial target confirmation'],
                     packet_tests_executed=1, probe_tests_executed=1)
        self.assertIsNone(RUNNER.validate_report(value, 1))

    def test_zero_or_absent_observations_cannot_pass(self):
        for field, invalid in [('checks', 0), ('packet_tests_executed', 0),
                               ('probe_tests_executed', 2), ('target_confirmations_accepted', 1)]:
            with self.subTest(field=field):
                value = report()
                value[field] = invalid
                if field == 'checks':
                    value['check_names'] = []
                self.rejects(value)
                value = report()
                del value[field]
                self.rejects(value)
        value = report()
        value['packet_tests_executed'] = 9
        self.rejects(value)

    def test_operator_counts_are_integral_and_complete(self):
        for field, invalid in [('setup_operator_commands_executed', 17),
                               ('setup_operator_commands_executed', 18.0),
                               ('target_operator_commands_executed', 6),
                               ('target_operator_commands_executed', True),
                               ('operator_commands_executed', 26),
                               ('operator_commands_executed', 27.0)]:
            with self.subTest(field=field, value=invalid):
                value = report()
                value[field] = invalid
                self.rejects(value)

    def test_production_boundaries_and_preflight_must_be_explicit(self):
        for field in ['production_signing_allowed', 'production_dispatch_allowed',
                      'dispatch_allowed', 'production_supported']:
            for invalid in [True, None, 0]:
                with self.subTest(field=field, value=invalid):
                    value = report()
                    value[field] = invalid
                    self.rejects(value)
            value = report()
            del value[field]
            self.rejects(value)
        for invalid in [False, None, 1]:
            value = report()
            value['negative_service_preflight_verified'] = invalid
            self.rejects(value)

    def test_schema_and_exit_cannot_disagree(self):
        value = report()
        value['schema_version'] = 'fw.protected-signer-smoke/v1'
        self.rejects(value)
        self.rejects(report(), 1)
        self.rejects(report(), 2)
        self.rejects(report(), False)
        value = report()
        value['status'] = 'FAIL'
        self.rejects(value, 0)

    def test_count_and_unique_check_names_must_describe_one_inventory(self):
        for invalid in [True, 3.0, 2]:
            value = report()
            value['checks'] = invalid
            self.rejects(value)
        for names in [['same', 'same', 'other'], ['', 'second', 'third'], ['x' * 257, 'second', 'third']]:
            value = report()
            value['check_names'] = names
            self.rejects(value)

    def test_duplicate_json_fields_are_rejected_at_every_depth(self):
        for raw in ['{"status":"FAIL","status":"PASS"}',
                    '{"observations":{"dispatch_allowed":true,"dispatch_allowed":false}}']:
            with self.assertRaises(RUNNER.StageFailure):
                json.loads(raw, object_pairs_hook=RUNNER.strict_object)

    def test_private_fixture_fields_cannot_become_report_evidence(self):
        for field in ['seed', 'private_key', 'raw_assertion', 'clientDataJSON', 'authenticatorData', 'config']:
            with self.subTest(field=field):
                value = report()
                value['observations']['nested'] = {field: 'private-marker-never-write-to-artifact'}
                self.rejects(value)

    def test_inner_report_cannot_claim_outer_provenance_or_cleanup(self):
        for field, claim in [('container_removed', True), ('source_unchanged', True),
                             ('source_sha256', {}), ('binary_sha256', {}),
                             ('build_mode', 'internal_build'), ('runner_exit_code', 0)]:
            value = report()
            value[field] = claim
            self.rejects(value)
        value = report()
        value['observations']['duration'] = float('nan')
        self.rejects(value)

    def test_prebuild_inventory_includes_compiled_contract_and_excludes_binaries(self):
        paths = set(RUNNER.source_paths())
        self.assertIn(RUNNER.ROOT / 'docs/specs/F_기준자료/F_개발계약/F_계약_예제.json', paths)
        self.assertIn(SCRIPT, paths)
        for binary in RUNNER.BINARY_PATHS.values():
            self.assertNotIn(RUNNER.ROOT / binary, paths)


if __name__ == '__main__':
    unittest.main()
