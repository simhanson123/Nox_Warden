"""Report/diagnostic contracts; no container, privileged namespace or packet operations."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/target-bootstrap-linux-lab.py'
SPEC = importlib.util.spec_from_file_location('target_bootstrap_outer_contract', SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
INNER_SPEC = importlib.util.spec_from_file_location('target_bootstrap_inner_contract', SCRIPT.parents[1] / 'native/linux/target_bootstrap_lab.py')
INNER = importlib.util.module_from_spec(INNER_SPEC)
INNER_SPEC.loader.exec_module(INNER)


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


class NamespaceDiagnosticContract(unittest.TestCase):
    @staticmethod
    def packet():
        # Independent wire data: these values never claim an actual namespace.
        return {'version': 1, 'status': 'ERROR', 'stage': 'mount_private_propagation',
                'errno': 1, 'cleanup_errno': None, 'euid': 0, 'egid': 0,
                'cap_eff': '00000000002011c3', 'cap_prm': '00000000002011c3',
                'cap_bnd': '00000000002011c3', 'no_new_privs': 1, 'seccomp': 2,
                'lsm': 'docker-default (enforce)'}

    def rejected(self, raw):
        with self.assertRaisesRegex(RuntimeError, '^namespace diagnostic channel rejected$'):
            INNER.parse_namespace_diagnostic(raw)

    def test_independent_error_and_ready_frames_preserve_observed_boundary(self):
        value = self.packet()
        raw = json.dumps(value).encode('ascii')
        self.assertLessEqual(len(raw), 512)
        self.assertEqual(INNER.parse_namespace_diagnostic(raw), value)
        value.update(status='READY', stage='ready', errno=None)
        self.assertEqual(INNER.parse_namespace_diagnostic(json.dumps(value).encode()), value)

    def test_exception_text_and_filename_never_enter_the_bounded_frame(self):
        private = 'PRIVATE_KEY_PATH_AND_EXCEPTION_MARKER'
        error = PermissionError(errno.EPERM, private, '/' + private)
        value = INNER.namespace_diagnostic('ERROR', 'mount_private_proc', error)
        raw = INNER.namespace_diagnostic_bytes(value)
        self.assertLessEqual(len(raw), 512)
        self.assertNotIn(private.encode(), raw)
        self.assertEqual(INNER.parse_namespace_diagnostic(raw)['errno'], errno.EPERM)

    def test_malformed_private_oversized_and_contradictory_frames_fail_closed(self):
        for key, bad in [('version', True), ('stage', '/private/exception/path'),
                         ('errno', True), ('cleanup_errno', -1), ('euid', -1),
                         ('cap_eff', 'not-a-capability-mask'), ('no_new_privs', True),
                         ('seccomp', 3), ('lsm', 'profile\nprivate-stderr'),
                         ('lsm', 'x' * 97), ('exception', 'PRIVATE_MARKER')]:
            with self.subTest(key=key, value=bad):
                value = self.packet()
                value[key] = bad
                self.rejected(json.dumps(value).encode())
        for raw in [b' ', b'\xff', b'x' * 513,
                    b'{"version":1,"version":1}',
                    json.dumps({**self.packet(), 'status': 'READY', 'stage': 'ready'}).encode()]:
            self.rejected(raw)

    def test_current_namespace_state_is_read_only_and_rejects_unexpected_values(self):
        for text, expected in [('0\n', 0), ('1\n', 1)]:
            with self.subTest(text=text), patch.object(Path, 'read_text', return_value=text), \
                    patch.object(INNER.os, 'readlink', return_value='net:[101]'):
                self.assertEqual(INNER.current_namespace_state(),
                                 {'network_namespace': 'net:[101]', 'conntrack_tcp_loose': expected})
        for text in ['', '2', '-1', 'true']:
            with self.subTest(text=text), patch.object(Path, 'read_text', return_value=text):
                with self.assertRaisesRegex(RuntimeError, '^unexpected namespace conntrack value$'):
                    INNER.current_namespace_state()

    @unittest.skipUnless(hasattr(os, 'fork'), 'diagnostic child pipe requires fork')
    def test_retained_target_requires_zero_without_unshare_or_mount(self):
        # Real child/pipe/reap. Every privileged operation is forbidden by the
        # fake libc; a retained namespace must only inspect its current state.
        fake = SimpleNamespace(unshare=Mock(side_effect=AssertionError('must not unshare')))
        identity = os.readlink('/proc/self/ns/net')
        for loose, succeeds in [(0, True), (1, False)]:
            with self.subTest(loose=loose), patch.object(INNER, 'libc', fake), \
                    patch.object(INNER, 'current_namespace_state', return_value={
                        'network_namespace': identity, 'conntrack_tcp_loose': loose}), \
                    patch.dict(INNER.observations, {}, clear=True):
                if succeeds:
                    pid = INNER.new_namespace('target', retain_initial=True)
                    INNER.reap_namespace(pid)
                    self.assertEqual(INNER.observations['namespace_setup_diagnostics'][0]['status'], 'READY')
                else:
                    with self.assertRaisesRegex(RuntimeError, '^isolated namespace setup refused$'):
                        INNER.new_namespace('target', retain_initial=True)
                    value = INNER.observations['namespace_setup_diagnostics'][0]
                    self.assertEqual((value['stage'], value['errno']), ('verify_initial_conntrack', None))

    @unittest.skipUnless(hasattr(os, 'fork'), 'diagnostic child pipe requires fork')
    def test_newnet_refusal_preserves_errno_without_exception_text(self):
        def denied(*_args):
            INNER.ctypes.set_errno(errno.EACCES)
            return -1
        fake = SimpleNamespace(unshare=Mock(side_effect=denied))
        with patch.object(INNER, 'libc', fake), patch.dict(INNER.observations, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, '^isolated namespace setup refused$'):
                INNER.new_namespace('peer')
            value = INNER.observations['namespace_setup_diagnostics'][0]
            self.assertEqual((value['stage'], value['errno'], value['cleanup_errno']),
                             ('unshare_net', errno.EACCES, None))
            self.assertNotIn('fixture unshare failed', json.dumps(value))


if __name__ == '__main__':
    unittest.main()
