"""Refusal observations permit natural token aging, never changed native state."""
import copy
import base64
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

import core_access_lifecycle as core
import signed_lifecycle as lab


class OriginalBoundaryProof(unittest.TestCase):
    def fixture(self):
        name = 'fw_live_' + '3' * 24
        installation = {'manifest': {
            'binding': {'wall_time_unix': 100, 'monotonic_millis': 1000,
                        'clock_uncertainty_seconds': 1, 'elapsed_seconds': 0, 'commit_budget_seconds': 5},
            'tokens': [{'token_name': name, 'absolute_expiry_unix': 160,
                        'cutoff_unix': 159, 'timeout_seconds': 54}],
        }}
        record = {'observed_at_unix': 110, 'started_monotonic_millis': 10900, 'monotonic_millis': 11000,
                  'raw': {'nftables': [{'set': {'name': name, 'elem': [
                      {'elem': {'val': 6, 'timeout': 54, 'expires': 44}}]}}]}}
        return record, installation, {'expires_at_unix': 160, 'core_token_names': [name]}

    def test_initial_and_original_end_minus_eight_have_positive_independent_lower_bounds(self):
        record, installation, metadata = self.fixture()
        self.assertEqual(core.original_token_lifetime_bounds(record, installation, metadata)['minimum_remaining_seconds'], 43)
        record.update(observed_at_unix=152, started_monotonic_millis=52900, monotonic_millis=53000)
        record['raw']['nftables'][0]['set']['elem'][0]['elem']['expires'] = 2
        self.assertEqual(core.original_token_lifetime_bounds(record, installation, metadata)['minimum_remaining_seconds'], 1)

    def test_short_lifetime_that_old_upper_bound_only_check_accepted_is_refused(self):
        record, installation, metadata = self.fixture()
        record['raw']['nftables'][0]['set']['elem'][0]['elem']['expires'] = 1
        # The old check only compared this value with the E-based maximum (49).
        self.assertLess(1, metadata['expires_at_unix'] - record['observed_at_unix'])
        with self.assertRaises(ValueError):
            core.original_token_lifetime_bounds(record, installation, metadata)

    def test_changed_timeout_and_manifest_cannot_lower_the_independent_minimum(self):
        record, installation, metadata = self.fixture()
        element = record['raw']['nftables'][0]['set']['elem'][0]['elem']
        element.update(timeout=2, expires=1)
        installation['manifest']['tokens'][0]['timeout_seconds'] = 2
        with self.assertRaises(ValueError):
            core.original_token_lifetime_bounds(record, installation, metadata)

    def test_missing_refreshed_and_too_late_token_samples_are_refused(self):
        record, installation, metadata = self.fixture()
        for mutate in (
            lambda value: value['raw']['nftables'].clear(),
            lambda value: value['raw']['nftables'][0]['set']['elem'][0]['elem'].update(expires=50),
            lambda value: value.update(observed_at_unix=155, started_monotonic_millis=55900, monotonic_millis=56000),
            lambda value: value.update(started_monotonic_millis=999),
        ):
            changed = copy.deepcopy(record)
            mutate(changed)
            with self.assertRaises(ValueError):
                core.original_token_lifetime_bounds(changed, installation, metadata)

    def test_positive_bracket_cannot_pass_by_sampling_early_late_or_after_clock_rollback(self):
        self.assertTrue(core.original_positive_bracket(152, 160, 6, 152.01, 152.05, .04))
        for started, finished, duration in ((151, 151.1, .1), (154, 154.1, .1),
                                            (152, 154.1, 2.1), (152, 151.9, .1),
                                            (152, 152.2, .01)):
            self.assertFalse(core.original_positive_bracket(152, 160, 6, started, finished, duration))


class ExactRefusalProof(unittest.TestCase):
    loader_warning = "/lab/fw_linux_executor: /lib/x86_64-linux-gnu/libc.so.6: weak version `GLIBC_2.39' not found (required by /lab/fw_linux_executor)\n"

    def test_forgery_reaches_ed25519_signature_shape_instead_of_old_66_byte_length_failure(self):
        forged = base64.b64decode(core.forged_core_signature(), validate=True)
        self.assertEqual(len(forged), 64)
        self.assertNotEqual(len(base64.b64decode('A' * 88, validate=True)), len(forged))

    def test_exact_primary_code_and_trust_load_stage_are_recorded(self):
        crypto = subprocess.CompletedProcess([], 1, '', 'CORE_BUNDLE_GRANT_SIGNATURE\nCORE_ACCESS_BUNDLE_REJECTED\n')
        self.assertEqual(lab.refusal_reason(crypto, 'CORE_BUNDLE_GRANT_SIGNATURE'),
                         {'reason_code': 'CORE_BUNDLE_GRANT_SIGNATURE', 'refusal_stage': 'core-bundle'})
        trust = subprocess.CompletedProcess([], 1, '', 'LAB_TRUST_BINDING\n')
        self.assertEqual(lab.refusal_reason(trust, 'LAB_TRUST_BINDING')['refusal_stage'], 'trust-load')
        with self.assertRaises(AssertionError):
            lab.refusal_reason(trust, 'CORE_BUNDLE_GRANT_SIGNATURE')

    def test_actual_leading_loader_warning_preserves_exact_signature_and_parse_refusals(self):
        for expected, diagnostic in (
            ('CORE_BUNDLE_GRANT_SIGNATURE', 'CORE_BUNDLE_GRANT_SIGNATURE\nCORE_ACCESS_BUNDLE_REJECTED\n'),
            ('CORE_BUNDLE_MATERIAL', 'CORE_BUNDLE_MATERIAL\nCORE_ACCESS_BUNDLE_PARSE\nCORE_ACCESS_BUNDLE_REJECTED\n'),
            ('LAB_TRUST_BINDING', 'LAB_TRUST_BINDING\n'),
        ):
            result = subprocess.CompletedProcess([], 1, '', self.loader_warning + diagnostic)
            self.assertEqual(lab.split_loader_warning(result.stderr), (diagnostic, True))
            self.assertEqual(lab.refusal_reason(result, expected)['reason_code'], expected)

    def test_loader_warning_never_hides_missing_primary_wrong_nested_reason_or_extra_output(self):
        refusal = 'CORE_BUNDLE_GRANT_SIGNATURE\nCORE_ACCESS_BUNDLE_REJECTED\n'
        for stderr in (
            self.loader_warning,
            self.loader_warning + 'CORE_ACCESS_BUNDLE_REJECTED\n',
            self.loader_warning + 'CORE_BUNDLE_GRANT_TIME\nCORE_ACCESS_BUNDLE_REJECTED\n',
            self.loader_warning + 'CORE_BUNDLE_GRANT_TIME\n' + refusal,
            self.loader_warning * 2 + refusal,
            refusal + self.loader_warning,
            self.loader_warning + refusal + 'CORE_ACCESS_BUNDLE_REJECTED\n',
            self.loader_warning + refusal + 'unexpected output\n',
            self.loader_warning.replace('2.39', '2.40') + refusal,
            self.loader_warning.replace('fw_linux_executor', 'other_binary') + refusal,
            self.loader_warning.replace('libc.so.6', 'libcrypto.so.3') + refusal,
            self.loader_warning.rstrip('\n') + refusal,
            self.loader_warning + 'CORE_BUNDLE_GRANT_SIGNATURE\nCORE_ACCESS_BUNDLE_PARSE\nCORE_ACCESS_BUNDLE_REJECTED\n',
        ):
            with self.subTest(stderr=stderr), self.assertRaises(AssertionError):
                lab.refusal_reason(subprocess.CompletedProcess([], 1, '', stderr), 'CORE_BUNDLE_GRANT_SIGNATURE')

    def test_old_nonzero_exit_acceptance_cannot_hide_other_reasons_or_unbounded_output(self):
        for code, stdout, stderr in (
            (1, '', 'CORE_BUNDLE_GRANT_TIME\nCORE_ACCESS_BUNDLE_REJECTED\n'),
            (1, '', 'CORE_ACCESS_BUNDLE_REJECTED\n'),
            (1, '', 'CORE_BUNDLE_GRANT_TIME\nCORE_BUNDLE_GRANT_SIGNATURE\n'),
            (1, 'unexpected output', 'CORE_BUNDLE_GRANT_SIGNATURE\n'),
            (1, '', 'sensitive arbitrary stderr\nCORE_BUNDLE_GRANT_SIGNATURE\n'),
            (1, '', 'CORE_BUNDLE_GRANT_SIGNATURE\n' * 200),
            (2, '', 'CORE_BUNDLE_GRANT_SIGNATURE\n'),
        ):
            with self.assertRaises(AssertionError):
                lab.refusal_reason(subprocess.CompletedProcess([], code, stdout, stderr), 'CORE_BUNDLE_GRANT_SIGNATURE')


class RefusalSnapshotProof(unittest.TestCase):
    def fixture(self):
        token = 'fw_live_' + '1' * 24
        bundle = {'previous_installation': {'manifest': {
            'binding': {'wall_time_unix': 100, 'monotonic_millis': 1000},
            'tokens': [{'token_name': token, 'cutoff_unix': 200}],
        }}}
        raw = {'nftables': [
            {'table': {'family': 'inet', 'name': 'fw_fixture', 'handle': 1}},
            {'set': {'name': token, 'handle': 2, 'type': 'inet_proto', 'flags': ['timeout'],
                     'elem': [{'elem': {'val': 6, 'timeout': 95, 'expires': 85}}]}},
            {'rule': {'handle': 3, 'expr': [{'drop': None}], 'comment': 'deny fixture'}},
        ]}
        before = {'raw': raw, 'observed_at_unix': 110, 'started_monotonic_millis': 10900, 'monotonic_millis': 11000}
        after = copy.deepcopy(before)
        after.update(observed_at_unix=113, started_monotonic_millis=13900, monotonic_millis=14000)
        after['raw']['nftables'][1]['set']['elem'][0]['elem']['expires'] = 82
        return before, after, bundle

    def test_natural_expiry_decay_keeps_all_static_native_fields(self):
        before, after, bundle = self.fixture()
        self.assertNotEqual(before['raw'], after['raw'])
        self.assertTrue(core.identical_native_state_with_aging(before, after, bundle))

    def test_static_mutations_cannot_be_hidden_as_aging(self):
        before, after, bundle = self.fixture()
        for mutate in (
            lambda raw: raw['nftables'][0]['table'].update(handle=10),
            lambda raw: raw['nftables'][1]['set']['elem'][0]['elem'].update(timeout=96),
            lambda raw: raw['nftables'][1]['set']['elem'][0]['elem'].update(val=17),
            lambda raw: raw['nftables'][2]['rule'].update(expr=[{'accept': None}]),
            lambda raw: raw['nftables'][2]['rule'].update(expires=82),
        ):
            changed = copy.deepcopy(after)
            mutate(changed['raw'])
            self.assertFalse(core.identical_native_state_with_aging(before, changed, bundle))

    def test_refresh_disappearance_and_original_cutoff_violations_fail(self):
        before, after, bundle = self.fixture()
        for remaining in (86, 85, 0):
            changed = copy.deepcopy(after)
            changed['raw']['nftables'][1]['set']['elem'][0]['elem']['expires'] = remaining
            self.assertFalse(core.identical_native_state_with_aging(before, changed, bundle))
        missing = copy.deepcopy(after)
        missing['raw']['nftables'][1]['set']['elem'] = []
        self.assertFalse(core.identical_native_state_with_aging(before, missing, bundle))
        late = copy.deepcopy(after)
        late.update(observed_at_unix=199)
        late['raw']['nftables'][1]['set']['elem'][0]['elem']['expires'] = 2
        self.assertFalse(core.identical_native_state_with_aging(before, late, bundle))
        # An unrelated old token's decay must not hide a flat/refreshed token.
        old = copy.deepcopy(before['raw']['nftables'][1])
        old['set']['name'] = 'fw_live_' + '2' * 24
        old['set']['handle'] = 4
        before['raw']['nftables'].append(old)
        after['raw']['nftables'].append(copy.deepcopy(old))
        bundle['previous_installation']['manifest']['tokens'].append(
            {'token_name': old['set']['name'], 'cutoff_unix': 200})
        before['raw']['nftables'][1]['set']['elem'][0]['elem']['expires'] = 10
        after['raw']['nftables'][1]['set']['elem'][0]['elem']['expires'] = 10
        after['raw']['nftables'][-1]['set']['elem'][0]['elem']['expires'] = 75
        self.assertFalse(core.identical_native_state_with_aging(before, after, bundle))


class ReadonlyMaterialSnapshot(unittest.TestCase):
    def setup_database(self, root, material):
        state = root / 'state'
        state.mkdir()
        database = sqlite3.connect(state / 'journal.sqlite3')
        database.executescript('PRAGMA user_version=3; '
                              'CREATE TABLE identity(singleton,org_id,target_id,epoch,highest); '
                              'CREATE TABLE operations(operation_id,grant_hash,generation,baseline_hash,desired_state_hash,'
                              'issued_at,not_after,confirm_not_after,submitted_at,confirm_deadline,state); '
                              'CREATE TABLE execution_material(operation_id,material_hash,material_bytes);')
        database.execute("INSERT INTO identity VALUES(1,'org','target','1','1')")
        database.execute("INSERT INTO operations VALUES('operation','grant','1','before','after',100,145,150,120,150,'VERIFYING')")
        database.execute("INSERT INTO execution_material VALUES('operation','material',?)", (material,))
        database.commit()
        return database, {'directory': root, 'metadata': {'operation_id': 'operation'}}

    def test_observer_reads_without_recovery_and_allows_external_state_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            database, case = self.setup_database(Path(temporary), b'{}')
            try:
                before, raw_before = core.readonly_candidate_material(case)
                self.assertEqual(database.execute('SELECT state FROM operations').fetchone()[0], 'VERIFYING')
                self.assertTrue(before['query_only'])
                self.assertEqual(before['total_changes'], 0)
                self.assertNotIn('state', before)
                # A separate writer's legitimate restart transition is outside
                # this observer's immutable-material comparison.
                database.execute("UPDATE operations SET state='UNKNOWN'")
                database.commit()
                after, raw_after = core.readonly_candidate_material(case)
                self.assertEqual((before, raw_before), (after, raw_after))
                self.assertEqual(database.execute('SELECT state FROM operations').fetchone()[0], 'UNKNOWN')
            finally:
                database.close()

    def test_material_size_bound_does_not_return_an_oversized_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            database, case = self.setup_database(Path(temporary), b'x' * (1024 * 1024 + 1))
            try:
                with self.assertRaises(ValueError):
                    core.readonly_candidate_material(case)
                self.assertEqual(database.execute('SELECT state FROM operations').fetchone()[0], 'VERIFYING')
            finally:
                database.close()


if __name__ == '__main__':
    unittest.main()
