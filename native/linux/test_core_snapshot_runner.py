"""Refusal observations permit natural token aging, never changed native state."""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest

import core_access_lifecycle as core


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
