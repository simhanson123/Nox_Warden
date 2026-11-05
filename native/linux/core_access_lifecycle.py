#!/usr/bin/env python3
"""Real core-plan semantics and crypto in the isolated Linux lab.

Approval, workload/delegation and trust provisioning remain synthetic fixtures.
This profile measures actual owned-table state and packets, without production
signing, dispatch or native qualification claims.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading
import time

import signed_lifecycle as lab

captures = []
clock_samples = []
readback_diagnostics = []
refusal_snapshot_diagnostics = []
readonly_journal_observations = []


def sample_clock(case, stage):
    metadata = case['metadata']
    sampled = int(time.time())
    clock_samples.append({'case': case['directory'].name, 'stage': stage, 'sampled_at_unix': sampled,
                          'seconds_since_original_start': sampled - metadata['not_before_unix'],
                          'dispatch_seconds_remaining': metadata['dispatch_not_after_unix'] - sampled,
                          'plan_seconds_remaining': metadata['plan_valid_until_unix'] - sampled,
                          'lease_seconds_remaining': metadata['expires_at_unix'] - sampled})


def initialize_with_readback_diagnostic(case, bundle):
    try:
        return lab.driver(case, 'init')
    except BaseException:
        # Keep only the synthetic owned table, never a host ruleset or private
        # fixture keys. The outer runner retains this bounded failure evidence
        # before its unconditional disposable-container cleanup.
        try:
            diagnostic = {'case': case['directory'].name, 'stage': 'baseline-init',
                          'expected_native': bundle['previous_installation']['native']['nft_json'],
                          'actual_owned_table': lab.snapshot(case['metadata']['table'])}
            if len(json.dumps(diagnostic, separators=(',', ':')).encode()) <= 1024 * 1024:
                readback_diagnostics.append(diagnostic)
            else:
                readback_diagnostics.append({'stage': 'baseline-init', 'reason': 'bounded-diagnostic-size-exceeded'})
        except BaseException:
            readback_diagnostics.append({'stage': 'baseline-init', 'reason': 'owned-table-diagnostic-unavailable'})
        raise


def collect_core_observation(case, role):
    sample_clock(case, role + '-capture-start')
    directory = case['directory']
    retained_before = None
    if role == 'candidate':
        retained_before, material_bytes = readonly_candidate_material(case)
        with open(directory / 'candidate-material.json', 'xb') as output:
            os.chmod(output.name, 0o600)
            output.write(material_bytes)
        lab.private_json(directory / 'candidate-journal-snapshot.json', retained_before)
    challenge = lab.command([lab.FIXTURE, 'challenge-core-observation', str(directory), role])
    output = directory / ('observation-' + role + '.json')
    collected = lab.command([lab.DRIVER, 'collect-evidence',
                             '--artifact', str(directory / ('artifact-' + role + '.json')),
                             '--installation', str(directory / ('installation-' + role + '.json')),
                             '--observer-key', str(directory / 'observer-key.json'),
                             '--challenge', str(directory / ('challenge-' + role + '.json')),
                             '--output', str(output)])
    verified = lab.command([lab.FIXTURE, 'verify-core-observation', str(directory), role, str(output)])
    lab.check('core_' + role + '_actual_signed_capture_matches', collected['captured']
              and verified['comparison'] == 'match' and verified['synthetic_observer_trust']
              and not verified['authority_admission_performed'] and not verified['production_authorized']
              and not challenge['authority_admission_performed'])
    captures.append({'artifact_role': role, 'compilation_hash': challenge['compilation_hash'],
                     'challenge_hash': challenge['challenge_hash'], 'proof_hash': verified['proof_hash'],
                     'readback_hash': verified['readback_hash'], 'observed_state_hash': verified['observed_state_hash']})
    if role == 'candidate':
        retained_after, material_after = readonly_candidate_material(case)
        lab.check('core_candidate_observer_keeps_immutable_journal_material',
                  retained_after == retained_before and material_after == material_bytes
                  and retained_before['total_changes'] == retained_after['total_changes'] == 0)
        readonly_journal_observations.append({'material_hash': retained_before['material_hash'],
                                             'highest_generation': retained_before['highest_generation'],
                                             'query_only': True, 'total_changes_before': 0, 'total_changes_after': 0,
                                             'immutable_material_unchanged': True,
                                             'mutable_operation_state_compared': False})
    if role == 'baseline':
        invalid = json.loads(output.read_text())
        invalid['signature'] = 'A' * 86
        invalid_path = directory / 'invalid-observer-proof.json'
        lab.private_json(invalid_path, invalid)
        lab.command([lab.FIXTURE, 'verify-core-observation', str(directory), role, str(invalid_path)], expected=1)
        lab.check('core_signed_capture_tampering_refused', True)
    sample_clock(case, role + '-capture-finished')


def readonly_candidate_material(case):
    """Read one bounded committed snapshot without opening executor recovery."""
    uri = 'file:' + str(case['directory'] / 'state/journal.sqlite3') + '?mode=ro'
    with sqlite3.connect(uri, uri=True) as database:
        database.execute('PRAGMA query_only=ON')
        database.execute('BEGIN')
        version = database.execute('SELECT user_version FROM pragma_user_version').fetchone()[0]
        query_only = database.execute('SELECT query_only FROM pragma_query_only').fetchone()[0]
        row = database.execute(
            'SELECT m.material_hash,CASE WHEN length(m.material_bytes) BETWEEN 1 AND ? '
            'THEN m.material_bytes ELSE NULL END,o.operation_id,o.grant_hash,o.generation,'
            'o.baseline_hash,o.desired_state_hash,o.issued_at,o.not_after,o.confirm_not_after,'
            'o.submitted_at,o.confirm_deadline,i.org_id,i.target_id,i.epoch,i.highest '
            'FROM execution_material m JOIN operations o ON o.operation_id=m.operation_id '
            'JOIN identity i ON i.singleton=1 WHERE o.operation_id=?',
            (1024 * 1024, case['metadata']['operation_id'])).fetchone()
        changes = database.total_changes
    if version != 3 or query_only != 1 or changes != 0 or row is None:
        raise ValueError('readonly journal snapshot unavailable')
    keys = ('material_hash', 'material_bytes', 'operation_id', 'grant_hash', 'generation',
            'baseline_hash', 'desired_state_hash', 'issued_at', 'not_after', 'confirm_not_after',
            'submitted_at', 'confirm_deadline', 'org_id', 'target_id', 'authority_epoch', 'highest_generation')
    snapshot = dict(zip(keys, row))
    material_bytes = snapshot.pop('material_bytes')
    if type(material_bytes) is not bytes or not 0 < len(material_bytes) <= 1024 * 1024:
        raise ValueError('readonly journal material size')
    snapshot.update(schema_version='fw.core-lab-readonly-material/v1', journal_version=version,
                    query_only=True, total_changes=changes)
    return snapshot, material_bytes


class CoreEchoServers(lab.EchoServers):
    def __init__(self):
        super().__init__()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 18084))
        listener.settimeout(.1)
        listener.listen(16)
        self.listeners.append(listener)
        threading.Thread(target=self.tcp, args=(listener,), daemon=True).start()


def wait_for_original_expiry(timestamp):
    # The complete minimum 60-second original lease remains untouched. This is
    # an outer test wait, independent of every native/dispatch/commit deadline.
    remaining = timestamp - time.time()
    if remaining > 75:
        raise AssertionError('core fixture bounded original expiry wait')
    while remaining > 0:
        time.sleep(min(remaining, 5))
        remaining = timestamp - time.time()


def check_current_dispatch_budget(metadata, name):
    sampled = int(time.time())
    lab.check(name, metadata['core_projection_preverified']
              and sampled < metadata['dispatch_not_after_unix'],
              lease_not_before_unix=metadata['not_before_unix'],
              issued_at_unix=metadata['issued_at_unix'],
              prepared_at_unix=metadata['prepared_at_unix'], sampled_at_unix=sampled,
              dispatch_not_after_unix=metadata['dispatch_not_after_unix'],
              plan_valid_until_unix=metadata['plan_valid_until_unix'],
              preparation_elapsed_seconds=metadata['prepared_at_unix'] - metadata['not_before_unix'],
              dispatch_seconds_remaining=metadata['dispatch_not_after_unix'] - sampled)


def install_initial_baseline(case, bundle):
    binding = bundle['previous_installation']['manifest']['binding']
    payload = json.dumps(bundle['previous_installation']['native']['nft_json'])
    submitted_at = int(time.time())
    submitted_millis = time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000
    elapsed = submitted_millis - binding['monotonic_millis']
    lab.check('core_' + case['metadata']['fixture_execution_profile'] + '_initial_binding_submission_budget',
              Path('/proc/sys/kernel/random/boot_id').read_text().strip() == binding['boot_id']
              and os.readlink('/proc/self/ns/net') == binding['network_namespace']
              and submitted_at >= binding['wall_time_unix']
              and 0 <= elapsed and elapsed + 2000 <= binding['commit_budget_seconds'] * 1000,
              binding_wall_time_unix=binding['wall_time_unix'], submitted_at_unix=submitted_at,
              elapsed_since_binding_millis=elapsed, commit_budget_seconds=binding['commit_budget_seconds'])
    result = subprocess.run(['/usr/sbin/nft', '-j', '-f', '-'], input=payload, text=True,
                            capture_output=True, timeout=2)
    finished_millis = time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000
    lab.check('core_' + case['metadata']['fixture_execution_profile'] + '_initial_baseline_transaction',
              result.returncode == 0 and finished_millis >= submitted_millis
              and 0 <= finished_millis - binding['monotonic_millis'] <= binding['commit_budget_seconds'] * 1000,
              elapsed_millis=finished_millis - submitted_millis,
              completed_since_binding_millis=finished_millis - binding['monotonic_millis'])


def verify_live_dispatch(case, stage, original_window, expected_grant_hash=None):
    verified = lab.command([lab.FIXTURE, 'verify-core-authority', str(case['directory']), 'dispatch'])
    sampled = int(time.time())
    lab.check(stage, verified['verified'] and verified['purpose'] == 'dispatch'
              and verified['not_before'] == original_window['not_before']
              and verified['expires_at'] == original_window['expires_at']
              and verified['checked_at_unix'] <= sampled < case['metadata']['dispatch_not_after_unix']
              and (expected_grant_hash is None or verified['grant_hash'] == expected_grant_hash),
              authority_checked_at_unix=verified['checked_at_unix'], sampled_at_unix=sampled,
              dispatch_not_after_unix=case['metadata']['dispatch_not_after_unix'])
    sample_clock(case, stage)
    return verified['grant_hash']


def native_snapshot_record(case):
    started = time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000
    observed_at = int(time.time())
    raw = lab.snapshot(case['metadata']['table'])
    return {'raw': raw, 'observed_at_unix': observed_at,
            'started_monotonic_millis': started,
            'monotonic_millis': time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000}


def identical_native_state_with_aging(before, after, bundle):
    return identical_installation_state_with_aging(before, after, bundle['previous_installation'])


def identical_installation_state_with_aging(before, after, installation):
    """Ignore only known token expires, then independently constrain their age."""
    manifest = installation['manifest']
    expected = {token['token_name']: token for token in manifest['tokens']}
    binding = manifest['binding']

    def normalize(record):
        if record['monotonic_millis'] < record['started_monotonic_millis']:
            raise ValueError('invalid snapshot time bracket')
        raw = copy.deepcopy(record['raw'])
        remaining = {}
        for item in raw['nftables']:
            token_set = item.get('set')
            if not token_set or token_set.get('name') not in expected:
                continue
            name = token_set['name']
            members = token_set.get('elem')
            if name in remaining or not isinstance(members, list) or len(members) != 1:
                raise ValueError('unsupported token membership')
            element = members[0]['elem']
            expires = element.pop('expires')
            if type(expires) is not int or type(element.get('timeout')) is not int:
                raise ValueError('unsupported token lifetime')
            if not 0 < expires <= element['timeout']:
                raise ValueError('invalid token lifetime')
            remaining[name] = expires
        if remaining.keys() != expected.keys():
            raise ValueError('changed token membership')
        for name, expires in remaining.items():
            token = expected[name]
            utc_maximum = max(0, token['cutoff_unix'] - record['observed_at_unix'])
            horizon_millis = binding['monotonic_millis'] + (token['cutoff_unix'] - binding['wall_time_unix']) * 1000
            monotonic_maximum = max(0, (horizon_millis - record['started_monotonic_millis'] + 999) // 1000)
            if record['started_monotonic_millis'] < binding['monotonic_millis'] or expires > min(utc_maximum, monotonic_maximum):
                raise ValueError('token exceeds original cutoff')
        return raw, remaining

    try:
        old_structure, old_remaining = normalize(before)
        new_structure, new_remaining = normalize(after)
        elapsed = after['started_monotonic_millis'] - before['monotonic_millis']
        # nft JSON represents remaining lifetime in integer seconds. One second
        # is the existing representation quantization, not an expiry extension.
        minimum_decay = max(0, elapsed // 1000 - 1)
        return (len(expected) == len(manifest['tokens']) and elapsed >= 0
                and old_structure == new_structure
                and all(new_remaining[name] <= old_remaining[name] - minimum_decay for name in expected))
    except (KeyError, TypeError, ValueError):
        return False


def verify_refusal_state(case, before, bundle, check_id, retain_pair=False):
    after = native_snapshot_record(case)
    retained = True
    if retain_pair:
        pair = {'check': check_id, 'before': before, 'after': after}
        retained = len(json.dumps(pair, separators=(',', ':')).encode()) <= 1024 * 1024
        if retained:
            refusal_snapshot_diagnostics.append(pair)
    lab.check(check_id, retained and identical_native_state_with_aging(before, after, bundle),
              expires_are_the_only_ignored_fields=True,
              observed_at_unix=after['observed_at_unix'],
              minimum_elapsed_monotonic_millis=after['started_monotonic_millis'] - before['monotonic_millis'])
    return after


def core_access_flow():
    directory = Path('/lab/core-access')
    metadata = lab.command([lab.FIXTURE, 'prepare-core', str(directory)])
    bundle = json.loads((directory / 'bundle.json').read_text())
    plan = bundle['plan']
    case = {'directory': directory, 'metadata': metadata}
    before = bundle['review']['before']
    after = bundle['review']['after']
    old_policies = {policy['policy_id']: policy for policy in before['policies']}
    all_policies = {policy['policy_id']: policy for policy in after['policies']}
    old_output_tcp = [policy for policy in before['policies'] if policy['action'] == 'allow'
                      and policy['scope']['direction'] == 'output'
                      and policy['scope']['transport']['protocol'] == 'tcp']
    lab.check('core_scalar_baseline_preserves_exact_old_output_port_union', len(old_output_tcp) == 3
              and sorted(port['start'] for policy in old_output_tcp
                         for port in policy['scope']['transport']['destination_ports']) == [18080, 18082, 18084]
              and all(len(policy['scope']['transport']['destination_ports']) == 1
                      and policy['scope']['transport']['destination_ports'][0]['start']
                      == policy['scope']['transport']['destination_ports'][0]['end']
                      for policy in old_output_tcp))
    lab.check('core_original_closed_plan_contract', bundle['schema_version'] == 'fw.isolated-core-access-execution-bundle/v1'
              and plan['schema_version'] == 'f.plan/v1' and plan['change_kind'] == 'add_access_lease'
              and 'operations' not in plan and 'candidate_state_ref' not in plan)
    lab.check('core_full_baseline_policies_and_associations_preserved',
              all(all_policies.get(identity) == policy for identity, policy in old_policies.items())
              and all(association in after['associations'] for association in before['associations'])
              and len(after['policies']) == len(before['policies']) + len(plan['requested_policies']))
    lab.check('core_one_fixed_full_original_window', metadata['lease_seconds'] == 60
              and metadata['expires_at_unix'] - metadata['not_before_unix'] == 60
              and all(policy['scope']['family'] == 'ipv4' and policy['scope']['direction'] == 'input'
                      and policy['scope']['transport']['protocol'] == 'tcp'
                      and policy['lifetime']['not_before'] == bundle['lease_window']['not_before']
                      and policy['lifetime']['expires_at'] == bundle['lease_window']['expires_at']
                      for policy in plan['requested_policies']))
    lab.check('core_fixture_trust_and_quota_claims_are_explicit', metadata['synthetic_fixture_authority']
              and metadata['synthetic_approval'] and metadata['development_quota_ledger_reserved']
              and not metadata['human_approval_tested'] and not metadata['workload_delegation_authority_verified']
              and not metadata['production_authorized'])
    check_current_dispatch_budget(metadata, 'core_fixture_preparation_within_original_dispatch_window')
    sample_clock(case, 'before-init')
    original_final_bundle_bytes = (directory / 'bundle.json').read_bytes()
    metadata['final_bundle_hash'] = 'sha256:' + hashlib.sha256(original_final_bundle_bytes).hexdigest()
    install_initial_baseline(case, bundle)
    initialized = initialize_with_readback_diagnostic(case, bundle)
    lab.check('core_actual_full_baseline_readback', initialized.get('initialized') is True
              and initialized['highest_generation'] == '0' and not initialized['production_authorized'])
    sample_clock(case, 'after-init')
    collect_core_observation(case, 'baseline')
    lab.probe(socket.AF_INET, 'tcp', 18084, True, 'core_old_tcp_lease_live_before_patch')
    lab.probe(socket.AF_INET, 'udp', 18081, True, 'core_old_udp_lease_live_before_patch')
    lab.probe(socket.AF_INET, 'tcp', 18080, False, 'core_requested_tcp_dropped_before_patch')
    lab.probe(socket.AF_INET, 'tcp', 18082, False, 'core_existing_deny_live_before_patch')
    baseline_snapshot = native_snapshot_record(case)
    live_grant_hash = verify_live_dispatch(case, 'core_negative_block_starts_with_current_crypto_authority', bundle['lease_window'])
    for name, mutate in [
        ('bad-core-signature', lambda value: value['grant']['dsse']['signatures'][0].update(sig='A' * 88)),
        ('shifted-core-window', lambda value: value['lease_window'].update(not_before='2030-01-01T00:00:00Z')),
        ('extra-core-plan-field', lambda value: value['plan'].update(candidate_state_ref={'object_hash': plan['desired_state_hash']})),
        ('removed-core-after-baseline-policy', lambda value: value['review']['after']['policies'].pop(0)),
    ]:
        invalid = copy.deepcopy(bundle)
        mutate(invalid)
        path = directory / (name + '.json')
        lab.private_json(path, invalid)
        bad_case = dict(case, bundle=path)
        lab.driver(bad_case, 'apply', expected=1)
        baseline_snapshot = verify_refusal_state(case, baseline_snapshot, bundle,
                                                name + '-refused-before-write', name == 'bad-core-signature')
        sample_clock(case, name + '-refused')
    wrong_target_path = directory / 'valid-signature-wrong-core-target.json'
    lab.command([lab.FIXTURE, 'forge-core-target', str(directory), str(wrong_target_path)])
    lab.driver(dict(case, bundle=wrong_target_path), 'apply', expected=1)
    baseline_snapshot = verify_refusal_state(case, baseline_snapshot, bundle,
                                            'core_valid_signature_wrong_target_refused_before_write')
    production_trust = json.loads((directory / 'trust.json').read_text())
    production_trust['production_authorized'] = True
    production_trust_path = directory / 'production-trust-refused.json'
    lab.private_json(production_trust_path, production_trust)
    lab.command([lab.DRIVER, 'apply', '--state-dir', str(directory / 'state'),
                 '--bundle', str(directory / 'bundle.json'), '--trust', str(production_trust_path)], expected=1)
    verify_refusal_state(case, baseline_snapshot, bundle, 'core_production_trust_switch_refused_before_write')
    with sqlite3.connect('file:' + str(directory / 'state/journal.sqlite3') + '?mode=ro', uri=True) as database:
        highest = database.execute('SELECT highest FROM identity WHERE singleton=1').fetchone()[0]
        operation_count = database.execute('SELECT COUNT(*) FROM operations').fetchone()[0]
    lab.check('core_refusals_do_not_consume_generation', highest == '0' and operation_count == 0)
    verify_live_dispatch(case, 'core_negative_block_ends_with_same_current_crypto_authority',
                         bundle['lease_window'], live_grant_hash)
    sample_clock(case, 'before-apply')
    applied = lab.driver(case, 'apply')
    lab.check('core_signed_actual_apply_requires_readback', lab.state(applied) == 'VERIFYING'
              and applied['highest_generation'] == '1' and not applied['production_authorized'])
    sample_clock(case, 'after-apply')
    first_tokens = lab.remaining_tokens(metadata['table'])
    lab.check('core_new_and_old_kernel_tokens_present', set(metadata['core_token_names']) <= first_tokens.keys()
              and len(first_tokens) > len(metadata['core_token_names']))
    probe_path = directory / 'probes.json'
    lab.driver(case, 'probe', extra=['--output', str(probe_path)])
    report = json.loads(probe_path.read_text())
    lab.packet_count += len(report['observations'])
    lab.check('core_real_positive_negative_probe_report', len(report['observations']) == 3
              and not report['production_management_probe'])
    confirmation_path = directory / 'confirmation.json'
    lab.command([lab.FIXTURE, 'confirm-core', str(directory), str(probe_path), str(confirmation_path)])
    sample_clock(case, 'before-confirm')
    confirmed = lab.driver(case, 'confirm', extra=['--confirmation', str(confirmation_path)])
    lab.check('core_exact_signed_confirmation', lab.state(confirmed) == 'CONFIRMED'
              and confirmed['highest_generation'] == '1')
    sample_clock(case, 'after-confirm')
    established = lab.session(socket.AF_INET, 'tcp')
    lab.probe(socket.AF_INET, 'tcp', 18080, True, 'core_established_tcp_live_before_original_expiry', established)
    live_at = int(time.time())
    lab.check('core_requested_connection_is_live_inside_original_window', live_at < metadata['expires_at_unix'],
              observed_at_unix=live_at, expires_at_unix=metadata['expires_at_unix'])
    sample_clock(case, 'established-flow-live')
    lab.probe(socket.AF_INET, 'tcp', 18084, True, 'core_old_tcp_lease_preserved_after_patch')
    lab.probe(socket.AF_INET, 'tcp', 18082, False, 'core_deny_overrides_new_requested_allow')
    # Replay and observation are now confirmation history. They retain the same
    # accepted bundle/installation and never create a fresh submission window.
    retained_before_replay, material_before_replay = readonly_candidate_material(case)
    accepted_installation = json.loads(material_before_replay)['installation_manifest']['installation']
    before_replay = native_snapshot_record(case)
    # Guarantee a positive minimum decay even with one second of nft lifetime
    # representation quantization; incidental verification cost is unnecessary.
    time.sleep(2.1)
    replay = lab.driver(case, 'apply')
    after_replay = native_snapshot_record(case)
    repeated_tokens = lab.remaining_tokens(metadata['table'])
    lab.check('core_same_grant_retry_does_not_refresh_original_window', lab.state(replay) == 'CONFIRMED'
              and replay['highest_generation'] == '1' and repeated_tokens.keys() == first_tokens.keys()
              and all(repeated_tokens[name] <= seconds for name, seconds in first_tokens.items())
              and any(repeated_tokens[name] < seconds for name, seconds in first_tokens.items())
              and identical_installation_state_with_aging(before_replay, after_replay, accepted_installation)
              and (directory / 'bundle.json').read_bytes() == original_final_bundle_bytes,
              actual_state=lab.state(replay), observed_at_unix=int(time.time()),
              highest_generation=replay['highest_generation'],
              remaining_tokens_before=dict(sorted(first_tokens.items())[:16]),
              remaining_tokens_after=dict(sorted(repeated_tokens.items())[:16]))
    reopened = lab.driver(case, 'observe')
    after_reopen = native_snapshot_record(case)
    retained_after_reopen, material_after_reopen = readonly_candidate_material(case)
    reopened_tokens = lab.remaining_tokens(metadata['table'])
    lab.check('core_reopen_observes_saved_installation', lab.state(reopened) == 'CONFIRMED'
              and reopened['highest_generation'] == '1' and reopened_tokens.keys() == repeated_tokens.keys()
              and all(seconds <= repeated_tokens[name] for name, seconds in reopened_tokens.items())
              and identical_installation_state_with_aging(after_replay, after_reopen, accepted_installation)
              and retained_after_reopen == retained_before_replay
              and material_after_reopen == material_before_replay,
              actual_state=lab.state(reopened), observed_at_unix=int(time.time()),
              highest_generation=reopened['highest_generation'],
              retained_material_hash=retained_before_replay['material_hash'],
              remaining_tokens=dict(sorted(reopened_tokens.items())[:16]))
    sample_clock(case, 'after-replay-reopen')
    collect_core_observation(case, 'candidate')
    wait_for_original_expiry(metadata['expires_at_unix'] + 1)
    lab.probe(socket.AF_INET, 'tcp', 18080, False, 'core_established_tcp_expires_at_original_absolute_end', established)
    lab.probe(socket.AF_INET, 'tcp', 18080, False, 'core_new_tcp_blocked_after_original_absolute_end')
    lab.probe(socket.AF_INET, 'tcp', 18084, True, 'core_unrelated_old_tcp_lease_survives_core_expiry')
    lab.probe(socket.AF_INET, 'udp', 18081, True, 'core_unrelated_old_udp_lease_survives_core_expiry')
    lab.probe(socket.AF_INET, 'tcp', 18082, False, 'core_existing_deny_survives_core_expiry')
    expired_tokens = lab.remaining_tokens(metadata['table'])
    lab.check('core_only_original_request_tokens_expire', not set(metadata['core_token_names']) & expired_tokens.keys()
              and bool(expired_tokens))
    late_replay = lab.driver(case, 'apply')
    lab.check('core_expired_retry_keeps_history_and_cannot_rebind', lab.state(late_replay) == 'CONFIRMED'
              and (directory / 'bundle.json').read_bytes() == original_final_bundle_bytes
              and not set(metadata['core_token_names']) & lab.remaining_tokens(metadata['table']).keys())
    model = lab.command([lab.FIXTURE, 'verify-core-time-model', str(directory)])
    lab.check('core_original_authority_clock_model_after_actual_expiry', model['verified']
              and model['not_before'] == bundle['lease_window']['not_before']
              and model['expires_at'] == bundle['lease_window']['expires_at']
              and (directory / 'bundle.json').read_bytes() == original_final_bundle_bytes)
    metadata['pure_core_authority_clock_model'] = model
    sample_clock(case, 'after-pure-time-model')
    lab.remove_table(case)
    return metadata


def core_recovery_flow():
    """Exercise the core verifier's historical recovery branch in a real write.

    This operation remains unconfirmed. Its ordinary watcher reaches the
    original confirmation cap after the normal plan expires; no journal state,
    signing deadline, policy lifetime or process clock is changed by the test.
    """
    directory = Path('/lab/core-access-recovery')
    metadata = lab.command([lab.FIXTURE, 'prepare-core-recovery', str(directory)])
    bundle_path = directory / 'bundle.json'
    original_bundle_bytes = bundle_path.read_bytes()
    bundle = json.loads(original_bundle_bytes)
    case = {'directory': directory, 'metadata': metadata}
    lab.check('core_recovery_original_full_window', metadata['expires_at_unix'] - metadata['not_before_unix'] == 60)
    check_current_dispatch_budget(metadata, 'core_recovery_preparation_within_original_dispatch_window')
    sample_clock(case, 'before-init')
    install_initial_baseline(case, bundle)
    initialized = initialize_with_readback_diagnostic(case, bundle)
    lab.check('core_recovery_actual_baseline_readback', initialized['initialized']
              and initialized['highest_generation'] == '0')
    applied = lab.driver(case, 'apply')
    lab.check('core_recovery_candidate_accepted_unconfirmed', lab.state(applied) == 'VERIFYING'
              and applied['highest_generation'] == '1')
    sample_clock(case, 'after-apply')
    established = lab.session(socket.AF_INET, 'tcp')
    lab.probe(socket.AF_INET, 'tcp', 18080, True, 'core_recovery_candidate_established_before_timeout', established)
    lab.probe(socket.AF_INET, 'tcp', 18084, True, 'core_recovery_old_lease_positive_control')

    database_uri = 'file:' + str(directory / 'state/journal.sqlite3') + '?mode=ro'

    def retained_material():
        with sqlite3.connect(database_uri, uri=True) as database:
            material_hash, material_bytes = database.execute(
                'SELECT material_hash,material_bytes FROM execution_material WHERE operation_id=?',
                (metadata['operation_id'],)).fetchone()
        return material_hash, bytes(material_bytes)

    original_material_hash, original_material_bytes = retained_material()
    original_material = json.loads(original_material_bytes)
    original_installation = original_material['installation_manifest']['installation']
    wait_for_original_expiry(metadata['confirm_not_after_unix'] + 1)
    sample_clock(case, 'after-original-confirmation-cap')
    verified = lab.command([lab.FIXTURE, 'verify-core-authority', str(directory), 'recovery'])
    lab.command([lab.FIXTURE, 'verify-core-authority', str(directory), 'dispatch'], expected=1)
    lab.check('core_recovery_uses_own_valid_original_authority_after_plan_expiry', verified['verified']
              and verified['purpose'] == 'recovery'
              and metadata['plan_valid_until_unix'] <= verified['checked_at_unix'] < metadata['recovery_valid_until_unix']
              and verified['not_before'] == bundle['lease_window']['not_before']
              and verified['expires_at'] == bundle['lease_window']['expires_at'])
    fresh_state = directory / 'expired-fresh-state'
    lab.command([lab.DRIVER, 'init', '--state-dir', str(fresh_state), '--bundle', str(bundle_path),
                 '--trust', str(directory / 'trust.json')], expected=1)
    lab.check('core_expired_normal_authority_refuses_fresh_acceptance', not fresh_state.exists())

    # Observe the autonomous watcher's actual recovery. A bounded scheduling
    # allowance avoids treating a wakeup race as proof of completed recovery.
    deadline = time.monotonic() + 8
    while True:
        with sqlite3.connect(database_uri, uri=True) as database:
            state, recovered_at = database.execute(
                'SELECT o.state,m.recovered_at FROM operations o JOIN execution_material m '
                'ON m.operation_id=o.operation_id WHERE o.operation_id=?',
                (metadata['operation_id'],)).fetchone()
        if state == 'ROLLED_BACK' or time.monotonic() >= deadline:
            break
        time.sleep(.1)
    lab.check('core_watch_recovers_actual_state_with_historical_core_plan', state == 'ROLLED_BACK'
              and recovered_at is not None
              and metadata['plan_valid_until_unix'] <= recovered_at < metadata['recovery_valid_until_unix'])
    recovered = lab.driver(case, 'recover')
    lab.check('core_recovery_actual_readback_matches_signed_projection', lab.state(recovered) == 'ROLLED_BACK'
              and recovered['highest_generation'] == '1')
    lab.probe(socket.AF_INET, 'tcp', 18080, False, 'core_recovery_existing_requested_flow_blocked', established)
    lab.probe(socket.AF_INET, 'tcp', 18080, False, 'core_recovery_new_requested_flow_blocked')
    lab.probe(socket.AF_INET, 'tcp', 18084, False, 'core_recovery_conservatively_removes_old_allow')
    lab.probe(socket.AF_INET, 'udp', 18081, False, 'core_recovery_conservatively_removes_old_udp_allow')
    lab.probe(socket.AF_INET, 'tcp', 18082, False, 'core_recovery_preserves_existing_explicit_deny')
    readback = lab.snapshot(metadata['table'])
    comments = [item['rule'].get('comment', '') for item in readback['nftables'] if 'rule' in item]
    lab.check('core_restrictive_projection_contains_deny_without_allow_tokens',
              any(comment.startswith('deny:') for comment in comments)
              and not lab.remaining_tokens(metadata['table']))
    with sqlite3.connect(database_uri, uri=True) as database:
        current_state_hash = database.execute('SELECT state_hash FROM identity WHERE singleton=1').fetchone()[0]
    lab.check('core_recovery_records_exact_signed_projection_hash',
              current_state_hash == bundle['recovery']['desired_state_hash'])
    recovery_files = {path.name: path.read_bytes()
                      for path in (directory / 'state').glob('recovery-*-attempt-*.json')}
    lab.check('core_recovery_retains_one_immutable_installation', len(recovery_files) == 1)
    for label, command in [('retry', 'recover'), ('reopen', 'observe'), ('historical-grant', 'apply')]:
        result = lab.driver(case, command)
        lab.check('core_recovery_' + label + '_is_observation_without_reinstall',
                  lab.state(result) == 'ROLLED_BACK' and result['highest_generation'] == '1'
                  and lab.snapshot(metadata['table']) == readback
                  and {path.name: path.read_bytes() for path in (directory / 'state').glob('recovery-*-attempt-*.json')} == recovery_files)
    final_hash, final_material_bytes = retained_material()
    final_material = json.loads(final_material_bytes)
    lab.check('core_recovery_preserves_original_bundle_window_and_candidate_installation',
              bundle_path.read_bytes() == original_bundle_bytes
              and final_hash == original_material_hash and final_material_bytes == original_material_bytes
              and final_material['installation_manifest']['installation'] == original_installation)
    sample_clock(case, 'after-recovery-retries')
    lab.remove_table(case)
    return {'not_before_unix': metadata['not_before_unix'], 'expires_at_unix': metadata['expires_at_unix'],
            'normal_plan_valid_until_unix': metadata['plan_valid_until_unix'],
            'recovery_valid_until_unix': metadata['recovery_valid_until_unix'],
            'authority_checked_at_unix': verified['checked_at_unix'], 'recovered_at_unix': recovered_at,
            'original_material_hash': original_material_hash, 'projection_hash': current_state_hash,
            'final_bundle_hash': 'sha256:' + hashlib.sha256(original_bundle_bytes).hexdigest(),
            'autonomous_watcher_tested': True, 'original_window_rebound': False}


def main():
    farm = None
    report = {'schema_version': 'fw.core-access-linux-lab/v1', 'status': 'FAIL', 'checks': lab.checks,
              'production_supported': False, 'production_signing_allowed': False, 'dispatch_allowed': False,
              'synthetic_fixture_authority': True, 'synthetic_confirmation_authority': True,
              'human_approval_tested': False, 'workload_delegation_authority_verified': False,
              'native_port_policy_profile': 'scalar-port-policy-revisions',
              'multiport_conntrack_set_readback_qualified': False,
              'host_firewall_changed': False, 'independent_hung_owner_watchdog_tested': False}
    try:
        marker = Path('/lab/DISPOSABLE_NETWORK_NAMESPACE').read_text()
        namespace = os.readlink('/proc/self/ns/net')
        outer = os.environ.get('NOX_LAB_OUTER_NETNS')
        lab.check('core_disposable_isolated_namespace', marker == 'nox-linux-loopback-lab-v1\n'
                  and outer is not None and namespace != outer)
        links = json.loads(lab.command(['/usr/sbin/ip', '-j', 'link'], decode=False))
        lab.check('core_only_loopback_interface', [link['ifname'] for link in links] == ['lo'])
        lab.command(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], decode=False)
        farm = CoreEchoServers()
        lab.probe(socket.AF_INET, 'tcp', 18082, True, 'core_negative_probe_service_positive_control')
        lab.probe(socket.AF_INET, 'tcp', 18084, True, 'core_unrelated_service_positive_control')
        metadata = core_access_flow()
        report['original_lease_window'] = {'not_before_unix': metadata['not_before_unix'],
                                         'expires_at_unix': metadata['expires_at_unix'],
                                         'lease_seconds': metadata['lease_seconds']}
        report['pure_core_authority_clock_model'] = metadata['pure_core_authority_clock_model']
        report['final_bundle_hash'] = metadata['final_bundle_hash']
        report['core_recovery'] = core_recovery_flow()
        report['status'] = 'PASS'
    except BaseException as error:
        report['failed_at_unix'] = int(time.time())
        report['error'] = {'type': type(error).__name__}
        if isinstance(error, AssertionError):
            report['error']['check'] = str(error)
        if lab.last_failure:
            report['error']['subprocess'] = lab.last_failure
    finally:
        for resource in lab.resources:
            resource.close()
        if farm:
            farm.close()
        report['count'] = len(lab.checks)
        report['packet_tests_executed'] = lab.packet_count
        report['capture_count'] = len(captures)
        report['native_captures'] = captures
        report['clock_samples'] = clock_samples
        report['owned_table_failure_diagnostics'] = readback_diagnostics
        report['refused_grant_snapshot_diagnostics'] = refusal_snapshot_diagnostics
        report['readonly_journal_observations'] = readonly_journal_observations
        report['synthetic_observer_trust'] = True
        report['authority_native_admission_performed'] = False
        report['network_namespace'] = os.readlink('/proc/self/ns/net')
        print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
