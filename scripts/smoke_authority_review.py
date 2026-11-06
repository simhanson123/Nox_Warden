#!/usr/bin/env python3
"""Exercise the shipped independent review UI against the real authority service.

The separate Rust fixture provisions a disposable pinned test key and real
planner evidence; Chromium signs via a CDP virtual CTAP2 authenticator. This
checks protocol integration, not physical-key support, human consent, host
firewall enforcement, independent OS deployment or release qualification.
Private fixture material stays in a temporary directory and is never reported.
"""
import argparse
import copy
from contextlib import ExitStack
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://localhost:8790'

# Keep service diagnostics separate from smoke phases. Only these exact pairs
# may survive private-directory cleanup; never retain arbitrary log lines.
STARTUP_DIAGNOSTICS = {
    'arguments': 'AUTHORITY_ARGUMENTS_REJECTED',
    'config': 'AUTHORITY_CONFIG_REJECTED',
    'session_key': 'AUTHORITY_SESSION_KEY_REJECTED',
    'origin': 'AUTHORITY_ORIGIN_REJECTED',
    'database': 'AUTHORITY_DATABASE_REJECTED',
    'trust': 'AUTHORITY_TRUST_REJECTED',
    'ui_assets': 'AUTHORITY_UI_ASSETS_REJECTED',
    'review_evidence': 'AUTHORITY_REVIEW_EVIDENCE_REJECTED',
    'runtime_key': 'AUTHORITY_RUNTIME_KEY_UNAVAILABLE',
    'bind': 'AUTHORITY_BIND_UNAVAILABLE',
    'listener': 'AUTHORITY_LISTENER_STOPPED',
}
SERVICE_LOG_LIMIT = 1024
SERVICE_READY_LINE = (b'Authority review is listening on its configured loopback origin. '
                      b'No signer or host enforcement is enabled.\n')
EXPECTED_SERVICE_STARTS = 2
STAGES = frozenset({
    'initialization', 'fixture_provision', 'service_start', 'service_ready',
    'browser_start', 'browser_checks', 'service_restart', 'service_restart_ready',
    'session_recovery', 'cleanup', 'complete',
})


def signing_readiness_matches_fixture(value, detail):
    """The fixture has no quota pin, generation or retained signing intent."""
    return (isinstance(value, dict)
            and set(value) == {'schema_version', 'org_id', 'project_id', 'target_id',
                               'plan_id', 'plan_hash', 'checked_at', 'valid_until',
                               'signing_allowed', 'dispatch_allowed', 'reasons',
                               'approval_set_hash', 'quota_configured', 'target_generation',
                               'latest_intent', 'quota_scope', 'quota_root_id',
                               'latest_dispatch_unknown_seen'}
            and value['schema_version'] == 'fw.signing-readiness/v2'
            and all(value[field] == detail['plan'][field]
                    for field in ('org_id', 'project_id', 'target_id', 'plan_id'))
            and value['plan_hash'] == detail['plan_hash']
            and value['signing_allowed'] is False and value['dispatch_allowed'] is False
            and value['quota_configured'] is False and value['target_generation'] is None
            and value['latest_intent'] is None and value['latest_dispatch_unknown_seen'] is None
            and value['quota_scope'] is None and value['quota_root_id'] is None)


V3_PERMANENT_BLOCKERS = frozenset({
    'BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED',
    'POLICY_SIGNER_KEY_REQUIRED', 'PROTECTED_SIGNER_UNAVAILABLE',
})
V3_SIGNING_REASONS = V3_PERMANENT_BLOCKERS | frozenset({
    'BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED', 'BOOTSTRAP_AUTHORIZATION_REQUIRED',
    'BOOTSTRAP_AUTHORIZATION_NOT_CURRENT', 'TARGET_EPOCH_CONFIRMATION_REQUIRED',
    'WORKLOAD_SOURCE_ATTESTATION_REQUIRED', 'WORKLOAD_BINDING_NOT_CURRENT',
    'OWNER_PROOF_REQUIRED', 'PLAN_STALE', 'REVIEW_EVIDENCE_MISSING',
    'APPROVAL_SET_MISSING', 'TARGET_METADATA_MISSING', 'NATIVE_BASELINE_UNAVAILABLE',
    'QUOTA_CONFIGURATION_MISSING', 'TARGET_GENERATION_UNINITIALIZED',
    'CORE_REQUEST_BINDING_UNAVAILABLE', 'CORE_SIGNING_PROFILE_UNAVAILABLE',
})


def canonical_readiness_time(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}Z', value):
        return None
    try:
        seconds = int(datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp())
        return seconds if seconds >= 0 else None
    except (ValueError, OverflowError):
        return None


def readiness_hash(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


def readiness_counter(value, *, positive=False):
    return (isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value) is not None
            and int(value) <= 18446744073709551615 and (not positive or value != '0'))


def signing_readiness_v3_matches_profile(value, detail):
    """Closed v3 evidence for the smoke's no-quota, no-job diagnostic profile.

    Accepted target history and current plan eligibility are separate. This
    parser never derives production permission from either of them.
    """
    keys = {'schema_version', 'org_id', 'project_id', 'target_id', 'plan_id', 'plan_hash',
            'checked_at', 'valid_until', 'signing_allowed', 'dispatch_allowed', 'reasons',
            'approval_set_hash', 'quota_configured', 'target_generation', 'latest_intent',
            'quota_scope', 'quota_root_id', 'latest_dispatch_unknown_seen',
            'bootstrap_authorization_hash', 'target_bootstrap'}
    if not isinstance(value, dict) or set(value) != keys or not isinstance(detail, dict) or not isinstance(detail.get('plan'), dict):
        return False
    try:
        if (value['schema_version'] != 'fw.signing-readiness/v3'
                or any(value[field] != detail['plan'][field] for field in ('org_id', 'project_id', 'target_id', 'plan_id'))
                or value['plan_hash'] != detail['plan_hash']
                or value['signing_allowed'] is not False or value['dispatch_allowed'] is not False
                or value['quota_configured'] is not False or value['target_generation'] is not None
                or value['latest_intent'] is not None or value['latest_dispatch_unknown_seen'] is not None
                or value['quota_scope'] is not None or value['quota_root_id'] is not None):
            return False
        checked = canonical_readiness_time(value['checked_at'])
        deadline = canonical_readiness_time(value['valid_until'])
        plan_end = canonical_readiness_time(detail['plan']['valid_until'])
        if None in (checked, deadline, plan_end) or deadline > plan_end or deadline - checked > 60:
            return False
        reasons = value['reasons']
        if (not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons)
                or len(reasons) > len(V3_SIGNING_REASONS) or len(set(reasons)) != len(reasons)
                or not set(reasons) <= V3_SIGNING_REASONS or not V3_PERMANENT_BLOCKERS <= set(reasons)):
            return False
        reasons = set(reasons)
        approval = value['approval_set_hash']
        authorization = value['bootstrap_authorization_hash']
        if (approval is not None and not readiness_hash(approval)
                or ('APPROVAL_SET_MISSING' in reasons) != (approval is None)
                or 'QUOTA_CONFIGURATION_MISSING' not in reasons
                or 'TARGET_GENERATION_UNINITIALIZED' not in reasons
                or authorization is not None and not readiness_hash(authorization)
                or ('BOOTSTRAP_AUTHORIZATION_REQUIRED' in reasons) != (authorization is None)
                or authorization is not None and 'BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED' in reasons):
            return False
        target = value['target_bootstrap']
        current_for_plan = False
        if target is not None:
            target_keys = {'state', 'target_id', 'confirmation_revision', 'accepted_epoch', 'highest_generation',
                           'confirmation_hash', 'observed_at', 'admitted_at', 'valid_until',
                           'current_confirmation_eligibility', 'current_for_plan', 'signing_allowed', 'dispatch_allowed'}
            if (not isinstance(target, dict) or set(target) != target_keys
                    or target['state'] != 'target_confirmed_pending_qualification' or target['target_id'] != value['target_id']
                    or not readiness_counter(target['confirmation_revision'], positive=True)
                    or not readiness_counter(target['accepted_epoch'], positive=True) or target['highest_generation'] != '0'
                    or not readiness_hash(target['confirmation_hash'])
                    or type(target['current_confirmation_eligibility']) is not bool or type(target['current_for_plan']) is not bool
                    or target['signing_allowed'] is not False or target['dispatch_allowed'] is not False):
                return False
            observed = canonical_readiness_time(target['observed_at'])
            admitted = canonical_readiness_time(target['admitted_at'])
            target_end = canonical_readiness_time(target['valid_until'])
            if (None in (observed, admitted, target_end) or not observed <= admitted <= checked or target_end <= admitted
                    or target['current_confirmation_eligibility'] and target_end <= checked):
                return False
            current_for_plan = target['current_for_plan']
            if current_for_plan and (not target['current_confirmation_eligibility']
                    or target['accepted_epoch'] != detail['plan']['authority_epoch']
                    or authorization is None or deadline > target_end):
                return False
        return ('TARGET_EPOCH_CONFIRMATION_REQUIRED' in reasons) == (not current_for_plan)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def signing_readiness_v3_matches_fixture(value, detail):
    """Human plan approvals never create bootstrap authority in this fixture."""
    return (signing_readiness_v3_matches_profile(value, detail)
            and value['bootstrap_authorization_hash'] is None and value['target_bootstrap'] is None)


def retain_service_diagnostic(report, path):
    """Called after child shutdown and before its temporary directory is removed."""
    report.pop('startup_failure', None)
    report.pop('service_ready_count', None)
    try:
        with path.open('rb') as source:
            contents = source.read(SERVICE_LOG_LIMIT + 1)
    except OSError:
        report['service_log_status'] = 'unavailable'
        return
    if not contents:
        report['service_log_status'] = 'empty'
        return
    ready = 0
    while ready < EXPECTED_SERVICE_STARTS and contents.startswith(SERVICE_READY_LINE):
        ready += 1
        contents = contents[len(SERVICE_READY_LINE):]
    if not contents:
        report['service_log_status'] = 'ready' if ready == EXPECTED_SERVICE_STARTS else 'incomplete'
        report['service_ready_count'] = ready
        return
    for stage, code in STARTUP_DIAGNOSTICS.items():
        exact = f'AUTHORITY_STARTUP stage={stage} code={code}'.encode('ascii')
        if (contents in (exact, exact + b'\n')
                and (ready < EXPECTED_SERVICE_STARTS or stage == 'listener')):
            report['service_log_status'] = 'startup_failure'
            report['service_ready_count'] = ready
            report['startup_failure'] = {'stage': stage, 'code': code}
            return
    # Only the expected ready lines followed by at most one exact failure are
    # recognized. Extra lines, non-UTF8 and panic output are all untrusted.
    report['service_log_status'] = 'unrecognized'


def failure_category(error):
    if isinstance(error, CheckFailed):
        return 'AUTHORITY_SMOKE_CHECK_FAILED'
    if isinstance(error, AssertionError):
        return 'AUTHORITY_SMOKE_ASSERTION_FAILED'
    if type(error).__name__ == 'TimeoutError':
        return 'AUTHORITY_SMOKE_BROWSER_TIMEOUT'
    if type(error).__module__.startswith('playwright.'):
        return 'AUTHORITY_SMOKE_BROWSER_FAILED'
    if isinstance(error, ImportError):
        return 'AUTHORITY_SMOKE_BROWSER_TOOLS_MISSING'
    if isinstance(error, (OSError, subprocess.SubprocessError)):
        return 'AUTHORITY_SMOKE_PROCESS_OR_IO_FAILED'
    return 'AUTHORITY_SMOKE_UNEXPECTED_ERROR'


class CheckFailed(Exception):
    pass


def check(report, label, condition):
    report['checks'].append({'name': label, 'passed': bool(condition)})
    if not condition:
        raise CheckFailed(label)


def require_canonical_time_patterns(root, selected):
    """Keep our dependency-free format checker confined to these exact contracts."""
    pattern = r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
    visited = set()

    def visit(schema):
        if isinstance(schema, dict):
            if schema.get('format') == 'date-time' and schema.get('pattern') != pattern:
                raise CheckFailed('selected preserved contracts retain canonical UTC whole-second timestamps')
            reference = schema.get('$ref')
            if reference and reference not in visited:
                if not reference.startswith('#/'):
                    raise CheckFailed('selected preserved authority contract references are local')
                visited.add(reference)
                target = root
                for segment in reference[2:].split('/'):
                    target = target[segment.replace('~1', '/').replace('~0', '~')]
                visit(target)
            for value in schema.values():
                visit(value)
        elif isinstance(schema, list):
            for value in schema:
                visit(value)

    visit(selected)


def contract_validators():
    """Use preserved definitions verbatim; validate embedded wire objects only."""
    api = json.loads((ROOT / 'docs/specs/F_OpenAPI.json').read_text())
    extended = json.loads((ROOT / 'docs/specs/F_확장계약_스키마.json').read_text())
    # Base jsonschema intentionally omits the optional date-time dependency.
    # These preserved contracts already require this exact UTC representation;
    # parsing also rejects impossible dates instead of silently ignoring format.
    formats = jsonschema.FormatChecker()

    @formats.checks('date-time', raises=ValueError)
    def canonical_utc_time(value):
        if isinstance(value, str):
            datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
        return True

    definitions = {}
    for name in ('PolicyChangePlan', 'ApprovalRequirements', 'HumanApproval', 'ApprovalSet'):
        require_canonical_time_patterns(api, api['components']['schemas'][name])
        require_canonical_time_patterns(extended, extended['$defs'][name])
        definitions[name] = (
            jsonschema.Draft202012Validator(
                {'$ref': '#/components/schemas/' + name, 'components': api['components']},
                format_checker=formats),
            jsonschema.Draft202012Validator(
                {'$ref': '#/$defs/' + name, '$defs': extended['$defs']},
                format_checker=formats),
        )
    return definitions


def matches_contract(validators, name, value):
    return all(validator.is_valid(value) for validator in validators[name])


def contract_negative_controls(report, validators, emitted):
    # Mutate copies of actual HTTP output. Never substitute canned fixture JSON
    # for the positive serializer check, and never emit object/exception contents.
    unknown_fields_rejected = True
    for name, value in emitted.items():
        changed = copy.deepcopy(value)
        changed['unexpected_contract_field'] = True
        unknown_fields_rejected &= all(not validator.is_valid(changed) for validator in validators[name])
    check(report, 'both preserved schemas reject unknown fields on every emitted authority object',
          unknown_fields_rejected)

    formats_rejected = True
    for field, invalid in (('approval_id', 'not-a-uuid'), ('created_at', '2030-02-30T12:00:00Z')):
        changed = copy.deepcopy(emitted['HumanApproval'])
        changed[field] = invalid
        formats_rejected &= all(not validator.is_valid(changed) for validator in validators['HumanApproval'])
    check(report, 'both preserved schemas reject malformed approval UUID and invalid calendar timestamp',
          formats_rejected)

    changed = copy.deepcopy(emitted['ApprovalSet'])
    changed['approvals'][0]['decision'] = 'reject'
    check(report, 'both preserved approval-set schemas reject a substituted rejection member',
          all(not validator.is_valid(changed) for validator in validators['ApprovalSet']))


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_ready(process):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CheckFailed('authority service starts with private fixture')
        try:
            with urllib.request.urlopen(ORIGIN + '/', timeout=1) as response:
                if response.status == 200 and process.poll() is None:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise CheckFailed('authority service becomes ready')


def run(args, report):
    from playwright.sync_api import sync_playwright, expect
    validators = contract_validators()
    with tempfile.TemporaryDirectory(prefix='fw-authority-browser-') as temporary, ExitStack() as cleanup:
        state = Path(temporary) / 'private'
        report['stage'] = 'fixture_provision'
        provision = subprocess.run([str(args.fixture_binary), str(state), str(args.ui_directory)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        check(report, 'independent fixture provisions new private authority state', provision.returncode == 0)
        fixture = json.loads((state / 'fixture.json').read_text())
        device = json.loads((state / 'virtual_authenticator.json').read_text())
        log_path = Path(temporary) / 'service.log'
        # ExitStack is inside TemporaryDirectory and callbacks run LIFO: stop
        # every service child first, then retain only the closed diagnostic.
        cleanup.callback(retain_service_diagnostic, report, log_path)
        with log_path.open('wb') as log:
            report['stage'] = 'service_start'
            process = subprocess.Popen([str(args.service_binary), '--config', str(state / 'config.json'),
                                        '--session-key-file', str(state / 'session.key')], stdout=log, stderr=log)
            cleanup.callback(stop, process)
            report['stage'] = 'service_ready'
            wait_ready(process)
            report['stage'] = 'browser_start'
            with sync_playwright() as playwright, ExitStack() as browser_cleanup:
                launch = {'headless': True, 'args': ['--no-sandbox']}
                executable = args.browser_executable or shutil.which('chromium')
                if executable:
                    launch['executable_path'] = executable
                browser = playwright.chromium.launch(**launch)
                browser_cleanup.callback(browser.close)
                context = browser.new_context(viewport={'width': 1280, 'height': 900}, locale='ko-KR')
                page = context.new_page()
                page.set_default_timeout(15000)
                errors = []
                page.on('pageerror', lambda _error: errors.append('browser_error'))
                cdp = context.new_cdp_session(page)
                cdp.send('WebAuthn.enable')
                authenticator = cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                    'protocol': 'ctap2', 'transport': 'usb', 'hasResidentKey': True,
                    'hasUserVerification': True, 'isUserVerified': True,
                    'automaticPresenceSimulation': True}})['authenticatorId']
                cdp.send('WebAuthn.addCredential', {'authenticatorId': authenticator, 'credential': device})
                report['stage'] = 'browser_checks'
                response = page.goto(ORIGIN)
                check(report, 'authority serves its own review entry and restrictive CSP',
                      response.status == 200 and "frame-ancestors 'none'" in response.headers.get('content-security-policy', ''))
                expect(page.get_by_label('Language', exact=True)).to_have_value('en')
                check(report, 'first non-English browser visit defaults to English', True)
                expect(page.get_by_label('Authority profile', exact=True)).to_have_value('')
                initial = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials']
                check(report, 'visiting authority does not request a passkey assertion', initial[0]['signCount'] == 0)

                def login():
                    page.get_by_label('Authority profile', exact=True).fill(fixture['profile'])
                    page.get_by_role('button', name='Sign in to authority', exact=True).click()
                    expect(page.get_by_role('button', name=fixture['plan_id'], exact=True)).to_be_visible()

                def read_detail(plan_id, action):
                    with page.expect_response(lambda response: response.request.method == 'GET'
                                              and response.url == ORIGIN + '/authority/v1/plans/' + plan_id) as received:
                        action()
                    if received.value.status != 200:
                        raise CheckFailed('authenticated detail response succeeds before contract validation')
                    return received.value.json()

                def review(plan_id):
                    detail = read_detail(plan_id, lambda: page.get_by_role('button', name=plan_id, exact=True).click())
                    expect(page.get_by_role('heading', name='Review immutable plan')).to_be_visible()
                    return detail

                login()
                check(report, 'pinned authority credential signs in through browser WebAuthn', True)
                evidence_url = ORIGIN + '/authority/v1/plans/' + fixture['plan_id'] + '/native-evidence'
                signing_url = ORIGIN + '/authority/v3/plans/' + fixture['plan_id'] + '/signing-readiness'
                with page.expect_response(lambda response: response.request.method == 'GET'
                                          and response.url == evidence_url) as evidence_response:
                    with page.expect_response(lambda response: response.request.method == 'GET'
                                              and response.url == signing_url) as signing_response:
                        detail = review(fixture['plan_id'])
                evidence = evidence_response.value.json()
                check(report, 'authenticated native evidence summary binds the plan without raw captures or dispatch authority',
                      evidence_response.value.status == 200
                      and set(evidence) == {'schema_version', 'org_id', 'project_id', 'target_id',
                                            'plan_id', 'plan_hash', 'checked_at', 'production_qualified',
                                            'dispatch_allowed', 'reasons', 'observation_head_hash',
                                            'compilation', 'observation'}
                      and evidence['schema_version'] == 'fw.native-evidence-status/v1'
                      and all(evidence[field] == detail['plan'][field]
                              for field in ('org_id', 'project_id', 'target_id', 'plan_id'))
                      and evidence['plan_hash'] == detail['plan_hash']
                      and evidence['production_qualified'] is False
                      and evidence['dispatch_allowed'] is False
                      and evidence['compilation'] is None and evidence['observation'] is None)
                native_panel = page.get_by_role('region', name='Development execution evidence', exact=True)
                expect(native_panel.get_by_text('No retained evidence.', exact=True)).to_have_count(2)
                expect(native_panel).to_contain_text('These lab results do not qualify host protection or permit policy signing or deployment.')
                check(report, 'native evidence panel distinguishes missing compilation and observation from qualification', True)
                readiness = signing_response.value.json()
                permanent_blockers = V3_PERMANENT_BLOCKERS
                check(report, 'authenticated signing readiness binds the plan and refuses unqualified issuance',
                      signing_response.value.status == 200
                      and signing_readiness_v3_matches_fixture(readiness, detail)
                      and permanent_blockers <= set(readiness['reasons'])
                      and 'APPROVAL_SET_MISSING' in readiness['reasons']
                      and readiness['approval_set_hash'] is None
                      and readiness['latest_intent'] is None
                      and readiness['quota_configured'] is False and readiness['target_generation'] is None)
                signing_panel = page.get_by_role('region', name='Signing readiness', exact=True)
                expect(signing_panel).to_be_visible()
                expect(signing_panel.get_by_role('button')).to_have_count(1)
                target_panel = signing_panel.get_by_role('region', name='Target bootstrap confirmation', exact=True)
                expect(target_panel).to_contain_text('No accepted target confirmation is retained.')
                expect(signing_panel).to_contain_text('An independently protected policy signing key is required.')
                check(report, 'v3 target panel distinguishes absent target history from production qualification', True)
                before_signing_refresh = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                with page.expect_response(lambda response: response.request.method == 'GET'
                                          and response.url == signing_url) as refreshed_signing:
                    signing_panel.get_by_role('button', name='Refresh signing readiness', exact=True).click()
                check(report, 'signing readiness refresh neither consumes a passkey assertion nor enables consent',
                      refreshed_signing.value.status == 200
                      and signing_readiness_v3_matches_fixture(refreshed_signing.value.json(), detail)
                      and before_signing_refresh == cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                      and not page.get_by_role('checkbox').is_checked())
                before_evidence_refresh = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                with page.expect_response(lambda response: response.request.method == 'GET'
                                          and response.url == evidence_url) as refreshed_evidence:
                    native_panel.get_by_role('button', name='Refresh execution evidence', exact=True).click()
                expect(native_panel.get_by_text('No retained evidence.', exact=True)).to_have_count(2)
                after_evidence_refresh = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                check(report, 'execution evidence refresh performs an authenticated read without another signature or consent',
                      refreshed_evidence.value.status == 200
                      and before_evidence_refresh == after_evidence_refresh
                      and not page.get_by_role('checkbox').is_checked())
                check(report, 'actual policy-change plan and requirements conform to both preserved schemas',
                      matches_contract(validators, 'PolicyChangePlan', detail['plan'])
                      and matches_contract(validators, 'ApprovalRequirements', detail['requirements']))
                expect(page.get_by_role('region', name='Before', exact=True)).to_be_visible()
                expect(page.get_by_role('region', name='After', exact=True)).to_be_visible()
                expect(page.get_by_role('region', name='Current authority status', exact=True)).to_contain_text('Awaiting independent approvals')
                check(report, 'fresh current authority read reports pending before any signed decision', True)
                expect(page.get_by_role('checkbox')).not_to_be_checked()
                expect(page.get_by_role('button', name='Approve plan', exact=True)).to_be_disabled()
                check(report, 'trusted full before and after scopes require explicit unselected consent', True)
                page.get_by_label('Decision role', exact=True).focus()
                page.keyboard.press('Tab')
                expect(page.get_by_role('checkbox')).to_be_focused()
                check(report, 'keyboard navigation reaches explicit decision consent', True)
                page.get_by_label('Decision role', exact=True).select_option('owner')
                page.get_by_role('checkbox').check()
                with page.expect_response(lambda response: response.request.method == 'POST'
                                          and response.url == ORIGIN + '/authority/v1/approvals/assertions') as admitted:
                    page.get_by_role('button', name='Approve plan', exact=True).click()
                approval = admitted.value.json()['approval']
                check(report, 'actual signed approval conforms to both preserved HumanApproval schemas',
                      admitted.value.status == 200 and approval['decision'] == 'approve'
                      and matches_contract(validators, 'HumanApproval', approval))
                expect(page.get_by_role('status')).to_contain_text('Decision recorded')
                expect(page.get_by_role('status')).to_contain_text('approve')
                expect(page.get_by_role('status')).to_contain_text('This does not issue a grant or apply firewall changes.')
                check(report, 'fresh decision-bound browser assertion records approval without host claims', True)
                aggregate = page.get_by_role('region', name='Current authority status', exact=True)
                expect(aggregate).to_contain_text('Current approval set verified')
                expect(aggregate).to_contain_text('Included signed approvals: 1')
                expect(page.get_by_text('Admission result (historical)', exact=True)).to_be_visible()
                check(report, 'fresh detail verifies current set separately from historical admission acknowledgement', True)
                expect(native_panel.get_by_text('No retained evidence.', exact=True)).to_have_count(2)
                expect(native_panel).to_contain_text('These lab results do not qualify host protection or permit policy signing or deployment.')
                check(report, 'human approval does not create native observations or remove the deployment qualification boundary', True)
                current = read_detail(fixture['plan_id'], lambda: page.get_by_role('button', name='Refresh', exact=True).click())
                approval_set = current['current_approval_set']['content']
                before_signing_refresh = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                with page.expect_response(lambda response: response.request.method == 'GET'
                                          and response.url == signing_url) as approved_readiness:
                    signing_panel.get_by_role('button', name='Refresh signing readiness', exact=True).click()
                approved_signing = approved_readiness.value.json()
                check(report, 'current human quorum remains separate from missing production signer qualification',
                      approved_readiness.value.status == 200
                      and signing_readiness_v3_matches_fixture(approved_signing, current)
                      and isinstance(approved_signing['approval_set_hash'], str)
                      and 'APPROVAL_SET_MISSING' not in approved_signing['reasons']
                      and permanent_blockers <= set(approved_signing['reasons'])
                      and approved_signing['signing_allowed'] is False
                      and approved_signing['dispatch_allowed'] is False
                      and approved_signing['latest_intent'] is None
                      and before_signing_refresh == cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount'])
                check(report, 'actual current human ApprovalSet conforms to both preserved schemas and includes the admitted approval',
                      approval_set['kind'] == 'human' and approval in approval_set['approvals']
                      and matches_contract(validators, 'ApprovalSet', approval_set))
                contract_negative_controls(report, validators, {
                    'PolicyChangePlan': detail['plan'], 'ApprovalRequirements': detail['requirements'],
                    'HumanApproval': approval, 'ApprovalSet': approval_set,
                })
                storage = page.evaluate('({local:Object.keys(localStorage),session:Object.keys(sessionStorage)})')
                check(report, 'session proof and signed assertions never enter browser persistent storage',
                      storage == {'local': [], 'session': []})
                signed = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials']
                check(report, 'login and policy decision each require a fresh signature', signed[0]['signCount'] >= 2)
                page.reload()
                expect(page.get_by_label('Authority profile', exact=True)).to_be_visible()
                check(report, 'reload does not recover an authenticated authority session from cookies alone', True)
                login()
                review(fixture['plan_id'])
                expect(page.get_by_role('status')).to_contain_text('approve')
                expect(page.get_by_role('button', name='Approve plan', exact=True)).to_be_disabled()
                check(report, 'verified retained decision survives reload and prevents duplicate approval', True)
                expect(page.get_by_role('checkbox')).not_to_be_checked()
                before_rejection = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                page.get_by_label('Decision role', exact=True).select_option('owner')
                page.get_by_role('checkbox').check()
                with page.expect_response(lambda response: response.request.method == 'POST'
                                          and response.url == ORIGIN + '/authority/v1/approvals/assertions') as rejected:
                    page.get_by_role('button', name='Reject plan', exact=True).click()
                rejection = rejected.value.json()['approval']
                check(report, 'actual signed rejection conforms to both preserved HumanApproval schemas',
                      rejected.value.status == 200 and rejection['decision'] == 'reject'
                      and matches_contract(validators, 'HumanApproval', rejection))
                expect(page.get_by_role('status')).to_contain_text('reject')
                expect(page.get_by_role('region', name='Current authority status', exact=True)).to_contain_text('Blocked by signed rejection')
                after_rejection = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                check(report, 'the same reviewer can replace prior approval with fresh explicit signed dissent', after_rejection > before_rejection)

                page.get_by_role('button', name='Back to plans', exact=True).click()
                if fixture.get('reject_plan_id'):
                    review(fixture['reject_plan_id'])
                    page.get_by_label('Decision role', exact=True).select_option('owner')
                    page.get_by_role('checkbox').check()
                    page.get_by_role('button', name='Reject plan', exact=True).click()
                    expect(page.get_by_role('status')).to_contain_text('reject')
                    check(report, 'separate decision-bound browser assertion records rejection', True)
                    expect(page.get_by_role('region', name='Current authority status', exact=True)).to_contain_text('Blocked by signed rejection')
                    check(report, 'signed rejection is displayed as terminal dissent rather than completed quorum', True)
                    page.get_by_role('button', name='Back to plans', exact=True).click()
                if fixture.get('missing_evidence_plan_id'):
                    review(fixture['missing_evidence_plan_id'])
                    expect(page.get_by_text('Full before and after scope evidence is unavailable. Approval is blocked.')).to_be_visible()
                    page.get_by_label('Decision role', exact=True).select_option('owner')
                    page.get_by_role('checkbox').check()
                    expect(page.get_by_role('button', name='Approve plan', exact=True)).to_be_disabled()
                    expect(page.get_by_role('button', name='Reject plan', exact=True)).to_be_enabled()
                    check(report, 'missing trusted scope evidence blocks approval while allowing explicit rejection', True)
                if fixture.get('stale_plan_id'):
                    page.get_by_role('button', name='Back to plans', exact=True).click()
                    review(fixture['stale_plan_id'])
                    expect(page.get_by_role('region', name='Current authority status', exact=True)).to_contain_text('Current approval set is stale')
                    expect(page.get_by_role('button', name='Approve plan', exact=True)).to_be_disabled()
                    check(report, 'mismatched current authority epoch is shown stale without a current set', True)
                if process.poll() is not None:
                    raise CheckFailed('authority service remains running before restart')
                report['stage'] = 'service_restart'
                stop(process)
                process = subprocess.Popen([str(args.service_binary), '--config', str(state / 'config.json'),
                                            '--session-key-file', str(state / 'session.key')], stdout=log, stderr=log)
                cleanup.callback(stop, process)
                report['stage'] = 'service_restart_ready'
                wait_ready(process)
                report['stage'] = 'session_recovery'
                before_recovery = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                page.get_by_role('button', name='Back to plans', exact=True).click()
                expect(page.get_by_role('alert')).to_be_visible()
                page.get_by_role('button', name='Refresh', exact=True).click()
                expect(page.get_by_label('Authority profile', exact=True)).to_have_value('')
                after_refresh = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                check(report, 'expired authority session recovers anonymous binding with Refresh', True)
                check(report, 'session recovery does not automatically sign in or submit another decision', before_recovery == after_refresh)
                login()
                review(fixture['plan_id'])
                expect(page.get_by_role('status')).to_contain_text('approve')
                expect(page.get_by_role('region', name='Current authority status', exact=True)).to_contain_text('Blocked by signed rejection')
                check(report, 'fresh passkey sign-in after service restart restores only the retained decision', True)
                expect(native_panel.get_by_text('No retained evidence.', exact=True)).to_have_count(2)
                check(report, 'restarted authority still shows missing native evidence without inventing observations', True)
                with page.expect_response(lambda response: response.request.method == 'GET'
                                          and response.url == signing_url) as restarted_readiness:
                    signing_panel.get_by_role('button', name='Refresh signing readiness', exact=True).click()
                restarted_signing = restarted_readiness.value.json()
                check(report, 'restart and signed dissent do not create signing jobs or dispatch authority',
                      restarted_readiness.value.status == 200
                      and signing_readiness_v3_matches_fixture(restarted_signing, detail)
                      and restarted_signing['approval_set_hash'] is None
                      and restarted_signing['latest_intent'] is None
                      and restarted_signing['signing_allowed'] is False
                      and restarted_signing['dispatch_allowed'] is False)
                page.get_by_role('button', name='Back to plans', exact=True).click()
                core_id = fixture['core_access_plan_id']
                core_url = ORIGIN + '/authority/v1/plans/' + core_id + '/core-access-evidence'
                with page.expect_response(lambda response: response.request.method == 'GET'
                                          and response.url == core_url) as core_response:
                    core_detail = review(core_id)
                core_evidence = core_response.value.json()
                core_window = core_evidence['lease_window']
                check(report, 'real core plan retains its complete review and fixed original lease window',
                      core_response.value.status == 200
                      and core_detail['plan']['change_kind'] == 'add_access_lease'
                      and core_detail['review']['available'] is True
                      and core_detail['review']['before']['policies'] == []
                      and core_detail['review']['after']['policies'] == core_detail['plan']['requested_policies']
                      and core_evidence['schema_version'] == 'fw.core-access-evidence/v1'
                      and core_evidence['plan_hash'] == core_detail['plan_hash']
                      and core_window['lease_seconds'] == 3600 and core_window['current'] is True
                      and core_evidence['signing_allowed'] is False
                      and core_evidence['dispatch_allowed'] is False)
                core_panel = page.get_by_role('region', name='Core access lease window', exact=True)
                expect(core_panel).to_contain_text('Current at last read')
                expect(core_panel).to_contain_text('Approval and retries never restart the lease.')
                expect(page.get_by_role('region', name='Before', exact=True)).to_be_visible()
                expect(page.get_by_role('region', name='After', exact=True)).to_be_visible()
                page.get_by_label('Decision role', exact=True).select_option('owner')
                page.get_by_role('checkbox').check()
                before_core_decision = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                with page.expect_response(lambda response: response.request.method == 'POST'
                                          and response.url == ORIGIN + '/authority/v1/approvals/assertions') as core_admission:
                    page.get_by_role('button', name='Approve plan', exact=True).click()
                check(report, 'original core review requires its own real virtual-passkey human approval',
                      core_admission.value.status == 200
                      and core_admission.value.json()['approval']['decision'] == 'approve'
                      and cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount'] > before_core_decision)
                expect(page.get_by_role('region', name='Current authority status', exact=True)).to_contain_text('Current approval set verified')
                after_core_decision = cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount']
                with page.expect_response(lambda response: response.request.method == 'GET'
                                          and response.url == core_url) as refreshed_core:
                    core_panel.get_by_role('button', name='Refresh lease evidence', exact=True).click()
                refreshed_core_evidence = refreshed_core.value.json()
                check(report, 'human core approval and evidence refresh preserve absolute times without deployment authority',
                      refreshed_core.value.status == 200
                      and all(refreshed_core_evidence['lease_window'][key] == core_window[key]
                              for key in ('window_hash', 'not_before', 'expires_at', 'admitted_at'))
                      and refreshed_core_evidence['signing_allowed'] is False
                      and refreshed_core_evidence['dispatch_allowed'] is False
                      and cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator})['credentials'][0]['signCount'] == after_core_decision)
                expect(core_panel).to_contain_text('CORE_SIGNING_PROFILE_UNAVAILABLE')
                expect(page.get_by_role('region', name='Signing readiness', exact=True)).to_contain_text('Access lease signing is unavailable in this build.')
                check(report, 'shipped review runs without browser exceptions', not errors)
                context.close()
        report['stage'] = 'cleanup'
        if process.poll() is not None:
            raise CheckFailed('authority service remains running until intentional cleanup')
        stop(process)
        check(report, 'authority service and browser cleanup complete', process.poll() is not None)
    report['stage'] = 'complete'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-binary', type=Path, required=True)
    parser.add_argument('--fixture-binary', type=Path, required=True)
    parser.add_argument('--ui-directory', type=Path, default=ROOT / 'web/dist-authority')
    parser.add_argument('--browser-executable')
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/authority-browser.json')
    args = parser.parse_args()
    report = {'schema_version': 'fw.authority-browser-smoke/v1', 'checks': [],
              'stage': 'initialization', 'passed': False, 'status': 'FAIL',
              'scope': 'real authority service and Chromium virtual CTAP2 integration; no native enforcement qualification'}
    try:
        args.service_binary = args.service_binary.resolve()
        args.fixture_binary = args.fixture_binary.resolve()
        args.ui_directory = args.ui_directory.resolve()
        run(args, report)
        if (report.get('stage') != 'complete' or not report['checks']
                or not all(item.get('passed') is True for item in report['checks'])
                or report.get('service_log_status') != 'ready'
                or report.get('service_ready_count') != EXPECTED_SERVICE_STARTS):
            raise CheckFailed('authority smoke completion evidence is incomplete')
    except Exception as error:
        report['stage'] = report.get('stage') if report.get('stage') in STAGES else 'initialization'
        report['failure_stage'] = report['stage']
        report['failure'] = failure_category(error)
        # Preserve the bounded original category when an early browser failure
        # prevents the planned restart and leaves only one service-ready line.
        report['primary_failure'] = report['failure']
        if report.get('service_log_status') == 'startup_failure':
            report['failure'] = 'AUTHORITY_SMOKE_SERVICE_FAILED'
        elif report.get('service_log_status') in ('empty', 'incomplete', 'unrecognized', 'unavailable'):
            report['failure'] = 'AUTHORITY_SMOKE_SERVICE_DIAGNOSTIC_UNAVAILABLE'
        report['passed'] = False
        report['status'] = 'FAIL'
    else:
        report['passed'] = True
        report['status'] = 'PASS'
    try:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    except OSError:
        print('FAIL: stage=report_write code=AUTHORITY_SMOKE_REPORT_WRITE_FAILED')
        raise SystemExit(1) from None
    diagnostic = '' if report['passed'] else f"; stage={report['failure_stage']} code={report['failure']}"
    if report.get('startup_failure'):
        diagnostic += f" startup_stage={report['startup_failure']['stage']} startup_code={report['startup_failure']['code']}"
    print(('PASS' if report['passed'] else 'FAIL') + f": {sum(item['passed'] for item in report['checks'])} authority browser checks" + diagnostic)
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
