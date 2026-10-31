#!/usr/bin/env python3
"""Exercise the shipped independent review UI against the real authority service.

The separate Rust fixture provisions a disposable pinned test key and real
planner evidence; Chromium signs via a CDP virtual CTAP2 authenticator. This
checks protocol integration, not physical-key support, human consent, host
firewall enforcement, independent OS deployment or release qualification.
Private fixture material stays in a temporary directory and is never reported.
"""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://localhost:8790'


class CheckFailed(Exception):
    pass


def check(report, label, condition):
    report['checks'].append({'name': label, 'passed': bool(condition)})
    if not condition:
        raise CheckFailed(label)


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
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise CheckFailed('authority service becomes ready')


def run(args, report):
    from playwright.sync_api import sync_playwright, expect
    with tempfile.TemporaryDirectory(prefix='fw-authority-browser-') as temporary, ExitStack() as cleanup:
        state = Path(temporary) / 'private'
        provision = subprocess.run([str(args.fixture_binary), str(state), str(args.ui_directory)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        check(report, 'independent fixture provisions new private authority state', provision.returncode == 0)
        fixture = json.loads((state / 'fixture.json').read_text())
        device = json.loads((state / 'virtual_authenticator.json').read_text())
        with (Path(temporary) / 'service.log').open('wb') as log:
            process = subprocess.Popen([str(args.service_binary), '--config', str(state / 'config.json'),
                                        '--session-key-file', str(state / 'session.key')], stdout=log, stderr=log)
            cleanup.callback(stop, process)
            wait_ready(process)
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

                def review(plan_id):
                    page.get_by_role('button', name=plan_id, exact=True).click()
                    expect(page.get_by_role('heading', name='Review immutable plan')).to_be_visible()

                login()
                check(report, 'pinned authority credential signs in through browser WebAuthn', True)
                review(fixture['plan_id'])
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
                page.get_by_role('button', name='Approve plan', exact=True).click()
                expect(page.get_by_role('status')).to_contain_text('Decision recorded')
                expect(page.get_by_role('status')).to_contain_text('approve')
                expect(page.get_by_role('status')).to_contain_text('This does not issue a grant or apply firewall changes.')
                check(report, 'fresh decision-bound browser assertion records approval without host claims', True)
                aggregate = page.get_by_role('region', name='Current authority status', exact=True)
                expect(aggregate).to_contain_text('Current approval set verified')
                expect(aggregate).to_contain_text('Included signed approvals: 1')
                expect(page.get_by_text('Admission result (historical)', exact=True)).to_be_visible()
                check(report, 'fresh detail verifies current set separately from historical admission acknowledgement', True)
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
                page.get_by_role('button', name='Reject plan', exact=True).click()
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
                stop(process)
                process = subprocess.Popen([str(args.service_binary), '--config', str(state / 'config.json'),
                                            '--session-key-file', str(state / 'session.key')], stdout=log, stderr=log)
                cleanup.callback(stop, process)
                wait_ready(process)
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
                check(report, 'shipped review runs without browser exceptions', not errors)
                context.close()
        stop(process)
        check(report, 'authority service and browser cleanup complete', process.poll() is not None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-binary', type=Path, required=True)
    parser.add_argument('--fixture-binary', type=Path, required=True)
    parser.add_argument('--ui-directory', type=Path, default=ROOT / 'web/dist-authority')
    parser.add_argument('--browser-executable')
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/authority-browser.json')
    args = parser.parse_args()
    args.service_binary = args.service_binary.resolve()
    args.fixture_binary = args.fixture_binary.resolve()
    args.ui_directory = args.ui_directory.resolve()
    report = {'schema_version': 'fw.authority-browser-smoke/v1', 'checks': [],
              'scope': 'real authority service and Chromium virtual CTAP2 integration; no native enforcement qualification'}
    try:
        run(args, report)
    except Exception as error:
        report['failure'] = str(error) if isinstance(error, CheckFailed) else type(error).__name__
        report['passed'] = False
    else:
        report['passed'] = True
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(('PASS' if report['passed'] else 'FAIL') + f": {sum(item['passed'] for item in report['checks'])} authority browser checks; {args.report}")
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
