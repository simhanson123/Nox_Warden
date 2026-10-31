#!/usr/bin/env python3
"""Exercise real certificate enrollment, mTLS identity and revocation on loopback.

Uses disposable private state and real fw_control/fw_cli/fw_agent processes.
No enrollment token, private key, cookie, or certificate bytes enter the report.
Optional --browser verifies that a genuinely registered device can be selected
when creating a service; it requires local Playwright and Chromium.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--http-port', type=int, default=8792)
    parser.add_argument('--tls-port', type=int, default=8793)
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/enrollment-smoke.json')
    parser.add_argument('--browser', action='store_true')
    parser.add_argument('--browser-executable', default='/usr/bin/chromium')
    args = parser.parse_args()
    checks = []
    report = {'status': 'FAIL', 'checks': checks, 'native_firewall_changed': False,
              'credential_values_recorded': False, 'browser_executed': False,
              'scope': 'loopback TLS device registration; no policy authorization or native dispatch'}
    schema = json.loads((ROOT / 'docs/specs/F_OpenAPI.json').read_text())
    internal_schema = json.loads((ROOT / 'docs/specs/F_내부통신_스키마.json').read_text())

    def check(label, condition):
        if not condition:
            raise AssertionError(label)
        checks.append(label)

    def validate(name, value):
        definition = {'$ref': '#/components/schemas/' + name, 'components': schema['components']}
        jsonschema.Draft202012Validator(definition, format_checker=jsonschema.FormatChecker()).validate(value)

    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='nox-enrollment-') as temporary:
            state = Path(temporary)
            api = f'http://127.0.0.1:{args.http_port}'
            internal = f'https://127.0.0.1:{args.tls_port}'
            controller_dir = state / 'controller'
            pki_dir = state / 'pki'
            device_dir = state / 'device'
            session_file = state / 'operator/session.json'
            invitation_file = state / 'operator/invitation.json'
            environment = dict(os.environ, FW_STATE_DIR=str(controller_dir),
                               FW_PORT=str(args.http_port), FW_ENROLLMENT_PORT=str(args.tls_port),
                               FW_ENROLLMENT_DIR=str(pki_dir), FW_API_URL=api, FW_PUBLIC_ORIGIN=api,
                               FW_BOOTSTRAP_FILE=str(controller_dir / 'bootstrap-token'),
                               FW_SESSION_FILE=str(session_file), FW_WEB_DIR=str(ROOT / 'web/dist'))
            protected_values = []

            def command(binary, arguments, success=True):
                result = subprocess.run([str(ROOT / 'target/debug' / binary), *arguments],
                                        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=20)
                if (result.returncode == 0) != success:
                    # Commands have file-path arguments only. Suppress arbitrary
                    # child output rather than accidentally printing credentials.
                    raise AssertionError(f'unexpected exit status: {binary} {arguments[0]}')
                for secret in protected_values:
                    if secret in result.stdout or secret in result.stderr:
                        raise AssertionError('credential appeared in command output')
                return json.loads(result.stdout) if success else None

            def start_controller():
                child = subprocess.Popen([str(ROOT / 'target/debug/fw_control')], cwd=ROOT,
                                         env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                for _ in range(100):
                    if child.poll() is not None:
                        raise AssertionError('enrollment controller startup failed')
                    try:
                        with opener.open(api + '/healthz', timeout=1):
                            return child
                    except OSError:
                        time.sleep(.05)
                stop_controller(child)
                raise AssertionError('enrollment controller readiness timed out')

            def stop_controller(child):
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()

            def public(path, body=None):
                session = json.loads(session_file.read_text())
                headers = {'Cookie': session['cookie']}
                if body is not None:
                    headers.update({'Origin': api, 'X-CSRF-Token': session['csrf_token'],
                                    'Idempotency-Key': str(uuid.uuid4()), 'Content-Type': 'application/json'})
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                return request(opener, api + '/api/v1' + path, headers, body)

            def request(opener, url, headers, body=None):
                encoded = json.dumps(body).encode() if body is not None else None
                try:
                    with opener.open(urllib.request.Request(url, data=encoded, headers=headers), timeout=5) as response:
                        return response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    return error.code, json.load(error)

            pki = command('fw_control', ['init-enrollment-ca'])
            pin = 'sha256:' + hashlib.sha256((pki_dir / 'ca.pem').read_bytes()).hexdigest()
            check('explicit controller root initialized without exporting a private key', pki['trust_bundle_hash'] == pin)
            command('fw_control', ['init-enrollment-ca'], success=False)
            check('existing controller trust root cannot be silently replaced', True)
            process = start_controller()
            command('fw_cli', ['login'])
            session = json.loads(session_file.read_text())
            protected_values.extend([session['cookie'], session['csrf_token']])
            device = command('fw_agent', ['init', '--state-dir', str(device_dir)])
            command('fw_agent', ['init', '--state-dir', str(device_dir)], success=False)
            check('device key initialized once and not overwritten', device['platform'] == 'linux')
            invitation_args = ['enroll-token', '--name', 'Registered test device', '--platform', 'linux',
                               '--fingerprint', device['key_fingerprint'], '--output', str(invitation_file)]
            receipt = command('fw_cli', invitation_args)
            invitation = json.loads(invitation_file.read_text())
            protected_values.append(invitation['token'])
            repeated = command('fw_cli', invitation_args)
            check('invitation retries retain the same target and expiry', repeated == receipt)
            check('invitation credential remains in a private file', invitation_file.stat().st_mode & 0o777 == 0o600)
            status, before = public('/targets')
            validate('TargetsResponse', before)
            check('issuing an invitation does not fabricate an enrolled target', status == 200 and before['data'] == [])
            tls_args = ['--state-dir', str(device_dir), '--controller', internal,
                        '--ca-file', str(pki_dir / 'ca.pem'), '--trust-bundle-hash', pin]
            enroll_args = ['enroll', *tls_args, '--invitation-file', str(invitation_file)]
            wrong_pin = enroll_args.copy()
            wrong_pin[wrong_pin.index('--trust-bundle-hash') + 1] = 'sha256:' + '0' * 64
            command('fw_agent', wrong_pin, success=False)
            check('mismatched controller trust pin rejected before enrollment', not (device_dir / 'enrollment.json').exists())

            context = ssl.create_default_context(cafile=str(pki_dir / 'ca.pem'))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            no_identity = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
            status, _ = request(no_identity, internal + '/internal/v1/device-status', {}, None)
            check('TLS server rejects device status without a client certificate', status == 401)
            enrolled = command('fw_agent', enroll_args)
            target_id = receipt['target_id']
            check('real CSR enrollment is bound to the invited target and observe mode',
                  enrolled['target_id'] == target_id and enrolled['mode'] == 'observe' and enrolled['enforcement'] is False)
            saved = json.loads((device_dir / 'enrollment.json').read_text())['response']
            definition = {'$ref': '#/$defs/EnrollmentResponse', '$defs': internal_schema['$defs']}
            jsonschema.Draft202012Validator(definition, format_checker=jsonschema.FormatChecker()).validate(saved)
            check('issued response conforms to the original enrollment contract', saved['trust_bundle_hash'] == pin)
            original_certificate = (device_dir / 'certificate.pem').read_bytes()
            command('fw_agent', enroll_args)
            check('enrollment retry does not reissue or extend the certificate',
                  (device_dir / 'certificate.pem').read_bytes() == original_certificate)
            status, before = public('/targets')
            check('enrollment alone does not invent a capability hash', status == 200 and before['data'] == [])
            command('fw_agent', ['report', *tls_args])
            command('fw_agent', ['status', *tls_args])
            status, targets = public('/targets')
            validate('TargetsResponse', targets)
            target = targets['data'][0]
            check('mutually authenticated report creates a real observe-only target view',
                  status == 200 and len(targets['data']) == 1 and target['target_id'] == target_id
                  and target['state'] == 'observe_only' and target['observed_state_hash'] is None
                  and target['capability_hash'] != 'sha256:' + '0' * 64)
            status, current = public('/status')
            check('registration never enables native dispatch', status == 200 and current['data']['enforcement'] is False
                  and current['data']['native_dispatch_enabled'] is False)

            status, current_session = public('/session')
            check('operator session remains valid', status == 200)
            owner = current_session['data']['principal_id']
            asset = {'definition': {'name': 'Registered device destination', 'asset_kind': 'host', 'owner_id': owner,
                                    'addresses': [{'family': 'ipv4', 'cidr': '192.0.2.10/32', 'interface': None}],
                                    'criticality': 'normal', 'isolation': 'host', 'provenance': 'manual', 'source_evidence': None},
                     'state': 'active'}
            status, asset_response = public('/assets', asset)
            validate('AssetResponse', asset_response)
            check('manual destination catalogue remains independent from transport enrollment', status == 201)
            asset_id = asset_response['data']['asset_id']
            service = {'service_id': 'enrolled-device-https', 'definition': {'name': 'Registered HTTPS service', 'owner_id': owner,
                        'destination_asset_ids': [asset_id], 'target_ids': [target_id],
                        'transport': {'protocol': 'tcp', 'destination_ports': [{'start': 443, 'end': 443}]},
                        'description': 'A registered transport identity, not permission to pass packets', 'criticality': 'normal'}}
            status, service_response = public('/services', service)
            validate('ServiceResponse', service_response)
            check('service registration succeeds with a genuinely enrolled target', status == 201)

            if args.browser:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=args.browser_executable, headless=True, args=['--no-sandbox'])
                    browser_context = browser.new_context(viewport={'width': 1440, 'height': 1000}, locale='ko-KR')
                    cookie = session['cookie'].split('=', 1)[1]
                    browser_context.add_cookies([{'name': 'fw_session', 'value': cookie, 'url': api,
                                                 'httpOnly': True, 'sameSite': 'Strict'}])
                    page = browser_context.new_page()
                    errors = []
                    page.on('pageerror', lambda error: errors.append(type(error).__name__))
                    page.goto(api + '/targets')
                    page.get_by_role('button', name='Registered test device', exact=True).wait_for()
                    check('live target page renders the genuinely enrolled device', page.locator('html').get_attribute('lang') == 'en')
                    page.goto(api + '/services')
                    page.get_by_role('button', name='Register service', exact=True).click()
                    page.get_by_label('Service ID', exact=True).fill('browser-enrolled-https')
                    page.get_by_label('Display name', exact=True).fill('Browser registered HTTPS')
                    page.get_by_label('Description', exact=True).fill('Actual enrolled target selection')
                    page.get_by_label('Destination assets', exact=True).select_option(asset_id)
                    page.get_by_label('Registered targets', exact=True).select_option(target_id)
                    page.get_by_role('button', name='Save immutable revision', exact=True).click()
                    page.wait_for_url('**/services/browser-enrolled-https')
                    page.reload()
                    page.get_by_role('button', name='Create new revision', exact=True).wait_for()
                    check('browser service creation persists the actual registered target', not errors)
                    browser.close()
                    report['browser_executed'] = True

            stop_controller(process)
            process = start_controller()
            command('fw_agent', ['status', *tls_args])
            check('registered client certificate survives controller restart', True)
            command('fw_cli', ['login'])
            session = json.loads(session_file.read_text())
            protected_values.extend([session['cookie'], session['csrf_token']])
            command('fw_cli', ['revoke-target', target_id])
            command('fw_agent', ['status', *tls_args], success=False)
            command('fw_agent', ['report', *tls_args], success=False)
            check('revoked certificate cannot authenticate or upload new capabilities', True)
            service['service_id'] = 'revoked-device-service'
            status, _ = public('/services', service)
            check('revoked enrollment cannot authorize a new service reference', status in (403, 404, 409, 422))
            status, audit = public('/audit/events')
            validate('AuditEventsResponse', audit)
            lifecycle = {(event['event_type'], event['reason_code']) for event in audit['data']
                         if event['resource_kind'] == 'target' and event['resource_id'] == target_id}
            check('enrollment and revocation produce contract-valid lifecycle audit records', status == 200 and {
                ('administration', 'ENROLLMENT_TOKEN_REGISTERED'), ('authentication', 'ENROLLMENT_RESERVED'),
                ('registry', 'TARGET_ENROLLED'), ('registry', 'CAPABILITY_UNVERIFIED'),
                ('revocation', 'NETWORK_REVOCATION_UNCONFIRMED')} <= lifecycle)
            check('controller private keys stay private', (pki_dir / 'ca-key.pem').stat().st_mode & 0o777 == 0o600)
            check('device private key stays private', (device_dir / 'key.pem').stat().st_mode & 0o777 == 0o600)
            report['status'] = 'PASS'
            stop_controller(process)
            process = None
    except Exception as error:
        report['error'] = {'type': type(error).__name__}
        if isinstance(error, AssertionError):
            report['error']['check'] = str(error)
        if isinstance(error, jsonschema.ValidationError):
            report['error']['schema_path'] = list(error.absolute_schema_path)
            report['error']['instance_path'] = list(error.absolute_path)
            report['error']['validator'] = error.validator
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        report['count'] = len(checks)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
