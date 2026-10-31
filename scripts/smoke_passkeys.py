#!/usr/bin/env python3
"""Verify local owner passkeys with Chromium's virtual WebAuthn authenticator.

This runs the real controller, browser WebAuthn API and credential verifier with
disposable private state. The authenticator is an automated CDP test device, not
a physical security key or evidence that a human approved a firewall policy.
No private key, credential ID, assertion, cookie or console token enters reports.
"""

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]

# Exercise the native browser API rather than constructing a signed response in
# the test runner. These are the same standard JSON/base64url conversions needed
# by a browser application; raw responses remain in disposable process memory.
CEREMONY = r"""async ({kind, options}) => {
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')
    + '='.repeat((4 - value.length % 4) % 4)), char => char.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  const publicKey = structuredClone(options);
  publicKey.challenge = decode(publicKey.challenge);
  publicKey.timeout = 10000;
  if (publicKey.user) publicKey.user.id = decode(publicKey.user.id);
  for (const name of ['allowCredentials', 'excludeCredentials']) {
    if (publicKey[name]) publicKey[name] = publicKey[name].map(value => ({...value, id: decode(value.id)}));
  }
  const credential = kind === 'create'
    ? await navigator.credentials.create({publicKey})
    : await navigator.credentials.get({publicKey});
  const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
  if (kind === 'create') {
    response.attestationObject = encode(credential.response.attestationObject);
    response.transports = credential.response.getTransports();
  } else {
    response.authenticatorData = encode(credential.response.authenticatorData);
    response.signature = encode(credential.response.signature);
    response.userHandle = credential.response.userHandle === null ? null : encode(credential.response.userHandle);
  }
  return {id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response, clientExtensionResults: credential.getClientExtensionResults()};
}"""

REQUEST = """async ({path, body, csrf, key}) => {
  const headers = {Accept: 'application/json'};
  if (csrf) headers['X-CSRF-Token'] = csrf;
  if (body !== null) {
    headers['Content-Type'] = 'application/json';
    headers['Idempotency-Key'] = key;
  }
  const response = await fetch('/api/v1' + path, {method: body === null ? 'GET' : 'POST',
    credentials: 'same-origin', cache: 'no-store', headers,
    body: body === null ? undefined : JSON.stringify(body)});
  return {status: response.status, body: await response.json()};
}"""


class CheckFailed(Exception):
    """Carries only a static test label, never arbitrary external exception text."""
    def __init__(self, label, response=None):
        super().__init__(label)
        self.http_status = response[0] if response else None
        reason = response[1].get('detail') if response else None
        self.reason = reason if isinstance(reason, str) and re.fullmatch(r'[A-Z0-9_]{1,80}', reason) else None


def check(report, label, condition, response=None):
    if not condition:
        raise CheckFailed(label, response)
    report['checks'].append(label)


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
    if child.poll() is None:
        raise CheckFailed('test child process was removed after the test')


def close_browser(browser, report):
    browser.close()
    report['browser_closed'] = True


def browser_diagnostics(page, report, events):
    if report.get('stage') == 'complete':
        return
    # Only fixed route names, HTTP status numbers and bounded static problem
    # identifiers are retained. DOM text, paths with IDs and request bodies are
    # intentionally excluded from this failure diagnostic.
    report['http_events'] = events[-16:]
    try:
        codes = page.locator('[role="alert"] code').all_text_contents()
        report['visible_error_codes'] = [code for code in codes if re.fullmatch(r'[A-Z0-9_]{1,80}', code)]
    except Exception:
        report['visible_error_codes'] = []


def cli_prompt(child, origin):
    """Read bounded, explicitly public prompt fields without printing stderr."""
    received = b''
    deadline = time.monotonic() + 15
    with selectors.DefaultSelector() as selector:
        selector.register(child.stderr, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _ in selector.select(.2):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    raise CheckFailed('CLI login emits a bounded browser authorization prompt')
                received += chunk
                if len(received) > 8192:
                    raise CheckFailed('CLI authorization prompt does not emit unbounded output')
            uri = re.search(rb'^Open this controller page in your browser: (\S+)$', received, re.MULTILINE)
            code = re.search(rb'^Enter this code and approve CLI login: ([0-9A-F]{8})$', received, re.MULTILINE)
            if uri and code:
                destination = uri.group(1).decode('ascii')
                if not re.fullmatch(re.escape(origin) + r'/cli-login/[0-9a-f-]{36}', destination):
                    raise CheckFailed('CLI authorization stays on the exact local controller origin')
                return destination, code.group(1).decode('ascii')
    raise CheckFailed('CLI login emits its browser prompt before timing out')


def cli_status(environment):
    result = subprocess.run([str(ROOT / 'target/debug/fw_cli'), 'status'], cwd=ROOT,
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    # Report only the exit result. The runner never forwards arbitrary CLI output.
    return result.returncode


def start(environment, origin):
    child = subprocess.Popen([str(ROOT / 'target/debug/fw_control')], cwd=ROOT,
                             env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        for _ in range(150):
            if child.poll() is not None:
                raise CheckFailed('controller starts with private disposable state')
            try:
                with opener.open(origin + '/healthz', timeout=1) as response:
                    if response.status == 200:
                        return child
            except OSError:
                time.sleep(.05)
        raise CheckFailed('controller becomes ready within the bounded startup wait')
    except Exception:
        stop(child)
        raise


def tamper_client_origin(credential):
    changed = json.loads(json.dumps(credential))
    encoded = changed['response']['clientDataJSON']
    client = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    client['origin'] = 'https://untrusted.invalid'
    changed['response']['clientDataJSON'] = base64.urlsafe_b64encode(
        json.dumps(client, separators=(',', ':')).encode()).decode().rstrip('=')
    return changed


def raw_request(origin, path, body, cookie=None, csrf=None, request_origin=None):
    headers = {'Origin': request_origin or origin, 'Content-Type': 'application/json',
               'Idempotency-Key': str(uuid.uuid4())}
    if cookie:
        headers['Cookie'] = cookie
    if csrf:
        headers['X-CSRF-Token'] = csrf
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(origin + '/api/v1' + path,
                                     data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


class BrowserClient:
    def __init__(self, page):
        self.page = page
        self.csrf = None

    def request(self, path, body=None, key=None):
        result = self.page.evaluate(REQUEST, {'path': path, 'body': body,
                                            'csrf': self.csrf, 'key': key or str(uuid.uuid4())})
        return result['status'], result['body']

    def session(self):
        status, result = self.request('/session')
        if status == 200:
            self.csrf = result['data']['csrf_token']
            return result['data']
        return None

    def complete(self, path, body):
        status, result = self.request(path, body)
        if 200 <= status < 300:
            self.csrf = result['data'].get('csrf_token')
        return status, result

    def cookie(self):
        for value in self.page.context.cookies():
            if value['name'] == 'fw_session':
                return 'fw_session=' + value['value']
        raise CheckFailed('authenticated browser receives a session cookie')


def ui_login(page, client):
    # A new document deliberately has no in-memory session proof. Capture the
    # real login response just as the UI does; never recover it from a cookie or
    # place it in browser storage to evade the product's security boundary.
    with page.expect_response(lambda response: response.url.endswith('/api/v1/auth/passkeys/login/complete')
                              and response.request.method == 'POST') as completion:
        page.get_by_role('button', name='Sign in with a passkey', exact=True).click()
    result = completion.value
    if result.status != 200:
        raise CheckFailed('shipped browser sign-in completes with a signed assertion')
    client.csrf = result.json()['data']['csrf_token']
    page.get_by_role('button', name='Sign out', exact=True).wait_for()


class VirtualDevices:
    """Only test-authenticator memory is exported; nothing is persisted or logged."""
    def __init__(self, context, page):
        self.cdp = context.new_cdp_session(page)
        self.cdp.send('WebAuthn.enable')
        self.saved = {}
        self.current_name = None
        self.current_id = None

    def select(self, name):
        if self.current_id is not None:
            self.saved[self.current_name] = self.cdp.send(
                'WebAuthn.getCredentials', {'authenticatorId': self.current_id})['credentials']
            self.cdp.send('WebAuthn.removeVirtualAuthenticator', {'authenticatorId': self.current_id})
        self.current_id = self.cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
            'protocol': 'ctap2', 'transport': 'usb', 'hasResidentKey': True,
            'hasUserVerification': True, 'isUserVerified': True,
            'automaticPresenceSimulation': True}})['authenticatorId']
        self.current_name = name
        for credential in self.saved.get(name, []):
            self.cdp.send('WebAuthn.addCredential', {'authenticatorId': self.current_id,
                                                   'credential': credential})


def run(args, report):
    from playwright.sync_api import sync_playwright
    with tempfile.TemporaryDirectory(prefix='nox-passkeys-') as temporary:
        state = Path(temporary)
        os.chmod(state, 0o700)
        origin = f'http://localhost:{args.port}'
        environment = dict(os.environ, FW_STATE_DIR=str(state), FW_PORT=str(args.port),
                           FW_PUBLIC_ORIGIN=origin, FW_WEB_DIR=str(ROOT / 'web/dist'))
        # An optional enrollment configuration from another local task must not
        # attach unrelated identity state to this disposable controller.
        environment.pop('FW_ENROLLMENT_DIR', None)
        process = None
        try:
            process = start(environment, origin)
            token_path = state / 'bootstrap-token'
            token = token_path.read_text()
            check(report, 'initial console token is stored privately', token_path.stat().st_mode & 0o777 == 0o600)
            with sync_playwright() as playwright, ExitStack() as cleanup:
                launch = {'headless': True, 'args': ['--no-sandbox']}
                executable = args.browser_executable or shutil.which('chromium')
                if executable:
                    launch['executable_path'] = executable
                browser = playwright.chromium.launch(**launch)
                cleanup.callback(close_browser, browser, report)
                report['browser_version'] = browser.version
                context = browser.new_context(viewport={'width': 1440, 'height': 1000}, locale='ko-KR')
                page = context.new_page()
                page.set_default_timeout(15000)
                http_events = []
                def response_event(response):
                    path = urllib.parse.urlsplit(response.url).path
                    if path not in {'/api/v1/auth/passkeys/registration/options', '/api/v1/auth/passkeys/registration/complete',
                                    '/api/v1/auth/passkeys/login/options', '/api/v1/auth/passkeys/login/complete',
                                    '/api/v1/auth/passkeys', '/api/v1/session'}:
                        return
                    event = {'route': path, 'status': response.status}
                    if response.status >= 400:
                        try:
                            reason = response.json().get('detail')
                            if isinstance(reason, str) and re.fullmatch(r'[A-Z0-9_]{1,80}', reason):
                                event['reason'] = reason
                        except Exception:
                            pass
                    http_events.append(event)
                page.on('response', response_event)
                cleanup.callback(browser_diagnostics, page, report, http_events)
                page_errors = []
                page.on('pageerror', lambda error: page_errors.append(type(error).__name__))
                page.goto(origin)
                page.wait_for_load_state('networkidle')
                report['browser_executed'] = True
                client = BrowserClient(page)
                devices = VirtualDevices(context, page)
                devices.select('primary')
                status, result = client.request('/auth/status')
                check(report, 'configured localhost origin enables browser passkeys before owner enrollment',
                      status == 200 and result['data']['passkey_available'] is True
                      and result['data']['owner_enrolled'] is False and result['data']['bootstrap_available'] is True)
                check(report, 'first page remains English in a Korean browser', page.locator('html').get_attribute('lang') == 'en')
                status, result = client.complete('/session/bootstrap', {'token': token})
                check(report, 'local console token starts the first enrollment session',
                      status == 200 and result['data']['authentication_method'] == 'bootstrap')
                bootstrap_cookie, bootstrap_csrf = client.cookie(), client.csrf
                status, result = client.request('/auth/passkeys/registration/options', {'name': 'Primary passkey'})
                check(report, 'registration requests real user verification', status == 200 and
                      result['data']['public_key']['authenticatorSelection']['userVerification'] == 'required')
                ceremony = result['data']
                credential = page.evaluate(CEREMONY, {'kind': 'create', 'options': ceremony['public_key']})
                status, rejected = client.request('/auth/passkeys/registration/complete', {
                    'ceremony_id': ceremony['ceremony_id'], 'credential': tamper_client_origin(credential)})
                check(report, 'registration rejects a response bound to a different browser origin',
                      status == 401 and rejected.get('detail') == 'PASSKEY_VERIFICATION_FAILED', (status, rejected))
                status, result = client.complete('/auth/passkeys/registration/complete', {
                    'ceremony_id': ceremony['ceremony_id'], 'credential': credential})
                check(report, 'registration requires a signed authentication before granting a passkey session',
                      status == 200 and result['data']['registered'] is True
                      and result['data']['authentication_required'] is True and client.session() is None,
                      (status, result))
                primary_id = result['data']['credential_id']
                status, authentication = client.request('/auth/passkeys/login/options', {})
                check(report, 'newly registered owner can request the required possession proof', status == 200)
                first_assertion = page.evaluate(CEREMONY, {'kind': 'get', 'options': authentication['data']['public_key']})
                status, result = client.complete('/auth/passkeys/login/complete', {
                    'ceremony_id': authentication['data']['ceremony_id'], 'credential': first_assertion})
                check(report, 'actual signed browser assertion activates the initial passkey session',
                      status == 200 and result['data']['credential_id'] == primary_id
                      and result['data']['authentication_method'] == 'passkey' and client.cookie() != bootstrap_cookie)
                status, _ = raw_request(origin, '/session', None, client.cookie())
                check(report, 'a passkey session cookie alone cannot disclose the in-memory session proof', status in (401, 403))
                status, _ = raw_request(origin, '/status', None, client.cookie())
                check(report, 'a passkey session cookie alone cannot read protected controller state', status in (401, 403))
                status, _ = raw_request(origin, '/auth/passkeys/registration/options', {'name': 'Unauthorized key'},
                                        bootstrap_cookie, bootstrap_csrf)
                check(report, 'old bootstrap session cannot enroll another credential after owner creation', status in (401, 403))
                status, result = client.request('/auth/passkeys/registration/complete', {
                    'ceremony_id': ceremony['ceremony_id'], 'credential': credential})
                check(report, 'used registration proof cannot create another session or credential',
                      status == 404 and result.get('detail') == 'NOT_FOUND', (status, result))
                status, result = client.request('/auth/passkeys')
                check(report, 'credential listing exposes metadata without credential key material',
                      status == 200 and len(result['data']['credentials']) == 1
                      and set(result['data']['credentials'][0]) <= {'id', 'name', 'created_at', 'last_used_at', 'revoked_at', 'current', 'verified_at'})
                status, result = client.request(f'/auth/passkeys/{primary_id}/revocations', {})
                check(report, 'the last active passkey cannot be revoked', status == 409 and result['detail'] == 'LAST_PASSKEY_REQUIRED')
                status, _ = raw_request(origin, '/auth/passkeys/login/options', {}, request_origin='https://untrusted.invalid')
                check(report, 'authentication challenge creation rejects an untrusted request Origin', status == 403)

                stop(process)
                process = start(environment, origin)
                check(report, 'controller restart does not generate a replacement owner console token', not token_path.exists())
                status, result = client.request('/auth/status')
                check(report, 'owner enrollment remains durable across a controller restart',
                      status == 200 and result['data']['owner_enrolled'] is True and result['data']['bootstrap_available'] is False)
                status, _ = client.request('/session/bootstrap', {'token': token})
                check(report, 'the previous console token cannot replace the persisted owner after restart', status in (401, 403, 409))
                status, _ = client.request('/session')
                check(report, 'restart does not restore an expired in-memory browser session', status == 401)
                status, result = client.request('/auth/passkeys/login/options', {})
                check(report, 'persisted credential produces a fresh user-verifying authentication challenge',
                      status == 200 and result['data']['public_key']['userVerification'] == 'required')
                ceremony = result['data']
                assertion = page.evaluate(CEREMONY, {'kind': 'get', 'options': ceremony['public_key']})
                forged = json.loads(json.dumps(assertion))
                signature = forged['response']['signature']
                forged['response']['signature'] = ('A' if signature[0] != 'A' else 'B') + signature[1:]
                status, _ = client.request('/auth/passkeys/login/complete', {'ceremony_id': ceremony['ceremony_id'], 'credential': forged})
                check(report, 'forged authenticator signature cannot authenticate the owner', status == 401)
                status, result = client.complete('/auth/passkeys/login/complete', {'ceremony_id': ceremony['ceremony_id'], 'credential': assertion})
                check(report, 'actual browser assertion authenticates the persisted owner after restart',
                      status == 200 and result['data']['credential_id'] == primary_id)
                status, _ = client.request('/auth/passkeys/login/complete', {'ceremony_id': ceremony['ceremony_id'], 'credential': assertion})
                check(report, 'used authentication proof cannot issue a new session', status in (401, 403, 409, 410))
                del token, credential, assertion, first_assertion, forged

                # Exercise the shipped UI with actual navigator.credentials calls.
                report['stage'] = 'ui_sign_in'
                page.reload()
                ui_login(page, client)
                check(report, 'shipped sign-in page completes a real browser passkey ceremony', client.session() is not None)
                report['stage'] = 'ui_security_navigation'
                page.get_by_role('link', name='Security', exact=True).click()
                page.get_by_label('Passkey name', exact=True).wait_for()
                devices.select('secondary')
                report['stage'] = 'ui_second_registration'
                page.get_by_label('Passkey name', exact=True).fill('Recovery passkey')
                page.get_by_role('button', name='Add passkey', exact=True).click()
                report['stage'] = 'ui_second_signed_login'
                ui_login(page, client)
                page.get_by_role('button', name='Revoke Recovery passkey', exact=True).wait_for()
                session = client.session()
                status, result = client.request('/auth/passkeys')
                check(report, 'security page registers a second real credential without a new bootstrap token',
                      session is not None and status == 200 and len(result['data']['credentials']) == 2)
                secondary_id = next(row['id'] for row in result['data']['credentials'] if row['name'] == 'Recovery passkey')
                cli_session = state / 'operator/session.json'
                cli_environment = dict(environment, FW_API_URL=origin,
                                       FW_SESSION_FILE=str(cli_session),
                                       FW_BOOTSTRAP_FILE=str(token_path))
                cli = subprocess.Popen([str(ROOT / 'target/debug/fw_cli'), 'login'], cwd=ROOT,
                                       env=cli_environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                cleanup.callback(stop, cli)
                report['stage'] = 'cli_browser_prompt'
                destination, code = cli_prompt(cli, origin)
                page.goto(destination)
                report['stage'] = 'cli_page_signed_login'
                ui_login(page, client)
                report['stage'] = 'cli_browser_authorization'
                code_input = page.get_by_label('Code from your terminal', exact=True)
                code_input.fill('00000000' if code != '00000000' else 'FFFFFFFF')
                page.get_by_role('button', name='Approve terminal sign-in', exact=True).click()
                page.get_by_text('The code does not match this sign-in request.', exact=True).wait_for()
                check(report, 'browser requires the matching terminal verification code', cli.poll() is None)
                code_input.fill(code)
                page.get_by_role('button', name='Approve terminal sign-in', exact=True).click()
                page.get_by_text('Terminal sign-in authorized. Return to your terminal to finish.', exact=True).wait_for()
                cli.communicate(timeout=15)
                check(report, 'real CLI receives a browser-authorized session without a new console token', cli.returncode == 0)
                check(report, 'CLI saves its credential only in a private session file',
                      cli_session.is_file() and cli_session.stat().st_mode & 0o777 == 0o600)
                check(report, 'browser-authorized CLI session can read the real controller', cli_status(cli_environment) == 0)
                report['cli_handoff_executed'] = True

                status, pending = client.request('/auth/cli/requests', {})
                check(report, 'CLI handoff issues a bounded one-use request', status == 201)
                pending = pending['data']
                route = '/auth/cli/requests/' + pending['request_id']
                status, _ = raw_request(origin, route, None, client.cookie())
                check(report, 'a session cookie alone cannot read a terminal authorization request', status in (401, 403))
                status, _ = client.request(route + '/authorize', {'user_code': '00000000' if pending['user_code'] != '00000000' else 'FFFFFFFF'})
                check(report, 'server rejects an incorrect CLI verification code', status == 403)
                status, _ = raw_request(origin, route + '/authorize', {'user_code': pending['user_code']},
                                        bootstrap_cookie, bootstrap_csrf)
                check(report, 'former bootstrap credentials cannot authorize a terminal session', status in (401, 403))
                status, _ = client.request(route + '/authorize', {'user_code': pending['user_code']})
                check(report, 'fresh passkey session authorizes the matching CLI request', status == 200)
                status, _ = raw_request(origin, route + '/exchange', {'poll_token': pending['poll_token']})
                check(report, 'CLI polling secret exchanges only an authorized request', status == 200)
                status, _ = raw_request(origin, route + '/exchange', {'poll_token': pending['poll_token']})
                check(report, 'CLI polling secret cannot be exchanged twice', status == 409)
                del pending, code

                # Keep a still-active browser session belonging to the credential
                # about to be revoked, together with its in-memory request proof.
                secondary_cookie, secondary_csrf = client.cookie(), client.csrf
                # Open another browser session without logging out the secondary
                # one. Its retained cookie must work before, and fail after,
                # revocation; a previously rotated-away cookie is not evidence.
                context.clear_cookies(name='fw_session')
                devices.select('primary')
                report['stage'] = 'revocation'
                status, result = client.request('/auth/passkeys/login/options', {})
                check(report, 'an existing owner can request a new passkey step-up', status == 200)
                ceremony = result['data']
                assertion = page.evaluate(CEREMONY, {'kind': 'get', 'options': ceremony['public_key']})
                status, result = client.complete('/auth/passkeys/login/complete', {'ceremony_id': ceremony['ceremony_id'], 'credential': assertion})
                check(report, 'fresh authentication binds administrative changes to the selected credential',
                      status == 200 and result['data']['credential_id'] == primary_id)
                status, _ = raw_request(origin, '/session', None, secondary_cookie, secondary_csrf)
                check(report, 'the second browser session is still valid immediately before revocation', status == 200)
                check(report, 'the second CLI session is still valid immediately before revocation', cli_status(cli_environment) == 0)
                status, result = client.request(f'/auth/passkeys/{secondary_id}/revocations', {})
                check(report, 'owner can revoke a second passkey while retaining recovery access', status in (200, 204))
                status, _ = raw_request(origin, '/auth/passkeys/registration/options', {'name': 'Revoked session key'},
                                        secondary_cookie, secondary_csrf)
                check(report, 'a session bound to a revoked credential cannot enroll another passkey', status in (401, 403))
                check(report, 'credential revocation also invalidates its saved CLI session', cli_status(cli_environment) != 0)
                status, result = client.request('/auth/passkeys')
                rows = result['data']['credentials'] if status == 200 else []
                check(report, 'revocation is retained without deleting credential history',
                      status == 200 and any(row['id'] == secondary_id and row['revoked_at'] is not None for row in rows))
                status, result = client.request('/status')
                check(report, 'passkey authentication does not enable firewall dispatch', status == 200 and
                      result['data']['enforcement'] is False and result['data']['native_dispatch_enabled'] is False)
                status, _ = client.request('/auth/logout', {})
                session_status, _ = client.request('/session')
                check(report, 'logout immediately invalidates the current session', status in (200, 204) and session_status == 401)
                check(report, 'browser flow has no uncaught application errors', not page_errors)
                report['stage'] = 'complete'
        finally:
            if process is not None:
                stop(process)
                report['controller_stopped'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8796)
    parser.add_argument('--browser-executable')
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/passkey-smoke.json')
    args = parser.parse_args()
    report = {'schema_version': 'fw.passkey-smoke/v1', 'status': 'FAIL', 'checks': [],
              'authenticator': 'Chromium CDP virtual CTAP2 with user verification',
              'physical_authenticator_tested': False, 'human_policy_approval_tested': False,
              'native_firewall_changed': False, 'credential_values_recorded': False,
              'browser_executed': False, 'cli_handoff_executed': False,
              'browser_closed': False, 'controller_stopped': False}
    try:
        if not 1024 <= args.port <= 65535:
            raise CheckFailed('test port is an unprivileged TCP port')
        report['commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['working_tree_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip())
        report['controller_sha256'] = hashlib.sha256((ROOT / 'target/debug/fw_control').read_bytes()).hexdigest()
        report['cli_sha256'] = hashlib.sha256((ROOT / 'target/debug/fw_cli').read_bytes()).hexdigest()
        run(args, report)
        report['status'] = 'PASS'
    except ModuleNotFoundError:
        report['status'] = 'NOT_RUN'
        report['error'] = {'code': 'BROWSER_TEST_DEPENDENCY_UNAVAILABLE'}
    except Exception as error:
        report['error'] = {'type': type(error).__name__}
        if isinstance(error, CheckFailed):
            report['error']['check'] = str(error)
            if error.http_status is not None:
                report['error']['http_status'] = error.http_status
            if error.reason is not None:
                report['error']['reason'] = error.reason
    finally:
        report['count'] = len(report['checks'])
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 2 if report['status'] == 'NOT_RUN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
