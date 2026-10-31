#!/usr/bin/env python3
"""Exercise owner login after anonymous ceremony floods using real HTTP/WebAuthn.

All identity state and software-authenticator material are disposable. Reports
contain fixed check names and counts, never tickets, cookies or signed proofs.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

from smoke_passkeys import (BrowserClient, CEREMONY, CheckFailed, ROOT,
                            VirtualDevices, check, raw_request, start, stop)


def run(args, report):
    from playwright.sync_api import sync_playwright
    origin = f'http://localhost:{args.port}'
    with tempfile.TemporaryDirectory(prefix='nox-login-admission-') as directory:
        state = Path(directory)
        environment = dict(os.environ, FW_STATE_DIR=str(state), FW_PORT=str(args.port),
                           FW_PUBLIC_ORIGIN=origin, FW_WEB_DIR=str(state / 'absent-web'))
        environment.pop('FW_ENROLLMENT_DIR', None)
        child = start(environment, origin)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, args=['--no-sandbox'],
                    executable_path=args.browser_executable or shutil.which('chromium'))
                try:
                    context = browser.new_context()
                    page = context.new_page()
                    page.goto(origin + '/healthz')
                    client = BrowserClient(page)
                    devices = VirtualDevices(context, page)
                    devices.select('owner')
                    status, _ = client.complete('/session/bootstrap',
                                               {'token': (state / 'bootstrap-token').read_text()})
                    check(report, 'console bootstrap permits initial enrollment', status == 200)
                    status, result = client.request('/auth/passkeys/registration/options', {'name': 'Owner'})
                    check(report, 'authenticated registration creates browser options', status == 200)
                    ceremony = result['data']
                    proof = page.evaluate(CEREMONY, {'kind': 'create', 'options': ceremony['public_key']})
                    status, _ = client.complete('/auth/passkeys/registration/complete',
                        {'ceremony_id': ceremony['ceremony_id'], 'credential': proof})
                    check(report, 'real browser registration creates a pending owner key', status == 200)
                    status, result = client.request('/auth/passkeys/login/options', {})
                    check(report, 'owner receives a login ceremony before anonymous traffic', status == 200)
                    victim = result['data']
                    with sqlite3.connect(state / 'controller.sqlite3') as database:
                        before = database.execute('SELECT count(*) FROM passkey_challenges').fetchone()[0]
                    statuses = Counter(raw_request(origin, '/auth/passkeys/login/options', {})[0]
                                       for _ in range(1005))
                    report['anonymous_option_statuses'] = dict(statuses)
                    check(report, 'all anonymous option requests remain allocation-free and available',
                          statuses == {200: 1005})
                    status, _ = client.request('/auth/passkeys/login/options', {})
                    check(report, 'anonymous issuance cannot exhaust the owners login admission', status == 200)
                    with sqlite3.connect(state / 'controller.sqlite3') as database:
                        after = database.execute('SELECT count(*) FROM passkey_challenges').fetchone()[0]
                    check(report, 'anonymous issuance allocates no durable pending challenge rows', before == after)
                    proof = page.evaluate(CEREMONY, {'kind': 'get', 'options': victim['public_key']})
                    binding = next('fw_auth=' + value['value'] for value in context.cookies()
                                   if value['name'] == 'fw_auth')
                    status, _ = client.complete('/auth/passkeys/login/complete',
                        {'ceremony_id': victim['ceremony_id'], 'credential': proof})
                    check(report, 'an earlier legitimate ceremony survives unrelated anonymous issuance', status == 200)
                    status, _ = raw_request(origin, '/auth/passkeys/login/complete',
                        {'ceremony_id': victim['ceremony_id'], 'credential': proof}, cookie=binding)
                    check(report, 'completed login cannot mint another session', status == 409)
                    status, _ = client.request('/auth/passkeys/registration/options', {'name': 'Spare'})
                    check(report, 'anonymous login traffic cannot exhaust authenticated key registration', status == 200)
                    status, result = client.request('/auth/passkeys/login/options', {})
                    check(report, 'owner can begin authentication before restart', status == 200)
                    pending = result['data']
                    proof = page.evaluate(CEREMONY, {'kind': 'get', 'options': pending['public_key']})
                    stop(child)
                    child = start(environment, origin)
                    status, _ = client.complete('/auth/passkeys/login/complete',
                        {'ceremony_id': pending['ceremony_id'], 'credential': proof})
                    check(report, 'restart invalidates pending encrypted login tickets', status == 401)
                    status, result = client.request('/auth/passkeys/login/options', {})
                    check(report, 'restart permits fresh authentication without a bootstrap token', status == 200)
                    fresh = result['data']
                    proof = page.evaluate(CEREMONY, {'kind': 'get', 'options': fresh['public_key']})
                    status, _ = client.complete('/auth/passkeys/login/complete',
                        {'ceremony_id': fresh['ceremony_id'], 'credential': proof})
                    check(report, 'fresh signed login works after ticket key rotation', status == 200)
                finally:
                    browser.close()
                    report['browser_closed'] = True
        finally:
            stop(child)
            report['controller_stopped'] = child.poll() is not None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18979)
    parser.add_argument('--browser-executable')
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/login-admission-smoke.json')
    args = parser.parse_args()
    report = {'status': 'FAIL', 'checks': [], 'browser_closed': False, 'controller_stopped': False}
    try:
        run(args, report)
        report['status'] = 'PASS'
    except CheckFailed as error:
        report['failure'] = str(error)
    except Exception as error:
        report['failure'] = type(error).__name__
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
