#!/usr/bin/env python3
"""Exercise bounded denial evidence and audit snapshot paging over real HTTP.

Uses a disposable local controller, actual registry mutations and Chromium's
shipped audit screen. It changes no firewall rules and records no credentials,
event contents, identifiers or cursor values in its generated report.
"""

import argparse
from contextlib import ExitStack
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

import jsonschema

from smoke_passkeys import CheckFailed, check, close_browser, start, stop


ROOT = Path(__file__).resolve().parents[1]
SPEC = json.loads((ROOT / 'docs/specs/F_OpenAPI.json').read_text())
VALIDATORS = {}


def validate(name, value):
    if name not in VALIDATORS:
        schema = {'$ref': '#/components/schemas/' + name, 'components': SPEC['components']}
        VALIDATORS[name] = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    VALIDATORS[name].validate(value)


class Client:
    def __init__(self, origin):
        self.origin = origin
        self.csrf = None
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPCookieProcessor(self.cookies))

    def call(self, path, body=None, extra=None):
        headers = {'Accept': 'application/json'}
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Origin': self.origin,
                            'Idempotency-Key': str(uuid.uuid4())})
        headers.update(extra or {})
        request = urllib.request.Request(self.origin + path, headers=headers,
                                         data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.opener.open(request, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def audit(self, limit=25, cursor=None, after=None):
        query = {'limit': str(limit)}
        if cursor:
            query['cursor'] = cursor
        if after is not None:
            query['after_sequence'] = str(after)
        status, result = self.call('/api/v1/audit/events?' + urllib.parse.urlencode(query))
        if status != 200:
            raise CheckFailed('authenticated audit snapshot page is available', (status, result))
        validate('AuditEventsResponse', result)
        if len(result['data']) > limit:
            raise CheckFailed('each audit page respects the requested limit')
        cursor = result['next_cursor']
        if cursor is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,2048}', cursor):
            raise CheckFailed('continuation token matches the original opaque cursor contract')
        return result

    def scan(self, limit=25, first=None):
        page = first or self.audit(limit)
        rows, tokens = [], set()
        for _ in range(30):
            rows.extend(page['data'])
            cursor = page['next_cursor']
            if cursor is None:
                return rows
            if cursor in tokens:
                raise CheckFailed('audit continuation progresses without a cursor loop')
            tokens.add(cursor)
            page = self.audit(limit, cursor)
        raise CheckFailed('bounded fixture audit scan finishes')

    def mcp(self, arguments):
        return self.call('/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                 'params': {'name': 'get_audit_events', 'arguments': arguments}})


def mcp_page(client, arguments):
    status, body = client.mcp(arguments)
    result = body.get('result', {})
    if status != 200 or result.get('isError') is not False:
        raise CheckFailed('MCP audit reader returns an authenticated bounded page')
    page = result['structuredContent']
    validate('AuditEventsResponse', page)
    if json.loads(result['content'][0]['text']) != page:
        raise CheckFailed('MCP text and structured audit evidence agree')
    return page


def asset(client, owner, index):
    body = {'definition': {'name': f'Audit pagination fixture {index}', 'asset_kind': 'host',
                          'owner_id': owner, 'addresses': [{'family': 'ipv4', 'cidr': f'192.0.2.{index + 1}/32', 'interface': None}],
                          'criticality': 'normal', 'isolation': 'host', 'provenance': 'manual', 'source_evidence': None},
            'state': 'active'}
    status, result = client.call('/api/v1/assets', body)
    if status != 201:
        raise CheckFailed('real registry mutation creates audit fixture evidence', (status, result))
    validate('AssetResponse', result)
    return result['data']['asset_id']


def run(args, report):
    from playwright.sync_api import sync_playwright
    with tempfile.TemporaryDirectory(prefix='nox-audit-') as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        origin = f'http://localhost:{args.port}'
        environment = dict(os.environ, FW_STATE_DIR=str(directory), FW_PORT=str(args.port),
                           FW_PUBLIC_ORIGIN=origin, FW_WEB_DIR=str(ROOT / 'web/dist'))
        environment.pop('FW_ENROLLMENT_DIR', None)
        process = start(environment, origin)
        try:
            anonymous = Client(origin)
            report['stage'] = 'denial_flood'
            for _ in range(100):
                status, response = anonymous.call('/api/v1/status')
                report['anonymous_requests'] += 1
                if status != 401:
                    raise CheckFailed('anonymous status requests remain unauthorized', (status, response))
                validate('Problem', response)
            check(report, 'one hundred anonymous status requests remain unauthorized', True)
            for _ in range(100):
                status, response = anonymous.call('/api/v1/status', extra={'Cookie': 'fw_session=invalid-test-cookie'})
                report['invalid_cookie_requests'] += 1
                if status != 401:
                    raise CheckFailed('invalid credential requests remain unauthorized', (status, response))
            check(report, 'one hundred invalid-cookie attempts remain unauthorized', True)

            report['stage'] = 'bootstrap'
            token_file = directory / 'bootstrap-token'
            token = token_file.read_text()
            client = Client(origin)
            status, response = client.call('/api/v1/session/bootstrap', {'token': token})
            check(report, 'legitimate console authentication still succeeds after the denial flood', status == 200, (status, response))
            client.csrf = response['data']['csrf_token']
            owner = response['data']['principal_id']
            check(report, 'successful bootstrap removes its consumed token file before returning', not token_file.exists())
            del token
            initial = client.audit(25)
            check(report, 'audit reads remain available and bounded after authentication noise',
                  len(initial['data']) <= 2 and initial['next_cursor'] is None)
            first_mcp = mcp_page(client, {'limit': 25})
            check(report, 'MCP audit reads remain available after authentication noise', len(first_mcp['data']) <= 25)

            report['stage'] = 'registry_mutations'
            created = {asset(client, owner, index) for index in range(110)}
            check(report, 'real registry requests create more than one hundred legitimate audit events', len(created) == 110)
            reference = client.scan(25)
            expected = [(row['sequence'], row['event_id']) for row in reference]
            check(report, 'original audit response schema validates throughout a complete multi-page scan', len(reference) > 100)
            check(report, 'all successful registry mutations have retained audit evidence',
                  created <= {row['resource_id'] for row in reference})

            report['stage'] = 'snapshot_membership'
            first = client.audit(25)
            continuation = first['next_cursor']
            check(report, 'a full audit page returns a bounded opaque continuation token',
                  0 < len(first['data']) <= 25 and continuation is not None)
            appended = asset(client, owner, 111)
            snapshot = client.scan(25, first)
            observed = [(row['sequence'], row['event_id']) for row in snapshot]
            check(report, 'snapshot traversal contains every original event once in stable order',
                  observed == expected and len({row['event_id'] for row in snapshot}) == len(snapshot)
                  and [int(row['sequence']) for row in snapshot] == sorted(int(row['sequence']) for row in snapshot))
            check(report, 'an event appended after the first page cannot enter that snapshot',
                  all(row['resource_id'] != appended for row in snapshot))
            current = client.scan(25)
            check(report, 'a new audit scan includes the later registry event',
                  any(row['resource_id'] == appended for row in current) and len(current) > len(snapshot))

            report['stage'] = 'cursor_rejection'
            bad = ('A' if continuation[0] != 'A' else 'B') + continuation[1:]
            status, response = client.call('/api/v1/audit/events?' + urllib.parse.urlencode({'limit': 25, 'cursor': bad}))
            validate('Problem', response)
            check(report, 'modified audit cursors are rejected', status == 400)
            status, response = client.call('/api/v1/audit/events?' + urllib.parse.urlencode({'limit': 24, 'cursor': continuation}))
            check(report, 'a cursor cannot silently change the requested page size', status == 400)
            status, response = client.call('/api/v1/audit/events?' + urllib.parse.urlencode({'limit': 25, 'after_sequence': 1, 'cursor': continuation}))
            check(report, 'a cursor cannot silently change its original sequence filter', status == 400)
            status, response = client.mcp({'limit': 25, 'cursor': continuation})
            check(report, 'REST audit cursors cannot be replayed through the MCP route',
                  status == 200 and response.get('result', {}).get('isError') is True)

            report['stage'] = 'mcp_pagination'
            current = client.scan(25)
            mcp_rows = []
            mcp_cursor = None
            for _ in range(30):
                arguments = {'limit': 25}
                if mcp_cursor:
                    arguments['cursor'] = mcp_cursor
                page = mcp_page(client, arguments)
                if len(page['data']) > 25:
                    raise CheckFailed('MCP page respects its requested limit')
                mcp_rows.extend(page['data'])
                mcp_cursor = page['next_cursor']
                if mcp_cursor is None:
                    break
            else:
                raise CheckFailed('bounded MCP audit scan finishes')
            check(report, 'MCP continuation traverses the same retained audit evidence without omissions',
                  [(row['sequence'], row['event_id']) for row in mcp_rows]
                  == [(row['sequence'], row['event_id']) for row in current])

            report['stage'] = 'browser_pagination'
            # Before owner enrollment a restart provides a new local console
            # token. Authenticate the browser through the actual setup form;
            # importing a cookie cannot recover its separate in-memory proof.
            stop(process)
            process = start(environment, origin)
            with sync_playwright() as playwright, ExitStack() as cleanup:
                launch = {'headless': True, 'args': ['--no-sandbox']}
                executable = args.browser_executable or shutil.which('chromium')
                if executable:
                    launch['executable_path'] = executable
                browser = playwright.chromium.launch(**launch)
                cleanup.callback(close_browser, browser, report)
                report['browser_version'] = browser.version
                context = browser.new_context(locale='en-US')
                browser_page = context.new_page()
                browser_page.set_default_timeout(15000)
                errors = []
                browser_page.on('pageerror', lambda error: errors.append(type(error).__name__))
                def audit_response(response):
                    return urllib.parse.urlsplit(response.url).path == '/api/v1/audit/events'
                browser_page.goto(origin + '/audit')
                browser_page.get_by_label('Console token', exact=True).fill(token_file.read_text())
                with browser_page.expect_response(audit_response) as loading:
                    browser_page.get_by_role('button', name='Start session', exact=True).click()
                report['browser_executed'] = True
                loaded = loading.value
                first_visible = loaded.json()
                validate('AuditEventsResponse', first_visible)
                browser_page.get_by_role('button', name=first_visible['data'][0]['sequence'], exact=True).wait_for()
                check(report, 'shipped audit page displays the first bounded page after the flood',
                      loaded.status == 200 and browser_page.locator('tbody tr').count() == len(first_visible['data']))
                with browser_page.expect_response(audit_response) as next_loading:
                    browser_page.get_by_role('button', name='Next page', exact=True).click()
                loaded = next_loading.value
                next_visible = loaded.json()
                validate('AuditEventsResponse', next_visible)
                browser_page.get_by_role('button', name=next_visible['data'][0]['sequence'], exact=True).wait_for()
                check(report, 'Next page loads later audit events without RESULT_TOO_LARGE',
                      loaded.status == 200 and int(next_visible['data'][0]['sequence']) > int(first_visible['data'][-1]['sequence'])
                      and browser_page.locator('[role="alert"]').count() == 0)
                check(report, 'audit browser pagination has no uncaught application errors', not errors)
            report['snapshot_events_verified'] = len(snapshot)
            report['new_scan_events_verified'] = len(current)
            report['stage'] = 'complete'
        finally:
            stop(process)
            report['controller_stopped'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8797)
    parser.add_argument('--browser-executable')
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/audit-smoke.json')
    args = parser.parse_args()
    report = {'schema_version': 'fw.audit-smoke/v1', 'status': 'FAIL', 'checks': [],
              'anonymous_requests': 0, 'invalid_cookie_requests': 0,
              'native_firewall_changed': False, 'credential_values_recorded': False,
              'browser_executed': False, 'browser_closed': False, 'controller_stopped': False}
    try:
        if not 1024 <= args.port <= 65535:
            raise CheckFailed('test port is an unprivileged TCP port')
        report['commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['working_tree_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip())
        report['controller_sha256'] = hashlib.sha256((ROOT / 'target/debug/fw_control').read_bytes()).hexdigest()
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
        if isinstance(error, jsonschema.ValidationError):
            report['error']['schema_path'] = list(error.absolute_schema_path)
    finally:
        report['count'] = len(report['checks'])
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 2 if report['status'] == 'NOT_RUN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
