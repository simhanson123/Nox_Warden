#!/usr/bin/env python3
"""Check shipped catalogue pagination against a real disposable controller.

Creates only manual catalogue records in private temporary controller state.
It does not enroll targets, change authority, or write a host firewall.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


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
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def ready(process, origin):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CheckFailed('controller starts')
        try:
            with opener.open(origin + '/healthz', timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise CheckFailed('controller becomes ready')


SEED = """async ({csrf, owner}) => {
  for (let index = 1; index <= 65; index++) {
    const response = await fetch('/api/v1/assets', {method:'POST', credentials:'same-origin', cache:'no-store',
      headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,'Idempotency-Key':crypto.randomUUID()},
      body:JSON.stringify({state:'active',definition:{name:'Catalogue host '+index,asset_kind:'host',owner_id:owner,
        addresses:[{family:'ipv4',cidr:'192.0.2.'+index+'/32',interface:null}],criticality:'normal',isolation:'host',provenance:'manual',source_evidence:null}})});
    if (response.status !== 201) return {ok:false,status:response.status};
  }
  return {ok:true};
}"""


def run(args, report):
    from playwright.sync_api import sync_playwright, expect
    origin = f'http://localhost:{args.port}'
    with tempfile.TemporaryDirectory(prefix='fw-catalogue-browser-') as temporary, ExitStack() as cleanup:
        state = Path(temporary)
        env = dict(os.environ, FW_STATE_DIR=str(state), FW_PORT=str(args.port), FW_PUBLIC_ORIGIN=origin,
                   FW_WEB_DIR=str(args.ui_directory))
        env.pop('FW_ENROLLMENT_DIR', None)
        with (state / 'controller.log').open('wb') as log:
            process = subprocess.Popen([str(args.controller_binary)], cwd=ROOT, env=env, stdout=log, stderr=log)
            cleanup.callback(stop, process)
            ready(process, origin)
            with sync_playwright() as playwright, ExitStack() as browser_cleanup:
                launch = {'headless': True, 'args': ['--no-sandbox']}
                executable = args.browser_executable or shutil.which('chromium')
                if executable:
                    launch['executable_path'] = executable
                browser = playwright.chromium.launch(**launch)
                browser_cleanup.callback(browser.close)
                context = browser.new_context(viewport={'width': 1440, 'height': 1000}, locale='ja-JP')
                page = context.new_page()
                page.set_default_timeout(15000)
                errors = []
                page.on('pageerror', lambda _error: errors.append('browser_error'))
                page.goto(origin + '/assets')
                page.get_by_label('Console token', exact=True).fill((state / 'bootstrap-token').read_text())
                with page.expect_response(lambda response: response.url.endswith('/api/v1/session/bootstrap')) as completed:
                    page.get_by_role('button', name='Start session', exact=True).click()
                session = completed.value.json()['data']
                check(report, 'shipped UI starts a proof-bound setup session', completed.value.status == 200)
                seeded = page.evaluate(SEED, {'csrf': session['csrf_token'], 'owner': session['principal_id']})
                check(report, 'real controller stores 65 manual asset records', seeded.get('ok') is True)
                page.get_by_role('button', name='Refresh', exact=True).click()
                rows = page.locator('main table tbody tr')
                expect(rows).to_have_count(25)
                first = rows.all_text_contents()
                page.get_by_role('button', name='Next page', exact=True).click()
                expect(page.get_by_text('Page 2', exact=False)).to_be_visible()
                expect(rows).to_have_count(25)
                second = rows.all_text_contents()
                page.get_by_role('button', name='Next page', exact=True).click()
                expect(rows).to_have_count(15)
                third = rows.all_text_contents()
                check(report, 'all 65 rows are reachable without duplicates across three pages', len(set(first + second + third)) == 65)
                page.get_by_role('button', name='Previous page', exact=True).click()
                expect(page.get_by_text('Page 2', exact=False)).to_be_visible()
                expect(rows).to_have_count(25)
                check(report, 'previous moves from the third page to the second snapshot page', rows.all_text_contents() == second)
                page.get_by_label('Rows per page', exact=True).select_option('50')
                expect(rows).to_have_count(50)
                expect(page.get_by_text('Page 1', exact=False)).to_be_visible()
                check(report, 'page-size change resets the cursor and retrieves 50 rows', True)
                page.get_by_role('button', name='Next page', exact=True).click()
                expect(rows).to_have_count(15)
                page.get_by_role('button', name='Refresh', exact=True).click()
                expect(rows).to_have_count(50)
                check(report, 'refresh starts the first page with the selected size', True)
                page.get_by_role('button', name='Next page', exact=True).click()
                expect(rows).to_have_count(15)
                page.get_by_role('button', name='Register asset', exact=True).click()
                page.get_by_label('Display name', exact=True).fill('Created through the paged UI')
                page.get_by_label('Canonical CIDR 1', exact=True).fill('192.0.2.99/32')
                page.get_by_role('button', name='Save immutable revision', exact=True).click()
                expect(page.get_by_text('Registry revision saved. Existing policies have not been rewritten.', exact=True)).to_be_visible()
                page.get_by_role('button', name='Back to registry', exact=True).click()
                expect(rows).to_have_count(50)
                expect(page.get_by_text('Page 1', exact=False)).to_be_visible()
                check(report, 'saved mutation discards old cursors before returning to the collection', True)
                page.get_by_role('link', name='Access requests', exact=True).click()
                page.get_by_role('button', name='New request', exact=True).click()
                source = page.get_by_label('Source asset ID', exact=True)
                expect(source).to_be_enabled()
                picker = source.locator('..').locator('..')
                options = source.locator('option')
                selected = options.nth(1).get_attribute('value')
                source.select_option(selected)
                picker.get_by_role('button', name='Load next registry page', exact=True).click()
                expect(options).to_have_count(51)
                expect(source).to_have_value(selected)
                check(report, 'eligible asset picker loads beyond 25 options while preserving selection', True)
                picker.get_by_role('button', name='Refresh choices', exact=True).click()
                expect(options).to_have_count(26)
                expect(source).to_have_value(selected)
                check(report, 'picker refresh starts a new eligible page without discarding selection', True)

                check(report, 'browser renders without exceptions', not errors)
                context.close()
        stop(process)
        check(report, 'browser and controller cleanup complete', process.poll() is not None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller-binary', type=Path, required=True)
    parser.add_argument('--ui-directory', type=Path, default=ROOT / 'web/dist')
    parser.add_argument('--port', type=int, default=18983)
    parser.add_argument('--browser-executable')
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/catalogue-browser.json')
    args = parser.parse_args()
    args.controller_binary = args.controller_binary.resolve()
    args.ui_directory = args.ui_directory.resolve()
    report = {'schema_version': 'fw.catalogue-browser/v1', 'checks': [], 'scope': 'real controller catalogue and shipped browser UI; no native enforcement qualification'}
    try:
        run(args, report)
    except Exception as error:
        report['failure'] = str(error) if isinstance(error, CheckFailed) else type(error).__name__
        report['passed'] = False
    else:
        report['passed'] = True
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(('PASS' if report['passed'] else 'FAIL') + f": {sum(item['passed'] for item in report['checks'])} catalogue browser checks; {args.report}")
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
