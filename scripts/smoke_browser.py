#!/usr/bin/env python3
"""Run live local-controller UI integration checks; never record credentials.

Requires Python Playwright and a Chromium executable. Each run needs a fresh
one-use bootstrap token. Run only against a development controller: this creates
one manual asset with two revisions and one explicitly untrusted validation-failure
request, which must remain needs_info with no native dispatch. Service creation
is expected to remain blocked when genuine target enrollment is unavailable.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8787')
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('reports/browser'))
    parser.add_argument('--browser-executable', default='/usr/bin/chromium')
    args = parser.parse_args()
    base = args.base_url.rstrip('/')
    parsed = urlsplit(base)
    if parsed.hostname not in {'127.0.0.1', 'localhost', '::1'} or parsed.path not in {'', '/'}:
        parser.error('Use a loopback development controller URL without a path.')
    args.output.mkdir(parents=True, exist_ok=True)
    result = {'status': 'FAIL', 'browser': 'Chromium', 'browser_version': None,
              'viewports': {'desktop': {'width': 1440, 'height': 1000}, 'mobile': {'width': 390, 'height': 844}},
              'screens': [], 'checks': [], 'console_errors': [], 'external_requests': [],
              'limits': ['Not a complete WCAG audit.', 'Translation requires human security review.',
                         'No native firewall or packet-enforcement qualification is performed.',
                         'Service success is not verified: no genuine enrolled target exists.',
                         'The request fixture intentionally lacks trusted binding/service authority.']}
    root = Path(__file__).resolve().parents[1]
    catalogs = json.loads((root / 'web/src/locales.json').read_text())
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.browser_executable, headless=True,
                                                 args=['--no-sandbox'])
            result['browser_version'] = browser.version
            context = browser.new_context(viewport=result['viewports']['desktop'], locale='en-US',
                                          reduced_motion='reduce')
            page = context.new_page()
            page.on('pageerror', lambda error: result['console_errors'].append(str(error)))
            # Store destination origin only; never URL query strings or credentials.
            def record_destination(request):
                target = urlsplit(request.url)
                if (target.scheme, target.hostname, target.port) != (parsed.scheme, parsed.hostname, parsed.port):
                    result['external_requests'].append(f'{target.scheme}://{target.hostname}')
            page.on('request', record_destination)
            page.goto(base + '/overview')
            token = args.token_file.read_text().strip()
            page.get_by_label('Console token').fill(token)
            del token
            page.get_by_role('button', name='Start session').click()
            page.get_by_text(catalogs['en']['overview.noEnforcement']).wait_for()
            result['checks'].append('live cookie bootstrap and observe-only indication')
            page.screenshot(path=str(args.output / 'overview-desktop.png'), full_page=True)
            result['screens'].append('overview-desktop.png')
            assert page.evaluate('localStorage.length') == 1
            assert page.evaluate('localStorage.getItem("fw.locale")') == 'en'
            result['checks'].append('only locale persisted in localStorage')
            page.goto(base + '/overview')
            page.get_by_text(catalogs['en']['overview.noEnforcement']).wait_for()
            page.keyboard.press('Tab')
            assert page.evaluate('document.activeElement.className') == 'skip-link'
            page.keyboard.press('Enter')
            assert page.evaluate('document.activeElement.id') == 'main'
            result['checks'].append('keyboard skip link focuses main content')
            page.get_by_role('link', name='Assets', exact=True).click()
            page.get_by_role('button', name='Register asset', exact=True).click()
            page.get_by_label('Display name', exact=True).fill('Browser asset <img src=x onerror="window.registryCompromised=1">')
            page.get_by_label('Canonical CIDR 1', exact=True).fill('192.0.2.10/32')
            page.get_by_role('button', name='Save immutable revision', exact=True).click()
            page.get_by_text(catalogs['en']['registry.saved'], exact=True).wait_for()
            page.locator('.registry-detail .badge').filter(has_text='r1').wait_for()
            asset_id = page.url.rsplit('/', 1)[-1]
            first_record = page.request.get(base + '/api/v1/assets/' + asset_id).json()['data']
            assert first_record['definition']['provenance'] == 'manual'
            assert first_record['definition']['source_evidence'] is None
            assert page.evaluate('window.registryCompromised') is None
            assert page.locator('.registry-detail img').count() == 0
            result['checks'].append('manual asset registration persists exact address without trusted identity claim; hostile name escaped')
            page.get_by_role('button', name='Create new revision', exact=True).click()
            page.get_by_label('Display name', exact=True).fill('Browser asset revised')
            page.get_by_label('Canonical CIDR 1', exact=True).fill('192.0.2.11/32')
            page.get_by_role('button', name='Save immutable revision', exact=True).click()
            page.locator('.registry-detail .badge').filter(has_text='r2').wait_for()
            revised = page.request.get(base + '/api/v1/assets/' + asset_id).json()['data']
            assert revised['revision'] == 2
            assert revised['previous_revision_hash'] == first_record['content_hash']
            assert revised['content_hash'] != first_record['content_hash']
            assert revised['definition']['addresses'][0]['cidr'] == '192.0.2.11/32'
            page.reload()
            page.locator('.registry-detail .badge').filter(has_text='r2').wait_for()
            result['checks'].append('asset revision uses exact ETag, preserves hash predecessor, and detail survives reload')
            page.evaluate('document.activeElement.blur(); window.scrollTo(0, 0)')
            page.screenshot(path=str(args.output / 'asset-revision-desktop.png'), full_page=True)
            result['screens'].append('asset-revision-desktop.png')
            page.get_by_role('link', name='Services', exact=True).click()
            page.get_by_role('button', name='Register service', exact=True).click()
            page.get_by_text(catalogs['en']['registry.noTargets'], exact=True).wait_for()
            assert page.request.get(base + '/api/v1/targets?limit=25').json()['data'] == []
            assert page.get_by_label('Registered targets', exact=True).is_disabled()
            assert page.get_by_role('button', name='Save immutable revision', exact=True).is_disabled()
            result['checks'].append('service creation is visibly blocked without a genuine registered target; no service success claimed')
            page.evaluate('document.activeElement.blur(); window.scrollTo(0, 0)')
            page.screenshot(path=str(args.output / 'service-prerequisite-desktop.png'), full_page=True)
            result['screens'].append('service-prerequisite-desktop.png')
            page.get_by_role('link', name='Access requests', exact=True).click()
            page.get_by_role('button', name='New request', exact=True).click()
            page.get_by_label('Source asset ID', exact=True).locator('option[value="' + asset_id + '"]').wait_for(state='attached')
            assert page.get_by_label('Service ID', exact=True).is_disabled()
            assert page.get_by_role('button', name='Submit request', exact=True).is_disabled()
            result['checks'].append('request form selects real registry assets and cannot invent an unavailable service')
            # Explicit negative fixture: API ingestion is not authorization. No service,
            # enrolled target or trusted workload binding is created for this request.
            session = page.request.get(base + '/api/v1/session').json()['data']
            key = str(uuid.uuid4())
            fixture_id = '11111111-1111-4111-8111-111111111111'
            negative_request = {'schema_version': 'f.access-request/v1', 'idempotency_key': key,
                                'workflow_id': 'browser-untrusted-validation-fixture',
                                'workload_binding_id': fixture_id, 'source_asset_ids': [asset_id],
                                'destination_asset_ids': [asset_id], 'service_id': 'unregistered-browser-fixture',
                                'lease_seconds': 60,
                                'purpose': 'Untrusted validation failure <img src=x onerror="window.compromised=1">'}
            accepted = page.request.post(base + '/api/v1/access-requests', data=negative_request,
                                         headers={'Origin': base, 'X-CSRF-Token': session['csrf_token'], 'Idempotency-Key': key})
            del session
            assert accepted.status == 202
            request_id = accepted.json()['data']['resource_id']
            page.goto(base + '/requests/' + request_id)
            page.get_by_role('dialog').wait_for()
            page.wait_for_function('document.querySelector("dialog")?.textContent.includes("needs_info")')
            assert page.evaluate('window.compromised') is None
            assert page.locator('dialog img').count() == 0
            result['checks'].append('explicitly untrusted API request remains needs_info; hostile purpose escaped without an enforcement claim')
            assert '/requests/' in page.url
            page.reload()
            page.get_by_role('dialog').wait_for()
            assert 'needs_info' in page.get_by_role('dialog').inner_text()
            result['checks'].append('request deep link survives page reload')
            page.get_by_role('dialog').get_by_role('button', name='Close', exact=True).last.click()
            page.get_by_role('link', name='Audit trail', exact=True).click()
            page.get_by_role('table').wait_for()
            assert page.locator('tbody tr').count() > 0
            result['checks'].append('live request and authentication audit records rendered')
            page.screenshot(path=str(args.output / 'audit-desktop.png'), full_page=True)
            result['screens'].append('audit-desktop.png')
            page.get_by_role('link', name='Targets', exact=True).click()
            page.get_by_text('Platform qualification', exact=True).wait_for()
            assert page.get_by_text('nftables', exact=True).count() == 1
            assert page.get_by_text('windows_wfp', exact=True).count() == 1
            assert page.get_by_text('macos_network_extension', exact=True).count() == 1
            result['checks'].append('server-provided qualification matrix distinguishes unverified and unsupported')
            page.get_by_role('link', name='Overview', exact=True).click()
            for locale, catalog in catalogs.items():
                page.locator('.language-label select').select_option(locale)
                page.get_by_text(catalog['overview.noEnforcement']).wait_for()
                assert page.locator('html').get_attribute('lang') == locale
            result['checks'].append('six locales preserve no-enforcement meaning in live UI')
            page.locator('.language-label select').select_option('ko')
            page.get_by_text(catalogs['ko']['overview.noEnforcement']).wait_for()
            page.set_viewport_size(result['viewports']['mobile'])
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            scroll_region = page.locator('.table-scroll').first
            assert scroll_region.evaluate('(element) => element.scrollWidth > element.clientWidth')
            scroll_region.focus()
            assert scroll_region.evaluate('(element) => document.activeElement === element')
            for label in ('개요', '접근 요청', '자산', '서비스', '정책', '대상', '감사 기록'):
                assert page.get_by_role('link', name=label, exact=True).count() == 1
            result['checks'].append('390px viewport has no document overflow; internal table scroll and icon navigation have keyboard names')
            page.evaluate('document.activeElement.blur(); window.scrollTo(0, 0)')
            page.screenshot(path=str(args.output / 'overview-mobile-ko.png'), full_page=True)
            result['screens'].append('overview-mobile-ko.png')
            page.set_viewport_size(result['viewports']['desktop'])
            page.evaluate('window.scrollTo(0, 0)')
            page.screenshot(path=str(args.output / 'overview-desktop-ko.png'), full_page=True)
            result['screens'].append('overview-desktop-ko.png')
            assert not result['console_errors'], result['console_errors']
            assert not result['external_requests'], result['external_requests']
            result['checks'].append('no page exceptions or external requests')
            result['status'] = 'PASS'
            context.close()
            browser.close()
    except Exception as error:
        # Errors contain selector/route diagnostics, but never token or cookie values.
        result['failure'] = {'type': type(error).__name__, 'message': str(error)}
    (args.output / 'result.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
