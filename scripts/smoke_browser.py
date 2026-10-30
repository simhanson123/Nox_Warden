#!/usr/bin/env python3
"""Run live local-controller UI integration checks; never record credentials.

Requires Python Playwright and a Chromium executable. Each run needs a fresh
one-use bootstrap token. Run only against a development controller: this creates
one synthetic request, which must remain needs_info with no native dispatch.
"""
from __future__ import annotations

import argparse
import json
import sys
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
                         'No native firewall or packet-enforcement qualification is performed.']}
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
            page.get_by_role('button', name='New request', exact=True).click()
            fixture_id = '11111111-1111-4111-8111-111111111111'
            page.get_by_label('Workflow ID', exact=True).fill('browser-qualification')
            page.get_by_label('Workload binding ID', exact=False).fill(fixture_id)
            page.get_by_label('Source asset ID', exact=True).fill(fixture_id)
            page.get_by_label('Destination asset ID', exact=True).fill(fixture_id)
            page.get_by_label('Service ID', exact=True).fill('https')
            page.get_by_label('Purpose', exact=True).fill('Browser integration check <img src=x onerror="window.compromised=1">')
            page.get_by_role('button', name='Submit request', exact=True).click()
            page.get_by_role('dialog').wait_for()
            page.wait_for_function('document.querySelector("dialog")?.textContent.includes("needs_info")')
            assert page.evaluate('window.compromised') is None
            assert page.locator('dialog img').count() == 0
            result['checks'].append('real request accepted, stored as needs_info; hostile purpose escaped')
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
            for label in ('개요', '접근 요청', '정책', '대상', '감사 기록'):
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
