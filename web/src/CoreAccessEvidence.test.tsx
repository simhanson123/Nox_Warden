// @vitest-environment-options {"url":"http://localhost:8790"}
import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthorityClient } from './authority-api';
import type { AuthorityPlan } from './authority-api';
import CoreAccessEvidence from './CoreAccessEvidence';
import { parseCoreAccessEvidence, readCoreAccessResponse } from './core-access-evidence';
import catalog from './authority-locales.json';
import { locales } from './i18n';

const hash = (digit: string) => 'sha256:' + digit.repeat(64);
const uuid = (digit: string) => digit.repeat(8) + '-' + digit.repeat(4) + '-4' + digit.repeat(3) + '-8' + digit.repeat(3) + '-' + digit.repeat(12);
const at = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z');
const now = () => Math.floor(Date.now() / 1000) * 1000;
function plan(): AuthorityPlan {
  return { plan_hash: hash('a'), requirements_hash: hash('b'), roles: [], current_principal_decisions: [], requirements: {},
    plan: { change_kind: 'add_access_lease', plan_id: uuid('4'), org_id: uuid('2'), project_id: uuid('3'), target_id: uuid('9'),
      request_id: uuid('5'), request_revision: 1, request_hash: hash('c'), valid_until: at(now() + 300000),
      requested_policies: [{ lifetime: { kind: 'lease', not_before: at(now() - 1000), expires_at: at(now() + 3599000) } }] } };
}
function evidence(detail = plan()) {
  return { schema_version: 'fw.core-access-evidence/v1', org_id: detail.plan.org_id, project_id: detail.plan.project_id,
    target_id: detail.plan.target_id, plan_id: detail.plan.plan_id, plan_hash: detail.plan_hash, checked_at: at(now()),
    signing_allowed: false, dispatch_allowed: false, gates: ['CORE_SIGNING_PROFILE_UNAVAILABLE'],
    lease_window: { schema_version: 'fw.core-access-lease-window-status/v1', org_id: detail.plan.org_id, project_id: detail.plan.project_id,
      target_id: detail.plan.target_id, plan_id: detail.plan.plan_id, plan_hash: detail.plan_hash,
      request_id: detail.plan.request_id, request_revision: 1, request_hash: detail.plan.request_hash, provenance_hash: hash('d'),
      lease_id: uuid('6'), lease_seconds: 3600, window_hash: hash('e'), not_before: at(now() - 1000), expires_at: at(now() + 3599000),
      admitted_at: at(now() - 1000), checked_at: at(now()), current: true, signing_allowed: false, dispatch_allowed: false } };
}
function response(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status }); }
const authenticatedSession = { authenticated: true, csrf_token: 'memory-proof', principal_id: 'human', org_id: 'org', project_id: 'project', expires_at: '2099-01-01T00:00:00Z' };
function client() {
  const result = new AuthorityClient();
  result.acceptSession(authenticatedSession);
  return result;
}
afterEach(() => { vi.useRealTimers(); });

test('fixed lease evidence is a bounded authenticated read with no approval or deployment action', async () => {
  const detail = plan(); const data = evidence(detail);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(data));
  render(<CoreAccessEvidence client={client()} detail={detail} locale="en" onUnauthorized={vi.fn()}/>);
  const panel = await screen.findByRole('region', { name: catalog.en['core.heading'] });
  expect(await within(panel).findByText(catalog.en['core.current'])).toBeInTheDocument();
  expect(panel).toHaveTextContent(catalog.en['core.fixed']);
  expect(panel).toHaveTextContent(catalog.en['core.boundary']);
  expect(panel).toHaveTextContent('3600');
  expect(within(panel).getByText(hash('e'))).toBeInTheDocument();
  expect(within(panel).getAllByRole('button')).toHaveLength(1);
  expect(fetch.mock.calls[0][0]).toBe('/authority/v1/plans/' + detail.plan.plan_id + '/core-access-evidence');
  expect(fetch.mock.calls[0][1]).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store' });
  expect(new Headers(fetch.mock.calls[0][1]?.headers).get('X-Authority-CSRF')).toBe('memory-proof');
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

test.each([
  ['tenant', (v: ReturnType<typeof evidence>) => { v.org_id = uuid('1'); }],
  ['plan hash', (v: ReturnType<typeof evidence>) => { v.plan_hash = hash('f'); }],
  ['request', (v: ReturnType<typeof evidence>) => { v.lease_window.request_id = uuid('1'); }],
  ['revision', (v: ReturnType<typeof evidence>) => { v.lease_window.request_revision = 2; }],
  ['duration', (v: ReturnType<typeof evidence>) => { v.lease_window.lease_seconds = 1800; }],
  ['shifted window', (v: ReturnType<typeof evidence>) => { v.lease_window.not_before = at(now() + 1000); v.lease_window.expires_at = at(now() + 3601000); }],
  ['signing', (v: ReturnType<typeof evidence>) => { v.signing_allowed = true; }],
  ['dispatch', (v: ReturnType<typeof evidence>) => { v.lease_window.dispatch_allowed = true; }],
  ['missing blocker', (v: ReturnType<typeof evidence>) => { v.gates = []; }],
  ['invalid date', (v: ReturnType<typeof evidence>) => { v.checked_at = '2026-02-31T00:00:00Z'; }],
  ['future admission', (v: ReturnType<typeof evidence>) => { v.lease_window.admitted_at = at(now() + 1000); }],
  ['unbounded raw request', (v: ReturnType<typeof evidence>) => { Object.assign(v.lease_window, { request: { purpose: 'private' } }); }],
])('malformed core evidence fails closed: %s', (_name, mutate) => {
  const detail = plan(); const value = evidence(detail); mutate(value);
  expect(() => parseCoreAccessEvidence(value, detail)).toThrow();
});

test('duplicate members, invalid UTF-8, oversized bodies and floating numbers are rejected before JSON decoding', async () => {
  for (const body of ['{"lease_window":null,"lease_window":{}}', '{"item":{"x":1,"\\u0078":2}}', '{"seconds":1.0}', ' '.repeat(16385), new Uint8Array([0xff])]) {
    await expect(readCoreAccessResponse(new Response(body))).rejects.toThrow();
  }
  await expect(readCoreAccessResponse(response(evidence()))).resolves.toMatchObject({ schema_version: 'fw.core-access-evidence/v1' });
});

test('missing evidence is explicit and failed refresh clears the last current badge', async () => {
  const detail = plan(); const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response({ ...evidence(detail), lease_window: null }));
  const api = client(); render(<CoreAccessEvidence client={api} detail={detail} locale="en" onUnauthorized={vi.fn()}/>);
  expect(await screen.findByText(catalog.en['core.missing'])).toBeInTheDocument();
  fetch.mockResolvedValueOnce(response(evidence(detail)));
  await userEvent.click(screen.getByRole('button'));
  await screen.findByText(catalog.en['core.current']);
  fetch.mockResolvedValueOnce(response({ error: 'unavailable' }, 503));
  await userEvent.click(screen.getByRole('button'));
  expect(await screen.findByText(catalog.en['core.unavailable'])).toBeInTheDocument();
  expect(screen.queryByText(catalog.en['core.current'])).not.toBeInTheDocument();
});

test('future and historical windows never become current without another authority read', async () => {
  const detail = plan(); const data = evidence(detail);
  data.lease_window.current = false; data.lease_window.not_before = at(now() + 60000); data.lease_window.expires_at = at(now() + 3660000);
  detail.plan.requested_policies = [{ lifetime: { kind: 'lease', not_before: data.lease_window.not_before, expires_at: data.lease_window.expires_at } }];
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response(data));
  render(<CoreAccessEvidence client={client()} detail={detail} locale="en" onUnauthorized={vi.fn()}/>);
  await screen.findByText(catalog.en['core.future']);
  fetch.mockResolvedValueOnce(response({ ...data, lease_window: { ...data.lease_window, not_before: at(now() - 1000), expires_at: at(now() + 3599000) } }));
  // An inconsistent shifted response is refused rather than replacing the fixed window.
  await userEvent.click(screen.getByRole('button'));
  await screen.findByText(catalog.en['core.unavailable']);
  expect(screen.queryByText(catalog.en['core.current'])).not.toBeInTheDocument();
});

test('a backwards authority clock can report retained history inside the window or before admission', async () => {
  const detail = plan(); const data = evidence(detail);
  data.lease_window.current = false;
  data.checked_at = at(now() - 1000); data.lease_window.checked_at = data.checked_at;
  // A separately persisted conservative floor can leave the actual sample
  // before admission without making the retained evidence invalid.
  data.lease_window.admitted_at = at(now());
  expect(parseCoreAccessEvidence(data, detail).lease_window?.current).toBe(false);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(data));
  render(<CoreAccessEvidence client={client()} detail={detail} locale="en" onUnauthorized={vi.fn()}/>);
  expect(await screen.findByText(catalog.en['core.historical'])).toBeInTheDocument();
  expect(screen.queryByText(catalog.en['core.current'])).not.toBeInTheDocument();
  expect(screen.queryByText(catalog.en['core.expired'])).not.toBeInTheDocument();
});

test('expiry cannot renew currentness, even if the wall clock rolls back', async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-05T12:00:00Z'));
  const detail = plan(); detail.plan.valid_until = at(now() + 2000);
  const data = evidence(detail); data.lease_window.not_before = at(now() - 3598000); data.lease_window.expires_at = at(now() + 2000);
  detail.plan.requested_policies = [{ lifetime: { kind: 'lease', not_before: data.lease_window.not_before, expires_at: data.lease_window.expires_at } }];
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(data));
  const api = client(); const callback = vi.fn(); let view!: ReturnType<typeof render>;
  await act(async () => { view = render(<CoreAccessEvidence client={api} detail={detail} locale="en" onUnauthorized={callback}/>); });
  expect(screen.getByText(catalog.en['core.current'])).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(2001); });
  expect(screen.getByText(catalog.en['core.expired'])).toBeInTheDocument();
  vi.setSystemTime(new Date('2026-11-05T11:00:00Z'));
  await act(async () => { view.rerender(<CoreAccessEvidence client={api} detail={detail} locale="en" onUnauthorized={callback}/>); });
  expect(screen.queryByText(catalog.en['core.current'])).not.toBeInTheDocument();
});

test('late old-plan response is discarded, while locale changes retain the same evidence and saved locale policy', async () => {
  const first = plan(); const second = { ...first, plan_hash: hash('f'), plan: { ...first.plan, plan_id: uuid('7') } };
  let deliver!: (response: Response) => void;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => new Promise(resolve => { deliver = resolve; })).mockResolvedValueOnce(response(evidence(second)));
  const api = client(); const callback = vi.fn();
  const view = render(<CoreAccessEvidence client={api} detail={first} locale="en" onUnauthorized={callback}/>);
  view.rerender(<CoreAccessEvidence client={api} detail={second} locale="en" onUnauthorized={callback}/>);
  await screen.findByText(catalog.en['core.current']);
  await act(async () => { deliver(response(evidence(first))); });
  for (const locale of locales) {
    view.rerender(<CoreAccessEvidence client={api} detail={second} locale={locale} onUnauthorized={callback}/>);
    expect(screen.getByRole('region', { name: catalog[locale]['core.heading'] })).toHaveTextContent(catalog[locale]['core.current']);
  }
  expect(fetch).toHaveBeenCalledTimes(2); expect(callback).not.toHaveBeenCalled();
});

test('a consumed deadline stays expired after wall rollback, same-session refresh, remount and returning from another plan', async () => {
  vi.useFakeTimers(); const base = Date.parse('2026-11-05T12:00:00Z'); vi.setSystemTime(base);
  const detail = plan(); detail.plan.valid_until = at(base + 2000);
  const data = evidence(detail); data.lease_window.not_before = at(base - 3598000); data.lease_window.expires_at = at(base + 2000);
  detail.plan.requested_policies = [{ lifetime: { kind: 'lease', not_before: data.lease_window.not_before, expires_at: data.lease_window.expires_at } }];
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => response(data));
  const api = client(); const callback = vi.fn(); let view!: ReturnType<typeof render>;
  await act(async () => { view = render(<CoreAccessEvidence client={api} detail={detail} locale="en" onUnauthorized={callback}/>); });
  expect(screen.getByText(catalog.en['core.current'])).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(2001); });
  expect(screen.getByText(catalog.en['core.expired'])).toBeInTheDocument();
  vi.setSystemTime(base + 1000);
  data.checked_at = at(base + 1000); data.lease_window.checked_at = data.checked_at;
  // An unchanged server-side session synchronization cannot clear the display
  // floor. The fresh response is authentically current on the server's clock.
  api.acceptSession(authenticatedSession);
  await act(async () => { screen.getByRole('button').click(); });
  expect(screen.getByText(catalog.en['core.expired'])).toBeInTheDocument();
  view.unmount();
  await act(async () => { view = render(<CoreAccessEvidence client={api} detail={detail} locale="en" onUnauthorized={callback}/>); });
  expect(screen.getByText(catalog.en['core.expired'])).toBeInTheDocument();
  const other = { ...detail, plan_hash: hash('f'), plan: { ...detail.plan, plan_id: uuid('7') } };
  fetch.mockImplementationOnce(async () => response({ ...data, plan_hash: other.plan_hash, plan_id: other.plan.plan_id,
    lease_window: { ...data.lease_window, plan_hash: other.plan_hash, plan_id: other.plan.plan_id } }));
  await act(async () => { view.rerender(<CoreAccessEvidence client={api} detail={other} locale="en" onUnauthorized={callback}/>); });
  await act(async () => { view.rerender(<CoreAccessEvidence client={api} detail={detail} locale="en" onUnauthorized={callback}/>); });
  expect(screen.getByText(catalog.en['core.expired'])).toBeInTheDocument();
  expect(screen.queryByText(catalog.en['core.current'])).not.toBeInTheDocument();
  expect(callback).not.toHaveBeenCalled();
  // A new authenticated client starts a new explicit authority observation.
  // No floor, proof or other session state is persisted in browser storage.
  view.unmount();
  await act(async () => { render(<CoreAccessEvidence client={client()} detail={detail} locale="en" onUnauthorized={callback}/>); });
  expect(screen.getByText(catalog.en['core.current'])).toBeInTheDocument();
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});
