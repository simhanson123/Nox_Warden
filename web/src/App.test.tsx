import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
import { ApiError, api, setCsrfToken } from './api';
import { locales, translator } from './i18n';

const session = { authenticated: true, org_id: 'org-local', project_id: 'project-local', principal_id: 'owner-local', csrf_token: 'csrf-session-test' };
function response(data: unknown, status = 200) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }); }
function mockController(options: { noSession?: boolean; auditError?: boolean; audit?: unknown[] } = {}) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const path = String(input);
    if (path === '/api/v1/session') return options.noSession ? response({ code: 'UNAUTHENTICATED' }, 401) : response({ data: session, actions: [{ action_id: 'requests.create', allowed: true, reason_code: null }] });
    if (path === '/api/v1/session/bootstrap') return response({ data: session, actions: [{ action_id: 'requests.create', allowed: true, reason_code: null }] });
    if (path === '/api/v1/status') return response({ data: { mode: 'observe', enforcement: false, version: '0.1.0' } });
    if (path.includes('/audit/events')) return options.auditError ? response({ code: 'STORE_UNAVAILABLE', detail: 'Audit store unavailable' }, 503) : response({ data: options.audit ?? [], next_cursor: null });
    return response({ data: [], next_cursor: null });
  });
}
beforeEach(() => {
  localStorage.clear(); localStorage.setItem('fw.locale', 'en'); setCsrfToken(undefined);
  history.replaceState(null, '', '/overview');
  HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
});

test('displays observe-only and no enforcement without inventing native success', async () => {
  mockController(); render(<App />);
  expect(await screen.findByText('This controller is not enforcing network traffic.')).toBeInTheDocument();
  expect(screen.getByText('Observe only')).toBeInTheDocument();
  expect(screen.queryByText('Active — enforcement has been observed and confirmed.')).not.toBeInTheDocument();
  expect(screen.getByText('Optional telemetry is off.')).toBeInTheDocument();
});

test('an audit read failure is visible and is not shown as an empty collection', async () => {
  mockController({ auditError: true }); render(<App />);
  expect(await screen.findByText('STORE_UNAVAILABLE')).toBeInTheDocument();
  expect(screen.queryByText('Nothing here yet')).not.toBeInTheDocument();
});

test('audit labels containing HTML are rendered as escaped text', async () => {
  const malicious = '<img src=x onerror="window.hacked=1">';
  mockController({ audit: [{ sequence: '1', event_type: malicious, event_id: 'event-1', server_time: '2026-10-30T00:00:00Z' }] });
  const { container } = render(<App />);
  expect(await screen.findByText(malicious)).toBeInTheDocument();
  expect(container.querySelector('img')).toBeNull();
});

test('bootstrap token stays out of storage and CSRF binds subsequent POST', async () => {
  const fetch = mockController({ noSession: true }); render(<App />);
  const token = await screen.findByLabelText('Console token');
  await userEvent.type(token, 'console-secret-test');
  await userEvent.click(screen.getByRole('button', { name: 'Start session' }));
  await screen.findByText('This controller is not enforcing network traffic.');
  const bootstrap = fetch.mock.calls.find(([input]) => String(input).endsWith('/session/bootstrap'));
  expect(JSON.parse(String(bootstrap?.[1]?.body))).toEqual({ token: 'console-secret-test' });
  expect(bootstrap?.[1]?.credentials).toBe('same-origin');
  expect(localStorage.length).toBe(1);
  expect(localStorage.getItem('fw.locale')).toBe('en');
  await api('/access-requests', { body: { example: true }, key: 'stable-key' });
  const last = fetch.mock.calls.at(-1)?.[1];
  expect(last?.headers).toMatchObject({ 'X-CSRF-Token': session.csrf_token, 'Idempotency-Key': 'stable-key' });
});

test('locale selector changes security meaning with complete catalog parity', async () => {
  mockController(); render(<App />);
  await screen.findByText('This controller is not enforcing network traffic.');
  fireEvent.change(screen.getByLabelText('Display language'), { target: { value: 'ko' } });
  expect(await screen.findByText('이 제어 서비스는 네트워크 트래픽을 집행하지 않습니다.')).toBeInTheDocument();
  expect(document.documentElement.lang).toBe('ko');
  for (const locale of locales) {
    expect(translator(locale)('request.description')).not.toBe('request.description');
    expect(translator(locale)('operation.accepted')).not.toBe('operation.accepted');
  }
});

test('a failed request retry retains the same idempotency key and exact payload', async () => {
  const fetch = mockController();
  const base = fetch.getMockImplementation()!;
  let attempts = 0;
  fetch.mockImplementation(async (input, init) => {
    if (String(input) === '/api/v1/access-requests' && init?.method === 'POST') { attempts++; return response({ code: 'TEMPORARY_FAILURE' }, 503); }
    return base(input, init);
  });
  history.replaceState(null, '', '/requests/new'); render(<App />);
  await screen.findByLabelText('Workflow ID');
  const uuid = '11111111-1111-4111-8111-111111111111';
  fireEvent.change(screen.getByLabelText('Workflow ID'), { target: { value: 'workflow-test' } });
  fireEvent.change(screen.getByLabelText(/Workload binding ID/), { target: { value: uuid } });
  fireEvent.change(screen.getByLabelText('Source asset ID'), { target: { value: uuid } });
  fireEvent.change(screen.getByLabelText('Destination asset ID'), { target: { value: uuid } });
  fireEvent.change(screen.getByLabelText('Service ID'), { target: { value: 'https' } });
  fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'A scoped test request' } });
  await userEvent.click(screen.getByRole('button', { name: 'Submit request' }));
  await screen.findByText('TEMPORARY_FAILURE');
  await userEvent.click(screen.getByRole('button', { name: 'Submit request' }));
  await waitFor(() => expect(attempts).toBe(2));
  const mutations = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(mutations[0][1]?.body).toBe(mutations[1][1]?.body);
  const body = JSON.parse(String(mutations[0][1]?.body));
  expect(body.schema_version).toBe('f.access-request/v1');
  expect(mutations[0][1]?.headers).toMatchObject({ 'Idempotency-Key': body.idempotency_key });
});

test('API errors preserve denial codes rather than returning a success envelope', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ code: 'FORBIDDEN', detail: 'Denied', request_id: 'r1' }, 403));
  await expect(api('/audit/events')).rejects.toEqual(new ApiError(403, 'FORBIDDEN', 'Denied', 'r1'));
});

test('missing server action hints disable mutation controls even for an authenticated session', async () => {
  const fetch = mockController(); const base = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input, init) => String(input) === '/api/v1/session' ? response({ data: session }) : base(input, init));
  render(<App />);
  expect(await screen.findByRole('button', { name: 'New request' })).toBeDisabled();
});

test('a request detail deep link retrieves the exact resource from the API', async () => {
  const id = '11111111-1111-4111-8111-111111111111';
  const fetch = mockController(); const base = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input, init) => String(input) === '/api/v1/access-requests/' + id ? response({ data: { request_id: id, state: 'needs_info', purpose: 'A linked request' } }) : base(input, init));
  history.replaceState(null, '', '/requests/' + id); render(<App />);
  expect(await screen.findByRole('dialog')).toHaveTextContent('A linked request');
  expect(screen.getByRole('dialog')).toHaveTextContent('needs_info');
  await userEvent.click(screen.getAllByRole('button', { name: 'Close' })[0]);
  expect(location.pathname).toBe('/requests');
});

test('a malformed collection response is rejected instead of shown as empty', async () => {
  const fetch = mockController(); const base = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input, init) => String(input).includes('/audit/events') ? response({ data: { unexpected: true } }) : base(input, init));
  render(<App />);
  expect(await screen.findByText('INVALID_RESPONSE')).toBeInTheDocument();
  expect(screen.queryByText('Nothing here yet')).not.toBeInTheDocument();
});
