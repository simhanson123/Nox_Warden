import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CliLoginPage, PasskeysPage, SessionGate } from './Passkeys';
import { setCsrfToken } from './api';
import { translator } from './i18n';
import { encodeBase64Url } from './webauthn';

const t = translator('en');
const status = { passkey_available: true, passkey_unavailable_reason: null, owner_enrolled: true, bootstrap_available: false, rp_id: 'localhost', origin: 'http://localhost:8787' };
const session = { authenticated: true, principal_id: 'owner', org_id: 'org', project_id: 'project', csrf_token: 'test-csrf', authentication_method: 'passkey' as const, authenticated_at: Math.floor(Date.now() / 1000), credential_id: 'AQI', owner_enrolled: true };
const challenge = encodeBase64Url(Uint8Array.from(Array(32).fill(7)).buffer);
const loginOptions = { ceremony_id: 'ceremony-login', expires_at: '2026-10-31T09:00:00Z', public_key: { rpId: 'localhost', challenge, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: 'AQI' }] } };
const registerOptions = { ceremony_id: 'ceremony-register', expires_at: '2026-10-31T09:00:00Z', public_key: { rp: { id: 'localhost', name: 'Warden' }, user: { id: 'AQI', name: 'owner', displayName: 'Owner' }, challenge, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { userVerification: 'required' } } };
const record = { id: 'AQI', name: '<img src=x>', created_at: '2026-10-31T08:00:00Z', last_used_at: '2026-10-31T08:00:00Z', revoked_at: null, verified_at: '2026-10-31T08:00:00Z', current: true };
function response(data: unknown, statusCode = 200) { return new Response(JSON.stringify(statusCode === 200 ? { data } : data), { status: statusCode, headers: { 'Content-Type': 'application/json' } }); }
const originalCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
function browser() {
  vi.stubGlobal('isSecureContext', true); vi.stubGlobal('PublicKeyCredential', class {});
  const common = { id: 'AQI', rawId: Uint8Array.from([1, 2]).buffer, type: 'public-key', getClientExtensionResults: () => ({}) };
  const create = vi.fn().mockResolvedValue({ ...common, response: { attestationObject: Uint8Array.from([1, 2, 3]).buffer, clientDataJSON: Uint8Array.from([4, 5, 6]).buffer, getTransports: () => ['internal'] } });
  const get = vi.fn().mockResolvedValue({ ...common, response: { authenticatorData: Uint8Array.from([1, 2, 3]).buffer, clientDataJSON: Uint8Array.from([4, 5, 6]).buffer, signature: Uint8Array.from([7, 8]).buffer, userHandle: null } });
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create, get } });
  return { create, get };
}
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); setCsrfToken('test-csrf'); });
afterEach(() => { vi.unstubAllGlobals(); if (originalCredentials) Object.defineProperty(navigator, 'credentials', originalCredentials); else Reflect.deleteProperty(navigator, 'credentials'); });

test('enrolled login hides bootstrap and invokes the authenticator only after an explicit click', async () => {
  const native = browser(); const onSession = vi.fn();
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    if (String(input).endsWith('/auth/status')) return response(status);
    if (String(input).endsWith('/login/options')) return response(loginOptions);
    if (String(input).endsWith('/login/complete')) return response(session);
    throw new Error('unexpected request');
  });
  render(<SessionGate t={t} onSession={onSession}/>);
  const button = await screen.findByRole('button', { name: 'Sign in with a passkey' });
  expect(screen.queryByLabelText('Console token')).not.toBeInTheDocument(); expect(native.get).not.toHaveBeenCalled();
  await userEvent.click(button);
  await waitFor(() => expect(onSession).toHaveBeenCalledWith(session, undefined));
  const finish = fetch.mock.calls.find(([input]) => String(input).endsWith('/login/complete'))![1]!;
  expect(JSON.parse(String(finish.body))).toMatchObject({ ceremony_id: 'ceremony-login', credential: { response: { clientDataJSON: 'BAUG', signature: 'Bwg' } } });
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

test('cancelling a passkey prompt never submits or displays a successful login', async () => {
  const native = browser(); native.get.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError')); const onSession = vi.fn();
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => response(String(input).endsWith('/auth/status') ? status : loginOptions));
  render(<SessionGate t={t} onSession={onSession}/>);
  await userEvent.click(await screen.findByRole('button', { name: 'Sign in with a passkey' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('No sign-in or registration was completed.');
  expect(fetch.mock.calls.some(([input]) => String(input).endsWith('/login/complete'))).toBe(false); expect(onSession).not.toHaveBeenCalled();
});

test('registration requires a subsequent signed login instead of treating attestation as authentication', async () => {
  browser(); const onSession = vi.fn(); const onRegistered = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const path = String(input);
    if (path.endsWith('/auth/status')) return response({ ...status, owner_enrolled: false, bootstrap_available: true });
    if (path.endsWith('/auth/passkeys')) return response({ credentials: [], fresh_authentication_required: false });
    if (path.endsWith('/registration/options')) return response(registerOptions);
    if (path.endsWith('/registration/complete')) return response({ registered: true, credential_id: 'AQI', authentication_required: true });
    throw new Error('unexpected request');
  });
  render(<PasskeysPage t={t} locale="en" session={{ ...session, authentication_method: 'bootstrap', credential_id: null, owner_enrolled: false }} onSession={onSession} onSignedOut={vi.fn()} onRegistered={onRegistered} revision={0}/>);
  await userEvent.type(await screen.findByLabelText('Passkey name'), 'My first key');
  await userEvent.click(screen.getByRole('button', { name: 'Register your first passkey' }));
  await waitFor(() => expect(onRegistered).toHaveBeenCalledWith('AQI'));
  expect(onSession).not.toHaveBeenCalled(); expect(localStorage.length).toBe(0);
});

test('the first login after registration explicitly verifies the newly registered credential', async () => {
  browser(); const onSession = vi.fn();
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => response(String(input).endsWith('/auth/status') ? status : String(input).endsWith('/login/options') ? loginOptions : session));
  render(<SessionGate t={t} onSession={onSession} registeredId="AQI"/>);
  await userEvent.click(await screen.findByRole('button', { name: 'Sign in with a passkey' }));
  await waitFor(() => expect(onSession).toHaveBeenCalled());
  const begin = fetch.mock.calls.find(([input]) => String(input).endsWith('/login/options'))![1]!;
  expect(JSON.parse(String(begin.body))).toEqual({ credential_id: 'AQI' });
});

test('server freshness denial uses the Problem reason and requires another passkey verification', async () => {
  browser();
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const path = String(input);
    if (path.endsWith('/auth/status')) return response(status);
    if (path.endsWith('/auth/passkeys')) return response({ credentials: [record], fresh_authentication_required: false });
    return response({ code: 'FORBIDDEN', detail: 'PASSKEY_REAUTHENTICATION_REQUIRED' }, 403);
  });
  render(<PasskeysPage t={t} locale="en" session={session} onSession={vi.fn()} onSignedOut={vi.fn()} onRegistered={vi.fn()} revision={0}/>);
  await userEvent.type(await screen.findByLabelText('Passkey name'), 'Another key');
  await userEvent.click(screen.getByRole('button', { name: 'Add passkey' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Verify with a passkey again');
  expect(screen.getByLabelText('Passkey name')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Verify with a passkey' })).toBeEnabled();
  expect(fetch.mock.calls.some(([input]) => String(input).endsWith('/registration/complete'))).toBe(false);
});

test('unverified backup does not permit revoking the last working passkey and names remain escaped', async () => {
  browser();
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => response(String(input).endsWith('/auth/status') ? status : { credentials: [record, { ...record, id: 'AwQ', name: 'Unverified backup', current: false, verified_at: null, last_used_at: null }], fresh_authentication_required: false }));
  const { container } = render(<PasskeysPage t={t} locale="en" session={session} onSession={vi.fn()} onSignedOut={vi.fn()} onRegistered={vi.fn()} revision={0}/>);
  expect(await screen.findByRole('button', { name: 'Revoke <img src=x>' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Revoke Unverified backup' })).toBeEnabled();
  expect(screen.getByText('Awaiting first sign-in')).toBeInTheDocument(); expect(container.querySelector('img')).toBeNull();
});

test('terminal sign-in is never authorized by visiting its URL or by entering a wrong code', async () => {
  const onSession = vi.fn(); const requestId = '11111111-1111-4111-8111-111111111111';
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
    if (init?.method !== 'POST') return response({ request_id: requestId, expires_at: '2026-10-31T09:00:00Z', state: 'pending', api_origin: 'http://localhost:8787' });
    return JSON.parse(String(init.body)).user_code === '4E2A91BF'
      ? response({ request_id: requestId, state: 'approved' })
      : response({ code: 'PERMISSION_DENIED', detail: 'CLI_CODE_MISMATCH' }, 403);
  });
  render(<CliLoginPage requestId={requestId} t={t} locale="en" session={session} onSession={onSession} onSignedOut={vi.fn()}/>);
  const input = await screen.findByLabelText('Code from your terminal');
  expect(input).toHaveValue(''); expect(fetch.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
  expect(screen.queryByText('4E2A91BF')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Approve terminal sign-in' })).toBeDisabled();
  await userEvent.type(input, '00000000'); await userEvent.click(screen.getByRole('button', { name: 'Approve terminal sign-in' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('The code does not match');
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(JSON.parse(String(fetch.mock.calls.at(-1)![1]!.body))).toEqual({ user_code: '00000000' });
  fireEvent.change(input, { target: { value: '4E2A91BF' } }); await userEvent.click(screen.getByRole('button', { name: 'Approve terminal sign-in' }));
  expect(await screen.findByRole('status')).toHaveTextContent('Terminal sign-in authorized');
  expect(JSON.parse(String(fetch.mock.calls.at(-1)![1]!.body))).toEqual({ user_code: '4E2A91BF' });
});

test('terminal authorization stays disabled until fresh passkey authentication exists', async () => {
  browser(); const requestId = '11111111-1111-4111-8111-111111111111';
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ request_id: requestId, expires_at: '2026-10-31T09:00:00Z', state: 'pending', api_origin: 'http://localhost:8787' }));
  render(<CliLoginPage requestId={requestId} t={t} locale="en" session={{ ...session, authenticated_at: 1 }} onSession={vi.fn()} onSignedOut={vi.fn()}/>);
  expect(await screen.findByLabelText('Code from your terminal')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Verify with a passkey' })).toBeEnabled();
});
