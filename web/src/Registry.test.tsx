import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
import { setCsrfToken } from './api';

const owner = '11111111-1111-4111-8111-111111111111';
const assetId = '22222222-2222-4222-8222-222222222222';
const targetId = '33333333-3333-4333-8333-333333333333';
const hash = 'sha256:' + '1'.repeat(64);
const etag = `"rev-1-${hash}"`;
const asset = { schema_version: 'f.asset/v1', asset_id: assetId, org_id: owner, project_id: owner, revision: 1, state: 'active', created_at: '2026-10-30T00:00:00Z', created_by: owner, content_hash: hash, previous_revision_hash: null, definition: { name: 'Registered host', asset_kind: 'host', owner_id: owner, addresses: [{ family: 'ipv4', cidr: '192.0.2.10/32', interface: null }], criticality: 'normal', isolation: 'host', provenance: 'manual', source_evidence: null } };
const actions = [{ action_id: 'registry.assets.write', allowed: true, reason_code: null }, { action_id: 'registry.services.write', allowed: true, reason_code: null }, { action_id: 'requests.create', allowed: true, reason_code: null }];
function response(data: unknown, status = 200, tag?: string) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...(tag ? { ETag: tag } : {}) } }); }
function server(options: { noPermission?: boolean; targets?: boolean; assetError?: boolean } = {}) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const path = String(input);
    if (path === '/api/v1/session') return response({ data: { authenticated: true, principal_id: owner, org_id: owner, project_id: owner, csrf_token: 'test-csrf' }, actions });
    if (path === '/api/v1/assets/' + assetId) return response({ data: asset, actions: options.noPermission ? [] : actions }, 200, etag);
    if (path.startsWith('/api/v1/assets?')) return options.assetError ? response({ code: 'REGISTRY_UNAVAILABLE' }, 503) : response({ data: [asset], actions: options.noPermission ? [] : actions, next_cursor: null });
    if (path.startsWith('/api/v1/targets?')) return response({ data: options.targets ? [{ target_id: targetId, display_name: 'Observed target fixture', state: 'observe_only' }] : [], actions, next_cursor: null });
    return response({ data: [], actions, next_cursor: null });
  });
}
beforeEach(() => {
  localStorage.clear(); localStorage.setItem('fw.locale','en'); setCsrfToken(undefined); history.replaceState(null, '', '/assets');
  HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open',''); };
  HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
});

test('manual asset creation sends only exact AssetWrite fields and no authority claim', async () => {
  const fetch = server(); const base = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input, init) => String(input) === '/api/v1/assets' && init?.method === 'POST' ? response({ data: asset, actions }, 201, etag) : base(input, init));
  render(<App />);
  await userEvent.click(await screen.findByRole('button', { name: 'Register asset' }));
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Manual lab host' } });
  fireEvent.change(screen.getByLabelText('Canonical CIDR 1'), { target: { value: '192.0.2.10/32' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save immutable revision' }));
  await screen.findByText('Registry revision saved. Existing policies have not been rewritten.');
  const call = fetch.mock.calls.find(([input, init]) => String(input) === '/api/v1/assets' && init?.method === 'POST');
  expect(JSON.parse(String(call?.[1]?.body))).toEqual({ definition: { ...asset.definition, name: 'Manual lab host' }, state: 'active' });
  expect(call?.[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'test-csrf' });
  expect(call?.[1]?.headers).not.toHaveProperty('If-Match');
  expect(screen.getByText(/Manual registration describes intended assets/)).toBeInTheDocument();
});

test('asset revisions bind the exact HTTP ETag and block further submit after a stale response', async () => {
  const fetch = server(); const base = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input, init) => String(input).endsWith('/revisions') && init?.method === 'POST' ? response({ code: 'ETAG_MISMATCH' }, 412) : base(input, init));
  history.replaceState(null, '', '/assets/' + assetId); render(<App />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Create new revision' })).toBeEnabled());
  await userEvent.click(screen.getByRole('button', { name: 'Create new revision' }));
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Revised host' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save immutable revision' }));
  expect(await screen.findByText('ETAG_MISMATCH')).toBeInTheDocument();
  expect(screen.getByText('This revision changed. Reload and review the latest record before trying again.')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Save immutable revision' })).not.toBeInTheDocument();
  const call = fetch.mock.calls.find(([input]) => String(input).endsWith('/revisions'));
  expect(call?.[1]?.headers).toMatchObject({ 'If-Match': etag });
  expect(JSON.parse(String(call?.[1]?.body))).toEqual({ definition: { ...asset.definition, name: 'Revised host' }, state: 'active' });
});

test('registry write buttons use registry action hints, not general session ownership', async () => {
  server({ noPermission: true }); render(<App />);
  await screen.findByText('Registered host');
  expect(screen.getByRole('button', { name: 'Register asset' })).toBeDisabled();
});

test('service creation cannot invent a target when target enrollment is unavailable', async () => {
  const fetch = server(); history.replaceState(null, '', '/services'); render(<App />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Register service' })).toBeEnabled());
  await userEvent.click(screen.getByRole('button', { name: 'Register service' }));
  await waitFor(() => expect(screen.getByLabelText('Destination assets')).toBeEnabled());
  expect(screen.getByLabelText('Registered targets')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Save immutable revision' })).toBeDisabled();
  expect(screen.getByText(/A genuine registered target is required/)).toBeInTheDocument();
  expect(fetch.mock.calls.filter(([,init]) => init?.method === 'POST')).toHaveLength(0);
});

test('service create uses registered choices and the exact ICMP transport union', async () => {
  const fetch = server({ targets: true }); const base = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input, init) => String(input) === '/api/v1/services' && init?.method === 'POST' ? response({ code: 'TEST_RECORDED' }, 422) : base(input, init));
  history.replaceState(null, '', '/services'); render(<App />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Register service' })).toBeEnabled());
  await userEvent.click(screen.getByRole('button', { name: 'Register service' }));
  fireEvent.change(screen.getByLabelText('Service ID'), { target: { value: 'echo-v6' } });
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'ICMP fixture' } });
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Registered destination test' } });
  await waitFor(() => expect(screen.getByLabelText('Registered targets')).toBeEnabled());
  await userEvent.selectOptions(screen.getByLabelText('Destination assets'), assetId);
  await userEvent.selectOptions(screen.getByLabelText('Registered targets'), targetId);
  await userEvent.selectOptions(screen.getByLabelText('Transport protocol'), 'icmpv6');
  fireEvent.change(screen.getByLabelText('ICMP type'), { target: { value: '128' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save immutable revision' }));
  await screen.findByText('TEST_RECORDED');
  const call = fetch.mock.calls.find(([input, init]) => String(input) === '/api/v1/services' && init?.method === 'POST');
  expect(JSON.parse(String(call?.[1]?.body))).toEqual({ service_id: 'echo-v6', definition: { name: 'ICMP fixture', owner_id: owner, destination_asset_ids: [assetId], target_ids: [targetId], transport: { protocol: 'icmpv6', type: 128, code: 0 }, description: 'Registered destination test', criticality: 'normal' } });
});

test('registry failures remain errors rather than empty lists', async () => {
  server({ assetError: true }); render(<App />);
  expect(await screen.findByText('REGISTRY_UNAVAILABLE')).toBeInTheDocument();
  expect(screen.queryByText('Nothing here yet')).not.toBeInTheDocument();
});

test('asset save retries preserve idempotency until submitted bytes change', async () => {
  const fetch = server(); const base = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input, init) => String(input) === '/api/v1/assets' && init?.method === 'POST' ? response({ code: 'TEMPORARY_FAILURE' }, 503) : base(input, init));
  render(<App />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Register asset' })).toBeEnabled());
  await userEvent.click(screen.getByRole('button', { name: 'Register asset' }));
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Retry host' } });
  fireEvent.change(screen.getByLabelText('Canonical CIDR 1'), { target: { value: '192.0.2.10/32' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save immutable revision' }));
  await screen.findByText('TEMPORARY_FAILURE');
  await userEvent.click(screen.getByRole('button', { name: 'Save immutable revision' }));
  await screen.findByText('TEMPORARY_FAILURE');
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Changed retry host' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save immutable revision' }));
  await screen.findByText('TEMPORARY_FAILURE');
  const calls = fetch.mock.calls.filter(([input, init]) => String(input) === '/api/v1/assets' && init?.method === 'POST');
  expect(calls).toHaveLength(3);
  expect(calls[0][1]?.body).toBe(calls[1][1]?.body);
  expect((calls[0][1]?.headers as Record<string,string>)['Idempotency-Key']).toBe((calls[1][1]?.headers as Record<string,string>)['Idempotency-Key']);
  expect((calls[1][1]?.headers as Record<string,string>)['Idempotency-Key']).not.toBe((calls[2][1]?.headers as Record<string,string>)['Idempotency-Key']);
});
