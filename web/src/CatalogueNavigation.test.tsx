import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import App from './App';
import { RegistryPicker } from './Registry';
import { translator } from './i18n';
import { setCsrfToken } from './api';
const t = translator('en');
const id = (n: number) => `11111111-1111-4111-8111-${String(n).padStart(12, '0')}`;
const actions = [{ action_id: 'registry.assets.write', allowed: true, reason_code: null }, { action_id: 'registry.services.write', allowed: true, reason_code: null }];
function response(data: unknown, status = 200) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }); }
function controller(route: string, expired = false) {
  const calls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const path = String(input); const url = new URL(path, 'http://localhost');
    if (path.endsWith('/session')) return response({ data: { authenticated: true, principal_id: id(999), org_id: 'org', project_id: 'project', csrf_token: 'memory-proof' } });
    if (path.endsWith('/status')) return response({ data: { mode: 'observe', enforcement: false } });
    if (url.pathname === '/api/v1/' + route) {
      calls.push(path); const cursor = url.searchParams.get('cursor');
      if (expired && cursor === 'page-three') return response({ code: 'CURSOR_EXPIRED' }, 410);
      const page = cursor === 'page-three' ? 3 : cursor === 'page-two' ? 2 : 1;
      const start = (page - 1) * 25 + 1;
      return response({ data: Array.from({ length: page === 3 ? 15 : 25 }, (_, i) => route === 'assets'
        ? { asset_id: id(start + i), revision: 1, state: 'active', definition: { name: `Host ${start + i}`, provenance: 'manual' } }
        : { target_id: id(start + i), name: `Host ${start + i}`, platform: 'linux', enforcement_backend: 'nftables', observed_at: null, qualification_state: 'unsupported-alias', state: 'observe_only' }),
        revision: 17, next_cursor: page === 1 ? 'page-two' : page === 2 ? 'page-three' : null, actions });
    }
    return response({ data: [], next_cursor: null });
  });
  return calls;
}
beforeEach(() => { localStorage.clear(); localStorage.setItem('fw.locale', 'en'); setCsrfToken(undefined); history.replaceState(null, '', '/targets'); });

async function next(name: string) { await userEvent.click(await screen.findByRole('button', { name: 'Next page' })); await screen.findByRole('button', { name }); }

test.each(['targets', 'assets'])('%s lists navigate forward and back one page and refresh starts a new snapshot', async route => {
  const calls = controller(route); history.replaceState(null, '', '/' + route); render(<App/>);
  await screen.findByRole('button', { name: 'Host 1' }); await next('Host 26'); await next('Host 51');
  await userEvent.click(screen.getByRole('button', { name: 'Previous page' }));
  expect(await screen.findByRole('button', { name: 'Host 26' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Host 1' })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await screen.findByRole('button', { name: 'Host 1' });
  expect(new URL(calls.at(-1)!, 'http://localhost').searchParams.has('cursor')).toBe(false);
});

test('page size changes and expired cursor retry restart at the first page', async () => {
  const calls = controller('targets', true); render(<App/>); await screen.findByRole('button', { name: 'Host 1' });
  await userEvent.selectOptions(screen.getByLabelText('Rows per page'), '50');
  await waitFor(() => expect(calls.at(-1)).toContain('limit=50'));
  await next('Host 26'); await userEvent.click(screen.getByRole('button', { name: 'Next page' }));
  await screen.findByText('CURSOR_EXPIRED');
  await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
  await screen.findByRole('button', { name: 'Host 1' });
  expect(new URL(calls.at(-1)!, 'http://localhost').searchParams.get('limit')).toBe('50');
  expect(new URL(calls.at(-1)!, 'http://localhost').searchParams.has('cursor')).toBe(false);
});

test('target list uses actual backend and observation fields without qualification aliases', async () => {
  controller('targets'); render(<App/>); await screen.findByRole('button', { name: 'Host 1' });
  expect(screen.getByRole('columnheader', { name: 'Enforcement backend' })).toBeInTheDocument();
  expect(screen.getByRole('columnheader', { name: 'Last observed (UTC)' })).toBeInTheDocument();
  expect(screen.getAllByText('nftables')).toHaveLength(25);
  expect(screen.getAllByText('Not observed')).toHaveLength(25);
  expect(screen.queryByText('unsupported-alias')).not.toBeInTheDocument();
});

function Picker({ path = '/targets', initial = [] }: { path?: '/targets' | '/assets'; initial?: string[] }) {
  const [value, setValue] = useState(initial); const [available, setAvailable] = useState(false);
  return <><RegistryPicker path={path} label="Choices" value={value} onChange={setValue} multiple t={t} onAvailability={setAvailable}/><output>{value.join(',')}</output><button disabled={!available}>Submit choices</button></>;
}
test('eligible pickers can traverse an empty page and preserve selected choices while loading more', async () => {
  const paths: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const path = String(input); paths.push(path); const url = new URL(path, 'http://localhost');
    const cursor = url.searchParams.get('cursor');
    return response({ data: cursor === 'empty' ? [] : cursor === 'last' ? [{ target_id: id(2), name: 'Later target', state: 'observe_only' }] : [{ target_id: id(1), name: 'First target', state: 'observe_only' }, { target_id: id(3), name: 'Quarantined target', state: 'quarantined' }], next_cursor: cursor === 'empty' ? 'last' : cursor === 'last' ? null : 'empty' });
  });
  render(<Picker/>);
  await screen.findByRole('option', { name: /First target/ });
  expect(screen.queryByRole('option', { name: /Quarantined target/ })).not.toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Choices'), id(1));
  await userEvent.click(screen.getByRole('button', { name: 'Load next registry page' }));
  await waitFor(() => expect(paths.at(-1)).toContain('cursor=empty'));
  await userEvent.click(screen.getByRole('button', { name: 'Load next registry page' }));
  await screen.findByRole('option', { name: /Later target/ });
  expect(screen.getByLabelText('Choices')).toHaveValue([id(1)]);
  expect(paths.every(path => new URL(path, 'http://localhost').searchParams.get('eligible') === 'true')).toBe(true);
});

test('an existing selected value outside the loaded picker pages stays visible and blocks submission until loaded', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => response({ data: String(input).includes('cursor=second') ? [{ asset_id: id(2), state: 'active', definition: { name: 'Selected later host' } }] : [{ asset_id: id(1), state: 'active', definition: { name: 'First host' } }], next_cursor: String(input).includes('cursor=second') ? null : 'second' }));
  render(<Picker path="/assets" initial={[id(2)]}/>);
  await screen.findByRole('option', { name: /First host/ });
  expect(screen.getByLabelText('Choices')).toHaveValue([id(2)]);
  expect(screen.getByRole('button', { name: 'Submit choices' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Load next registry page' }));
  await screen.findByRole('option', { name: /Selected later host/ });
  expect(screen.getByRole('button', { name: 'Submit choices' })).toBeEnabled();
  expect(screen.getByLabelText('Choices')).toHaveValue([id(2)]);
});

test('sidebar navigation exits a new registry form even when navigating to the same section', async () => {
  controller('assets'); history.replaceState(null, '', '/assets'); render(<App/>);
  await userEvent.click(await screen.findByRole('button', { name: 'Register asset' }));
  expect(screen.getByLabelText('Display name')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('link', { name: 'Assets' }));
  await screen.findByRole('button', { name: 'Host 1' });
  expect(screen.queryByLabelText('Display name')).not.toBeInTheDocument();
  expect(location.pathname).toBe('/assets');
});

test('picker retry after an expired cursor restarts eligible choices without discarding selection', async () => {
  const calls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const path = String(input); calls.push(path);
    return path.includes('cursor=expired') ? response({ code: 'CURSOR_EXPIRED' }, 410) : response({ data: [{ target_id: id(1), state: 'observe_only', name: 'Retained target' }], next_cursor: 'expired' });
  });
  render(<Picker/>); await screen.findByRole('option', { name: /Retained target/ });
  await userEvent.selectOptions(screen.getByLabelText('Choices'), id(1));
  await userEvent.click(screen.getByRole('button', { name: 'Load next registry page' }));
  await screen.findByText('CURSOR_EXPIRED');
  await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
  await screen.findByRole('option', { name: /Retained target/ });
  expect(calls.at(-1)).not.toContain('cursor=');
  expect(calls.at(-1)).toContain('eligible=true');
  expect(screen.getByLabelText('Choices')).toHaveValue([id(1)]);
});

test('saved registry mutations discard old collection cursors before returning to the list', async () => {
  const calls = controller('assets'); const fetch = vi.mocked(globalThis.fetch); const base = fetch.getMockImplementation()!;
  const saved = { asset_id: id(99), revision: 1, state: 'active', content_hash: 'sha256:' + 'a'.repeat(64), created_at: '2026-10-31T00:00:00Z', definition: { name: 'New host', owner_id: id(999), provenance: 'manual' } };
  fetch.mockImplementation(async (input, init) => String(input) === '/api/v1/assets' && init?.method === 'POST' ? response({ data: saved, actions }, 201) : String(input) === '/api/v1/assets/' + id(99) ? response({ data: saved, actions }) : base(input, init));
  history.replaceState(null, '', '/assets'); render(<App/>); await screen.findByRole('button', { name: 'Host 1' }); await next('Host 26');
  await userEvent.click(screen.getByRole('button', { name: 'Register asset' }));
  await userEvent.type(screen.getByLabelText('Display name'), 'New host');
  await userEvent.type(screen.getByLabelText('Canonical CIDR 1'), '192.0.2.99/32');
  await userEvent.click(screen.getByRole('button', { name: 'Save immutable revision' }));
  await screen.findByText('Registry revision saved. Existing policies have not been rewritten.');
  await userEvent.click(screen.getByRole('button', { name: 'Back to registry' }));
  await screen.findByRole('button', { name: 'Host 1' });
  expect(calls.at(-1)).not.toContain('cursor=');
});

test('refreshing picker choices rechecks eligibility without silently dropping the selected value', async () => {
  const calls: string[] = []; let eligible = true;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => { calls.push(String(input)); return response({ data: eligible ? [{ target_id: id(1), state: 'observe_only', name: 'Previously eligible' }] : [], next_cursor: null }); });
  render(<Picker/>); await screen.findByRole('option', { name: /Previously eligible/ });
  await userEvent.selectOptions(screen.getByLabelText('Choices'), id(1)); eligible = false;
  await userEvent.click(screen.getByRole('button', { name: 'Refresh choices' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Submit choices' })).toBeDisabled());
  expect(screen.getByText(id(1), { exact: false, selector: 'option' })).toHaveTextContent('Not loaded or eligible');
  expect(screen.getByLabelText('Choices')).toHaveValue([id(1)]);
  expect(calls.at(-1)).not.toContain('cursor=');
});

test('an empty eligible first page keeps loading available without claiming the catalogue is empty', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => response({ data: String(input).includes('cursor=second') ? [{ target_id: id(1), state: 'observe_only', name: 'Later eligible target' }] : [], next_cursor: String(input).includes('cursor=second') ? null : 'second' }));
  render(<Picker/>);
  expect(await screen.findByText('No available items on this page. Continue to the next page.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Load next registry page' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Load next registry page' }));
  await screen.findByRole('option', { name: /Later eligible target/ });
});
