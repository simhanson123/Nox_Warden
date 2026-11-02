// @vitest-environment-options {"url":"http://localhost:8790"}
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthorityClient } from './authority-api';
import type { AuthorityPlan } from './authority-api';
import SigningReadiness from './SigningReadiness';
import { parseSigningReadiness } from './signing-readiness';

const hash = (digit: string) => 'sha256:' + digit.repeat(64);
const id = (digit: string) => `${digit.repeat(8)}-${digit.repeat(4)}-4${digit.repeat(3)}-8${digit.repeat(3)}-${digit.repeat(12)}`;
const time = (value: number) => new Date(value).toISOString().replace('.000Z', 'Z');
const now = () => Math.floor(Date.now() / 1000) * 1000;
function detail(): AuthorityPlan {
  return { plan_hash: hash('a'), requirements_hash: hash('b'), roles: [], current_principal_decisions: [],
    plan: { plan_id: id('4'), org_id: id('2'), project_id: id('3'), target_id: id('9'),
      valid_until: time(now() + 3600000), authority_epoch: '2', target_generation: '7' }, requirements: {} };
}
function readiness(plan = detail()) {
  return { schema_version: 'fw.signing-readiness/v1', org_id: plan.plan.org_id, project_id: plan.plan.project_id,
    target_id: plan.plan.target_id, plan_id: plan.plan.plan_id, plan_hash: plan.plan_hash,
    checked_at: time(now()), valid_until: time(now() + 30000), signing_allowed: false, dispatch_allowed: false,
    reasons: ['PROTECTED_BOOTSTRAP_REQUIRED', 'BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED', 'PROTECTED_SIGNER_UNAVAILABLE'],
    approval_set_hash: hash('c'), quota_configured: true, target_generation: '8',
    latest_intent: { intent_id: id('5'), request_id: id('6'), plan_id: plan.plan.plan_id, plan_hash: plan.plan_hash,
      approval_set_hash: hash('d'), authority_epoch: '2', target_generation: '7', payload_hash: hash('e'), job_id: id('7'), reservation_id: id('8'),
      created_at: time(now() - 60000), valid_until: time(now() + 30000), state: 'ready', dispatch_state: 'unknown',
      reservation_state: 'unknown', reservation_held: true, current_eligible: false, grant_hash: hash('f'), dispatch_allowed: false } };
}
function client() {
  const result = new AuthorityClient();
  result.acceptSession({ authenticated: true, csrf_token: 'memory-proof', principal_id: 'reviewer', org_id: 'org', project_id: 'project', expires_at: '2099-01-01T00:00:00Z' });
  return result;
}
function response(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }); }
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { vi.useRealTimers(); });

test('current prerequisites and retained intents are separate read-only evidence, including old approval hashes and generations', async () => {
  const plan = detail(); const value = readiness(plan);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  const panel = screen.getByRole('region', { name: 'Signing readiness' });
  expect(await within(panel).findByText(value.approval_set_hash)).toBeInTheDocument();
  expect(panel).toHaveTextContent('Production signing and deployment remain blocked.');
  expect(panel).toHaveTextContent('Quota configuration is present; this read reserves no capacity.');
  const history = within(panel).getByRole('region', { name: 'Latest retained signing intent' });
  expect(history).toHaveTextContent('Retained history; not currently eligible for signing or dispatch');
  expect(history).toHaveTextContent('Signer result retained');
  expect(history).toHaveTextContent('Outcome unknown');
  expect(history).toHaveTextContent('Quota slots remain held by this reservation.');
  expect(history).toHaveTextContent(value.latest_intent.grant_hash);
  expect(parseSigningReadiness(value, plan).latest_intent?.approval_set_hash).not.toBe(value.approval_set_hash);
  expect(fetch.mock.calls[0][0]).toBe('/authority/v1/plans/' + plan.plan.plan_id + '/signing-readiness');
  expect(fetch.mock.calls[0][1]).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store' });
  expect(new Headers(fetch.mock.calls[0][1]?.headers).get('X-Authority-CSRF')).toBe('memory-proof');
  expect(within(panel).getAllByRole('button')).toHaveLength(1);
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

test.each([false, true])('core signing remains blocked when original request binding is unavailable: %s', async (bindingUnavailable) => {
  const plan = detail(); plan.plan.change_kind = 'add_access_lease';
  const value = { ...readiness(plan), latest_intent: null };
  value.reasons.push('CORE_SIGNING_PROFILE_UNAVAILABLE');
  if (bindingUnavailable) value.reasons.push('CORE_REQUEST_BINDING_UNAVAILABLE');
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  const panel = screen.getByRole('region', { name: 'Signing readiness' });
  expect(await within(panel).findByText('Access lease signing is unavailable in this build.')).toBeInTheDocument();
  expect(panel).toHaveTextContent('Production signing and deployment remain blocked.');
  expect(!!within(panel).queryByText('The required core request binding is unavailable.')).toBe(bindingUnavailable);
  expect(within(panel).getAllByRole('button')).toHaveLength(1);
  expect(parseSigningReadiness(value, plan)).toMatchObject({ signing_allowed: false, dispatch_allowed: false });
  expect(fetch.mock.calls.every(([, init]) => init?.method === 'GET' && init.body === undefined)).toBe(true);
});

test.each([
  ['another plan', (v: ReturnType<typeof readiness>) => { v.plan_id = id('1'); }],
  ['another tenant', (v: ReturnType<typeof readiness>) => { v.org_id = id('1'); }],
  ['another target', (v: ReturnType<typeof readiness>) => { v.target_id = id('1'); }],
  ['signing permission', (v: ReturnType<typeof readiness>) => { v.signing_allowed = true; }],
  ['dispatch permission', (v: ReturnType<typeof readiness>) => { v.dispatch_allowed = true; }],
  ['missing protected gate', (v: ReturnType<typeof readiness>) => { v.reasons.shift(); }],
  ['invented blocker', (v: ReturnType<typeof readiness>) => { v.reasons.push('ALL_CHECKS_PASSED'); }],
  ['inconsistent quota', (v: ReturnType<typeof readiness>) => { v.quota_configured = false; }],
  ['overflow generation', (v: ReturnType<typeof readiness>) => { v.target_generation = '18446744073709551616'; }],
  ['another intent plan', (v: ReturnType<typeof readiness>) => { v.latest_intent.plan_id = id('1'); }],
  ['another intent epoch', (v: ReturnType<typeof readiness>) => { v.latest_intent.authority_epoch = '3'; }],
  ['another proposed generation', (v: ReturnType<typeof readiness>) => { v.latest_intent.target_generation = '8'; }],
  ['promoted historical intent', (v: ReturnType<typeof readiness>) => { v.latest_intent.current_eligible = true; }],
  ['unknown state', (v: ReturnType<typeof readiness>) => { v.latest_intent.state = 'active'; }],
  ['invented delivery', (v: ReturnType<typeof readiness>) => { v.latest_intent.dispatch_state = 'success'; }],
  ['released UNKNOWN slots', (v: ReturnType<typeof readiness>) => { v.latest_intent.reservation_held = false; }],
  ['UNKNOWN with released reservation', (v: ReturnType<typeof readiness>) => { v.latest_intent.reservation_state = 'released'; }],
  ['delivery recorded with released quota', (v: ReturnType<typeof readiness>) => {
    v.latest_intent.dispatch_state = 'delivered'; v.latest_intent.reservation_state = 'active'; v.latest_intent.reservation_held = false;
  }],
  ['deadline beyond the plan', (v: ReturnType<typeof readiness>) => { v.valid_until = time(now() + 7200000); }],
  ['unbounded readiness window', (v: ReturnType<typeof readiness>) => { v.valid_until = time(now() + 120000); }],
  ['intent lifetime beyond five minutes', (v: ReturnType<typeof readiness>) => { v.latest_intent.created_at = time(now() - 600000); }],
  ['nonexistent calendar date', (v: ReturnType<typeof readiness>) => { v.checked_at = '2026-02-31T00:00:00Z'; }],
  ['raw signer content', (v: ReturnType<typeof readiness>) => { Object.assign(v.latest_intent, { signed_grant: 'private-marker' }); }],
])('malformed readiness cannot display authority: %s', (_name, mutate) => {
  const plan = detail(); const value = readiness(plan); mutate(value);
  expect(() => parseSigningReadiness(value, plan)).toThrow();
});

test.each([
  { name: 'prepared', state: 'prepared', dispatch: null, reservation: 'reserved', held: true, grant: false },
  { name: 'claimed signer', state: 'claimed', dispatch: null, reservation: 'reserved', held: true, grant: false },
  { name: 'cancelled before issuance', state: 'cancelled', dispatch: null, reservation: 'released', held: false, grant: false },
  { name: 'queued grant', state: 'ready', dispatch: 'queued', reservation: 'issued', held: true, grant: true },
  { name: 'claimed delivery', state: 'ready', dispatch: 'claimed', reservation: 'issued', held: true, grant: true },
  { name: 'reclaimed UNKNOWN delivery', state: 'ready', dispatch: 'claimed', reservation: 'unknown', held: true, grant: true },
  { name: 'UNKNOWN delivery', state: 'ready', dispatch: 'unknown', reservation: 'unknown', held: true, grant: true },
  { name: 'recorded delivery', state: 'ready', dispatch: 'delivered', reservation: 'active', held: true, grant: true },
])('coherent expired history remains readable without authority: $name', ({ state, dispatch, reservation, held, grant }) => {
  const plan = detail(); const base = readiness(plan);
  const value = { ...base, latest_intent: { ...base.latest_intent, state, dispatch_state: dispatch,
    reservation_state: reservation, reservation_held: held, grant_hash: grant ? hash('f') : null, valid_until: time(now() - 1000) } };
  expect(parseSigningReadiness(value, plan).latest_intent).toMatchObject({
    state, dispatch_state: dispatch, reservation_state: reservation, reservation_held: held,
    current_eligible: false, dispatch_allowed: false,
  });
});

test.each([
  { name: 'delivered grant with released quota', state: 'ready', dispatch: 'delivered', reservation: 'released', held: false, grant: true },
  { name: 'delivered grant with unacknowledged issuance', state: 'ready', dispatch: 'delivered', reservation: 'issued', held: true, grant: true },
  { name: 'ready signer without delivery', state: 'ready', dispatch: null, reservation: 'issued', held: true, grant: true },
  { name: 'ready signer without grant', state: 'ready', dispatch: 'queued', reservation: 'issued', held: true, grant: false },
  { name: 'prepared signer with a grant', state: 'prepared', dispatch: null, reservation: 'reserved', held: true, grant: true },
  { name: 'prepared signer with issued quota', state: 'prepared', dispatch: null, reservation: 'issued', held: true, grant: false },
  { name: 'claimed signer with queued delivery', state: 'claimed', dispatch: 'queued', reservation: 'issued', held: true, grant: true },
  { name: 'cancelled signer retaining reserved quota', state: 'cancelled', dispatch: null, reservation: 'reserved', held: true, grant: false },
  { name: 'cancelled signer with delivered grant', state: 'cancelled', dispatch: 'delivered', reservation: 'active', held: true, grant: true },
  { name: 'new queued delivery with UNKNOWN quota', state: 'ready', dispatch: 'queued', reservation: 'unknown', held: true, grant: true },
  { name: 'claimed delivery with completed quota', state: 'ready', dispatch: 'claimed', reservation: 'active', held: true, grant: true },
])('contradictory workflow history is rejected: $name', ({ state, dispatch, reservation, held, grant }) => {
  const plan = detail(); const base = readiness(plan);
  const value = { ...base, latest_intent: { ...base.latest_intent, state, dispatch_state: dispatch,
    reservation_state: reservation, reservation_held: held, grant_hash: grant ? hash('f') : null } };
  expect(() => parseSigningReadiness(value, plan)).toThrow();
});

test('an expired UNKNOWN intent keeps its held reservation and historical result', async () => {
  const plan = detail(); const value = readiness(plan);
  value.latest_intent.valid_until = time(now() - 1000);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  expect(await screen.findByText('The intent deadline has passed. Expiry alone does not release held quota.')).toBeInTheDocument();
  expect(screen.getByText('Quota slots remain held by this reservation.')).toBeInTheDocument();
  expect(screen.getByText('The delivery outcome is unknown. Quota remains held until verified reconciliation; expiry does not release it.')).toBeInTheDocument();
  expect(screen.queryByText('No quota slots are held by this reservation.')).not.toBeInTheDocument();
});

test('recorded delivery retains quota for a non-lease plan after intent expiry', async () => {
  const plan = detail(); plan.plan.change_kind = 'policy_change';
  const value = readiness(plan);
  value.latest_intent.dispatch_state = 'delivered';
  value.latest_intent.reservation_state = 'active';
  value.latest_intent.valid_until = time(now() - 1000);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  const panel = screen.getByRole('region', { name: 'Signing readiness' });
  expect(await within(panel).findByText('Delivery recorded; quota retained')).toBeInTheDocument();
  expect(panel).toHaveTextContent('Quota retained after delivery');
  expect(panel).toHaveTextContent('Quota slots remain held by this reservation.');
  expect(panel).toHaveTextContent('The intent deadline has passed. Expiry alone does not release held quota.');
  expect(panel).toHaveTextContent('A retained intent records workflow progress. It does not establish an active firewall policy.');
  expect(panel).toHaveTextContent('Retained history; not currently eligible for signing or dispatch');
  expect(within(panel).queryByText('No quota slots are held by this reservation.')).not.toBeInTheDocument();
  expect(parseSigningReadiness(value, plan).latest_intent).toMatchObject({
    reservation_held: true, current_eligible: false, dispatch_allowed: false,
  });
  expect(within(panel).getAllByRole('button')).toHaveLength(1);
  expect(within(panel).getByRole('button', { name: 'Refresh signing readiness' })).toBeInTheDocument();
  expect(fetch.mock.calls.every(([, init]) => init?.method === 'GET' && init.body === undefined)).toBe(true);
});

test('a delivery response claiming released quota cannot display contradictory retained history', async () => {
  const plan = detail(); const value = readiness(plan);
  value.latest_intent.dispatch_state = 'delivered';
  value.latest_intent.reservation_state = 'released';
  value.latest_intent.reservation_held = false;
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  expect(await screen.findByText('Signing readiness is unavailable. Refresh to recheck.')).toBeInTheDocument();
  expect(screen.queryByText('Delivery recorded; quota retained')).not.toBeInTheDocument();
  expect(screen.queryByText('No quota slots are held by this reservation.')).not.toBeInTheDocument();
  expect(screen.getByText('Production signing and deployment remain blocked.')).toBeInTheDocument();
});

test('refresh rechecks missing prerequisites without creating an intent or carrying forward a failed response', async () => {
  const plan = detail(); const value = readiness(plan);
  const missing = { ...value, approval_set_hash: null, target_generation: null, quota_configured: false, latest_intent: null,
    reasons: [...value.reasons, 'APPROVAL_SET_MISSING', 'TARGET_GENERATION_UNINITIALIZED', 'QUOTA_CONFIGURATION_MISSING'] };
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response(missing)).mockResolvedValueOnce(response({ error: 'unavailable' }, 503));
  render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  await screen.findByText('No signing intent has been retained for this plan.');
  expect(screen.getByText('No current independent human approval set is available.')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Refresh signing readiness' }));
  await screen.findByText('Signing readiness is unavailable. Refresh to recheck.');
  expect(screen.queryByText('No signing intent has been retained for this plan.')).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(fetch.mock.calls.every(([, init]) => init?.method === 'GET' && init.body === undefined)).toBe(true);
});

test('expiry updates without polling and an observed forward clock jump cannot be undone by rollback', async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-01T12:00:00Z'));
  const plan = detail(); const value = readiness(plan); const api = client(); const unauthorized = vi.fn();
  value.latest_intent.valid_until = time(now() + 2000);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  let rendered!: ReturnType<typeof render>;
  await act(async () => { rendered = render(<SigningReadiness client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>); });
  await act(async () => { await vi.advanceTimersByTimeAsync(2001); });
  expect(screen.getByText('The intent deadline has passed. Expiry alone does not release held quota.')).toBeInTheDocument();
  expect(screen.queryByText('This check has expired. Refresh signing readiness.')).not.toBeInTheDocument();
  vi.setSystemTime(new Date('2026-11-01T12:01:00Z'));
  rendered.rerender(<SigningReadiness client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>);
  expect(screen.getByText('This check has expired. Refresh signing readiness.')).toBeInTheDocument();
  expect(screen.queryByText(value.approval_set_hash)).not.toBeInTheDocument();
  expect(screen.queryByText('Quota configuration is present; this read reserves no capacity.')).not.toBeInTheDocument();
  vi.setSystemTime(new Date('2026-11-01T12:00:01Z'));
  rendered.rerender(<SigningReadiness client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>);
  expect(screen.getByText('This check has expired. Refresh signing readiness.')).toBeInTheDocument();
  expect(screen.queryByText(value.approval_set_hash)).not.toBeInTheDocument();
  expect(screen.getByText('Quota slots remain held by this reservation.')).toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('a delayed response cannot restart freshness when the browser clock is behind the server', async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-01T12:00:00Z'));
  const plan = detail(); const value = readiness(plan); value.valid_until = '2026-11-01T12:00:10Z';
  let deliver!: (response: Response) => void;
  vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(resolve => { deliver = resolve; }));
  await act(async () => { render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>); });
  await act(async () => { vi.setSystemTime(new Date('2026-11-01T11:00:00Z')); await vi.advanceTimersByTimeAsync(20000); deliver(response(value)); });
  expect(screen.getByText('This check has expired. Refresh signing readiness.')).toBeInTheDocument();
  expect(screen.getByText('Production signing and deployment remain blocked.')).toBeInTheDocument();
});

test('a previous plan response cannot replace a newer selected plan or expose its retained intent', async () => {
  const old = detail(); const next = { ...detail(), plan_hash: hash('9'), plan: { ...detail().plan, plan_id: id('1') } };
  let deliverOld!: (response: Response) => void;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => new Promise(resolve => { deliverOld = resolve; }))
    .mockResolvedValueOnce(response({ ...readiness(next), latest_intent: null }));
  const api = client(); const unauthorized = vi.fn();
  const rendered = render(<SigningReadiness client={api} detail={old} locale="en" onUnauthorized={unauthorized}/>);
  rendered.rerender(<SigningReadiness client={api} detail={next} locale="en" onUnauthorized={unauthorized}/>);
  await screen.findByText('No signing intent has been retained for this plan.');
  await act(async () => { deliverOld(response(readiness(old))); });
  expect(screen.queryByText(readiness(old).latest_intent.intent_id)).not.toBeInTheDocument();
  expect(screen.queryByText('Signing readiness is unavailable. Refresh to recheck.')).not.toBeInTheDocument();
  expect(fetch.mock.calls[0][1]?.signal?.aborted).toBe(true);
});

test('a changed approval context rechecks readiness without issuing a decision or signing request', async () => {
  const plan = detail(); const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(readiness(plan)));
  const api = client(); const unauthorized = vi.fn();
  const rendered = render(<SigningReadiness client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>);
  await screen.findByText('Signer result retained');
  rendered.rerender(<SigningReadiness client={api} detail={{ ...plan, aggregation: { state: 'pending' } }} locale="en" onUnauthorized={unauthorized}/>);
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  expect(fetch.mock.calls.every(([, init]) => init?.method === 'GET' && init.body === undefined)).toBe(true);
});

test('malformed evidence and expired sessions clear the panel rather than retaining authority', async () => {
  const plan = detail(); const onUnauthorized = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response({ ...readiness(plan), signing_allowed: true }))
    .mockResolvedValueOnce(response({ error: 'unauthorized' }, 401));
  render(<SigningReadiness client={client()} detail={plan} locale="en" onUnauthorized={onUnauthorized}/>);
  await screen.findByText('Signing readiness is unavailable. Refresh to recheck.');
  expect(screen.queryByText('Signer result retained')).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Refresh signing readiness' }));
  await waitFor(() => expect(onUnauthorized).toHaveBeenCalledWith(expect.objectContaining({ status: 401 })));
});
