// @vitest-environment-options {"url":"http://localhost:8790"}
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Authority from './Authority';

const hash = 'sha256:' + 'a'.repeat(64);
const requirementsHash = 'sha256:' + 'b'.repeat(64);
const csrf = 'authority-memory-proof';
const session = { authenticated: true, csrf_token: csrf, principal_id: 'independent-owner', org_id: 'org', project_id: 'project', roles: ['owner'], expires_at: '2099-01-01T00:00:00Z' };
const options = { publicKey: { rpId: 'localhost', challenge: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc', userVerification: 'required', allowCredentials: [{ type: 'public-key', id: 'AQI' }] } };
const gates = ['schema','identity','scope','quota','semantic','expiry','capability','baseline'].map(gate_id => ({ gate_id, required: true, result: 'PASS', evidence_hash: hash }));
const detail = {
  plan_hash: hash, requirements_hash: requirementsHash, roles: ['owner'],
  plan: { plan_id: 'plan-1', change_kind: 'policy_change', valid_until: '2099-01-01T00:00:00Z', target_id: '<img src=x>', org_id: 'org', project_id: 'project', authority_epoch: '1', baseline_hash: hash, desired_state_hash: hash, gates, effect_summary: { relation: 'restricting', complete: true }, operations: [{ op: 'remove_policy', policy_id: 'policy-1' }] },
  requirements: { minimum_humans: 1, required_roles: ['owner'], profile: 'lab_owner', distinct_principals: true, author_may_approve: true, require_webauthn: true, role_policy_hash: hash },
  review: { available: true, before: { policies: [{ scope: { source: ['192.0.2.0/24'], destination: ['198.51.100.1/32'], protocol: 'tcp', ports: [{ start: 443, end: 443 }] } }] }, after: { policies: [] } },
};
function reply(data: unknown, status = 200) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }); }
const originalCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
let submitted: Record<string, unknown>[];
let requests: { path: string; init?: RequestInit }[];
let nextDetail: unknown;
let assertionError: 'network' | 'stale' | undefined;
function browser() {
  vi.stubGlobal('isSecureContext', true); vi.stubGlobal('PublicKeyCredential', class {});
  const get = vi.fn().mockResolvedValue({ id: 'AQI', rawId: Uint8Array.from([1, 2]).buffer, type: 'public-key', response: { authenticatorData: Uint8Array.from([1, 2, 3]).buffer, clientDataJSON: Uint8Array.from([4, 5, 6]).buffer, signature: Uint8Array.from([7, 8]).buffer, userHandle: null }, getClientExtensionResults: () => ({}) });
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create: vi.fn(), get } });
  return get;
}
function server(authenticated = true) {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const path = String(input); requests.push({ path, init });
    if (path.endsWith('/session')) return reply(authenticated ? session : { authenticated: false, csrf_token: csrf });
    if (path.endsWith('/auth/options')) return reply({ ceremony_id: 'login-ceremony', options, kind: 'login' });
    if (path.endsWith('/auth/verify')) return reply(session);
    if (path.endsWith('/plans')) return reply({ plans: [{ plan_id: 'plan-1', plan_hash: hash, change_kind: 'policy_change', valid_until: '2099-01-01T00:00:00Z' }] });
    if (path.endsWith('/plans/plan-1')) return reply(nextDetail);
    if (path.endsWith('/challenges')) {
      const body = JSON.parse(String(init?.body));
      return reply({ challenge: { challenge_id: 'bound-challenge', decision: body.decision, role: body.role, requirements_hash: requirementsHash, principal_id: session.principal_id, org_id: session.org_id, project_id: session.project_id, subject: { subject_type: 'plan', plan_ref: { plan_id: 'plan-1', plan_hash: hash, plan_kind: 'policy_change' } }, rp_id: 'localhost', origin: 'http://localhost:8790', expires_at: '2099-01-01T00:00:00Z' }, options });
    }
    if (path.endsWith('/assertions')) {
      submitted.push(JSON.parse(String(init?.body)));
      if (assertionError === 'network') throw new TypeError('lost response');
      if (assertionError === 'stale') return reply({ error: 'conflict', reason: 'CHALLENGE_STALE' }, 409);
      return reply({ approval: { approval_id: 'decision-1', decision: 'approve', plan_hash: hash }, replayed: submitted.length > 1 });
    }
    throw new Error('Unexpected request: ' + path);
  });
}
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); submitted = []; requests = []; nextDetail = structuredClone(detail); assertionError = undefined; window.history.replaceState({}, '', '/'); });
afterEach(() => { vi.unstubAllGlobals(); if (originalCredentials) Object.defineProperty(navigator, 'credentials', originalCredentials); else Reflect.deleteProperty(navigator, 'credentials'); });
async function open() { render(<Authority/>); await userEvent.click(await screen.findByRole('button', { name: /plan-1/ })); await screen.findByRole('heading', { name: 'Review immutable plan' }); }
async function consent() { await userEvent.selectOptions(screen.getByLabelText('Decision role'), 'owner'); await userEvent.click(screen.getByRole('checkbox')); }

test('authority sign-in requires an explicit profile and fresh passkey and keeps session proof out of browser storage', async () => {
  const get = browser(); server(false); render(<Authority/>);
  expect(await screen.findByLabelText('Authority profile')).toHaveValue('');
  expect(get).not.toHaveBeenCalled();
  await userEvent.type(screen.getByLabelText('Authority profile'), 'local-owner');
  await userEvent.click(screen.getByRole('button', { name: 'Sign in to authority' }));
  await screen.findByRole('button', { name: /plan-1/ });
  expect(requests.find(r => r.path.endsWith('/auth/options'))?.init?.body).toBe('{"profile":"local-owner"}');
  expect(requests.find(r => r.path.endsWith('/auth/verify'))?.init?.body).toContain('"signature":"Bwg"');
  expect(requests.filter(r => !r.path.endsWith('/session')).every(r => new Headers(r.init?.headers).get('X-Authority-CSRF') === csrf)).toBe(true);
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

test('review shows full authority data and unknown quorum without requesting consent or rendering plan text as HTML', async () => {
  const get = browser(); server(); const { container } = render(<Authority/>);
  await userEvent.click(await screen.findByRole('button', { name: /plan-1/ }));
  expect(await screen.findByText('192.0.2.0/24', { exact: false })).toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'Before' })).toHaveTextContent('198.51.100.1/32');
  expect(screen.getByRole('region', { name: 'After' })).toHaveTextContent('[]');
  expect(screen.getByText('Quorum has not been evaluated by this service.')).toBeInTheDocument();
  expect(screen.getByRole('checkbox')).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Approve plan' })).toBeDisabled();
  expect(get).not.toHaveBeenCalled(); expect(container.querySelector('img')).toBeNull();
});

test('approve refetches immutable plan then signs a fresh bound challenge and submits the raw assertion', async () => {
  browser(); server(); await open(); await consent();
  await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  expect(await screen.findByRole('status')).toHaveTextContent('Decision recorded');
  expect(requests.filter(r => r.path.endsWith('/plans/plan-1'))).toHaveLength(3);
  expect(JSON.parse(String(requests.find(r => r.path.endsWith('/challenges'))?.init?.body))).toEqual({ plan_id: 'plan-1', plan_hash: hash, requirements_hash: requirementsHash, decision: 'approve', role: 'owner' });
  expect(submitted[0]).toMatchObject({ challenge_id: 'bound-challenge', assertion: { response: { signature: 'Bwg', clientDataJSON: 'BAUG' } } });
  expect(submitted[0].idempotency_key).toMatch(/^[0-9a-f-]{36}$/);
  expect(screen.getByRole('status')).toHaveTextContent('This does not issue a grant or apply firewall changes.');
});

test('changed immutable content blocks the authenticator and asks the reviewer to inspect the new plan', async () => {
  const get = browser(); server(); await open(); await consent();
  nextDetail = { ...detail, plan_hash: 'sha256:' + 'c'.repeat(64) };
  await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('changed');
  expect(get).not.toHaveBeenCalled(); expect(submitted).toHaveLength(0);
  expect(screen.getByRole('checkbox')).not.toBeChecked();
});

test('cancelled authenticator produces no decision and reject requires its own fresh signed assertion', async () => {
  const get = browser(); get.mockRejectedValueOnce(new DOMException('cancelled', 'NotAllowedError')); server(); await open(); await consent();
  await userEvent.click(screen.getByRole('button', { name: 'Reject plan' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('cancelled');
  expect(submitted).toHaveLength(0);
  expect(JSON.parse(String(requests.find(r => r.path.endsWith('/challenges'))?.init?.body)).decision).toBe('reject');
});

test('missing referenced scope, failed gate, absent current role and expired plan cannot enable approval', async () => {
  browser(); server(); nextDetail = { ...detail, review: undefined, roles: [], plan: { ...detail.plan, valid_until: '2000-01-01T00:00:00Z', gates: [{ gate_id: 'scope', required: true, result: 'UNKNOWN' }] } }; await open();
  expect(screen.getByText('Full before and after scope evidence is unavailable. Approval is blocked.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Approve plan' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Reject plan' })).toBeDisabled();
});

test('lost decision response keeps the exact signed request and idempotency key for a safe retry', async () => {
  browser(); server(); assertionError = 'network'; await open(); await consent();
  await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  const retry = await screen.findByRole('button', { name: 'Retry recorded decision request' });
  expect(screen.getByRole('button', { name: 'Reject plan' })).toBeDisabled();
  assertionError = undefined; await userEvent.click(retry);
  expect(await screen.findByRole('status')).toHaveTextContent('Decision recorded');
  expect(submitted).toHaveLength(2); expect(submitted[0]).toEqual(submitted[1]);
  expect(sessionStorage.length).toBe(0); expect(localStorage.length).toBe(0);
});

test('authority rejection of stale proof shows no recorded approval and clears consent', async () => {
  browser(); server(); assertionError = 'stale'; await open(); await consent();
  await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('CHALLENGE_STALE');
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.getByRole('checkbox')).not.toBeChecked();
});

test('keyboard language choice preserves English default and supports all eight existing locales', async () => {
  browser(); server(false); render(<Authority/>);
  const language = await screen.findByLabelText('Language');
  expect(language).toHaveValue('en'); expect(within(language).getAllByRole('option')).toHaveLength(8);
  await userEvent.selectOptions(language, 'ko');
  expect(document.documentElement.lang).toBe('ko'); expect(localStorage.getItem('fw.locale')).toBe('ko');
});

test('authority failure is an error instead of an empty plan list and retries the failed read', async () => {
  browser(); server();
  const fetch = vi.mocked(globalThis.fetch);
  const implementation = fetch.getMockImplementation()!;
  let unavailable = true;
  fetch.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith('/plans') && unavailable ? reply({ error: 'unavailable' }, 503) : implementation(input, init));
  render(<Authority/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('unavailable');
  expect(screen.queryByText('No plans are available for this authority profile.')).not.toBeInTheDocument();
  unavailable = false; await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  expect(await screen.findByRole('button', { name: /plan-1/ })).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test('server-bound decision mismatch never reaches the authenticator or assertion endpoint', async () => {
  const get = browser(); server();
  const fetch = vi.mocked(globalThis.fetch);
  const implementation = fetch.getMockImplementation()!;
  fetch.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const response = await implementation(input, init);
    if (String(input).endsWith('/challenges')) {
      const data = await response.json(); data.challenge.decision = 'reject'; return reply(data);
    }
    return response;
  });
  await open(); await consent(); await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('AUTHORITY_CHALLENGE_INVALID');
  expect(get).not.toHaveBeenCalled(); expect(submitted).toHaveLength(0);
});

test('plan expiry while a review remains open disables both decisions', async () => {
  browser(); server(); nextDetail = { ...detail, plan: { ...detail.plan, valid_until: new Date(Date.now() + 2000).toISOString() } };
  await open(); await consent();
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 2100)); });
  expect(screen.getByRole('button', { name: 'Approve plan' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Reject plan' })).toBeDisabled();
});

test('malformed authority review data becomes an error and never exposes decision controls', async () => {
  browser(); server(); nextDetail = { ...detail, plan: { ...detail.plan, gates: [null] } };
  render(<Authority/>); await userEvent.click(await screen.findByRole('button', { name: /plan-1/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent('AUTHORITY_RESPONSE_INVALID');
  expect(screen.queryByRole('button', { name: 'Approve plan' })).not.toBeInTheDocument();
});

test('retained current-principal rejection stays visible and prevents duplicate decisions', async () => {
  browser(); server(); nextDetail = { ...detail, current_principal_decisions: [{ approval: { approval_id: 'earlier-decision', decision: 'reject' }, current_valid: true }] }; await open();
  const recorded = screen.getByRole('status');
  expect(recorded).toHaveTextContent('earlier-decision'); expect(recorded).toHaveTextContent('reject');
  expect(screen.getByRole('button', { name: 'Approve plan' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Reject plan' })).toBeDisabled();
});

test('an expired authority session clears its memory proof before Refresh and requires fresh sign-in', async () => {
  browser(); server(); const fetch = vi.mocked(globalThis.fetch); const implementation = fetch.getMockImplementation()!;
  let sessions = 0; let signedIn = false;
  fetch.mockImplementation(async (input, init) => {
    const path = String(input);
    if (path.endsWith('/session')) {
      sessions++;
      if (sessions === 1) return reply(session);
      return new Headers(init?.headers).has('X-Authority-CSRF') ? reply({ error: 'unauthorized' }, 401) : reply({ authenticated: false, csrf_token: 'fresh-anonymous-proof' });
    }
    if (path.endsWith('/plans/plan-1') && !signedIn) return reply({ error: 'unauthorized' }, 401);
    if (path.endsWith('/auth/verify')) signedIn = true;
    return implementation(input, init);
  });
  render(<Authority/>); await userEvent.click(await screen.findByRole('button', { name: /plan-1/ }));
  await screen.findByRole('alert'); await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  const profile = await screen.findByLabelText('Authority profile');
  expect(profile).toHaveValue('');
  await userEvent.type(profile, 'local-owner'); await userEvent.click(screen.getByRole('button', { name: 'Sign in to authority' }));
  await screen.findByRole('button', { name: /plan-1/ });
  expect(requests.filter(request => request.path.endsWith('/assertions'))).toHaveLength(0);
  const freshOptions = requests.find(request => request.path.endsWith('/auth/options'))!;
  expect(new Headers(freshOptions.init?.headers).get('X-Authority-CSRF')).toBe('fresh-anonymous-proof');
});

const setHash = 'sha256:' + 'd'.repeat(64);
function liveSet(validUntil = '2099-01-01T00:00:00Z') {
  return { hash: setHash, valid_until: validUntil, content: { schema_version: 'f.approval-set/v1', approval_set_id: 'set-one', org_id: 'org', project_id: 'project', plan_ref: { plan_kind: 'policy_change', plan_id: 'plan-1', plan_hash: hash }, requirements_hash: requirementsHash, created_at: '2026-10-31T00:00:00Z', valid_until: validUntil, authority_epoch: '1', kind: 'human', approvals: [{ approval_id: 'decision-one', decision: 'approve' }], role_policy_hash: hash } };
}
const approved = { state: 'approved', approval_set_id: 'set-one', approval_set_hash: setHash };

test.each([
  ['pending', 'Awaiting independent approvals'],
  ['authority_unavailable', 'Independent authority unavailable'],
  ['blocked_by_dissent', 'Blocked by signed rejection'],
  ['stale', 'Current approval set is stale'],
  ['not_evaluated', 'Quorum not evaluated'],
  ['approved', 'Current approval set verified'],
])('authority aggregate %s is displayed from the current detail response', async (state, label) => {
  browser(); server(); nextDetail = { ...detail, aggregation: state === 'approved' ? approved : { state }, current_approval_set: state === 'approved' ? liveSet() : null }; await open();
  const aggregate = screen.getByRole('region', { name: 'Current authority status' });
  expect(aggregate).toHaveTextContent(label);
  if (state === 'approved') { expect(aggregate).toHaveTextContent(setHash); expect(aggregate).toHaveTextContent('Included signed approvals: 1'); }
  else expect(aggregate).not.toHaveTextContent(setHash);
});

test('historical approved acknowledgement is never used as current authority after a stale refetch', async () => {
  browser(); server(); nextDetail = { ...detail, aggregation: { state: 'pending' }, current_approval_set: null };
  const fetch = vi.mocked(globalThis.fetch); const implementation = fetch.getMockImplementation()!; let reads = 0;
  fetch.mockImplementation(async (input, init) => {
    if (String(input).endsWith('/plans/plan-1')) { reads++; return reply({ ...detail, aggregation: { state: reads >= 3 ? 'stale' : 'pending' }, current_approval_set: null }); }
    if (String(input).endsWith('/assertions')) return reply({ approval: { approval_id: 'old-decision', decision: 'approve', plan_hash: hash }, aggregation: approved, replayed: true });
    return implementation(input, init);
  });
  await open(); await consent(); await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  expect(await screen.findByRole('status')).toHaveTextContent('Decision recorded');
  await waitFor(() => expect(screen.getByRole('region', { name: 'Current authority status' })).toHaveTextContent('Current approval set is stale'));
  expect(screen.getByRole('region', { name: 'Current authority status' })).not.toHaveTextContent('Current approval set verified');
  expect(screen.getByText('Admission result (historical)')).toBeInTheDocument();
  expect(reads).toBe(3);
});

test('a failed current-status read preserves only the recorded decision and does not retry its signed request', async () => {
  browser(); server(); nextDetail = { ...detail, aggregation: { state: 'pending' }, current_approval_set: null };
  const fetch = vi.mocked(globalThis.fetch); const implementation = fetch.getMockImplementation()!; let reads = 0;
  fetch.mockImplementation(async (input, init) => {
    if (String(input).endsWith('/plans/plan-1') && ++reads >= 3) return reply({ error: 'unavailable' }, 503);
    return implementation(input, init);
  });
  await open(); await consent(); await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('unavailable');
  expect(screen.getByRole('alert')).not.toHaveTextContent('No new decision is confirmed.');
  expect(screen.getByRole('status')).toHaveTextContent('Decision recorded');
  expect(screen.queryByRole('region', { name: 'Current authority status' })).not.toBeInTheDocument();
  expect(screen.getByRole('alert')).toHaveTextContent('Current authority status is unavailable. Refresh to recheck.');
  expect(screen.queryByRole('button', { name: 'Retry recorded decision request' })).not.toBeInTheDocument();
  expect(submitted).toHaveLength(1);
});

test('an approved aggregate without its matching verified set is rejected instead of rendered as authorized', async () => {
  browser(); server(); nextDetail = { ...detail, aggregation: approved, current_approval_set: null };
  render(<Authority/>); await userEvent.click(await screen.findByRole('button', { name: /plan-1/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent('AUTHORITY_RESPONSE_INVALID');
  expect(screen.queryByText('Current approval set verified')).not.toBeInTheDocument();
});

test('a displayed approval set stops claiming current validity when its own deadline passes', async () => {
  browser(); server(); nextDetail = { ...detail, aggregation: approved, current_approval_set: liveSet(new Date(Date.now() + 2000).toISOString()) }; await open();
  expect(screen.getByRole('region', { name: 'Current authority status' })).toHaveTextContent('Current approval set verified');
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 2100)); });
  expect(screen.getByRole('region', { name: 'Current authority status' })).toHaveTextContent('The displayed approval set has expired. Refresh authority status.');
  expect(screen.getByRole('region', { name: 'Current authority status' })).not.toHaveTextContent('Current approval set verified');
});

test.each(['set_id', 'set_hash', 'plan_id', 'plan_hash', 'requirements', 'epoch'])('contradictory current approval set %s fails closed', async field => {
  browser(); server(); const set = liveSet();
  if (field === 'set_id') set.content.approval_set_id = 'different-set';
  if (field === 'set_hash') set.hash = 'sha256:' + 'e'.repeat(64);
  if (field === 'plan_id') set.content.plan_ref.plan_id = 'different-plan';
  if (field === 'plan_hash') set.content.plan_ref.plan_hash = 'sha256:' + 'e'.repeat(64);
  if (field === 'requirements') set.content.requirements_hash = 'sha256:' + 'e'.repeat(64);
  if (field === 'epoch') set.content.authority_epoch = '2';
  nextDetail = { ...detail, aggregation: approved, current_approval_set: set };
  render(<Authority/>); await userEvent.click(await screen.findByRole('button', { name: /plan-1/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent('AUTHORITY_RESPONSE_INVALID');
  expect(screen.queryByText('Current approval set verified')).not.toBeInTheDocument();
});

test('manual authority refresh replaces an old approved snapshot with current dissent and clears consent', async () => {
  browser(); server(); nextDetail = { ...detail, aggregation: approved, current_approval_set: liveSet() }; await open();
  nextDetail = { ...detail, aggregation: { state: 'blocked_by_dissent' }, current_approval_set: null };
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  expect(await screen.findByText('Blocked by signed rejection')).toBeInTheDocument();
  expect(screen.getByRole('checkbox')).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Approve plan' })).toBeDisabled();
  expect(screen.queryByText('Current approval set verified')).not.toBeInTheDocument();
});

function signedDecisionLifecycle() {
  const get = browser(); server(); nextDetail = { ...detail, aggregation: { state: 'pending' }, current_approval_set: null };
  const fetch = vi.mocked(globalThis.fetch); const implementation = fetch.getMockImplementation()!; let decision = 'approve';
  fetch.mockImplementation(async (input, init) => {
    if (String(input).endsWith('/challenges')) decision = JSON.parse(String(init?.body)).decision;
    const result = await implementation(input, init);
    if (String(input).endsWith('/assertions')) {
      const approval = { approval_id: `signed-${decision}`, decision };
      const aggregation = decision === 'approve' ? approved : { state: 'blocked_by_dissent' };
      nextDetail = { ...detail, aggregation, current_approval_set: decision === 'approve' ? liveSet() : null, current_principal_decisions: [{ approval, current_valid: true }] };
      return reply({ approval, aggregation, replayed: false });
    }
    return result;
  });
  return get;
}

test('a reviewer can reject their own prior approval only after new explicit consent and fresh verification', async () => {
  const get = signedDecisionLifecycle(); await open(); await consent();
  await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  await waitFor(() => expect(screen.getByRole('region', { name: 'Current authority status' })).toHaveTextContent('Current approval set verified'));
  expect(screen.getByRole('button', { name: 'Approve plan' })).toBeDisabled();
  expect(screen.getByRole('checkbox')).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Reject plan' })).toBeDisabled();
  await consent(); await userEvent.click(screen.getByRole('button', { name: 'Reject plan' }));
  await waitFor(() => expect(screen.getByRole('region', { name: 'Current authority status' })).toHaveTextContent('Blocked by signed rejection'));
  expect(get).toHaveBeenCalledTimes(2);
  expect(submitted).toHaveLength(2); expect(submitted[0].idempotency_key).not.toBe(submitted[1].idempotency_key);
  expect(requests.filter(request => request.path.endsWith('/challenges')).map(request => JSON.parse(String(request.init?.body)).decision)).toEqual(['approve', 'reject']);
});

test('a historical receipt does not prevent a fresh approval after the previous proof expires', async () => {
  const get = signedDecisionLifecycle(); await open(); await consent(); await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  await waitFor(() => expect(screen.getByRole('region', { name: 'Current authority status' })).toHaveTextContent('Current approval set verified'));
  nextDetail = { ...detail, aggregation: { state: 'pending' }, current_approval_set: null, current_principal_decisions: [{ approval: { approval_id: 'expired', decision: 'approve' }, current_valid: false }] };
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await screen.findByText('Awaiting independent approvals');
  expect(screen.getByRole('status')).toHaveTextContent('Decision recorded');
  await consent(); expect(screen.getByRole('button', { name: 'Approve plan' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Approve plan' }));
  await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
});
