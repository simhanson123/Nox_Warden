// @vitest-environment-options {"url":"http://localhost:8790"}
import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthorityClient } from './authority-api';
import type { AuthorityPlan } from './authority-api';
import NativeEvidence from './NativeEvidence';
import { parseNativeEvidence } from './native-evidence';

const hash = (digit: string) => 'sha256:' + digit.repeat(64);
const time = (value: number) => new Date(value).toISOString().replace('.000Z', 'Z');
const now = () => Math.floor(Date.now() / 1000) * 1000;
function detail(): AuthorityPlan {
  return { plan_hash: hash('a'), requirements_hash: hash('b'), roles: [], current_principal_decisions: [],
    plan: { plan_id: '44444444-4444-4444-8444-444444444444', org_id: '22222222-2222-4222-8222-222222222222', project_id: '33333333-3333-4333-8333-333333333333', target_id: '99999999-9999-4999-8999-999999999999',
      valid_until: time(now() + 3600000), artifact_hash: hash('c'), baseline_hash: hash('d'), desired_state_hash: hash('e') }, requirements: {} };
}
function evidence(plan = detail()) {
  return { schema_version: 'fw.native-evidence-status/v1', org_id: plan.plan.org_id, project_id: plan.plan.project_id, target_id: plan.plan.target_id, plan_id: plan.plan.plan_id, plan_hash: plan.plan_hash,
    checked_at: time(now()), production_qualified: false, dispatch_allowed: false,
    reasons: ['NATIVE_QUALIFICATION_REQUIRED', 'SIGNER_DISPATCH_UNAVAILABLE'], observation_head_hash: hash('f'),
    compilation: { evidence_hash: hash('1'), reference_revision: '1', metadata_receipt_hash: hash('2'), baseline_artifact_hash: hash('3'), candidate_artifact_hash: hash('c'), admitted_at: time(now() - 60000), valid_until: time(now() + 30000), current: true },
    observation: { receipt_hash: hash('f'), compilation_hash: hash('1'), observer_revision: '1', artifact_role: 'candidate', comparison: 'match', observed_state_hash: hash('e'), signature_valid: true, provenance: 'signed_lab_observer_claim', checked_at: time(now() - 10000), admitted_at: time(now() - 9000), valid_until: time(now() + 30000), current: true } };
}
function client() {
  const result = new AuthorityClient();
  result.acceptSession({ authenticated: true, csrf_token: 'memory-proof', principal_id: 'reviewer', org_id: 'org', project_id: 'project', expires_at: '2099-01-01T00:00:00Z' });
  return result;
}
function response(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }); }
afterEach(() => { vi.useRealTimers(); });

test('read-only evidence distinguishes the verified signature and recomputed match from production authority', async () => {
  const plan = detail(); const data = evidence(plan);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(data));
  render(<NativeEvidence client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  const panel = screen.getByRole('region', { name: 'Development execution evidence' });
  expect(await within(panel).findByText('Submitted capture matches the compiled rules.')).toBeInTheDocument();
  expect(within(panel).getAllByText('Current at last read')).toHaveLength(2);
  expect(panel).toHaveTextContent('Signature verified for the pinned lab observer.');
  expect(panel).toHaveTextContent('It does not independently prove that they came from the actual kernel.');
  expect(panel).toHaveTextContent('These lab results do not qualify host protection or permit policy signing or deployment.');
  expect(within(panel).getByText(hash('e'))).toBeInTheDocument();
  const [path, init] = fetch.mock.calls[0];
  expect(path).toBe('/authority/v1/plans/' + plan.plan.plan_id + '/native-evidence');
  expect(init).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store' });
  expect(new Headers(init?.headers).get('X-Authority-CSRF')).toBe('memory-proof');
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

test.each([
  ['another plan', (v: ReturnType<typeof evidence>) => { v.plan_id = '55555555-5555-4555-8555-555555555555'; }],
  ['another tenant', (v: ReturnType<typeof evidence>) => { v.org_id = '55555555-5555-4555-8555-555555555555'; }],
  ['another target', (v: ReturnType<typeof evidence>) => { v.target_id = '55555555-5555-4555-8555-555555555555'; }],
  ['production qualification', (v: ReturnType<typeof evidence>) => { v.production_qualified = true; }],
  ['dispatch permission', (v: ReturnType<typeof evidence>) => { v.dispatch_allowed = true; }],
  ['unverified signature', (v: ReturnType<typeof evidence>) => { v.observation.signature_valid = false; }],
  ['different compilation', (v: ReturnType<typeof evidence>) => { v.observation.compilation_hash = hash('9'); }],
  ['wrong artifact', (v: ReturnType<typeof evidence>) => { v.compilation.candidate_artifact_hash = hash('9'); }],
  ['wrong observation head', (v: ReturnType<typeof evidence>) => { v.observation_head_hash = hash('9'); }],
  ['invented observed state', (v: ReturnType<typeof evidence>) => { v.observation.observed_state_hash = hash('9'); }],
  ['UNKNOWN with observed hash', (v: ReturnType<typeof evidence>) => { v.observation.comparison = 'unknown'; v.reasons.push('OBSERVATION_UNKNOWN'); }],
  ['unknown comparison', (v: ReturnType<typeof evidence>) => { v.observation.comparison = 'approved'; }],
  ['invented provenance', (v: ReturnType<typeof evidence>) => { v.observation.provenance = 'attested_kernel'; }],
  ['noncanonical revision', (v: ReturnType<typeof evidence>) => { v.compilation.reference_revision = '01'; }],
  ['overflow revision', (v: ReturnType<typeof evidence>) => { v.observation.observer_revision = '18446744073709551616'; }],
  ['expired current observation', (v: ReturnType<typeof evidence>) => { v.observation.valid_until = v.checked_at; }],
  ['future admission', (v: ReturnType<typeof evidence>) => { v.compilation.admitted_at = time(now() + 10000); }],
  ['nonexistent calendar date', (v: ReturnType<typeof evidence>) => { v.checked_at = '2026-02-31T00:00:00Z'; }],
  ['missing qualification blocker', (v: ReturnType<typeof evidence>) => { v.reasons = ['SIGNER_DISPATCH_UNAVAILABLE']; }],
  ['extra raw capture', (v: ReturnType<typeof evidence>) => { Object.assign(v.observation, { raw_capture: { private: 'private-marker' } }); }],
])('invalid native evidence cannot display current authority: %s', (_name, mutate) => {
  const plan = detail(); const value = evidence(plan); mutate(value);
  expect(() => parseNativeEvidence(value, plan)).toThrow();
});

test('unknown retained observation displays no observed state hash and cannot imply current enforcement', async () => {
  const plan = detail(); const value = evidence(plan);
  const data = { ...value, reasons: [...value.reasons, 'COMPILATION_STALE', 'OBSERVATION_STALE', 'OBSERVATION_UNKNOWN'],
    compilation: { ...value.compilation, current: false }, observation: { ...value.observation, current: false, comparison: 'unknown', observed_state_hash: null } };
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(data));
  render(<NativeEvidence client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  expect(await screen.findByText('The submitted capture cannot be interpreted completely.')).toBeInTheDocument();
  expect(screen.getAllByText('Retained history only')).toHaveLength(2);
  expect(screen.queryByText('Corresponding state hash')).not.toBeInTheDocument();
  expect(screen.queryByText('Current at last read')).not.toBeInTheDocument();
});

test('another plan on the same target can own the CAS head without supplying this plan observation', () => {
  const plan = detail(); const value = evidence(plan);
  const parsed = parseNativeEvidence({ ...value, observation: null, reasons: [...value.reasons, 'OBSERVATION_MISSING'] }, plan);
  expect(parsed.observation).toBeNull();
  expect(parsed.observation_head_hash).toBe(hash('f'));
  expect(parsed.compilation?.current).toBe(true);
});

test('a later plan on the same target preserves this plan observation as history without promoting it to current', async () => {
  const plan = detail(); const value = evidence(plan);
  const historical = { ...value, observation_head_hash: hash('9'),
    observation: { ...value.observation, current: false }, reasons: [...value.reasons, 'OBSERVATION_STALE'] };
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(historical));
  render(<NativeEvidence client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  const observation = await screen.findByRole('region', { name: 'Signed observation' });
  expect(await within(observation).findByText('Retained history only')).toBeInTheDocument();
  expect(observation).toHaveTextContent('Submitted capture matches the compiled rules.');
  expect(within(observation).getByText(value.observation.receipt_hash)).toBeInTheDocument();
  expect(within(observation).queryByText('No retained evidence.')).not.toBeInTheDocument();
  expect(within(observation).queryByText('Current at last read')).not.toBeInTheDocument();
  expect(screen.queryByText(historical.observation_head_hash)).not.toBeInTheDocument();
  expect(() => parseNativeEvidence({ ...historical, observation: { ...historical.observation, current: true }, reasons: value.reasons }, plan)).toThrow();
});

test('refresh immediately clears current evidence and a failed read leaves no stale current badge', async () => {
  const plan = detail(); const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response(evidence(plan)));
  const api = client();
  render(<NativeEvidence client={api} detail={plan} locale="en" onUnauthorized={vi.fn()}/>);
  await screen.findByText('Submitted capture matches the compiled rules.');
  fetch.mockResolvedValueOnce(response({ error: 'unavailable' }, 503));
  await userEvent.click(screen.getByRole('button', { name: 'Refresh execution evidence' }));
  expect(await screen.findByText('Execution evidence is unavailable. Refresh to recheck.')).toBeInTheDocument();
  expect(screen.queryByText('Current at last read')).not.toBeInTheDocument();
  expect(screen.queryByText(hash('e'))).not.toBeInTheDocument();
  expect(fetch.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
});

test('expiry removes current badges without a new request and clock rollback cannot revive the same snapshot', async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-01T12:00:00Z'));
  const plan = detail(); const value = evidence(plan);
  value.compilation.valid_until = time(now() + 2000); value.observation.valid_until = time(now() + 2000);
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  const api = client(); const unauthorized = vi.fn();
  let rendered!: ReturnType<typeof render>;
  await act(async () => { rendered = render(<NativeEvidence client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>); });
  expect(screen.getAllByText('Current at last read')).toHaveLength(2);
  await act(async () => { await vi.advanceTimersByTimeAsync(2001); });
  expect(screen.getAllByText('Expired; refresh to recheck')).toHaveLength(2);
  vi.setSystemTime(new Date('2026-11-01T11:00:00Z'));
  await act(async () => { rendered.rerender(<NativeEvidence client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>); });
  expect(screen.queryByText('Current at last read')).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('response delay spends the server freshness window even when the browser wall clock rolls back', async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-01T12:00:00Z'));
  const plan = detail(); const value = evidence(plan);
  value.compilation.valid_until = '2026-11-01T12:00:10Z';
  value.observation.valid_until = '2026-11-01T12:00:10Z';
  let deliver!: (response: Response) => void;
  vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(resolve => { deliver = resolve; }));
  await act(async () => { render(<NativeEvidence client={client()} detail={plan} locale="en" onUnauthorized={vi.fn()}/>); });
  await act(async () => {
    vi.setSystemTime(new Date('2026-11-01T11:00:00Z'));
    await vi.advanceTimersByTimeAsync(20000);
    deliver(response(value));
  });
  expect(screen.queryAllByText('Current at last read')).toHaveLength(0);
  expect(screen.getAllByText('Expired; refresh to recheck')).toHaveLength(2);
  expect(screen.getByText(value.observation.receipt_hash)).toBeInTheDocument();
});

test('an expired authority session is reported to the parent instead of retaining evidence', async () => {
  const onUnauthorized = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ error: 'unauthorized' }, 401));
  render(<NativeEvidence client={client()} detail={detail()} locale="en" onUnauthorized={onUnauthorized}/>);
  await screen.findByText('Execution evidence is unavailable. Refresh to recheck.');
  expect(onUnauthorized).toHaveBeenCalledWith(expect.objectContaining({ status: 401 }));
  expect(screen.queryByText('Current at last read')).not.toBeInTheDocument();
});

test('a forward wall-clock observation that expires evidence stays expired after rollback before its monotonic deadline', async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-01T12:00:00Z'));
  const plan = detail(); const value = evidence(plan);
  const api = client(); const unauthorized = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value));
  let rendered!: ReturnType<typeof render>;
  await act(async () => { rendered = render(<NativeEvidence client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>); });
  expect(screen.getAllByText('Current at last read')).toHaveLength(2);
  vi.setSystemTime(new Date('2026-11-01T12:01:00Z'));
  rendered.rerender(<NativeEvidence client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>);
  expect(screen.getAllByText('Expired; refresh to recheck')).toHaveLength(2);
  vi.setSystemTime(new Date('2026-11-01T12:00:01Z'));
  rendered.rerender(<NativeEvidence client={api} detail={plan} locale="en" onUnauthorized={unauthorized}/>);
  expect(screen.queryByText('Current at last read')).not.toBeInTheDocument();
  expect(screen.getAllByText('Expired; refresh to recheck')).toHaveLength(2);
});

test('a response from the previous selected plan cannot replace the new plan evidence', async () => {
  const old = detail(); const next = { ...detail(), plan_hash: hash('9'), plan: { ...detail().plan, plan_id: '55555555-5555-4555-8555-555555555555' } };
  let resolveOld!: (response: Response) => void;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve; })).mockResolvedValueOnce(response(evidence(next)));
  const api = client(); const onUnauthorized = vi.fn();
  const rendered = render(<NativeEvidence client={api} detail={old} locale="en" onUnauthorized={onUnauthorized}/>);
  rendered.rerender(<NativeEvidence client={api} detail={next} locale="en" onUnauthorized={onUnauthorized}/>);
  await screen.findByText('Submitted capture matches the compiled rules.');
  await act(async () => { resolveOld(response({ ...evidence(old), dispatch_allowed: true })); });
  expect(screen.queryByText('Execution evidence is unavailable. Refresh to recheck.')).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(2);
});
