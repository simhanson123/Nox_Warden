import { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';
import type { JsonRecord } from './api';
import { initialLocale, locales, localeNames, formatTime } from './i18n';
import type { Locale } from './i18n';
import { getPasskey, passkeyError } from './webauthn';
import { AuthorityClient, authorityOrigin, record } from './authority-api';
import type { AuthoritySession, AuthorityPlan, AuthorityPlanSummary, AuthorityChallenge, SignedDecision, DecisionReceipt } from './authority-api';
import catalog from './authority-locales.json';

type Key = keyof typeof catalog.en;
const gateIds = ['schema', 'identity', 'scope', 'quota', 'semantic', 'expiry', 'capability', 'baseline'];
function fullScope(detail: AuthorityPlan) { return !!detail.review; }
function current(detail: AuthorityPlan) { return Date.parse(String(detail.plan.valid_until)) > Date.now(); }
function approvalReady(detail: AuthorityPlan) {
  const gates = detail.plan.gates as JsonRecord[];
  return fullScope(detail) && current(detail) && record(detail.plan.effect_summary).complete === true && gates.length === 8
    && gateIds.every(id => gates.filter(gate => gate?.gate_id === id && gate.required === true && gate.result === 'PASS').length === 1);
}
function context(detail: AuthorityPlan) {
  return JSON.stringify([detail.plan_hash, detail.requirements_hash, [...detail.roles].sort(), detail.plan, detail.requirements, detail.review, detail.current_principal_decisions, detail.aggregation, detail.current_approval_set]);
}
function errorValue(error: unknown) { return error instanceof ApiError ? error : passkeyError(error); }
function Json({ value }: { value: unknown }) { return <pre tabIndex={0}>{JSON.stringify(value, null, 2)}</pre>; }

export default function Authority() {
  const [client] = useState(() => new AuthorityClient());
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const t = (key: Key, values: Record<string, string | number> = {}) => catalog[locale][key].replace(/\{(\w+)\}/g, (match, name: string) => String(values[name] ?? match));
  const [session, setSession] = useState<AuthoritySession>();
  const [profile, setProfile] = useState('');
  const [plans, setPlans] = useState<AuthorityPlanSummary[]>();
  const [detail, setDetail] = useState<AuthorityPlan>();
  const [error, setError] = useState<ApiError>();
  const [busy, setBusy] = useState(false);
  const [clock, setClock] = useState(0);
  const lock = useRef(false);
  const [role, setRole] = useState('');
  const [consent, setConsent] = useState(false);
  const [pending, setPending] = useState<SignedDecision>();
  const [receipt, setReceipt] = useState<DecisionReceipt>();
  const [currentStatusError, setCurrentStatusError] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const abort = useRef<AbortController | undefined>(undefined);
  const active = useRef(true);
  useEffect(() => { document.documentElement.lang = locale; document.title = catalog[locale].title; }, [locale]);
  useEffect(() => {
    active.current = true;
    const controller = new AbortController();
    void client.session(controller.signal).then(setSession).catch(e => { if (!controller.signal.aborted) setError(errorValue(e)); });
    return () => { active.current = false; controller.abort(); abort.current?.abort(); };
  }, [client]);
  useEffect(() => { if (session?.authenticated) void loadPlans(); }, [session]);
  useEffect(() => { if (detail) heading.current?.focus(); }, [detail?.plan_hash]);
  useEffect(() => {
    const deadlines = [detail?.plan.valid_until, session?.expires_at, detail?.current_approval_set?.valid_until].map(value => Date.parse(String(value))).filter(value => value > Date.now());
    if (!deadlines.length) return;
    const timer = setTimeout(() => setClock(value => value + 1), Math.min(Math.min(...deadlines) - Date.now() + 1, 2_147_483_647));
    return () => clearTimeout(timer);
  }, [detail, session, clock]);
  async function loadPlans() {
    try {
      const data = await client.request<{ plans: AuthorityPlanSummary[] }>('/plans');
      if (!Array.isArray(data?.plans) || data.plans.some(plan => !plan || typeof plan.plan_id !== 'string' || typeof plan.plan_hash !== 'string')) throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
      if (active.current) setPlans(data.plans);
    } catch (e) { if (active.current) fail(e); }
  }
  function fail(e: unknown) {
    const err = errorValue(e); setError(err);
    if (err.status === 401) { client.clearSession(); setSession(undefined); setDetail(undefined); setPlans(undefined); setPending(undefined); setReceipt(undefined); setConsent(false); setRole(''); setCurrentStatusError(false); }
  }
  async function run(task: () => Promise<void>) {
    if (lock.current) return;
    lock.current = true; setBusy(true); setError(undefined);
    try { await task(); } catch (e) { if (active.current) fail(e); }
    finally { lock.current = false; if (active.current) setBusy(false); }
  }
  async function signIn() {
    const begin = await client.request<{ ceremony_id: string; options: unknown; kind: string }>('/auth/options', { profile: profile.trim() });
    abort.current = new AbortController();
    if (!active.current) return;
    const assertion = await getPasskey(record(begin.options).publicKey, abort.current.signal);
    if (!active.current) return;
    const session = client.acceptSession(await client.request('/auth/verify', { ceremony_id: begin.ceremony_id, assertion }));
    setSession(session); setProfile('');
  }
  async function openPlan(id: string) {
    const plan = await client.plan(id);
    setDetail(plan); setCurrentStatusError(false); setRole(''); setConsent(false); setReceipt(undefined); setPending(undefined);
  }
  async function refreshReview(id: string) {
    setDetail(previous => previous ? { ...previous, aggregation: undefined, current_approval_set: undefined } : previous);
    setConsent(false); setRole(''); setCurrentStatusError(true);
    const latest = await client.plan(id);
    setDetail(latest); setCurrentStatusError(false);
  }
  async function submitSigned(request: SignedDecision) {
    try {
      const result = await client.request<DecisionReceipt>('/approvals/assertions', request);
      if (!result?.approval || !['approve', 'reject'].includes(String(result.approval.decision)) || typeof result.replayed !== 'boolean') throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
      setPending(undefined); setReceipt(result); setConsent(false);
    } catch (e) {
      const err = errorValue(e);
      if (err.status > 0 && err.status < 500) { setPending(undefined); setConsent(false); }
      throw err;
    }
    // Admission acknowledgements are historical, including an exact retry.
    // Only a separate current read can supply a live aggregate/set projection.
    if (detail) await refreshReview(String(detail.plan.plan_id));
  }
  async function decide(decision: 'approve' | 'reject') {
    if (!detail || !session?.authenticated || !consent || !role || pending || !detail.roles.includes(role)) return;
    const ownCurrent = detail.current_principal_decisions.filter(item => item.current_valid);
    if ((decision === 'approve' && ownCurrent.length > 0) || (decision === 'reject' && ownCurrent.some(item => item.approval.decision === 'reject'))) return;
    const latest = await client.plan(String(detail.plan.plan_id));
    if (context(latest) !== context(detail)) { setDetail(latest); setConsent(false); setRole(''); throw new ApiError(0, 'AUTHORITY_CONTEXT_CHANGED', ''); }
    if (!current(latest) || (decision === 'approve' && (!approvalReady(latest) || latest.aggregation && latest.aggregation.state !== 'pending' || latest.current_principal_decisions.some(item => item.current_valid)))) throw new ApiError(0, 'AUTHORITY_REVIEW_BLOCKED', '');
    const begin = await client.request<AuthorityChallenge>('/approvals/challenges', { plan_id: latest.plan.plan_id, plan_hash: latest.plan_hash, requirements_hash: latest.requirements_hash, decision, role });
    const challenge = record(begin.challenge); const subject = record(challenge.subject); const planRef = record(subject.plan_ref);
    if (subject.subject_type !== 'plan' || planRef.plan_id !== latest.plan.plan_id || planRef.plan_hash !== latest.plan_hash || planRef.plan_kind !== latest.plan.change_kind
      || challenge.requirements_hash !== latest.requirements_hash || challenge.decision !== decision || challenge.role !== role
      || challenge.principal_id !== session.principal_id || challenge.org_id !== session.org_id || challenge.project_id !== session.project_id
      || challenge.rp_id !== 'localhost' || challenge.origin !== authorityOrigin || typeof challenge.challenge_id !== 'string'
      || Date.parse(String(challenge.expires_at)) <= Date.now() || !Number.isFinite(Date.parse(String(challenge.expires_at)))) {
      throw new ApiError(0, 'AUTHORITY_CHALLENGE_INVALID', '');
    }
    abort.current = new AbortController();
    if (!active.current) return;
    const assertion = await getPasskey(record(begin.options).publicKey, abort.current.signal);
    if (!active.current) return;
    const request = { challenge_id: challenge.challenge_id, idempotency_key: crypto.randomUUID(), assertion };
    setPending(request);
    setDetail(previous => previous ? { ...previous, aggregation: undefined, current_approval_set: undefined } : previous);
    setCurrentStatusError(true);
    await submitSigned(request);
  }
  const canDecide = !!session?.authenticated && Date.parse(String(session.expires_at)) > Date.now() && !!detail && current(detail) && !!role && detail.roles.includes(role) && consent && !busy && !pending;
  let reviewReady = false;
  try { reviewReady = !!detail && approvalReady(detail); } catch { /* Incomplete authority data blocks approval. */ }
  const ownCurrent = detail?.current_principal_decisions.filter(item => item.current_valid) ?? [];
  const hasCurrentRejection = ownCurrent.some(item => item.approval.decision === 'reject');
  const canApprove = ownCurrent.length === 0 && reviewReady && !currentStatusError && (!detail?.aggregation || detail.aggregation.state === 'pending');
  const setExpired = !!detail?.current_approval_set && Date.parse(detail.current_approval_set.valid_until) <= Date.now();
  const aggregateKey: Key | undefined = detail?.aggregation ? `aggregate.${detail.aggregation.state}` : undefined;
  const displayError = currentStatusError && receipt ? t('aggregate.unavailable') : error?.code === 'PASSKEY_CANCELLED' ? t('cancelled') : error?.code === 'AUTHORITY_CONTEXT_CHANGED' ? t('changed') : error?.code === 'AUTHORITY_REVIEW_BLOCKED' ? t('blocked') : t('error');
  return <div className="authority-app">
    <a className="skip-link" href="#authority-main">{t('skip')}</a>
    <header className="authority-header"><strong>{t('title')}</strong><label>{t('language')}<select aria-label={t('language')} value={locale} onChange={e => { const value = e.target.value as Locale; setLocale(value); try { localStorage.setItem('fw.locale', value); } catch { /* Locale preference is optional. */ } }}>{locales.map(value => <option key={value} value={value}>{localeNames[value]}</option>)}</select></label>
    {session?.authenticated && <button className="button" disabled={busy || !!pending} onClick={() => void run(async () => { const value = client.acceptSession(await client.request('/logout', {})); setSession(value); setDetail(undefined); setPlans(undefined); setReceipt(undefined); })}>{t('signOut')}</button>}</header>
    <main id="authority-main" tabIndex={-1}>
      <div className="authority-boundary"><h1>{t('title')}</h1><p>{t('boundary')}</p><p>{t('origin')}: <code>{authorityOrigin}</code></p>{session?.authenticated && <p><code>{session.principal_id} · {session.org_id} / {session.project_id}</code></p>}</div>
      {error && <div className="notice danger" role="alert"><p>{displayError} <code>{error.code} {error.detail}</code></p>{!session && <button className="button" disabled={busy} onClick={() => void run(async () => setSession(await client.session()))}>{t('refresh')}</button>}</div>}
      {busy && <p className="authority-loading" aria-live="polite">{t('loading')}</p>}
      {!session && !error && <p>{t('loading')}</p>}
      {session && !session.authenticated && <section className="panel authority-login"><h2>{t('signIn')}</h2><p>{t('profileHelp')}</p><form onSubmit={e => { e.preventDefault(); void run(signIn); }}><label>{t('profile')}<input required maxLength={128} value={profile} disabled={busy} onChange={e => setProfile(e.target.value)} autoComplete="off"/></label><button className="button primary" disabled={busy || !profile.trim()}>{t('signIn')}</button></form></section>}
      {session?.authenticated && !detail && <section className="panel authority-list"><div className="section-heading"><h2>{t('plans')}</h2><button className="button" disabled={busy} onClick={() => void run(loadPlans)}>{t('refresh')}</button></div>{plans ? plans.length ? <ul>{plans.map(plan => <li key={plan.plan_id}><button className="button" disabled={busy} onClick={() => void run(() => openPlan(plan.plan_id))}>{plan.plan_id}</button><code>{plan.plan_hash}</code><span>{plan.change_kind}</span><time>{formatTime(plan.valid_until, locale)}</time></li>)}</ul> : <p>{t('empty')}</p> : <p>{t('loading')}</p>}</section>}
      {detail && <article className="authority-review"><div className="page-heading"><h2 ref={heading} tabIndex={-1}>{t('review')}</h2><button className="button" disabled={busy || !!pending} onClick={() => void run(() => refreshReview(String(detail.plan.plan_id)))}>{t('refresh')}</button><button className="button" disabled={busy || !!pending} onClick={() => { setDetail(undefined); setError(undefined); void loadPlans(); }}>{t('back')}</button></div>
        <section className="panel authority-summary"><dl><dt>{t('target')}</dt><dd>{String(detail.plan.target_id ?? '—')}</dd><dt>{t('validUntil')}</dt><dd>{formatTime(detail.plan.valid_until, locale)}</dd><dt>{t('planHash')}</dt><dd><code>{detail.plan_hash}</code></dd><dt>{t('requirementsHash')}</dt><dd><code>{detail.requirements_hash}</code></dd><dt>{t('roles')}</dt><dd>{detail.roles.join(', ') || t('none')}</dd></dl></section>
        <div className="authority-scopes">{detail.review ? <><section className="panel" role="region" aria-label={t('before')}><h3>{t('before')}</h3><Json value={detail.review.before}/></section><section className="panel" role="region" aria-label={t('after')}><h3>{t('after')}</h3><Json value={detail.review.after}/></section></> : <p className="notice warning">{t('missingScope')}</p>}</div>
        <section className="panel authority-section"><h3>{t('gates')}</h3><ul>{(detail.plan.gates as JsonRecord[]).map((gate, i) => <li key={i}><code>{String(gate.gate_id)}: {String(gate.result)} · {String(gate.evidence_hash ?? '')}</code></li>)}</ul></section>
        <section className="panel authority-section"><h3>{t('requirements')}</h3><Json value={detail.requirements}/>{!detail.aggregation && <p className="notice warning">{t(currentStatusError ? 'aggregate.unavailable' : 'quorumUnknown')}</p>}</section>
        {detail.aggregation && aggregateKey && <section className="panel authority-section" role="region" aria-label={t('aggregate.heading')}><h3>{t('aggregate.heading')}</h3><p className="notice"><strong>{t(setExpired ? 'aggregate.expired' : aggregateKey)}</strong></p><p>{t('aggregate.snapshot')}</p>{detail.aggregation.state === 'blocked_by_dissent' && <p>{t('aggregate.dissentHelp')}</p>}{detail.current_approval_set && !setExpired && <><p>{t('aggregate.setHash')}: <code>{detail.current_approval_set.hash}</code></p><p>{t('aggregate.validUntil')}: {formatTime(detail.current_approval_set.valid_until, locale)}</p><p>{t('aggregate.members', { count: (detail.current_approval_set.content.approvals as unknown[]).length })}</p><details><summary>{t('aggregate.content')}</summary><Json value={detail.current_approval_set.content}/></details></>}</section>}
        <details className="panel authority-section" open><summary>{t('fullPlan')}</summary><Json value={detail.plan}/></details>
        <section className="panel authority-decision">{!reviewReady && <p className="notice warning">{t('blocked')}</p>}
          {detail.current_principal_decisions.length > 0 && <div role={receipt ? undefined : "status"} className="notice"><strong>{t('recorded')}</strong><p>{t('boundary')}</p><Json value={detail.current_principal_decisions}/></div>}
          {receipt && <div role="status" className="notice"><strong>{t('recorded')}: <code>{String(receipt.approval.decision)}</code></strong><p>{t('boundary')}</p><Json value={receipt.approval}/>{receipt.aggregation && <details><summary>{t('aggregate.historical')}</summary><p>{t('aggregate.historicalHelp')}</p><Json value={receipt.aggregation}/></details>}</div>}
          {pending && <div className="notice warning"><p>{t('uncertain')}</p><button className="button" disabled={busy} onClick={() => void run(() => submitSigned(pending))}>{t('retryDecision')}</button></div>}
          <fieldset disabled={busy || !!pending || hasCurrentRejection}><label>{t('role')}<select aria-label={t('role')} value={role} onChange={e => { setRole(e.target.value); setConsent(false); }}><option value="">{t('choose')}</option>{detail.roles.map(value => <option key={value} value={value}>{value}</option>)}</select></label><label className="authority-consent"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)}/><span>{t('consent')} <code>{detail.plan_hash}</code></span></label></fieldset>
          <div className="authority-actions"><button className="button primary" disabled={!canDecide || !canApprove} onClick={() => void run(() => decide('approve'))}>{t('approve')}</button><button className="button" disabled={!canDecide || hasCurrentRejection} onClick={() => void run(() => decide('reject'))}>{t('reject')}</button></div>
        </section>
      </article>}
    </main>
  </div>;
}
