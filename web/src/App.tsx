import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { api, ApiError, displayValue, listData, recordValue, setCsrfToken } from './api';
import type { AccessRequest, ActionPermission, ControllerStatus, JsonRecord, ReadEnvelope, Session } from './api';
import { formatTime, initialLocale, localeNames, locales, translator } from './i18n';
import type { Locale, MessageKey, Translate } from './i18n';

type View = 'overview' | 'requests' | 'policies' | 'targets' | 'audit';
const views: View[] = ['overview', 'requests', 'policies', 'targets', 'audit'];
const endpoints = { requests: '/access-requests', policies: '/policies', targets: '/targets', audit: '/audit/events' };
interface Resource<T> { state: 'loading' | 'ready' | 'error'; envelope?: ReadEnvelope<T>; error?: ApiError }
function useResource<T>(path: string | null, revision: number): Resource<T> {
  const [result, setResult] = useState<Resource<T>>({ state: 'loading' });
  useEffect(() => {
    if (!path) return;
    const controller = new AbortController();
    setResult({ state: 'loading' });
    void api<T>(path, { signal: controller.signal }).then(envelope => { if (Object.values(endpoints).some(prefix => path.startsWith(prefix + '?'))) listData(envelope); setResult({ state: 'ready', envelope }); }).catch((error: unknown) => {
      if (!controller.signal.aborted) setResult({ state: 'error', error: error instanceof ApiError ? error : new ApiError(0, 'INVALID_RESPONSE', '') });
    });
    return () => controller.abort();
  }, [path, revision]);
  return result;
}
function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    requests: <><path d="M8 3H4v18h16V3h-4M9 2h6v4H9zM8 11h8M8 16h5"/></>,
    policies: <><path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z"/><path d="m8 12 3 3 5-6"/></>,
    targets: <><rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6h.01M7 17h.01M12 6h5M12 17h5"/></>,
    audit: <><path d="M4 5h16M4 12h16M4 19h16M8 3v4M15 10v4M10 17v4"/></>,
    arrow: <path d="m9 5 7 7-7 7"/>, refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5 8a8 8 0 0 1 13-4l2 3M4 17l2 3a8 8 0 0 0 13-4"/></>,
    plus: <path d="M12 5v14M5 12h14"/>, close: <path d="m6 6 12 12M18 6 6 18"/>,
    info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.info}</svg>;
}
function ErrorNotice({ error, t, retry }: { error?: ApiError; t: Translate; retry?: () => void }) {
  return <div className="notice danger" role="alert"><Icon name="info"/><div><strong>{t(error?.status === 403 ? 'error.forbidden' : error?.status === 401 ? 'auth.required' : 'common.error')}</strong><p><code>{error?.code}</code>{error?.detail ? ` · ${error.detail}` : ''}</p>{error?.requestId && <small>{error.requestId}</small>}{retry && <button className="text-button" onClick={retry}>{t('error.retry')}</button>}</div></div>;
}
function Empty({ t }: { t: Translate }) {
  return <div className="empty"><span className="empty-icon"><Icon name="requests" size={28}/></span><h3>{t('list.emptyTitle')}</h3><p>{t('list.emptyText')}</p></div>;
}
function Loader({ t }: { t: Translate }) { return <div className="loading" role="status"><span className="spinner"/>{t('common.loading')}</div>; }
function Badge({ value, t }: { value: unknown; t: Translate }) {
  const raw = displayValue(value);
  const translations: Record<string, MessageKey> = { unverified: 'status.unverified', unknown: 'status.unknown', observe: 'status.observe', observe_only: 'status.observe', submitted: 'status.submitted', needs_info: 'status.needs_info', unsupported: 'state.unsupported' };
  return <span className={`badge ${['unknown', 'unverified', 'unsupported'].includes(raw) ? 'muted' : ''}`}>{translations[raw] ? t(translations[raw]) : raw}</span>;
}
function Freshness({ envelope, t, locale }: { envelope?: ReadEnvelope<unknown>; t: Translate; locale: Locale }) {
  if (!envelope?.freshness?.stale) return null;
  return <div className="notice warning"><Icon name="info"/><span>{t('common.stale', { time: formatTime(envelope.freshness.observed_at, locale) })}</span></div>;
}
function SessionGate({ t, onSession }: { t: Translate; onSession: (session: Session, actions?: ActionPermission[]) => void }) {
  const [token, setToken] = useState(''); const [pending, setPending] = useState(false); const [error, setError] = useState<ApiError>();
  const key = useRef(crypto.randomUUID());
  async function submit(event: FormEvent) {
    event.preventDefault(); if (pending || !token) return; setPending(true); setError(undefined);
    try { const result = await api<Session>('/session/bootstrap', { body: { token }, key: key.current }); setToken(''); onSession(result.data, result.actions); }
    catch (err) { setError(err as ApiError); } finally { setPending(false); }
  }
  return <div className="auth-container"><div className="auth-illustration"><Icon name="policies" size={56}/><span className="eyebrow">LOCAL / PRIVATE / AUDITABLE</span></div><section className="panel auth-panel"><span className="eyebrow">01 / SESSION</span><h1>{t('auth.title')}</h1><p className="muted-text">{t('auth.description')}</p>{error && <ErrorNotice error={error} t={t}/>}<form onSubmit={event => void submit(event)}><label>{t('auth.token')}<input type="password" autoComplete="off" required value={token} onChange={event => { setToken(event.target.value); key.current = crypto.randomUUID(); }}/></label><p className="field-hint">{t('auth.unstored')}</p><button className="button primary" disabled={pending || !token}>{pending ? t('common.loading') : t('action.connect')}<Icon name="arrow"/></button></form></section></div>;
}
function RequestForm({ t, onCreated, onCancel }: { t: Translate; onCreated: (record: JsonRecord) => void; onCancel: () => void }) {
  const [values, setValues] = useState({ workflow_id: '', workload_binding_id: '', source: '', destination: '', service_id: '', lease_seconds: '3600', purpose: '' });
  const [error, setError] = useState<ApiError>(); const [invalid, setInvalid] = useState(false); const [pending, setPending] = useState(false);
  const key = useRef(crypto.randomUUID());
  const change = (name: keyof typeof values, value: string) => { setValues(current => ({ ...current, [name]: value })); key.current = crypto.randomUUID(); setInvalid(false); };
  const uuidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
  async function submit(event: FormEvent) {
    event.preventDefault(); if (pending) return;
    const duration = Number(values.lease_seconds);
    if (!Number.isInteger(duration) || duration < 60 || duration > 86400 || !values.purpose.trim()) { setInvalid(true); return; }
    const body: AccessRequest = { schema_version: 'f.access-request/v1', idempotency_key: key.current, workflow_id: values.workflow_id,
      workload_binding_id: values.workload_binding_id, source_asset_ids: [values.source], destination_asset_ids: [values.destination],
      service_id: values.service_id, lease_seconds: duration, purpose: values.purpose };
    setPending(true); setError(undefined);
    try { const result = await api<JsonRecord>(endpoints.requests, { body, key: key.current }); onCreated(result.data); }
    catch (err) { setError(err as ApiError); } finally { setPending(false); }
  }
  return <section className="panel request-form"><div className="section-heading"><div><span className="eyebrow">ACCESS / REQUEST</span><h2>{t('action.new')}</h2></div><button className="icon-button" onClick={onCancel} aria-label={t('action.close')}><Icon name="close"/></button></div><p className="muted-text">{t('request.description')}</p>{error && <ErrorNotice error={error} t={t}/>}<form onSubmit={event => void submit(event)}><fieldset disabled={pending}><div className="form-grid">
    <label>{t('request.workflow')}<input required maxLength={128} value={values.workflow_id} onChange={e => change('workflow_id', e.target.value)}/></label>
    <label>{t('request.binding')}<input required pattern={uuidPattern} value={values.workload_binding_id} onChange={e => change('workload_binding_id', e.target.value)}/><span className="field-hint">{t('request.uuidHint')}</span></label>
    <label>{t('request.source')}<input required pattern={uuidPattern} value={values.source} onChange={e => change('source', e.target.value)}/></label>
    <label>{t('request.destination')}<input required pattern={uuidPattern} value={values.destination} onChange={e => change('destination', e.target.value)}/></label>
    <label>{t('request.service')}<input required maxLength={128} value={values.service_id} onChange={e => change('service_id', e.target.value)}/></label>
    <label>{t('request.duration')}<input required type="number" min={60} max={86400} step={1} value={values.lease_seconds} onChange={e => change('lease_seconds', e.target.value)}/><span className="field-hint">{t('request.durationHint')}</span></label>
    <label className="full">{t('list.purpose')}<textarea required maxLength={2000} rows={3} value={values.purpose} onChange={e => change('purpose', e.target.value)}/></label>
    </div>{invalid && <p role="alert" className="error-text">{t('request.invalid')}</p>}<div className="form-actions"><p>{t('operation.accepted')}</p><button className="button primary" type="submit">{pending ? t('common.loading') : t('action.submit')}<Icon name="arrow"/></button></div></fieldset></form></section>;
}
function Detail({ record, t, close }: { record: JsonRecord; t: Translate; close: () => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => { const dialog = dialogRef.current; dialog?.showModal(); return () => dialog?.close(); }, []);
  return <dialog ref={dialogRef} onCancel={close} className="detail-dialog"><div className="section-heading"><div><span className="eyebrow">RECORD / JSON</span><h2>{t('list.details')}</h2></div><button autoFocus className="icon-button" onClick={close} aria-label={t('action.close')}><Icon name="close"/></button></div><pre tabIndex={0}>{JSON.stringify(record, (key, value: unknown) => /^(token|csrf_token|secret|password|authorization|private_key)$/i.test(key) ? '[REDACTED]' : value, 2)}</pre><button className="button" onClick={close}>{t('action.close')}</button></dialog>;
}
function RecordTable({ kind, rows, t, locale, onSelect }: { kind: Exclude<View, 'overview'>; rows: JsonRecord[]; t: Translate; locale: Locale; onSelect: (row: JsonRecord) => void }) {
  if (!rows.length) return <Empty t={t}/>;
  const columns: Record<typeof kind, [MessageKey, string[]][]> = {
    requests: [['list.id', ['request_id', 'id']], ['list.purpose', ['purpose']], ['list.state', ['state', 'status']], ['list.created', ['created_at', 'received_at']]],
    policies: [['list.id', ['policy_id', 'id']], ['list.action', ['action']], ['list.target', ['target_id']], ['list.state', ['state', 'status', 'enforcement_state']]],
    targets: [['list.target', ['display_name', 'name', 'target_id', 'id']], ['list.platform', ['platform', 'os']], ['list.support', ['support_state', 'qualification_state', 'status']], ['list.state', ['state', 'mode']]],
    audit: [['list.sequence', ['sequence', 'seq']], ['list.event', ['event_type', 'kind', 'action']], ['list.id', ['event_id', 'id', 'resource_id']], ['list.time', ['recorded_at', 'server_time', 'occurred_at', 'created_at']]],
  };
  return <div className="table-scroll" role="region" aria-label={t('list.details')} tabIndex={0}><table><thead><tr>{columns[kind].map(([label]) => <th key={label} scope="col">{t(label)}</th>)}<th scope="col"><span className="sr-only">{t('list.details')}</span></th></tr></thead><tbody>{rows.map((row, index) => <tr key={displayValue(recordValue(row, 'id', 'request_id', 'policy_id', 'target_id', 'event_id')) + index}>{columns[kind].map(([label, keys], column) => { const value = recordValue(row, ...keys); return <td key={label}>{label === 'list.state' || label === 'list.support' ? <Badge value={value ?? 'unknown'} t={t}/> : label === 'list.time' || label === 'list.created' ? <span className="date">{formatTime(value, locale)}</span> : column === 0 ? <button className="record-link" onClick={() => onSelect(row)}>{displayValue(value)}</button> : <span className={label === 'list.purpose' ? 'purpose-cell' : ''}>{displayValue(value)}</span>}</td>; })}<td><button className="icon-button" onClick={() => onSelect(row)} aria-label={t('list.details')}><Icon name="arrow" size={16}/></button></td></tr>)}</tbody></table></div>;
}
function Listing({ kind, t, locale, revision, onSelect, onRefresh }: { kind: Exclude<View, 'overview'>; t: Translate; locale: Locale; revision: number; onSelect: (row: JsonRecord) => void; onRefresh: () => void }) {
  const [cursor, setCursor] = useState<string | null>(null);
  useEffect(() => { setCursor(null); }, [kind]);
  const resource = useResource<unknown>(endpoints[kind] + '?limit=25' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''), revision);
  return <section className="panel list-panel"><div className="section-heading"><h2>{t(`nav.${kind}`)}</h2><span className="table-note">{t('list.scope')}</span></div><Freshness envelope={resource.envelope} t={t} locale={locale}/>{resource.state === 'loading' ? <Loader t={t}/> : resource.state === 'error' ? <ErrorNotice error={resource.error} t={t} retry={onRefresh}/> : <RecordTable kind={kind} rows={listData(resource.envelope!)} t={t} locale={locale} onSelect={onSelect}/>}{(cursor || resource.envelope?.next_cursor) && <div className="pagination"><button className="button" disabled={!cursor} onClick={() => setCursor(null)}>{t('action.back')}</button><button className="button" disabled={!resource.envelope?.next_cursor} onClick={() => setCursor(resource.envelope?.next_cursor ?? null)}>{t('action.next')}</button></div>}</section>;
}
function PlatformMatrix({ t, revision }: { t: Translate; revision: number }) {
  const resource = useResource<ControllerStatus>('/status', revision);
  const platforms = resource.envelope?.data.platforms;
  if (resource.state === 'loading') return <Loader t={t}/>;
  if (resource.state === 'error') return <ErrorNotice error={resource.error} t={t}/>;
  if (!Array.isArray(platforms)) return null;
  return <section className="panel list-panel"><div className="section-heading"><h2>{t('targets.matrix')}</h2><span className="table-note">{t('status.noObservation')}</span></div><div className="table-scroll" role="region" aria-label={t('list.details')} tabIndex={0}><table><thead><tr><th scope="col">{t('list.platform')}</th><th scope="col">{t('list.support')}</th></tr></thead><tbody>{platforms.filter((item): item is JsonRecord => item !== null && typeof item === 'object').map(item => <tr key={displayValue(item.platform)}><td><strong>{displayValue(item.platform)}</strong><div className="field-hint">{displayValue(item.backend)}</div></td><td><Badge value={item.status ?? 'unverified'} t={t}/></td></tr>)}</tbody></table></div></section>;
}
function Overview({ t, locale, revision, onSelect, onNavigate, onRefresh }: { t: Translate; locale: Locale; revision: number; onSelect: (row: JsonRecord) => void; onNavigate: (view: View) => void; onRefresh: () => void }) {
  const status = useResource<ControllerStatus>('/status', revision);
  const requests = useResource<unknown>(endpoints.requests + '?limit=25', revision);
  const policies = useResource<unknown>(endpoints.policies + '?limit=25', revision);
  const targets = useResource<unknown>(endpoints.targets + '?limit=25', revision);
  const audit = useResource<unknown>(endpoints.audit + '?limit=25', revision);
  return <>{status.state === 'error' ? <ErrorNotice error={status.error} t={t} retry={onRefresh}/> : status.state === 'loading' ? <Loader t={t}/> : <div className="mode-banner"><span className="mode-icon"><Icon name="policies" size={25}/></span><div><div className="mode-title"><strong>{t('overview.mode')}</strong><Badge value={status.envelope?.data.mode ?? 'unknown'} t={t}/></div><p>{status.envelope?.data.enforcement === false ? t('overview.noEnforcement') : t('status.noObservation')}</p></div><span className="version">v{status.envelope?.data.version ?? '—'}</span></div>}
    <div className="metrics">{([['requests', requests, 'overview.requestCount'], ['policies', policies, 'overview.policyCount'], ['targets', targets, 'overview.targetCount']] as const).map(([view, resource, key]) => <button key={view} className="metric" onClick={() => onNavigate(view)}><div><span>{t(key)}</span><Icon name={view}/></div><strong>{resource.state === 'ready' ? listData(resource.envelope!).length : '—'}</strong><div><span className="metric-foot">{resource.state === 'error' ? t('common.error') : t('list.scope')}</span><Icon name="arrow" size={16}/></div></button>)}</div>
    <section className="panel list-panel"><div className="section-heading"><h2>{t('overview.recent')}</h2><button className="text-button" onClick={() => onNavigate('audit')}>{t('nav.audit')} <Icon name="arrow" size={14}/></button></div>{audit.state === 'loading' ? <Loader t={t}/> : audit.state === 'error' ? <ErrorNotice error={audit.error} t={t} retry={onRefresh}/> : <><Freshness envelope={audit.envelope} t={t} locale={locale}/><RecordTable kind="audit" rows={listData(audit.envelope!).slice(0, 5)} t={t} locale={locale} onSelect={onSelect}/></>}</section>
    <section className="evidence-section"><div className="section-heading"><h2>{t('overview.layers')}</h2><span className="eyebrow">INTENT ≠ OBSERVATION</span></div><div className="evidence-grid">{(['intent', 'backend', 'traffic'] as const).map((key, index) => <article key={key}><span className="evidence-number">0{index + 1}</span><h3>{t(`overview.${key}`)}</h3><p>{t(`overview.${key}Text`)}</p></article>)}</div></section></>;
}
export default function App() {
  const [locale, setLocale] = useState<Locale>(initialLocale); const t = translator(locale);
  const currentView = (): View => { const value = location.pathname.split('/')[1]; return views.includes(value as View) ? value as View : 'overview'; };
  const [view, setView] = useState<View>(currentView); const [session, setSession] = useState<Session | null>(null); const [authLoading, setAuthLoading] = useState(true); const [canCreate, setCanCreate] = useState(false);
  const [revision, setRevision] = useState(0); const [showForm, setShowForm] = useState(location.pathname === '/requests/new'); const [selected, setSelected] = useState<JsonRecord>(); const [success, setSuccess] = useState(false); const [detailError, setDetailError] = useState<ApiError>();
  useEffect(() => { document.documentElement.lang = locale; try { localStorage.setItem('fw.locale', locale); } catch { /* Optional preference only. */ } }, [locale]);
  const acceptSession = useCallback((value: Session, actions?: ActionPermission[]) => { setCanCreate(actions?.some(action => action.action_id === 'requests.create' && action.allowed) ?? false); setSession(value); setCsrfToken(value.csrf_token); setAuthLoading(false); }, []);
  useEffect(() => { const controller = new AbortController(); void api<Session>('/session', { signal: controller.signal }).then(result => acceptSession(result.data, result.actions)).catch(() => { if (!controller.signal.aborted) setAuthLoading(false); }); return () => controller.abort(); }, [acceptSession]);
  useEffect(() => { const pop = () => { setView(currentView()); setShowForm(location.pathname === '/requests/new'); setSelected(undefined); setRevision(value => value + 1); }; window.addEventListener('popstate', pop); return () => window.removeEventListener('popstate', pop); }, []);
  useEffect(() => {
    const match = /^\/requests\/([^/]+)$/.exec(location.pathname);
    if (!session || !match || match[1] === 'new') return;
    const controller = new AbortController();
    void api<JsonRecord>(endpoints.requests + '/' + encodeURIComponent(match[1]), { signal: controller.signal }).then(result => setSelected(result.data)).catch((error: unknown) => { if (!controller.signal.aborted) setDetailError(error as ApiError); });
    return () => controller.abort();
  }, [session, revision]);
  const openRecord = (record: JsonRecord) => {
    setSelected(record);
    const id = recordValue(record, 'request_id', 'id');
    if (view === 'requests' && typeof id === 'string') history.pushState(null, '', '/requests/' + encodeURIComponent(id));
  };
  const closeRecord = () => { setSelected(undefined); if (/^\/requests\/[^/]+$/.test(location.pathname)) history.replaceState(null, '', '/requests'); };
  const navigate = (next: View, newRequest = false) => { setSelected(undefined); setDetailError(undefined); setView(next); setShowForm(newRequest); setSuccess(false); history.pushState(null, '', '/' + next + (newRequest ? '/new' : '')); };
  const refresh = () => setRevision(value => value + 1);
  const descriptions: Record<View, MessageKey> = { overview: 'overview.description', requests: 'request.description', policies: 'policies.description', targets: 'targets.description', audit: 'audit.description' };
  return <div className="shell"><a className="skip-link" href="#main">{t('app.skip')}</a><aside className="sidebar"><a className="brand" aria-label="Warden" href="/overview" onClick={event => { event.preventDefault(); navigate('overview'); }}><span className="brand-mark"><Icon name="policies" size={26}/></span><span>WARDEN<span className="brand-sub">CONTROL / 01</span></span></a><div className="workspace"><span className="workspace-dot"/><div><strong>{t('app.workspace')}</strong><span>{t('app.version')}</span></div></div><span className="nav-heading">WORKSPACE</span><nav aria-label={t('app.workspace')}>{views.map(item => <a key={item} aria-label={t(`nav.${item}`)} href={'/' + item} className={view === item ? 'nav-item active' : 'nav-item'} aria-current={view === item ? 'page' : undefined} onClick={event => { event.preventDefault(); navigate(item); }}><Icon name={item}/><span>{t(`nav.${item}`)}</span>{view === item && <span className="nav-dot"/>}</a>)}</nav><div className="sidebar-bottom"><Icon name="policies"/><p>{t('security.note')}</p><div className="telemetry"><span/>{t('telemetry.off')}</div></div></aside><div className="main-wrap"><header className="topbar"><span className="breadcrumb">{t('app.subtitle')}<span>/</span><strong>{t(`nav.${view}`)}</strong></span><label className="language-label"><span className="sr-only">{t('app.language')}</span><select value={locale} onChange={e => setLocale(e.target.value as Locale)} aria-label={t('app.language')}>{locales.map(item => <option key={item} value={item}>{localeNames[item]}</option>)}</select></label></header><main id="main" tabIndex={-1}>
      {authLoading ? <Loader t={t}/> : !session ? <SessionGate t={t} onSession={acceptSession}/> : <><div className="page-heading"><div><span className="eyebrow">{view === 'overview' ? 'SYSTEM / OVERVIEW' : `WORKSPACE / ${view.toUpperCase()}`}</span><h1>{view === 'overview' ? t('overview.title') : t(`nav.${view}`)}</h1><p>{t(descriptions[view])}</p></div><div className="heading-actions"><button className="button" onClick={refresh}><Icon name="refresh" size={16}/>{t('action.refresh')}</button>{(view === 'requests' || view === 'overview') && <button className="button primary" disabled={!canCreate} title={!canCreate ? t('error.forbidden') : undefined} onClick={() => navigate('requests', true)}><Icon name="plus" size={16}/>{t('action.new')}</button>}</div></div>
      {detailError && <ErrorNotice error={detailError} t={t}/>}
      {success && <div className="notice success" role="status"><Icon name="info"/><span>{t('request.saved')} {t('operation.accepted')}</span></div>}
      {showForm && view === 'requests' && !canCreate && <ErrorNotice error={new ApiError(403, 'ACTION_UNAVAILABLE', '')} t={t}/>}
      {showForm && canCreate && view === 'requests' && <RequestForm t={t} onCancel={() => navigate('requests')} onCreated={record => { setShowForm(false); setSuccess(true); setSelected(record); const id = recordValue(record, 'resource_id', 'request_id', 'id'); history.replaceState(null, '', typeof id === 'string' ? '/requests/' + encodeURIComponent(id) : '/requests'); refresh(); }}/>}
      {view === 'targets' && <PlatformMatrix t={t} revision={revision}/>}
      {view === 'overview' ? <Overview t={t} locale={locale} revision={revision} onSelect={openRecord} onNavigate={navigate} onRefresh={refresh}/> : <Listing kind={view} t={t} locale={locale} revision={revision} onSelect={openRecord} onRefresh={refresh}/>}
      </>}
      <footer><span>{t('app.footer')}</span><span>Apache-2.0 · F-2.0</span></footer></main><div className="translation-note">{t('locale.preview')}</div></div>{selected && <Detail record={selected} t={t} close={closeRecord}/>}</div>;
}
