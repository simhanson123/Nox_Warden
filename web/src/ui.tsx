import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { ApiError, displayValue } from './api';
import type { JsonRecord, ReadEnvelope } from './api';
import { formatTime } from './i18n';
import type { Locale, MessageKey, Translate } from './i18n';

export function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    assets: <><path d="m12 3 9 5-9 5-9-5 9-5ZM3 8v9l9 5 9-5V8M12 13v9"/></>,
    services: <><circle cx="6" cy="12" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="m9 11 6-4M9 13l6 4"/></>,
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
export function ErrorNotice({ error, t, retry }: { error?: ApiError; t: Translate; retry?: () => void }) {
  return <div className="notice danger" role="alert"><Icon name="info"/><div><strong>{t(error?.status === 403 ? 'error.forbidden' : error?.status === 401 ? 'auth.required' : 'common.error')}</strong><p><code>{error?.code}</code>{error?.detail ? ` · ${error.detail}` : ''}</p>{error?.requestId && <small>{error.requestId}</small>}{retry && <button className="text-button" onClick={retry}>{t('error.retry')}</button>}</div></div>;
}
export function Empty({ t }: { t: Translate }) {
  return <div className="empty"><span className="empty-icon"><Icon name="requests" size={28}/></span><h3>{t('list.emptyTitle')}</h3><p>{t('list.emptyText')}</p></div>;
}
export function Loader({ t }: { t: Translate }) { return <div className="loading" role="status"><span className="spinner"/>{t('common.loading')}</div>; }
export function Badge({ value, t }: { value: unknown; t: Translate }) {
  const raw = displayValue(value);
  const translations: Record<string, MessageKey> = { unverified: 'status.unverified', unknown: 'status.unknown', observe: 'status.observe', observe_only: 'status.observe', submitted: 'status.submitted', needs_info: 'status.needs_info', unsupported: 'state.unsupported' };
  return <span className={`badge ${['unknown', 'unverified', 'unsupported'].includes(raw) ? 'muted' : ''}`}>{translations[raw] ? t(translations[raw]) : raw}</span>;
}
export function Freshness({ envelope, t, locale }: { envelope?: ReadEnvelope<unknown>; t: Translate; locale: Locale }) {
  if (!envelope?.freshness?.stale) return null;
  return <div className="notice warning"><Icon name="info"/><span>{t('common.stale', { time: formatTime(envelope.freshness.observed_at, locale) })}</span></div>;
}
export function Detail({ record, t, close }: { record: JsonRecord; t: Translate; close: () => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => { const dialog = dialogRef.current; dialog?.showModal(); return () => dialog?.close(); }, []);
  return <dialog ref={dialogRef} onCancel={close} className="detail-dialog"><div className="section-heading"><div><span className="eyebrow">RECORD / JSON</span><h2>{t('list.details')}</h2></div><button autoFocus className="icon-button" onClick={close} aria-label={t('action.close')}><Icon name="close"/></button></div><pre tabIndex={0}>{JSON.stringify(record, (key, value: unknown) => /^(token|csrf_token|secret|password|authorization|private_key)$/i.test(key) ? '[REDACTED]' : value, 2)}</pre><button className="button" onClick={close}>{t('action.close')}</button></dialog>;
}
