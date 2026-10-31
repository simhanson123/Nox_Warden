import { useEffect, useState } from 'react';
import { api, ApiError, listData } from './api';
import type { ReadEnvelope } from './api';
import type { Translate } from './i18n';

export function checkedPage(envelope: ReadEnvelope<unknown>) {
  const rows = listData(envelope);
  if (envelope.next_cursor !== undefined && envelope.next_cursor !== null && (typeof envelope.next_cursor !== 'string' || !envelope.next_cursor)) throw new ApiError(0, 'INVALID_RESPONSE', '');
  return { rows, next: envelope.next_cursor ?? null };
}

/** Each history entry is a cursor into the same server-selected snapshot. */
export function usePagedCollection(path: string, revision: string | number) {
  const scope = `${path}:${revision}`;
  const [navigation, setNavigation] = useState({ scope, cursors: [null] as (string | null)[], index: 0, limit: 25, attempt: 0 });
  const nav = navigation.scope === scope ? navigation : { ...navigation, scope, cursors: [null], index: 0 };
  const cursor = nav.cursors[nav.index];
  const request = path + '?limit=' + nav.limit + (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
  const key = `${scope}:${request}:${nav.attempt}`;
  const [result, setResult] = useState<{ key: string; envelope?: ReadEnvelope<unknown>; error?: ApiError }>({ key: '' });
  useEffect(() => {
    const controller = new AbortController();
    void api<unknown>(request, { signal: controller.signal }).then(envelope => {
      checkedPage(envelope);
      if (!controller.signal.aborted) setResult({ key, envelope });
    }).catch((error: unknown) => { if (!controller.signal.aborted) setResult({ key, error: error instanceof ApiError ? error : new ApiError(0, 'INVALID_RESPONSE', '') }); });
    return () => controller.abort();
  }, [key, request]);
  const loaded = result.key === key;
  const envelope = loaded ? result.envelope : undefined;
  const loading = !loaded;
  const error = loaded ? result.error : undefined;
  return { envelope, loading, error, index: nav.index, limit: nav.limit, previousAvailable: nav.index > 0,
    nextAvailable: !!envelope?.next_cursor,
    previous: () => { if (!loading && nav.index > 0) setNavigation({ ...nav, index: nav.index - 1 }); },
    next: () => { if (!loading && envelope?.next_cursor) setNavigation({ ...nav, cursors: [...nav.cursors.slice(0, nav.index + 1), envelope.next_cursor], index: nav.index + 1 }); },
    resize: (limit: number) => { if ([25, 50, 100].includes(limit)) setNavigation({ ...nav, cursors: [null], index: 0, limit }); },
    restart: () => setNavigation({ ...nav, cursors: [null], index: 0, attempt: nav.attempt + 1 }),
  };
}
export function PageNavigation({ page, t }: { page: ReturnType<typeof usePagedCollection>; t: Translate }) {
  return <nav className="pagination" aria-label={t('pagination.navigation')}>
    <label>{t('pagination.rows')}<select aria-label={t('pagination.rows')} value={page.limit} disabled={page.loading} onChange={event => page.resize(Number(event.target.value))}>{[25, 50, 100].map(limit => <option key={limit} value={limit}>{limit}</option>)}</select></label>
    <span aria-live="polite">{t('pagination.page', { page: page.index + 1 })}{page.envelope?.revision !== undefined && ` · ${t('pagination.snapshot', { revision: page.envelope.revision })}`}</span>
    <button className="button" disabled={page.loading || !!page.error || !page.previousAvailable} onClick={page.previous}>{t('pagination.previous')}</button>
    <button className="button" disabled={page.loading || !!page.error || !page.nextAvailable} onClick={page.next}>{t('action.next')}</button>
  </nav>;
}
