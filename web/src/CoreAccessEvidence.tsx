import { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';
import { AuthorityClient } from './authority-api';
import type { AuthorityPlan } from './authority-api';
import { parseCoreAccessEvidence } from './core-access-evidence';
import type { CoreAccessEvidence as Evidence } from './core-access-evidence';
import { formatTime } from './i18n';
import type { Locale } from './i18n';
import catalog from './authority-locales.json';

type Key = keyof typeof catalog.en;
interface Snapshot { value: Evidence; identity: string; wall: number; requested: number; received: number }
function remaining(end: string, snapshot: Snapshot, client: AuthorityClient) {
  const monotonic = performance.now();
  const floor = client.observeCoreEvidenceTime(Math.max(Date.now(),
    snapshot.wall + (monotonic - snapshot.received),
    Date.parse(snapshot.value.checked_at) + (monotonic - snapshot.requested)));
  return Date.parse(end) - floor;
}

export default function CoreAccessEvidence({ client, detail, locale, onUnauthorized }: {
  client: AuthorityClient; detail: AuthorityPlan; locale: Locale; onUnauthorized: (error: ApiError) => void;
}) {
  const t = (key: Key) => catalog[locale][key];
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [reload, setReload] = useState(0);
  const [clock, setClock] = useState(0);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const callback = useRef(onUnauthorized); callback.current = onUnauthorized;
  const plan = useRef(detail); plan.current = detail;
  const identity = JSON.stringify([detail.plan_hash, detail.plan.plan_id, detail.plan.org_id, detail.plan.project_id, detail.plan.target_id]);
  useEffect(() => {
    const controller = new AbortController(); const expected = plan.current;
    setSnapshot(undefined); setUnavailable(false); setLoading(true);
    const requested = performance.now();
    void client.request('/plans/' + encodeURIComponent(String(expected.plan.plan_id)) + '/core-access-evidence', undefined, controller.signal).then(value => {
      if (controller.signal.aborted) return;
      const parsed = parseCoreAccessEvidence(value, expected); const wall = Date.now();
      setSnapshot({ value: parsed, identity, wall, requested, received: performance.now() });
    }).catch(error => {
      if (controller.signal.aborted) return;
      setSnapshot(undefined); setUnavailable(true);
      if (error instanceof ApiError && error.status === 401) callback.current(error);
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [client, identity, reload]);
  useEffect(() => {
    if (!snapshot?.value.lease_window) return;
    const item = snapshot.value.lease_window;
    const deadlines = [item.not_before, item.expires_at, String(detail.plan.valid_until)]
      .map(end => remaining(end, snapshot, client)).filter(value => value > 0);
    if (!deadlines.length) return;
    const timer = setTimeout(() => setClock(value => value + 1), Math.min(Math.min(...deadlines) + 1, 2_147_483_647));
    return () => clearTimeout(timer);
  }, [snapshot, detail.plan.valid_until, clock, client]);
  const value = snapshot?.identity === identity ? snapshot.value : undefined;
  const item = value?.lease_window;
  let freshness: Key = 'core.historical';
  if (item && snapshot) {
    if (remaining(item.expires_at, snapshot, client) <= 0) freshness = 'core.expired';
    else if (remaining(item.not_before, snapshot, client) > 0) freshness = 'core.future';
    else if (item.current && remaining(String(detail.plan.valid_until), snapshot, client) > 0) freshness = 'core.current';
  }
  return <section className="panel authority-section" role="region" aria-label={t('core.heading')} aria-busy={loading}>
    <div className="authority-native-heading"><h3>{t('core.heading')}</h3><button className="button" disabled={loading} onClick={() => setReload(value => value + 1)}>{t('core.refresh')}</button></div>
    <p>{t('core.boundary')}</p>
    {loading && <p aria-live="polite">{t('core.loading')}</p>}
    {unavailable && <p className="notice warning" aria-live="polite">{t('core.unavailable')}</p>}
    {value && <><p>{t('core.checkedAt')}: {formatTime(value.checked_at, locale)}</p>
      {!item ? <p>{t('core.missing')}</p> : <>
        <p className="notice" aria-live="polite">{t(freshness)}</p><p>{t('core.fixed')}</p>
        <dl><dt>{t('core.leaseId')}</dt><dd><code>{item.lease_id}</code></dd>
          <dt>{t('core.notBefore')}</dt><dd>{formatTime(item.not_before, locale)}</dd>
          <dt>{t('core.expiresAt')}</dt><dd>{formatTime(item.expires_at, locale)}</dd>
          <dt>{t('core.leaseSeconds')}</dt><dd>{item.lease_seconds}</dd>
          <dt>{t('core.windowHash')}</dt><dd><code>{item.window_hash}</code></dd>
          <dt>{t('core.provenanceHash')}</dt><dd><code>{item.provenance_hash}</code></dd></dl>
      </>}
      <p><code>CORE_SIGNING_PROFILE_UNAVAILABLE</code></p>
    </>}
  </section>;
}
