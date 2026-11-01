import { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';
import { AuthorityClient } from './authority-api';
import type { AuthorityPlan } from './authority-api';
import { formatTime } from './i18n';
import type { Locale } from './i18n';
import { parseNativeEvidence } from './native-evidence';
import type { NativeCompilation, NativeEvidenceStatus, NativeObservation } from './native-evidence';
import catalog from './authority-locales.json';

type Key = keyof typeof catalog.en;
interface Snapshot { value: NativeEvidenceStatus; identity: string; wall: number; requestedMonotonic: number; receivedMonotonic: number; observedWall: { current: number } }
function remaining(item: NativeCompilation | NativeObservation, snapshot: Snapshot) {
  const end = Date.parse(item.valid_until);
  // This private clock belongs to one fetched snapshot. Once a render or timer
  // observes expiry, a wall-clock rollback cannot revive its current badge.
  snapshot.observedWall.current = Math.max(snapshot.observedWall.current, Date.now());
  const monotonic = performance.now();
  // The server check happened after request start. Conservatively spend the
  // entire request/response delay from its freshness window; receipt must not
  // restart that window when the browser's wall clock is behind the server.
  return Math.min(end - snapshot.observedWall.current,
    end - snapshot.wall - (monotonic - snapshot.receivedMonotonic),
    end - Date.parse(snapshot.value.checked_at) - (monotonic - snapshot.requestedMonotonic));
}

export default function NativeEvidence({ client, detail, locale, onUnauthorized }: {
  client: AuthorityClient; detail: AuthorityPlan; locale: Locale; onUnauthorized: (error: ApiError) => void;
}) {
  const t = (key: Key, values: Record<string, string | number> = {}) => catalog[locale][key].replace(/\{(\w+)\}/g, (match, name: string) => String(values[name] ?? match));
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [reload, setReload] = useState(0);
  const [clock, setClock] = useState(0);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const callback = useRef(onUnauthorized);
  callback.current = onUnauthorized;
  const plan = useRef(detail);
  plan.current = detail;
  const identity = JSON.stringify([detail.plan_hash, detail.plan.plan_id, detail.plan.org_id, detail.plan.project_id, detail.plan.target_id]);
  useEffect(() => {
    const controller = new AbortController();
    const expected = plan.current;
    setSnapshot(undefined); setUnavailable(false); setLoading(true);
    const requestedMonotonic = performance.now();
    void client.request('/plans/' + encodeURIComponent(String(expected.plan.plan_id)) + '/native-evidence', undefined, controller.signal).then(value => {
      if (controller.signal.aborted) return;
      const parsed = parseNativeEvidence(value, expected); const wall = Date.now();
      setSnapshot({ value: parsed, identity, wall, requestedMonotonic, receivedMonotonic: performance.now(), observedWall: { current: wall } });
    }).catch(error => {
      if (controller.signal.aborted) return;
      setSnapshot(undefined); setUnavailable(true);
      if (error instanceof ApiError && error.status === 401) callback.current(error);
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [client, identity, reload]);
  useEffect(() => {
    if (!snapshot) return;
    const deadlines = [snapshot.value.compilation, snapshot.value.observation]
      .filter((item): item is NativeCompilation | NativeObservation => item !== null && item.current)
      .map(item => remaining(item, snapshot)).filter(value => value > 0);
    if (!deadlines.length) return;
    const timer = setTimeout(() => setClock(value => value + 1), Math.min(Math.min(...deadlines) + 1, 2_147_483_647));
    return () => clearTimeout(timer);
  }, [snapshot, clock]);
  function freshness(item: NativeCompilation | NativeObservation) {
    if (!item.current) return t('native.historical');
    return t(snapshot && remaining(item, snapshot) > 0 ? 'native.current' : 'native.expired');
  }
  // Do not paint the prior plan's snapshot while the replacement effect starts.
  const value = snapshot?.identity === identity ? snapshot.value : undefined;
  return <section className="panel authority-section authority-native" role="region" aria-label={t('native.heading')} aria-busy={loading}>
    <div className="authority-native-heading"><h3>{t('native.heading')}</h3><button className="button" disabled={loading} onClick={() => setReload(value => value + 1)}>{t('native.refresh')}</button></div>
    <p>{t('native.boundary')}</p>
    {loading && <p className="authority-loading" aria-live="polite">{t('native.loading')}</p>}
    {unavailable && <p className="notice warning" aria-live="polite">{t('native.unavailable')}</p>}
    {value && <>
      <p>{t('native.snapshot', { time: formatTime(value.checked_at, locale) })}</p>
      <div className="authority-native-grid">
        <section aria-label={t('native.compilation')}><h4>{t('native.compilation')}</h4>
          {!value.compilation ? <p>{t('native.missing')}</p> : <>
            <p className="notice" aria-live="polite">{freshness(value.compilation)}</p>
            <dl><dt>{t('native.evidenceHash')}</dt><dd><code>{value.compilation.evidence_hash}</code></dd>
              <dt>{t('native.artifactHash')}</dt><dd><code>{value.compilation.candidate_artifact_hash}</code></dd>
              <dt>{t('native.referenceRevision')}</dt><dd>{value.compilation.reference_revision}</dd>
              <dt>{t('native.admittedAt')}</dt><dd>{formatTime(value.compilation.admitted_at, locale)}</dd>
              <dt>{t('native.validUntil')}</dt><dd>{formatTime(value.compilation.valid_until, locale)}</dd></dl>
          </>}
        </section>
        <section aria-label={t('native.observation')}><h4>{t('native.observation')}</h4>
          {!value.observation ? <p>{t('native.missing')}</p> : <>
            <p className="notice" aria-live="polite">{freshness(value.observation)}</p>
            <p>{t('native.signature')}</p><p>{t(`native.${value.observation.comparison}`)}</p>
            <dl><dt>{t('native.receiptHash')}</dt><dd><code>{value.observation.receipt_hash}</code></dd>
              <dt>{t('native.role')}</dt><dd>{t(`native.${value.observation.artifact_role}`)}</dd>
              <dt>{t('native.evidenceHash')}</dt><dd><code>{value.observation.compilation_hash}</code></dd>
              <dt>{t('native.observerRevision')}</dt><dd>{value.observation.observer_revision}</dd>
              <dt>{t('native.measuredAt')}</dt><dd>{formatTime(value.observation.checked_at, locale)}</dd>
              <dt>{t('native.validUntil')}</dt><dd>{formatTime(value.observation.valid_until, locale)}</dd>
              {value.observation.observed_state_hash && <><dt>{t('native.observedHash')}</dt><dd><code>{value.observation.observed_state_hash}</code></dd></>}
            </dl>
          </>}
        </section>
      </div>
      <p>{t('native.provenance')}</p>
      <ul aria-label={t('native.reasons')}>{value.reasons.map(reason => <li key={reason}>{t(`native.reason.${reason}`)}</li>)}</ul>
    </>}
  </section>;
}
