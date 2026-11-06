import { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';
import { AuthorityClient } from './authority-api';
import type { AuthorityPlan } from './authority-api';
import { formatTime } from './i18n';
import type { Locale } from './i18n';
import { parseSigningReadinessV3 } from './signing-readiness';
import type { SigningReadinessV3 as Readiness } from './signing-readiness';
import catalog from './authority-locales.json';

type Key = keyof typeof catalog.en;
interface Snapshot {
  value: Readiness; context: string; wall: number; requestedMonotonic: number; receivedMonotonic: number;
  observedWall: { current: number };
}
function remaining(deadline: string, snapshot: Snapshot) {
  const end = Date.parse(deadline);
  snapshot.observedWall.current = Math.max(snapshot.observedWall.current, Date.now());
  const monotonic = performance.now();
  // Spend the entire request delay from the server's validity window. A slow
  // reply or a wall-clock rollback must not renew the displayed check.
  return Math.min(end - snapshot.observedWall.current,
    end - snapshot.wall - (monotonic - snapshot.receivedMonotonic),
    end - Date.parse(snapshot.value.checked_at) - (monotonic - snapshot.requestedMonotonic));
}

export default function SigningReadiness({ client, detail, locale, onUnauthorized }: {
  client: AuthorityClient; detail: AuthorityPlan; locale: Locale; onUnauthorized: (error: ApiError) => void;
}) {
  const t = (key: Key, values: Record<string, string | number> = {}) => catalog[locale][key].replace(/\{(\w+)\}/g, (match, name: string) => String(values[name] ?? match));
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [reload, setReload] = useState(0);
  const [clock, setClock] = useState(0);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const plan = useRef(detail); plan.current = detail;
  const callback = useRef(onUnauthorized); callback.current = onUnauthorized;
  const context = JSON.stringify([detail.plan_hash, detail.plan.plan_id, detail.plan.org_id, detail.plan.project_id,
    detail.plan.target_id, detail.aggregation?.state, detail.current_approval_set?.hash]);
  useEffect(() => {
    const controller = new AbortController(); const expected = plan.current;
    setSnapshot(undefined); setUnavailable(false); setLoading(true);
    const requestedMonotonic = performance.now();
    void client.request('/plans/' + encodeURIComponent(String(expected.plan.plan_id)) + '/signing-readiness', undefined, controller.signal, 'v3').then(value => {
      if (controller.signal.aborted) return;
      const parsed = parseSigningReadinessV3(value, expected); const wall = Date.now();
      setSnapshot({ value: parsed, context, wall, requestedMonotonic, receivedMonotonic: performance.now(), observedWall: { current: wall } });
    }).catch(error => {
      if (controller.signal.aborted) return;
      setSnapshot(undefined); setUnavailable(true);
      if (error instanceof ApiError && error.status === 401) callback.current(error);
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [client, context, reload]);
  useEffect(() => {
    if (!snapshot) return;
    const deadlines = [snapshot.value.valid_until, snapshot.value.latest_intent?.valid_until]
      .filter((value): value is string => value !== undefined)
      .map(deadline => remaining(deadline, snapshot)).filter(value => value > 0);
    if (!deadlines.length) return;
    const timer = setTimeout(() => setClock(value => value + 1), Math.min(Math.min(...deadlines) + 1, 2_147_483_647));
    return () => clearTimeout(timer);
  }, [snapshot, clock]);
  const value = snapshot?.context === context ? snapshot.value : undefined;
  const intent = value?.latest_intent;
  const fresh = !!value && !!snapshot && remaining(value.valid_until, snapshot) > 0;
  return <section className="panel authority-section" role="region" aria-label={t('signing.heading')} aria-busy={loading}>
    <div className="authority-native-heading"><h3>{t('signing.heading')}</h3><button className="button" disabled={loading} onClick={() => setReload(value => value + 1)}>{t('signing.refresh')}</button></div>
    <p>{t('signing.boundary')}</p>
    <p className="notice warning">{t('signing.blocked')}</p>
    {loading && <p aria-live="polite">{t('signing.loading')}</p>}
    {unavailable && <p className="notice warning" aria-live="polite">{t('signing.unavailable')}</p>}
    {value && snapshot && <>
      <p>{t('signing.snapshot', { time: formatTime(value.checked_at, locale) })}</p>
      {!fresh && <p className="notice warning" aria-live="polite">{t('signing.expired')}</p>}
      <dl><dt>{t('signing.validUntil')}</dt><dd>{formatTime(value.valid_until, locale)}</dd>
        {fresh && value.approval_set_hash && <><dt>{t('signing.approvalHash')}</dt><dd><code>{value.approval_set_hash}</code></dd></>}
        {fresh && value.target_generation !== null && <><dt>{t('signing.generation')}</dt><dd>{value.target_generation}</dd></>}
      </dl>
      {fresh && value.quota_configured && <p>{t('signing.quotaConfigured')}</p>}
      {fresh && value.quota_scope && <p>{t(value.quota_scope === 'project' ? 'signing.projectQuota' : 'signing.rootQuota')}</p>}
      {fresh && value.quota_root_id && <p>{t('signing.quotaRoot')}: <code>{value.quota_root_id}</code></p>}
      <ul aria-label={t('signing.reasons')}>{value.reasons.map(reason => <li key={reason}>{t(`signing.reason.${reason}`)}</li>)}</ul>
      <section role="region" aria-label={t('signing.target.heading')}><h4>{t('signing.target.heading')}</h4>
        {!value.target_bootstrap ? <p>{t('signing.target.none')}</p> : <>
          <p>{t('signing.target.pending')}</p>
          <p>{t(fresh && value.target_bootstrap.current_for_plan ? 'signing.target.current' : 'signing.target.history')}</p>
          <dl><dt>{t('signing.target.epoch')}</dt><dd>{value.target_bootstrap.accepted_epoch}</dd>
            <dt>{t('signing.target.revision')}</dt><dd>{value.target_bootstrap.confirmation_revision}</dd>
            <dt>{t('signing.target.hash')}</dt><dd><code>{value.target_bootstrap.confirmation_hash}</code></dd>
            <dt>{t('signing.target.observed')}</dt><dd>{formatTime(value.target_bootstrap.observed_at, locale)}</dd>
            <dt>{t('signing.target.validUntil')}</dt><dd>{formatTime(value.target_bootstrap.valid_until, locale)}</dd></dl>
          <p>{t('signing.target.boundary')}</p>
        </>}
      </section>
      <section role="region" aria-label={t('signing.latestIntent')}><h4>{t('signing.latestIntent')}</h4>
        {!intent ? <p>{t('signing.noIntent')}</p> : <>
          <p>{t('signing.intentBoundary')}</p><p className="notice">{t('signing.historical')}</p>
          <dl><dt>{t('signing.intentId')}</dt><dd><code>{intent.intent_id}</code></dd>
            <dt>{t('signing.intentState')}</dt><dd>{t(`signing.job.${intent.state}`)}</dd>
            <dt>{t('signing.dispatchState')}</dt><dd>{t(`signing.delivery.${intent.dispatch_state ?? 'none'}`)}</dd>
            <dt>{t('signing.reservationState')}</dt><dd>{t(`signing.quota.${intent.reservation_state}`)}</dd>
            <dt>{t('signing.payloadHash')}</dt><dd><code>{intent.payload_hash}</code></dd>
            <dt>{t('signing.intentGeneration')}</dt><dd>{intent.target_generation}</dd>
            <dt>{t('signing.createdAt')}</dt><dd>{formatTime(intent.created_at, locale)}</dd>
            <dt>{t('signing.intentValidUntil')}</dt><dd>{formatTime(intent.valid_until, locale)}</dd>
            {intent.grant_hash && <><dt>{t('signing.grantHash')}</dt><dd><code>{intent.grant_hash}</code></dd></>}
          </dl>
          <p>{t(intent.reservation_held ? 'signing.held' : 'signing.notHeld')}</p>
          {intent.dispatch_state === 'unknown' && <p className="notice warning">{t('signing.unknownHelp')}</p>}
          {value.latest_dispatch_unknown_seen && intent.dispatch_state !== 'unknown' && <p className="notice warning">{t('signing.pastUnknown')}</p>}
          {remaining(intent.valid_until, snapshot) <= 0 && <p className="notice warning">{t('signing.intentExpired')}</p>}
        </>}
      </section>
    </>}
  </section>;
}
