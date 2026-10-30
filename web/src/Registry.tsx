import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError, displayValue, listData, recordValue } from './api';
import type { JsonRecord, ReadEnvelope } from './api';
import { formatTime } from './i18n';
import type { Locale, Translate } from './i18n';
import { Detail, Empty, ErrorNotice, Freshness, Icon, Loader } from './ui';

export type RegistryKind = 'assets' | 'services';
type RegistryState = 'active' | 'retired';
type AssetKind = 'host' | 'vm' | 'namespace' | 'subnet' | 'gateway';
type Criticality = 'normal' | 'critical' | 'management';
type Isolation = 'host' | 'vm' | 'network_namespace' | 'subnet';
interface AssetAddress { family: 'ipv4' | 'ipv6'; cidr: string; interface: string | null }
interface AssetDefinition { name: string; asset_kind: AssetKind; owner_id: string; addresses: AssetAddress[]; criticality: Criticality; isolation: Isolation; provenance: 'manual'; source_evidence: null }
type Transport = { protocol: 'tcp' | 'udp'; destination_ports: { start: number; end: number }[] } | { protocol: 'icmp' | 'icmpv6'; type: number; code: number };
interface ServiceDefinition { name: string; owner_id: string; destination_asset_ids: string[]; target_ids: string[]; transport: Transport; description: string; criticality: Criticality }
interface RegistryRecord extends JsonRecord { revision: number; state: RegistryState; content_hash: string; created_at: string; definition: AssetDefinition | ServiceDefinition }
interface Collection { loading: boolean; envelope?: ReadEnvelope<unknown>; error?: ApiError }
const uuidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const isAllowed = (envelope: ReadEnvelope<unknown> | undefined, kind: RegistryKind) => envelope?.actions?.some(action => action.action_id === `registry.${kind}.write` && action.allowed) ?? false;
const recordId = (record: JsonRecord, kind: RegistryKind) => displayValue(record[kind === 'assets' ? 'asset_id' : 'service_id']);
function locationRecord(kind: RegistryKind): string | null {
  const parts = location.pathname.split('/');
  try { return parts[1] === kind && parts[2] && parts[2] !== 'new' ? decodeURIComponent(parts[2]) : null; }
  catch { return null; }
}
function useCollection(path: string, revision: number): Collection {
  const [result, setResult] = useState<Collection>({ loading: true });
  useEffect(() => {
    const controller = new AbortController(); setResult({ loading: true });
    void api<unknown>(path, { signal: controller.signal }).then(envelope => {
      listData(envelope); setResult({ loading: false, envelope });
    }).catch((error: unknown) => { if (!controller.signal.aborted) setResult({ loading: false, error: error instanceof ApiError ? error : new ApiError(0, 'INVALID_RESPONSE', '') }); });
    return () => controller.abort();
  }, [path, revision]);
  return result;
}

/** Paged, server-backed registry choices; manual IDs cannot enter this control. */
export function RegistryPicker({ path, label, value, onChange, multiple = false, t, onAvailability }: {
  path: '/assets' | '/services' | '/targets'; label: string; value: string[];
  onChange: (ids: string[]) => void; multiple?: boolean; t: Translate; onAvailability?: (available: boolean) => void;
}) {
  const [items, setItems] = useState<JsonRecord[]>([]); const [cursor, setCursor] = useState<string | null>(null);
  const [next, setNext] = useState<string | null>(null); const [error, setError] = useState<ApiError>(); const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setLoading(true); setError(undefined);
    void api<unknown>(path + '?limit=25' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''), { signal: controller.signal }).then(envelope => {
      const page = listData(envelope).filter(item => item.state !== 'retired');
      setItems(previous => cursor ? [...previous, ...page.filter(item => !previous.some(existing => choiceId(existing, path) === choiceId(item, path)))] : page);
      setNext(envelope.next_cursor ?? null); setLoading(false);
    }).catch((err: unknown) => { if (!controller.signal.aborted) { setError(err instanceof ApiError ? err : new ApiError(0, 'INVALID_RESPONSE', '')); setLoading(false); } });
    return () => controller.abort();
  }, [path, cursor, attempt]);
  useEffect(() => { onAvailability?.(!loading && !error && items.length > 0); }, [loading, error, items, onAvailability]);
  return <div className="registry-picker"><label>{label}<select aria-label={label} required multiple={multiple} size={multiple ? 4 : undefined} value={multiple ? value : value[0] ?? ''} disabled={loading || !!error || items.length === 0} onChange={event => onChange(Array.from(event.target.selectedOptions).map(option => option.value).filter(Boolean))}>
    {!multiple && <option value="">{t('registry.select')}</option>}
    {items.map(item => <option key={choiceId(item, path)} value={choiceId(item, path)}>{choiceLabel(item, path)}</option>)}
  </select></label>{loading && <span role="status" className="field-hint">{t('common.loading')}</span>}{error && <ErrorNotice error={error} t={t} retry={() => setAttempt(value => value + 1)}/>}{!loading && !error && items.length === 0 && <p className="field-hint">{t('registry.noOptions')}</p>}{multiple && <p className="field-hint">{t('registry.multiHint')}</p>}{next && <button type="button" className="text-button" disabled={loading} onClick={() => setCursor(next)}>{t('registry.nextOptions')}</button>}</div>;
}
function choiceId(item: JsonRecord, path: string): string { return displayValue(recordValue(item, path === '/assets' ? 'asset_id' : path === '/services' ? 'service_id' : 'target_id', 'id')); }
function choiceLabel(item: JsonRecord, path: string): string {
  const definition = item.definition;
  const name = definition && typeof definition === 'object' && 'name' in definition ? definition.name : recordValue(item, 'display_name', 'name');
  return `${name ? displayValue(name) + ' · ' : ''}${choiceId(item, path)}${item.revision ? ' · r' + displayValue(item.revision) : ''}`;
}

function AssetEditor({ initial, principalId, t, submit, pending }: { initial?: RegistryRecord; principalId: string; t: Translate; submit: (body: unknown) => void; pending: boolean }) {
  const source = initial?.definition as AssetDefinition | undefined;
  const [definition, setDefinition] = useState<AssetDefinition>(source ?? { name: '', asset_kind: 'host', owner_id: principalId, addresses: [{ family: 'ipv4', cidr: '', interface: null }], criticality: 'normal', isolation: 'host', provenance: 'manual', source_evidence: null });
  const [state, setState] = useState<RegistryState>(initial?.state ?? 'active');
  const patch = <K extends keyof AssetDefinition>(key: K, value: AssetDefinition[K]) => setDefinition(current => ({ ...current, [key]: value }));
  const address = (index: number, update: Partial<AssetAddress>) => patch('addresses', definition.addresses.map((item, position) => index === position ? { ...item, ...update } : item));
  return <form onSubmit={(event: FormEvent) => { event.preventDefault(); submit({ definition, state }); }}><fieldset disabled={pending}><div className="form-grid">
    <label>{t('registry.name')}<input required maxLength={128} value={definition.name} onChange={event => patch('name', event.target.value)}/></label>
    <label>{t('registry.owner')}<input required pattern={uuidPattern} value={definition.owner_id} onChange={event => patch('owner_id', event.target.value)}/></label>
    <label>{t('registry.kind')}<select value={definition.asset_kind} onChange={event => patch('asset_kind', event.target.value as AssetKind)}>{['host','vm','namespace','subnet','gateway'].map(value => <option key={value}>{value}</option>)}</select></label>
    <label>{t('registry.isolation')}<select value={definition.isolation} onChange={event => patch('isolation', event.target.value as Isolation)}>{['host','vm','network_namespace','subnet'].map(value => <option key={value}>{value}</option>)}</select></label>
    <CriticalityField value={definition.criticality} onChange={value => patch('criticality', value)} t={t}/><StateField state={state} onChange={setState} t={t}/>
  </div><fieldset className="address-fieldset"><legend>{t('registry.addresses')}</legend><p className="field-hint">{t('registry.cidrHint')}</p>{definition.addresses.map((item, index) => <div className="address-row" key={index}>
    <label>{t('registry.family')}<select aria-label={`${t('registry.family')} ${index + 1}`} value={item.family} onChange={event => address(index, { family: event.target.value as AssetAddress['family'] })}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label>
    <label>{t('registry.cidr')}<input aria-label={`${t('registry.cidr')} ${index + 1}`} required maxLength={64} value={item.cidr} onChange={event => address(index, { cidr: event.target.value })}/></label>
    <label>{t('registry.interface')}<input aria-label={`${t('registry.interface')} ${index + 1}`} maxLength={128} value={item.interface ?? ''} onChange={event => address(index, { interface: event.target.value || null })}/></label>
    <button type="button" className="icon-button" aria-label={`${t('registry.remove')} ${index + 1}`} disabled={definition.addresses.length === 1} onClick={() => patch('addresses', definition.addresses.filter((_, position) => index !== position))}><Icon name="close"/></button>
  </div>)}<button type="button" className="button" disabled={definition.addresses.length >= 64} onClick={() => patch('addresses', [...definition.addresses, { family: 'ipv4', cidr: '', interface: null }])}><Icon name="plus" size={16}/>{t('registry.addAddress')}</button></fieldset>
  <div className="form-actions"><p>{t('registry.manualNotice')}</p><button type="submit" className="button primary">{pending ? t('common.loading') : t('registry.save')}</button></div></fieldset></form>;
}
function CriticalityField({ value, onChange, t }: { value: Criticality; onChange: (value: Criticality) => void; t: Translate }) { return <label>{t('registry.criticality')}<select value={value} onChange={event => onChange(event.target.value as Criticality)}>{['normal','critical','management'].map(item => <option key={item}>{item}</option>)}</select></label>; }
function StateField({ state, onChange, t }: { state: RegistryState; onChange: (state: RegistryState) => void; t: Translate }) { return <label>{t('list.state')}<select value={state} onChange={event => onChange(event.target.value as RegistryState)}><option value="active">{t('registry.stateActive')}</option><option value="retired">{t('registry.stateRetired')}</option></select><span className="field-hint">{t('registry.stateHint')}</span></label>; }
function ServiceEditor({ initial, principalId, t, submit, pending }: { initial?: RegistryRecord; principalId: string; t: Translate; submit: (body: unknown) => void; pending: boolean }) {
  const source = initial?.definition as ServiceDefinition | undefined;
  const [definition, setDefinition] = useState<ServiceDefinition>(source ?? { name: '', owner_id: principalId, destination_asset_ids: [], target_ids: [], transport: { protocol: 'tcp', destination_ports: [{ start: 443, end: 443 }] }, description: '', criticality: 'normal' });
  const [serviceId, setServiceId] = useState(initial ? recordId(initial, 'services') : ''); const [state, setState] = useState<RegistryState>(initial?.state ?? 'active');
  const [targetsReady, setTargetsReady] = useState(false); const [assetsReady, setAssetsReady] = useState(false); const [invalid, setInvalid] = useState(false);
  const patch = <K extends keyof ServiceDefinition>(key: K, value: ServiceDefinition[K]) => setDefinition(current => ({ ...current, [key]: value }));
  const ports = 'destination_ports' in definition.transport ? definition.transport.destination_ports : null;
  function onSubmit(event: FormEvent) {
    event.preventDefault(); if (!targetsReady || !assetsReady) return;
    const ranges = ports ? [...ports].sort((a,b) => a.start - b.start) : [];
    if (!definition.destination_asset_ids.length || definition.destination_asset_ids.length > 64 || !definition.target_ids.length || definition.target_ids.length > 16 || ranges.some((port,index) => !Number.isInteger(port.start) || !Number.isInteger(port.end) || port.start < 1 || port.end > 65535 || port.start > port.end || (index > 0 && ranges[index - 1].end >= port.start))) { setInvalid(true); return; }
    setInvalid(false); submit(initial ? { definition, state } : { service_id: serviceId, definition });
  }
  return <form onSubmit={onSubmit}><fieldset disabled={pending}><div className="form-grid">
    <label>{t('request.service')}<input required disabled={!!initial} pattern="[a-z0-9][a-z0-9._-]{0,127}" maxLength={128} value={serviceId} onChange={event => setServiceId(event.target.value)}/></label>
    <label>{t('registry.name')}<input required maxLength={128} value={definition.name} onChange={event => patch('name', event.target.value)}/></label>
    <label>{t('registry.owner')}<input required pattern={uuidPattern} value={definition.owner_id} onChange={event => patch('owner_id', event.target.value)}/></label>
    <CriticalityField value={definition.criticality} onChange={value => patch('criticality', value)} t={t}/>
    <RegistryPicker path="/assets" label={t('registry.destinations')} value={definition.destination_asset_ids} onChange={value => patch('destination_asset_ids', value)} multiple t={t} onAvailability={setAssetsReady}/>
    <RegistryPicker path="/targets" label={t('registry.targets')} value={definition.target_ids} onChange={value => patch('target_ids', value)} multiple t={t} onAvailability={setTargetsReady}/>
    <label>{t('registry.protocol')}<select value={definition.transport.protocol} onChange={event => { const protocol = event.target.value as Transport['protocol']; patch('transport', protocol === 'tcp' || protocol === 'udp' ? { protocol, destination_ports: [{ start: 443, end: 443 }] } : { protocol, type: 0, code: 0 }); }}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option></select></label>
    {initial && <StateField state={state} onChange={setState} t={t}/>}
    <label className="full">{t('registry.description')}<textarea required maxLength={2048} value={definition.description} onChange={event => patch('description', event.target.value)}/></label>
  </div>
  {ports ? <fieldset className="address-fieldset"><legend>{t('registry.protocol')}</legend>{ports.map((port,index) => <div className="port-row" key={index}><label>{t('registry.portStart')}<input aria-label={`${t('registry.portStart')} ${index + 1}`} type="number" required min={1} max={65535} step={1} value={port.start} onChange={event => patch('transport', { protocol: definition.transport.protocol as 'tcp' | 'udp', destination_ports: ports.map((item,position) => index === position ? { ...item, start: Number(event.target.value) } : item) })}/></label><label>{t('registry.portEnd')}<input aria-label={`${t('registry.portEnd')} ${index + 1}`} type="number" required min={1} max={65535} step={1} value={port.end} onChange={event => patch('transport', { protocol: definition.transport.protocol as 'tcp' | 'udp', destination_ports: ports.map((item,position) => index === position ? { ...item, end: Number(event.target.value) } : item) })}/></label><button type="button" className="icon-button" aria-label={`${t('registry.remove')} ${index + 1}`} disabled={ports.length === 1} onClick={() => patch('transport', { protocol: definition.transport.protocol as 'tcp' | 'udp', destination_ports: ports.filter((_,position) => index !== position) })}><Icon name="close"/></button></div>)}<button type="button" className="button" disabled={ports.length >= 64} onClick={() => patch('transport', { protocol: definition.transport.protocol as 'tcp' | 'udp', destination_ports: [...ports, { start: 1, end: 1 }] })}>{t('registry.addPort')}</button></fieldset> : <div className="form-grid transport-icmp">{(['type','code'] as const).map(field => <label key={field}>{t(field === 'type' ? 'registry.icmpType' : 'registry.icmpCode')}<input type="number" required min={0} max={255} step={1} value={'type' in definition.transport ? definition.transport[field] : 0} onChange={event => { if ('type' in definition.transport) patch('transport', { ...definition.transport, [field]: Number(event.target.value) }); }}/></label>)}</div>}
  {!targetsReady && <p className="notice warning">{t('registry.noTargets')}</p>}{invalid && <p className="error-text" role="alert">{t('registry.invalid')}</p>}<div className="form-actions"><p>{t('registry.stateHint')}</p><button type="submit" className="button primary" disabled={!targetsReady || !assetsReady}>{pending ? t('common.loading') : t('registry.save')}</button></div>
  </fieldset></form>;
}

function RegistryEditor({ kind, current, principalId, t, saved, close }: { kind: RegistryKind; current?: ReadEnvelope<RegistryRecord>; principalId: string; t: Translate; saved: (envelope: ReadEnvelope<RegistryRecord>) => void; close: () => void }) {
  const [pending, setPending] = useState(false); const [error, setError] = useState<ApiError>(); const [stale, setStale] = useState(false);
  const mutation = useRef<{ digest: string; key: string } | undefined>(undefined);
  async function submit(body: unknown) {
    if (pending || stale || (current && !current.httpEtag)) return;
    const digest = JSON.stringify(body);
    if (mutation.current?.digest !== digest) mutation.current = { digest, key: crypto.randomUUID() };
    setPending(true); setError(undefined);
    try { const envelope = await api<RegistryRecord>('/' + kind + (current ? '/' + encodeURIComponent(recordId(current.data, kind)) + '/revisions' : ''), { body, key: mutation.current.key, ifMatch: current?.httpEtag }); saved(envelope); }
    catch (err) { const problem = err as ApiError; setError(problem); if (problem.status === 412 || problem.status === 428) setStale(true); }
    finally { setPending(false); }
  }
  return <section className="panel request-form"><div className="section-heading"><h2>{t(current ? 'registry.newRevision' : kind === 'assets' ? 'registry.newAsset' : 'registry.newService')}</h2><button className="icon-button" aria-label={t('action.close')} onClick={close}><Icon name="close"/></button></div>{current && <div className="revision-binding"><span>r{current.data.revision}</span><code>{current.data.content_hash}</code></div>}{error && <ErrorNotice error={error} t={t}/>} {stale ? <div className="notice warning"><p>{t('registry.stale')}</p><button className="button" onClick={close}>{t('action.close')}</button></div> : current && !current.httpEtag ? <p className="notice warning">{t('registry.noEtag')}</p> : kind === 'assets' ? <AssetEditor initial={current?.data} principalId={principalId} t={t} submit={body => void submit(body)} pending={pending}/> : <ServiceEditor initial={current?.data} principalId={principalId} t={t} submit={body => void submit(body)} pending={pending}/>}</section>;
}

export function RegistryPage({ kind, t, locale, principalId, revision }: { kind: RegistryKind; t: Translate; locale: Locale; principalId: string; revision: number }) {
  const [cursor, setCursor] = useState<string | null>(null); const [selectedId, setSelectedId] = useState<string | null>(() => locationRecord(kind));
  const [current, setCurrent] = useState<ReadEnvelope<RegistryRecord>>(); const [detailError, setDetailError] = useState<ApiError>();
  const [editing, setEditing] = useState(location.pathname === '/' + kind + '/new'); const [refresh, setRefresh] = useState(0); const [saved, setSaved] = useState(false); const [raw, setRaw] = useState(false);
  const collection = useCollection('/' + kind + '?limit=25' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''), revision + refresh);
  useEffect(() => { const pop = () => { setSelectedId(locationRecord(kind)); setEditing(location.pathname === '/' + kind + '/new'); setCurrent(undefined); setDetailError(undefined); }; window.addEventListener('popstate', pop); return () => window.removeEventListener('popstate', pop); }, [kind]);
  useEffect(() => {
    if (!selectedId) return;
    const controller = new AbortController(); setCurrent(undefined); setDetailError(undefined);
    void api<RegistryRecord>('/' + kind + '/' + encodeURIComponent(selectedId), { signal: controller.signal }).then(setCurrent).catch((error: unknown) => { if (!controller.signal.aborted) setDetailError(error as ApiError); });
    return () => controller.abort();
  }, [kind, selectedId, revision, refresh]);
  const canWrite = isAllowed(selectedId ? current : collection.envelope, kind);
  const trusted = kind === 'assets' && current && (current.data.definition as AssetDefinition).provenance !== 'manual';
  function open(id: string) { setSelectedId(id); setEditing(false); setSaved(false); history.pushState(null, '', '/' + kind + '/' + encodeURIComponent(id)); }
  function close() { setSelectedId(null); setCurrent(undefined); setDetailError(undefined); setEditing(false); setSaved(false); history.pushState(null, '', '/' + kind); }
  return <>
    {kind === 'assets' && <div className="notice warning"><Icon name="info"/><p>{t('registry.manualNotice')}</p></div>}
    {saved && <div className="notice success" role="status">{t('registry.saved')}</div>}
    <div className="registry-toolbar">{selectedId ? <button className="button" onClick={close}>{t('registry.back')}</button> : <span/>}<button className="button primary" disabled={!canWrite || !!trusted || !!(selectedId && !current?.httpEtag)} title={trusted ? t('registry.trusted') : !canWrite ? t('error.forbidden') : undefined} onClick={() => { setEditing(true); setSaved(false); if (!selectedId) history.pushState(null, '', '/' + kind + '/new'); }}><Icon name="plus" size={16}/>{t(selectedId ? 'registry.newRevision' : kind === 'assets' ? 'registry.newAsset' : 'registry.newService')}</button></div>
    {editing && !canWrite && <ErrorNotice error={new ApiError(403, 'ACTION_UNAVAILABLE', '')} t={t}/>}
    {editing && canWrite && !trusted && <RegistryEditor key={`${kind}-${selectedId ?? 'new'}-${current?.data.revision ?? 0}`} kind={kind} current={selectedId ? current : undefined} principalId={principalId} t={t} close={() => { setEditing(false); if (!selectedId) history.replaceState(null, '', '/' + kind); else setRefresh(value => value + 1); }} saved={envelope => { const id = recordId(envelope.data, kind); setCurrent(envelope); setSelectedId(id); setEditing(false); setSaved(true); setRefresh(value => value + 1); history.replaceState(null, '', '/' + kind + '/' + encodeURIComponent(id)); }}/>}
    {selectedId ? detailError ? <ErrorNotice error={detailError} t={t} retry={() => setRefresh(value => value + 1)}/> : !current ? <Loader t={t}/> : <section className="panel registry-detail"><div className="section-heading"><div><span className="eyebrow">{recordId(current.data, kind)}</span><h2>{current.data.definition.name}</h2></div><span className="badge muted">r{current.data.revision}</span></div><Freshness envelope={current} t={t} locale={locale}/><dl><div><dt>{t('list.state')}</dt><dd>{t(current.data.state === 'active' ? 'registry.stateActive' : 'registry.stateRetired')}</dd></div><div><dt>{t('registry.owner')}</dt><dd><code>{current.data.definition.owner_id}</code></dd></div><div><dt>{t('list.created')}</dt><dd>{formatTime(current.data.created_at, locale)}</dd></div><div><dt>{t('registry.hash')}</dt><dd><code>{current.data.content_hash}</code></dd></div><div><dt>{t('registry.previousHash')}</dt><dd><code>{displayValue(current.data.previous_revision_hash)}</code></dd></div></dl><p className="field-hint">{t('registry.stateHint')}</p><button className="button" onClick={() => setRaw(true)}>{t('list.details')}</button></section> : <section className="panel list-panel"><div className="section-heading"><h2>{t(kind === 'assets' ? 'nav.assets' : 'nav.services')}</h2><span className="table-note">{t('list.scope')}</span></div><Freshness envelope={collection.envelope} t={t} locale={locale}/>{collection.loading ? <Loader t={t}/> : collection.error ? <ErrorNotice error={collection.error} t={t} retry={() => setRefresh(value => value + 1)}/> : !listData(collection.envelope!).length ? <Empty t={t}/> : <div className="table-scroll" role="region" aria-label={t(kind === 'assets' ? 'nav.assets' : 'nav.services')} tabIndex={0}><table><thead><tr><th scope="col">{t('registry.name')}</th><th scope="col">{t('list.id')}</th><th scope="col">{t('registry.revision')}</th><th scope="col">{t('list.state')}</th><th scope="col">{t(kind === 'assets' ? 'registry.provenance' : 'registry.protocol')}</th></tr></thead><tbody>{listData(collection.envelope!).map(item => { const definition = item.definition as JsonRecord; return <tr key={recordId(item, kind)}><td><button className="record-link" onClick={() => open(recordId(item, kind))}>{displayValue(definition.name)}</button></td><td><code>{recordId(item, kind)}</code></td><td>{displayValue(item.revision)}</td><td>{t(item.state === 'active' ? 'registry.stateActive' : 'registry.stateRetired')}</td><td>{displayValue(kind === 'assets' ? definition.provenance : (definition.transport as JsonRecord)?.protocol)}</td></tr>; })}</tbody></table></div>}{(cursor || collection.envelope?.next_cursor) && <div className="pagination"><button className="button" disabled={!cursor} onClick={() => setCursor(null)}>{t('action.back')}</button><button className="button" disabled={!collection.envelope?.next_cursor} onClick={() => setCursor(collection.envelope?.next_cursor ?? null)}>{t('action.next')}</button></div>}</section>}
    {raw && current && <Detail record={current.data} t={t} close={() => setRaw(false)}/>}
  </>;
}
