import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError } from './api';
import type { ActionPermission, ReadEnvelope, Session } from './api';
import { formatTime } from './i18n';
import type { Locale, Translate } from './i18n';
import { ErrorNotice, Icon, Loader } from './ui';
import { createPasskey, getPasskey, passkeyError, passkeysSupported } from './webauthn';

interface AuthStatus {
  passkey_available: boolean; passkey_unavailable_reason: string | null;
  owner_enrolled: boolean; bootstrap_available: boolean; rp_id: string | null; origin: string;
}
interface Ceremony { ceremony_id: string; public_key: unknown; expires_at: string }
interface PasskeyRecord { id: string; name: string; created_at: string; last_used_at: string | null; revoked_at: string | null; verified_at: string | null; current: boolean }
interface PasskeyList { credentials: PasskeyRecord[]; fresh_authentication_required: boolean }
type AcceptSession = (session: Session, actions?: ActionPermission[]) => void;

function validStatus(value: AuthStatus): AuthStatus {
  if (!value || typeof value.passkey_available !== 'boolean' || typeof value.owner_enrolled !== 'boolean' || typeof value.bootstrap_available !== 'boolean' || typeof value.origin !== 'string') throw new ApiError(0, 'INVALID_RESPONSE', '');
  return value;
}
function validList(value: PasskeyList): PasskeyList {
  if (!value || !Array.isArray(value.credentials) || typeof value.fresh_authentication_required !== 'boolean' || value.credentials.some(item => typeof item.id !== 'string' || typeof item.name !== 'string' || typeof item.current !== 'boolean' || (item.verified_at !== null && typeof item.verified_at !== 'string') || (item.revoked_at !== null && typeof item.revoked_at !== 'string'))) throw new ApiError(0, 'INVALID_RESPONSE', '');
  return value;
}
function reason(error: ApiError): string {
  // The public Problem contract uses a generic code and a bounded reason in
  // detail. Match only known reasons; never interpret arbitrary detail as code.
  return ['PASSKEY_REAUTHENTICATION_REQUIRED', 'LAST_PASSKEY_REQUIRED', 'CLI_LOGIN_EXPIRED'].includes(error.detail) ? error.detail : error.code;
}
function Failure({ error, t }: { error?: ApiError; t: Translate }) {
  if (!error) return null;
  const code = reason(error);
  const key = code === 'PASSKEY_CANCELLED' ? 'passkey.cancelled' : code === 'PASSKEY_ALREADY_REGISTERED' ? 'passkey.alreadyRegistered' : code === 'PASSKEY_REAUTHENTICATION_REQUIRED' ? 'passkey.reauthenticate' : code === 'LAST_PASSKEY_REQUIRED' ? 'passkey.keepAccess' : code === 'PASSKEY_BROWSER_UNAVAILABLE' ? 'passkey.browserUnavailable' : null;
  return key ? <p className="notice warning" role="alert">{t(key)}</p> : <ErrorNotice error={error} t={t}/>;
}
function Unavailable({ status, t }: { status: AuthStatus; t: Translate }) {
  return <p className="notice warning">{status.passkey_available ? t('passkey.browserUnavailable') : t('passkey.originUnavailable', { origin: status.origin })}</p>;
}

async function authenticate(signal: AbortSignal, credentialId?: string): Promise<ReadEnvelope<Session>> {
  const challenge = await api<Ceremony>('/auth/passkeys/login/options', { body: credentialId ? { credential_id: credentialId } : {}, signal });
  const proof = await getPasskey(challenge.data.public_key, signal);
  const result = await api<Session>('/auth/passkeys/login/complete', { body: { ceremony_id: challenge.data.ceremony_id, credential: proof }, signal });
  if (result.data.authenticated !== true || result.data.authentication_method !== 'passkey' || typeof result.data.credential_id !== 'string') throw new ApiError(0, 'INVALID_RESPONSE', '');
  return result;
}

export function SessionGate({ t, onSession, registeredId }: { t: Translate; onSession: AcceptSession; registeredId?: string }) {
  const [status, setStatus] = useState<AuthStatus>(); const [statusError, setStatusError] = useState<ApiError>();
  const [token, setToken] = useState(''); const [pending, setPending] = useState(false); const [error, setError] = useState<ApiError>();
  const key = useRef(crypto.randomUUID()); const ceremony = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    void api<AuthStatus>('/auth/status', { signal: controller.signal }).then(result => setStatus(validStatus(result.data))).catch((err: unknown) => { if (!controller.signal.aborted) setStatusError(passkeyError(err)); });
    return () => { controller.abort(); ceremony.current?.abort(); };
  }, []);
  async function submit(event: FormEvent) {
    event.preventDefault(); if (pending || !token || !status?.bootstrap_available) return; setPending(true); setError(undefined);
    try { const result = await api<Session>('/session/bootstrap', { body: { token }, key: key.current }); setToken(''); onSession(result.data, result.actions); }
    catch (err) { setError(passkeyError(err)); } finally { setPending(false); }
  }
  async function signIn() {
    if (pending) return;
    setPending(true); setError(undefined); const controller = new AbortController(); ceremony.current = controller;
    try { const result = await authenticate(controller.signal, registeredId); onSession(result.data, result.actions); }
    catch (err) { if (!controller.signal.aborted) setError(passkeyError(err)); }
    finally { if (!controller.signal.aborted) setPending(false); }
  }
  const available = status?.passkey_available && passkeysSupported();
  return <div className="auth-container"><div className="auth-illustration"><Icon name="security" size={56}/><span className="eyebrow">LOCAL / PRIVATE / AUDITABLE</span></div><section className="panel auth-panel"><span className="eyebrow">01 / SESSION</span><h1>{t('auth.title')}</h1>
    {statusError ? <ErrorNotice error={statusError} t={t}/> : !status ? <Loader t={t}/> : <><p className="muted-text">{t(status.owner_enrolled ? 'passkey.signInDescription' : 'auth.description')}</p>{registeredId && <p className="notice success" role="status">{t('passkey.registered')}</p>}<Failure error={error} t={t}/>
      {status.owner_enrolled ? <><button className="button primary passkey-login" onClick={() => void signIn()} disabled={pending || !available}>{pending ? t('common.loading') : t('passkey.signIn')}<Icon name="security"/></button>{!available && <Unavailable status={status} t={t}/>}</> : status.bootstrap_available ? <form onSubmit={event => void submit(event)}><label>{t('auth.token')}<input type="password" autoComplete="off" required value={token} onChange={event => { setToken(event.target.value); key.current = crypto.randomUUID(); }}/></label><p className="field-hint">{t('auth.unstored')}</p><button className="button primary" disabled={pending || !token}>{pending ? t('common.loading') : t('action.connect')}<Icon name="arrow"/></button></form> : <p className="notice warning">{t('passkey.bootstrapUnavailable')}</p>}
    </>}
  </section></div>;
}

export function PasskeysPage({ t, locale, session, onSession, onSignedOut, onRegistered, revision }: { t: Translate; locale: Locale; session: Session; onSession: AcceptSession; onSignedOut: () => void; onRegistered: (credentialId: string) => void; revision: number }) {
  const [status, setStatus] = useState<AuthStatus>(); const [list, setList] = useState<PasskeyList>();
  const [error, setError] = useState<ApiError>(); const [pending, setPending] = useState(false); const [name, setName] = useState('');
  const [success, setSuccess] = useState<'verified' | 'revoked'>(); const [refresh, setRefresh] = useState(0);
  const [revoke, setRevoke] = useState<PasskeyRecord>(); const operation = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController(); setError(undefined); setList(undefined);
    void Promise.all([api<AuthStatus>('/auth/status', { signal: controller.signal }), api<PasskeyList>('/auth/passkeys', { signal: controller.signal })]).then(([auth, records]) => { setStatus(validStatus(auth.data)); setList(validList(records.data)); }).catch((err: unknown) => { if (!controller.signal.aborted) { if (err instanceof ApiError && err.status === 401) onSignedOut(); else setError(passkeyError(err)); } });
    return () => controller.abort();
  }, [revision, refresh, session.credential_id, session.authenticated_at, onSignedOut]);
  useEffect(() => () => operation.current?.abort(), []);
  const available = status?.passkey_available && passkeysSupported();
  const fresh = !status?.owner_enrolled || list?.fresh_authentication_required === false;
  const activeCount = list?.credentials.filter(item => item.revoked_at === null).length ?? 0;
  const verifiedCount = list?.credentials.filter(item => item.revoked_at === null && item.verified_at !== null).length ?? 0;
  async function run(work: (signal: AbortSignal) => Promise<void>) {
    if (pending) return;
    const controller = new AbortController(); operation.current = controller; setPending(true); setError(undefined); setSuccess(undefined);
    try { await work(controller.signal); }
    catch (err) {
      if (!controller.signal.aborted) {
        const failure = passkeyError(err); setError(failure);
        if (failure.status === 401) onSignedOut();
        if (reason(failure) === 'PASSKEY_REAUTHENTICATION_REQUIRED') setList(value => value ? { ...value, fresh_authentication_required: true } : value);
      }
    } finally { if (!controller.signal.aborted) setPending(false); }
  }
  async function register(event: FormEvent) {
    event.preventDefault(); if (!name.trim() || !fresh || !available) return;
    await run(async signal => {
      const challenge = await api<Ceremony>('/auth/passkeys/registration/options', { body: { name: name.trim() }, signal });
      const proof = await createPasskey(challenge.data.public_key, signal);
      const result = await api<{ registered: boolean; credential_id: string; authentication_required: boolean }>('/auth/passkeys/registration/complete', { body: { ceremony_id: challenge.data.ceremony_id, credential: proof }, signal });
      if (result.data.registered !== true || result.data.authentication_required !== true || typeof result.data.credential_id !== 'string') throw new ApiError(0, 'INVALID_RESPONSE', '');
      setName(''); onRegistered(result.data.credential_id);
    });
  }
  async function verify() {
    await run(async signal => { const result = await authenticate(signal); onSession(result.data, result.actions); setSuccess('verified'); setRefresh(value => value + 1); });
  }
  async function revokePasskey() {
    if (!revoke || !fresh) return;
    await run(async signal => {
      await api('/auth/passkeys/' + encodeURIComponent(revoke.id) + '/revocations', { body: {}, signal });
      if (revoke.current) onSignedOut(); else { setRevoke(undefined); setSuccess('revoked'); setRefresh(value => value + 1); }
    });
  }
  return <section className="panel security-panel"><div className="section-heading"><h2>{t('passkey.title')}</h2><Icon name="security"/></div><div className="security-content">
    <p className="muted-text">{t('passkey.description')}</p><Failure error={error} t={t}/>
    {success && <p className="notice success" role="status">{t(`passkey.${success}`)}</p>}
    {!status || !list ? !error && <Loader t={t}/> : <>
      {!available && <Unavailable status={status} t={t}/>}
      {!status.owner_enrolled && <p className="notice warning">{t('passkey.firstNotice')}</p>}
      {status.owner_enrolled && <div className="passkey-verify"><p className="muted-text">{t(fresh ? 'passkey.fresh' : 'passkey.reauthenticate')}</p><button className="button" disabled={pending || !available} onClick={() => void verify()}>{t('passkey.verify')}</button></div>}
      <form onSubmit={event => void register(event)}><fieldset disabled={pending || !available || !fresh}><label>{t('passkey.name')}<input required maxLength={80} autoComplete="off" value={name} onChange={event => setName(event.target.value)}/></label><button className="button primary" disabled={!name.trim() || activeCount >= 8}>{t(status.owner_enrolled ? 'passkey.add' : 'passkey.first')}<Icon name="plus" size={16}/></button></fieldset></form>
      {activeCount >= 8 && <p className="field-hint">{t('passkey.limit')}</p>}
      <p className="field-hint passkey-retention">{t('passkey.keepAccess')}</p>
      {list.credentials.length > 0 && <div className="table-scroll" role="region" aria-label={t('passkey.title')} tabIndex={0}><table><thead><tr><th scope="col">{t('passkey.name')}</th><th scope="col">{t('list.created')}</th><th scope="col">{t('passkey.lastUsed')}</th><th scope="col">{t('list.state')}</th><th scope="col"><span className="sr-only">{t('passkey.revoke')}</span></th></tr></thead><tbody>{list.credentials.map(item => <tr key={item.id}><td>{item.name}{item.current && <span className="badge">{t('passkey.current')}</span>}</td><td>{formatTime(item.created_at, locale)}</td><td>{formatTime(item.last_used_at, locale)}</td><td>{t(item.revoked_at ? 'passkey.revokedState' : item.verified_at === null ? 'passkey.pending' : 'passkey.active')}</td><td>{!item.revoked_at && <button className="text-button" disabled={pending || !fresh || (item.verified_at !== null && verifiedCount <= 1)} onClick={() => setRevoke(item)} aria-label={t('passkey.revokeNamed', { name: item.name })}>{t('passkey.revoke')}</button>}</td></tr>)}</tbody></table></div>}
      {revoke && <div className="notice warning passkey-revoke" role="group" aria-label={t('passkey.revokeConfirmTitle')}><p>{t('passkey.revokeConfirm', { name: revoke.name })}{revoke.current && <> {t('passkey.currentRevoke')}</>}</p><div><button className="button" disabled={pending} onClick={() => setRevoke(undefined)}>{t('passkey.cancel')}</button><button className="button" disabled={pending || !fresh || (revoke.verified_at !== null && verifiedCount <= 1)} onClick={() => void revokePasskey()}>{t('passkey.confirmRevoke')}</button></div></div>}
    </>}
  </div></section>;
}

interface CliRequest { request_id: string; user_code: string; expires_at: string; state: 'pending' | 'approved' | 'consumed'; api_origin: string }
export function CliLoginPage({ requestId, t, locale, session, onSession, onSignedOut }: { requestId: string; t: Translate; locale: Locale; session: Session; onSession: AcceptSession; onSignedOut: () => void }) {
  const [request, setRequest] = useState<CliRequest>(); const [error, setError] = useState<ApiError>();
  const [code, setCode] = useState(''); const [pending, setPending] = useState(false); const [mismatch, setMismatch] = useState(false);
  const [forceVerification, setForceVerification] = useState(false); const operation = useRef<AbortController | null>(null);
  const fresh = !forceVerification && session.authentication_method === 'passkey' && typeof session.authenticated_at === 'number' && Date.now() / 1000 - session.authenticated_at < 300;
  useEffect(() => {
    const controller = new AbortController();
    void api<CliRequest>('/auth/cli/requests/' + encodeURIComponent(requestId), { signal: controller.signal }).then(result => {
      const data = result.data;
      if (!data || data.request_id !== requestId || !/^[0-9A-F]{8}$/.test(data.user_code) || !['pending', 'approved', 'consumed'].includes(data.state) || typeof data.api_origin !== 'string') throw new ApiError(0, 'INVALID_RESPONSE', '');
      setRequest(data);
    }).catch((err: unknown) => { if (!controller.signal.aborted) setError(passkeyError(err)); });
    return () => { controller.abort(); operation.current?.abort(); };
  }, [requestId]);
  async function verify() {
    if (pending) return; setPending(true); setError(undefined);
    const controller = new AbortController(); operation.current = controller;
    try { const result = await authenticate(controller.signal); onSession(result.data, result.actions); setForceVerification(false); }
    catch (err) { if (!controller.signal.aborted) setError(passkeyError(err)); }
    finally { if (!controller.signal.aborted) setPending(false); }
  }
  async function authorize(event: FormEvent) {
    event.preventDefault(); if (pending || !fresh || request?.state !== 'pending') return;
    if (code !== request.user_code) { setMismatch(true); return; }
    setPending(true); setError(undefined);
    try {
      const result = await api<{ request_id: string; state: string }>('/auth/cli/requests/' + encodeURIComponent(requestId) + '/authorize', { body: { user_code: code } });
      if (result.data.request_id !== requestId || result.data.state !== 'approved') throw new ApiError(0, 'INVALID_RESPONSE', '');
      setCode(''); setRequest({ ...request, state: 'approved' });
    } catch (err) {
      const failure = passkeyError(err); setError(failure);
      if (failure.status === 401) onSignedOut();
      if (reason(failure) === 'PASSKEY_REAUTHENTICATION_REQUIRED') setForceVerification(true);
      if (reason(failure) === 'CLI_LOGIN_EXPIRED') setRequest(undefined);
    } finally { setPending(false); }
  }
  return <section className="panel security-panel"><div className="section-heading"><h2>{t('cli.title')}</h2><Icon name="security"/></div><div className="security-content">
    <p className="muted-text">{t('cli.description')}</p><Failure error={error} t={t}/>
    {!request ? !error && <Loader t={t}/> : request.state !== 'pending' ? <p className="notice success" role="status">{t('cli.approved')}</p> : <>
      <dl className="cli-request-details"><div><dt>{t('cli.controller')}</dt><dd><code>{request.api_origin}</code></dd></div><div><dt>{t('cli.requestCode')}</dt><dd><code>{request.user_code}</code></dd></div><div><dt>{t('list.time')}</dt><dd>{formatTime(request.expires_at, locale)}</dd></div></dl>
      {!fresh && <div className="passkey-verify"><p>{t('passkey.reauthenticate')}</p><button className="button" disabled={pending || !passkeysSupported()} onClick={() => void verify()}>{t('passkey.verify')}</button></div>}
      <form onSubmit={event => void authorize(event)}><fieldset disabled={pending || !fresh}><label>{t('cli.codeLabel')}<input required autoComplete="off" spellCheck={false} maxLength={8} pattern="[0-9A-F]{8}" value={code} onChange={event => { setCode(event.target.value.toUpperCase()); setMismatch(false); }}/></label>{mismatch && <p className="error-text" role="alert">{t('cli.codeMismatch')}</p>}<button className="button primary" disabled={code.length !== 8}>{t('cli.approve')}</button></fieldset></form>
    </>}
  </div></section>;
}
