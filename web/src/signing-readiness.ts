import { ApiError } from './api';
import { record } from './authority-api';
import type { AuthorityPlan } from './authority-api';

export const signingReasons = ['PROTECTED_BOOTSTRAP_REQUIRED', 'BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED', 'PROTECTED_SIGNER_UNAVAILABLE', 'PLAN_STALE', 'REVIEW_EVIDENCE_MISSING', 'APPROVAL_SET_MISSING', 'TARGET_METADATA_MISSING', 'NATIVE_BASELINE_UNAVAILABLE', 'QUOTA_CONFIGURATION_MISSING', 'TARGET_GENERATION_UNINITIALIZED', 'CORE_REQUEST_BINDING_UNAVAILABLE', 'CORE_SIGNING_PROFILE_UNAVAILABLE'] as const;
const requiredReasons = signingReasons.slice(0, 4);
export const intentStates = ['prepared', 'claimed', 'ready', 'cancelled'] as const;
export const dispatchStates = ['queued', 'claimed', 'unknown', 'delivered'] as const;
export const reservationStates = ['reserved', 'issued', 'unknown', 'active', 'released'] as const;
export interface SigningIntentStatus {
  intent_id: string; request_id: string; plan_id: string; plan_hash: string; approval_set_hash: string;
  authority_epoch: string; target_generation: string; payload_hash: string; job_id: string; reservation_id: string;
  created_at: string; valid_until: string; state: typeof intentStates[number];
  dispatch_state: typeof dispatchStates[number] | null; reservation_state: typeof reservationStates[number];
  reservation_held: boolean; current_eligible: false; grant_hash: string | null; dispatch_allowed: false;
}
export interface SigningReadiness {
  schema_version: 'fw.signing-readiness/v1'; org_id: string; project_id: string; target_id: string;
  plan_id: string; plan_hash: string; checked_at: string; valid_until: string;
  signing_allowed: false; dispatch_allowed: false; reasons: typeof signingReasons[number][];
  approval_set_hash: string | null; quota_configured: boolean; target_generation: string | null;
  latest_intent: SigningIntentStatus | null;
}
function invalid(): never { throw new ApiError(0, 'SIGNING_READINESS_RESPONSE_INVALID', ''); }
function exact(value: unknown, keys: string[]) {
  const data = record(value);
  if (Object.keys(data).length !== keys.length || keys.some(key => !Object.hasOwn(data, key))) invalid();
  return data;
}
function hash(value: unknown): value is string { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
function uuid(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value); }
function generation(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
}
function utc(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value.replace('Z', '.000Z');
}

// The browser validates a bounded summary of the authority's read. It does not
// derive signing permission from plan gates, signatures or retained job states.
export function parseSigningReadiness(value: unknown, detail: AuthorityPlan): SigningReadiness {
  const data = exact(value, ['schema_version', 'org_id', 'project_id', 'target_id', 'plan_id', 'plan_hash', 'checked_at', 'valid_until', 'signing_allowed', 'dispatch_allowed', 'reasons', 'approval_set_hash', 'quota_configured', 'target_generation', 'latest_intent']);
  const planEnd = Date.parse(String(detail.plan.valid_until));
  if (data.schema_version !== 'fw.signing-readiness/v1' || data.org_id !== detail.plan.org_id || data.project_id !== detail.plan.project_id
    || data.target_id !== detail.plan.target_id || data.plan_id !== detail.plan.plan_id || data.plan_hash !== detail.plan_hash
    || !utc(data.checked_at) || !utc(data.valid_until) || !Number.isFinite(planEnd) || Date.parse(data.valid_until) > planEnd
    || Date.parse(data.valid_until) - Date.parse(data.checked_at) > 60000
    || data.signing_allowed !== false || data.dispatch_allowed !== false || typeof data.quota_configured !== 'boolean'
    || data.approval_set_hash !== null && !hash(data.approval_set_hash)
    || data.target_generation !== null && !generation(data.target_generation)
    || !Array.isArray(data.reasons) || data.reasons.length > signingReasons.length || new Set(data.reasons).size !== data.reasons.length
    || data.reasons.some(reason => !signingReasons.includes(reason as typeof signingReasons[number]))) invalid();
  const reasons = new Set(data.reasons);
  if (requiredReasons.some(reason => !reasons.has(reason))
    || reasons.has('APPROVAL_SET_MISSING') !== (data.approval_set_hash === null)
    || reasons.has('QUOTA_CONFIGURATION_MISSING') !== !data.quota_configured
    || reasons.has('TARGET_GENERATION_UNINITIALIZED') !== (data.target_generation === null)) invalid();
  let intent: SigningIntentStatus | null = null;
  if (data.latest_intent !== null) {
    const item = exact(data.latest_intent, ['intent_id', 'request_id', 'plan_id', 'plan_hash', 'approval_set_hash', 'authority_epoch', 'target_generation', 'payload_hash', 'job_id', 'reservation_id', 'created_at', 'valid_until', 'state', 'dispatch_state', 'reservation_state', 'reservation_held', 'current_eligible', 'grant_hash', 'dispatch_allowed']);
    if (![item.intent_id, item.request_id, item.job_id, item.reservation_id].every(uuid)
      || ![item.plan_hash, item.approval_set_hash, item.payload_hash].every(hash)
      || item.plan_id !== data.plan_id || item.plan_hash !== data.plan_hash
      || !generation(item.authority_epoch) || item.authority_epoch === '0' || item.authority_epoch !== detail.plan.authority_epoch
      || !generation(item.target_generation) || item.target_generation === '0' || item.target_generation !== detail.plan.target_generation
      || !utc(item.created_at) || !utc(item.valid_until) || Date.parse(item.created_at) >= Date.parse(item.valid_until)
      || Date.parse(item.valid_until) - Date.parse(item.created_at) > 300000
      || Date.parse(item.created_at) > Date.parse(data.checked_at) || Date.parse(item.valid_until) > planEnd
      || !intentStates.includes(item.state as typeof intentStates[number])
      || item.dispatch_state !== null && !dispatchStates.includes(item.dispatch_state as typeof dispatchStates[number])
      || !reservationStates.includes(item.reservation_state as typeof reservationStates[number]) || typeof item.reservation_held !== 'boolean'
      || item.current_eligible !== false || item.dispatch_allowed !== false || item.grant_hash !== null && !hash(item.grant_hash)
      || item.dispatch_state !== null && item.grant_hash === null) invalid();
    if (['reserved', 'issued', 'unknown'].includes(String(item.reservation_state)) && !item.reservation_held
      || item.reservation_state === 'released' && item.reservation_held
      || item.dispatch_state === 'unknown' && (item.reservation_state !== 'unknown' || !item.reservation_held)) invalid();
    // An expired/previously approved intent stays history. In particular, neither
    // expiry nor a different current approval hash releases UNKNOWN reservations.
    intent = item as unknown as SigningIntentStatus;
  }
  return { ...data, latest_intent: intent } as unknown as SigningReadiness;
}
