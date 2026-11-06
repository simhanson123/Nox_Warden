import { ApiError } from './api';
import { record } from './authority-api';
import type { AuthorityPlan } from './authority-api';

export const signingReasons = ['PROTECTED_BOOTSTRAP_REQUIRED', 'BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED', 'PROTECTED_SIGNER_UNAVAILABLE', 'PLAN_STALE', 'REVIEW_EVIDENCE_MISSING', 'APPROVAL_SET_MISSING', 'TARGET_METADATA_MISSING', 'NATIVE_BASELINE_UNAVAILABLE', 'QUOTA_CONFIGURATION_MISSING', 'TARGET_GENERATION_UNINITIALIZED', 'CORE_REQUEST_BINDING_UNAVAILABLE', 'CORE_SIGNING_PROFILE_UNAVAILABLE'] as const;
const requiredReasons = signingReasons.slice(0, 4);
// v1/v2 keep their published closed vocabulary. The v3 endpoint uses the
// authority's canonical diagnostic codes without reinterpreting old responses.
export const authoritySigningReasons = ['BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED', 'BOOTSTRAP_AUTHORIZATION_REQUIRED', 'BOOTSTRAP_AUTHORIZATION_NOT_CURRENT', 'BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED', 'TARGET_EPOCH_CONFIRMATION_REQUIRED', 'POLICY_SIGNER_KEY_REQUIRED', 'WORKLOAD_SOURCE_ATTESTATION_REQUIRED', 'WORKLOAD_BINDING_NOT_CURRENT', 'OWNER_PROOF_REQUIRED', 'PROTECTED_SIGNER_UNAVAILABLE', 'PLAN_STALE', 'REVIEW_EVIDENCE_MISSING', 'APPROVAL_SET_MISSING', 'TARGET_METADATA_MISSING', 'NATIVE_BASELINE_UNAVAILABLE', 'QUOTA_CONFIGURATION_MISSING', 'TARGET_GENERATION_UNINITIALIZED', 'CORE_REQUEST_BINDING_UNAVAILABLE', 'CORE_SIGNING_PROFILE_UNAVAILABLE'] as const;
const requiredV3Reasons = ['BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED', 'POLICY_SIGNER_KEY_REQUIRED', 'PROTECTED_SIGNER_UNAVAILABLE'] as const;
export const intentStates = ['prepared', 'claimed', 'ready', 'cancelled'] as const;
export const dispatchStates = ['queued', 'claimed', 'unknown', 'delivered'] as const;
export const reservationStates = ['reserved', 'issued', 'unknown', 'active', 'released'] as const;
const deliveryReservations: Record<typeof dispatchStates[number], readonly string[]> = {
  queued: ['issued'], claimed: ['issued', 'unknown'], unknown: ['unknown'], delivered: ['active'],
};
export interface SigningIntentStatus {
  intent_id: string; request_id: string; plan_id: string; plan_hash: string; approval_set_hash: string;
  authority_epoch: string; target_generation: string; payload_hash: string; job_id: string; reservation_id: string;
  created_at: string; valid_until: string; state: typeof intentStates[number];
  dispatch_state: typeof dispatchStates[number] | null; reservation_state: typeof reservationStates[number];
  reservation_held: boolean; current_eligible: false; grant_hash: string | null; dispatch_allowed: false;
}
export interface SigningReadiness {
  schema_version: 'fw.signing-readiness/v2'; org_id: string; project_id: string; target_id: string;
  plan_id: string; plan_hash: string; checked_at: string; valid_until: string;
  signing_allowed: false; dispatch_allowed: false; reasons: typeof signingReasons[number][];
  approval_set_hash: string | null; quota_configured: boolean; target_generation: string | null;
  latest_intent: SigningIntentStatus | null;
  quota_scope: 'root' | 'project' | null; quota_root_id: string | null;
  latest_dispatch_unknown_seen: boolean | null;
}
export interface TargetBootstrapReadiness {
  state: 'target_confirmed_pending_qualification'; target_id: string;
  confirmation_revision: string; accepted_epoch: string; highest_generation: string;
  confirmation_hash: string; observed_at: string; admitted_at: string; valid_until: string;
  current_confirmation_eligibility: boolean; current_for_plan: boolean;
  signing_allowed: false; dispatch_allowed: false;
}
export interface SigningReadinessV3 extends Omit<SigningReadiness, 'schema_version' | 'reasons'> {
  schema_version: 'fw.signing-readiness/v3'; reasons: typeof authoritySigningReasons[number][];
  bootstrap_authorization_hash: string | null; target_bootstrap: TargetBootstrapReadiness | null;
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
function parseReadiness(value: unknown, detail: AuthorityPlan, version: 'v2' | 'v3'): SigningReadiness | SigningReadinessV3 {
  const keys = ['schema_version', 'org_id', 'project_id', 'target_id', 'plan_id', 'plan_hash', 'checked_at', 'valid_until', 'signing_allowed', 'dispatch_allowed', 'reasons', 'approval_set_hash', 'quota_configured', 'target_generation', 'latest_intent', 'quota_scope', 'quota_root_id', 'latest_dispatch_unknown_seen'];
  if (version === 'v3') keys.push('bootstrap_authorization_hash', 'target_bootstrap');
  const data = exact(value, keys);
  const allowed: readonly string[] = version === 'v2' ? signingReasons : authoritySigningReasons;
  const planEnd = Date.parse(String(detail.plan.valid_until));
  if (data.schema_version !== 'fw.signing-readiness/' + version || data.org_id !== detail.plan.org_id || data.project_id !== detail.plan.project_id
    || data.target_id !== detail.plan.target_id || data.plan_id !== detail.plan.plan_id || data.plan_hash !== detail.plan_hash
    || !utc(data.checked_at) || !utc(data.valid_until) || !Number.isFinite(planEnd) || Date.parse(data.valid_until) > planEnd
    || Date.parse(data.valid_until) - Date.parse(data.checked_at) > 60000
    || data.signing_allowed !== false || data.dispatch_allowed !== false || typeof data.quota_configured !== 'boolean'
    || data.approval_set_hash !== null && !hash(data.approval_set_hash)
    || data.target_generation !== null && !generation(data.target_generation)
    || !Array.isArray(data.reasons) || data.reasons.length > allowed.length || new Set(data.reasons).size !== data.reasons.length
    || data.reasons.some(reason => !allowed.includes(reason as string))) invalid();
  const reasons = new Set(data.reasons);
  if ((version === 'v2' ? requiredReasons : requiredV3Reasons).some(reason => !reasons.has(reason))
    || reasons.has('APPROVAL_SET_MISSING') !== (data.approval_set_hash === null)
    || reasons.has('QUOTA_CONFIGURATION_MISSING') !== !data.quota_configured
    || reasons.has('TARGET_GENERATION_UNINITIALIZED') !== (data.target_generation === null)
    || ![null, 'root', 'project'].includes(data.quota_scope as string | null)
    || (data.quota_scope === 'root' ? !uuid(data.quota_root_id) : data.quota_root_id !== null)
    || data.quota_configured && data.quota_scope === null
    || detail.plan.change_kind === 'policy_change' && data.quota_configured !== (data.quota_scope !== null)
    || detail.plan.change_kind === 'add_access_lease' && data.quota_scope === 'project' && data.quota_configured
    || (data.latest_intent === null ? data.latest_dispatch_unknown_seen !== null : typeof data.latest_dispatch_unknown_seen !== 'boolean')) invalid();
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
      || item.current_eligible !== false || item.dispatch_allowed !== false || item.grant_hash !== null && !hash(item.grant_hash)) invalid();
    // The signing job, delivery and quota summary describe one retained workflow.
    // A delivery retry can retain UNKNOWN quota; a recorded delivery cannot release it.
    if (item.state === 'ready') {
      if (item.grant_hash === null || item.dispatch_state === null
        || !deliveryReservations[item.dispatch_state as typeof dispatchStates[number]].includes(String(item.reservation_state))) invalid();
    } else if (item.dispatch_state !== null || item.grant_hash !== null
      || item.reservation_state !== (item.state === 'cancelled' ? 'released' : 'reserved')) invalid();
    if (item.reservation_held !== (item.reservation_state !== 'released')) invalid();
    if (item.dispatch_state === 'unknown' && data.latest_dispatch_unknown_seen !== true
      || item.reservation_state === 'unknown' && data.latest_dispatch_unknown_seen !== true
      || data.latest_dispatch_unknown_seen && (item.state !== 'ready' || item.dispatch_state === null || item.dispatch_state === 'queued'
        || item.reservation_state !== (item.dispatch_state === 'delivered' ? 'active' : 'unknown'))) invalid();
    // An expired/previously approved intent stays history. In particular, neither
    // expiry nor a recorded delivery releases quota after grant issuance.
    intent = item as unknown as SigningIntentStatus;
  }
  return { ...data, latest_intent: intent } as unknown as SigningReadiness;
}

export function parseSigningReadiness(value: unknown, detail: AuthorityPlan): SigningReadiness {
  return parseReadiness(value, detail, 'v2') as SigningReadiness;
}

export function parseSigningReadinessV3(value: unknown, detail: AuthorityPlan): SigningReadinessV3 {
  const parsed = parseReadiness(value, detail, 'v3') as SigningReadinessV3;
  if (parsed.bootstrap_authorization_hash !== null && !hash(parsed.bootstrap_authorization_hash)
    || parsed.reasons.includes('BOOTSTRAP_AUTHORIZATION_REQUIRED') !== (parsed.bootstrap_authorization_hash === null)
    || parsed.bootstrap_authorization_hash !== null && parsed.reasons.includes('BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED')) invalid();
  let target: TargetBootstrapReadiness | null = null;
  if (parsed.target_bootstrap !== null) {
    const item = exact(parsed.target_bootstrap, ['state', 'target_id', 'confirmation_revision', 'accepted_epoch', 'highest_generation', 'confirmation_hash', 'observed_at', 'admitted_at', 'valid_until', 'current_confirmation_eligibility', 'current_for_plan', 'signing_allowed', 'dispatch_allowed']);
    if (item.state !== 'target_confirmed_pending_qualification' || item.target_id !== parsed.target_id
      || !generation(item.confirmation_revision) || item.confirmation_revision === '0'
      || !generation(item.accepted_epoch) || item.accepted_epoch === '0' || item.highest_generation !== '0'
      || !hash(item.confirmation_hash) || !utc(item.observed_at) || !utc(item.admitted_at) || !utc(item.valid_until)
      || Date.parse(item.observed_at) > Date.parse(item.admitted_at) || Date.parse(item.admitted_at) > Date.parse(parsed.checked_at)
      || Date.parse(item.valid_until) <= Date.parse(item.admitted_at)
      || typeof item.current_confirmation_eligibility !== 'boolean' || typeof item.current_for_plan !== 'boolean'
      || item.signing_allowed !== false || item.dispatch_allowed !== false
      || item.current_confirmation_eligibility && Date.parse(item.valid_until) <= Date.parse(parsed.checked_at)
      || item.current_for_plan && (!item.current_confirmation_eligibility || item.accepted_epoch !== detail.plan.authority_epoch
        || parsed.bootstrap_authorization_hash === null || Date.parse(parsed.valid_until) > Date.parse(item.valid_until))) invalid();
    target = item as unknown as TargetBootstrapReadiness;
  }
  if (parsed.reasons.includes('TARGET_EPOCH_CONFIRMATION_REQUIRED') !== !target?.current_for_plan) invalid();
  return { ...parsed, target_bootstrap: target };
}
