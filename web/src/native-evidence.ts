import { ApiError } from './api';
import { record } from './authority-api';
import type { AuthorityPlan } from './authority-api';

export const nativeReasons = ['COMPILATION_MISSING', 'COMPILATION_STALE', 'OBSERVATION_MISSING', 'OBSERVATION_STALE', 'OBSERVATION_MISMATCH', 'OBSERVATION_UNKNOWN', 'NATIVE_QUALIFICATION_REQUIRED', 'SIGNER_DISPATCH_UNAVAILABLE'] as const;
export type NativeReason = typeof nativeReasons[number];
export interface NativeCompilation {
  evidence_hash: string; reference_revision: string; metadata_receipt_hash: string;
  baseline_artifact_hash: string; candidate_artifact_hash: string;
  admitted_at: string; valid_until: string; current: boolean;
}
export interface NativeObservation {
  receipt_hash: string; compilation_hash: string; observer_revision: string;
  artifact_role: 'baseline' | 'candidate'; comparison: 'match' | 'mismatch' | 'unknown';
  observed_state_hash: string | null; signature_valid: true; provenance: 'signed_lab_observer_claim';
  checked_at: string; admitted_at: string; valid_until: string; current: boolean;
}
export interface NativeEvidenceStatus {
  schema_version: 'fw.native-evidence-status/v1'; org_id: string; project_id: string;
  target_id: string; plan_id: string; plan_hash: string; checked_at: string;
  production_qualified: false; dispatch_allowed: false; reasons: NativeReason[];
  observation_head_hash: string | null; compilation: NativeCompilation | null; observation: NativeObservation | null;
}
function invalid(): never { throw new ApiError(0, 'NATIVE_EVIDENCE_RESPONSE_INVALID', ''); }
function exact(value: unknown, keys: string[]) {
  const data = record(value);
  if (Object.keys(data).length !== keys.length || keys.some(key => !Object.hasOwn(data, key))) invalid();
  return data;
}
function hash(value: unknown): value is string { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
function revision(value: unknown): value is string { return typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n; }
function utc(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value) || !Number.isFinite(Date.parse(value))) return false;
  return new Date(value).toISOString() === value.replace('Z', '.000Z');
}
function interval(start: unknown, end: unknown, checked: string, current: unknown) {
  if (!utc(start) || !utc(end) || typeof current !== 'boolean' || Date.parse(start) >= Date.parse(end)
    || Date.parse(start) > Date.parse(checked) || current && Date.parse(end) <= Date.parse(checked)) invalid();
}

// The authority verifies signatures and storage. The browser validates this
// closed summary and its binding to the immutable plan, never a raw proof.
export function parseNativeEvidence(value: unknown, detail: AuthorityPlan): NativeEvidenceStatus {
  const data = exact(value, ['schema_version', 'org_id', 'project_id', 'target_id', 'plan_id', 'plan_hash', 'checked_at', 'production_qualified', 'dispatch_allowed', 'reasons', 'observation_head_hash', 'compilation', 'observation']);
  if (data.schema_version !== 'fw.native-evidence-status/v1' || data.org_id !== detail.plan.org_id || data.project_id !== detail.plan.project_id
    || data.target_id !== detail.plan.target_id || data.plan_id !== detail.plan.plan_id || data.plan_hash !== detail.plan_hash
    || !utc(data.checked_at) || data.production_qualified !== false || data.dispatch_allowed !== false
    || !Array.isArray(data.reasons) || data.reasons.length > nativeReasons.length
    || new Set(data.reasons).size !== data.reasons.length || data.reasons.some(reason => !nativeReasons.includes(reason as NativeReason))
    || !data.reasons.includes('NATIVE_QUALIFICATION_REQUIRED') || !data.reasons.includes('SIGNER_DISPATCH_UNAVAILABLE')) invalid();
  const checked = data.checked_at;
  let compilation: NativeCompilation | null = null;
  if (data.compilation !== null) {
    const item = exact(data.compilation, ['evidence_hash', 'reference_revision', 'metadata_receipt_hash', 'baseline_artifact_hash', 'candidate_artifact_hash', 'admitted_at', 'valid_until', 'current']);
    if (![item.evidence_hash, item.metadata_receipt_hash, item.baseline_artifact_hash, item.candidate_artifact_hash].every(hash) || !revision(item.reference_revision)) invalid();
    interval(item.admitted_at, item.valid_until, checked, item.current);
    if (Date.parse(String(item.valid_until)) > Date.parse(String(detail.plan.valid_until))) invalid();
    if (detail.plan.artifact_hash !== undefined && item.candidate_artifact_hash !== detail.plan.artifact_hash) invalid();
    compilation = item as unknown as NativeCompilation;
  }
  let observation: NativeObservation | null = null;
  if (data.observation !== null) {
    const item = exact(data.observation, ['receipt_hash', 'compilation_hash', 'observer_revision', 'artifact_role', 'comparison', 'observed_state_hash', 'signature_valid', 'provenance', 'checked_at', 'admitted_at', 'valid_until', 'current']);
    if (![item.receipt_hash, item.compilation_hash].every(hash) || !revision(item.observer_revision)
      || !['baseline', 'candidate'].includes(String(item.artifact_role)) || !['match', 'mismatch', 'unknown'].includes(String(item.comparison))
      || item.signature_valid !== true || item.provenance !== 'signed_lab_observer_claim' || !utc(item.checked_at)) invalid();
    interval(item.admitted_at, item.valid_until, checked, item.current);
    if (Date.parse(item.checked_at) > Date.parse(String(item.admitted_at)) || Date.parse(String(item.valid_until)) > Date.parse(String(detail.plan.valid_until))
      || item.current && (!compilation?.current || item.compilation_hash !== compilation.evidence_hash)) invalid();
    if (item.comparison === 'match') {
      const expected = item.artifact_role === 'baseline' ? detail.plan.baseline_hash : detail.plan.desired_state_hash;
      if (!hash(item.observed_state_hash) || item.observed_state_hash !== expected) invalid();
    } else if (item.observed_state_hash !== null) invalid();
    observation = item as unknown as NativeObservation;
  }
  // The target head also fences observations for other plans on that target.
  // Retained evidence for this plan may predate that head; only the actual head
  // can be eligible now. Matching historical content never restores eligibility.
  if (data.observation_head_hash !== null && !hash(data.observation_head_hash)
    || observation && (!hash(data.observation_head_hash) || observation.current && data.observation_head_hash !== observation.receipt_hash)) invalid();
  const reasons = new Set(data.reasons);
  if (reasons.has('COMPILATION_MISSING') !== !compilation || reasons.has('COMPILATION_STALE') !== !!(compilation && !compilation.current)
    || reasons.has('OBSERVATION_MISSING') !== !observation || reasons.has('OBSERVATION_STALE') !== !!(observation && !observation.current)
    || reasons.has('OBSERVATION_MISMATCH') !== (observation?.comparison === 'mismatch')
    || reasons.has('OBSERVATION_UNKNOWN') !== (observation?.comparison === 'unknown')) invalid();
  return { ...data, compilation, observation } as unknown as NativeEvidenceStatus;
}
