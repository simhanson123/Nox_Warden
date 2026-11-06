import { ApiError } from './api';
import type { AuthorityPlan } from './authority-api';

export interface CoreAccessWindow {
  schema_version: 'fw.core-access-lease-window-status/v1';
  org_id: string; project_id: string; target_id: string; plan_id: string; plan_hash: string;
  request_id: string; request_revision: number; request_hash: string; provenance_hash: string;
  lease_id: string; lease_seconds: number; window_hash: string; not_before: string; expires_at: string;
  admitted_at: string; checked_at: string; current: boolean; signing_allowed: false; dispatch_allowed: false;
}
export interface CoreAccessEvidence {
  schema_version: 'fw.core-access-evidence/v1';
  org_id: string; project_id: string; target_id: string; plan_id: string; plan_hash: string;
  checked_at: string; lease_window: CoreAccessWindow | null;
  signing_allowed: false; dispatch_allowed: false; gates: ['CORE_SIGNING_PROFILE_UNAVAILABLE'];
}
function invalid(): never { throw new ApiError(0, 'CORE_ACCESS_EVIDENCE_RESPONSE_INVALID', ''); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
function exact(value: unknown, keys: string[]) {
  const data = record(value);
  if (Object.keys(data).length !== keys.length || keys.some(key => !Object.hasOwn(data, key))) invalid();
  return data;
}
function hash(value: unknown): value is string { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
function utc(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value.replace('Z', '.000Z');
}
function bound(data: Record<string, unknown>, detail: AuthorityPlan) {
  return data.org_id === detail.plan.org_id && data.project_id === detail.plan.project_id
    && data.target_id === detail.plan.target_id && data.plan_id === detail.plan.plan_id && data.plan_hash === detail.plan_hash;
}
export function parseCoreAccessEvidence(value: unknown, detail: AuthorityPlan): CoreAccessEvidence {
  const data = exact(value, ['schema_version', 'org_id', 'project_id', 'target_id', 'plan_id', 'plan_hash', 'checked_at', 'lease_window', 'signing_allowed', 'dispatch_allowed', 'gates']);
  if (detail.plan.change_kind !== 'add_access_lease' || data.schema_version !== 'fw.core-access-evidence/v1' || !bound(data, detail) || !utc(data.checked_at)
    || data.signing_allowed !== false || data.dispatch_allowed !== false || !Array.isArray(data.gates)
    || data.gates.length !== 1 || data.gates[0] !== 'CORE_SIGNING_PROFILE_UNAVAILABLE') invalid();
  if (data.lease_window !== null) {
    const item = exact(data.lease_window, ['schema_version', 'org_id', 'project_id', 'target_id', 'plan_id', 'plan_hash', 'request_id', 'request_revision', 'request_hash', 'provenance_hash', 'lease_id', 'lease_seconds', 'window_hash', 'not_before', 'expires_at', 'admitted_at', 'checked_at', 'current', 'signing_allowed', 'dispatch_allowed']);
    if (item.schema_version !== 'fw.core-access-lease-window-status/v1' || !bound(item, detail)
      || item.request_id !== detail.plan.request_id || item.request_revision !== detail.plan.request_revision || item.request_hash !== detail.plan.request_hash
      || ![item.plan_hash, item.request_hash, item.provenance_hash, item.window_hash].every(hash)
      || !Number.isInteger(item.request_revision) || Number(item.request_revision) < 1 || Number(item.request_revision) > 4294967295
      || typeof item.lease_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(item.lease_id)
      || !Number.isInteger(item.lease_seconds) || Number(item.lease_seconds) < 60 || Number(item.lease_seconds) > 86400
      || !utc(item.not_before) || !utc(item.expires_at) || !utc(item.admitted_at) || item.checked_at !== data.checked_at
      || Date.parse(item.expires_at) - Date.parse(item.not_before) !== Number(item.lease_seconds) * 1000
      || Date.parse(String(detail.plan.valid_until)) > Date.parse(item.expires_at)
      || typeof item.current !== 'boolean'
      || item.signing_allowed !== false || item.dispatch_allowed !== false
      || item.current && (Date.parse(item.admitted_at) > Date.parse(data.checked_at)
        || Date.parse(item.not_before) > Date.parse(data.checked_at) || Date.parse(item.expires_at) <= Date.parse(data.checked_at)
        || Date.parse(String(detail.plan.valid_until)) <= Date.parse(data.checked_at))) invalid();
    // The displayed complete after-state must contain this same fixed window.
    const policies = detail.plan.requested_policies;
    if (!Array.isArray(policies) || !policies.length || policies.some(policy => {
      const lifetime = record(record(policy).lifetime);
      return lifetime.kind !== 'lease' || lifetime.not_before !== item.not_before || lifetime.expires_at !== item.expires_at;
    })) invalid();
  }
  return data as unknown as CoreAccessEvidence;
}

// JSON.parse silently accepts duplicate object members. Scan the small closed
// evidence response before decoding so an overwritten identity cannot pass.
export async function readCoreAccessResponse(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) invalid();
  let size = 0; const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const chunk = await reader.read(); if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 16384) { await reader.cancel(); invalid(); }
      chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    let at = 0;
    const whitespace = () => { while (/\s/.test(text[at] ?? '') && at < text.length) at++; };
    const string = (): string => {
      const start = at++; while (at < text.length) {
        const character = text[at++];
        if (character === '\\') at++;
        else if (character === '"') return JSON.parse(text.slice(start, at)) as string;
      }
      return invalid();
    };
    function value(depth: number): void {
      if (depth > 32) invalid(); whitespace();
      const character = text[at];
      if (character === '"') { string(); return; }
      if (character === '{') {
        at++; whitespace(); const keys = new Set<string>();
        if (text[at] === '}') { at++; return; }
        for (;;) {
          whitespace(); if (text[at] !== '"') invalid();
          const key = string(); if (keys.has(key)) invalid(); keys.add(key);
          whitespace(); if (text[at++] !== ':') invalid(); value(depth + 1); whitespace();
          const separator = text[at++]; if (separator === '}') return; if (separator !== ',') invalid();
        }
      }
      if (character === '[') {
        at++; whitespace(); if (text[at] === ']') { at++; return; }
        for (;;) { value(depth + 1); whitespace(); const separator = text[at++]; if (separator === ']') return; if (separator !== ',') invalid(); }
      }
      const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*))/.exec(text.slice(at))?.[0];
      if (!token) invalid(); at += token.length;
    }
    value(0); whitespace(); if (at !== text.length) invalid();
    return JSON.parse(text) as unknown;
  } catch { return invalid(); }
  finally { reader.releaseLock(); }
}
