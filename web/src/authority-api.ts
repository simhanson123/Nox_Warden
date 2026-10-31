import { ApiError } from './api';
import type { JsonRecord } from './api';

export const authorityOrigin = 'http://localhost:8790';
export interface AuthoritySession {
  authenticated: boolean; csrf_token: string; principal_id?: string; org_id?: string;
  project_id?: string; roles?: string[]; expires_at?: string;
}
export interface AuthorityPlanSummary { plan_id: string; plan_hash: string; change_kind: string; valid_until: string }
export type AuthorityAggregation = { state: 'not_evaluated' | 'authority_unavailable' | 'pending' | 'blocked_by_dissent' | 'approved' | 'stale'; approval_set_id?: string; approval_set_hash?: string };
export interface AuthorityApprovalSet { content: JsonRecord; hash: string; valid_until: string }
export interface AuthorityPlan {
  plan: JsonRecord; requirements: JsonRecord; plan_hash: string; requirements_hash: string; roles: string[];
  review?: { before: JsonRecord; after: JsonRecord };
  aggregation?: AuthorityAggregation; current_approval_set?: AuthorityApprovalSet | null;
  current_principal_decisions: { approval: JsonRecord; current_valid: boolean }[];
}
export interface AuthorityChallenge { challenge: JsonRecord; options: unknown }
export interface SignedDecision { challenge_id: string; idempotency_key: string; assertion: unknown }
export interface DecisionReceipt { approval: JsonRecord; replayed: boolean; aggregation?: AuthorityAggregation }
export function record(value: unknown): JsonRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
  return value as JsonRecord;
}
export function parseAuthorityPlan(value: unknown): AuthorityPlan {
  const data = record(value); const plan = record(data.plan); const requirements = record(data.requirements);
  if (typeof plan.plan_id !== 'string' || typeof plan.valid_until !== 'string' || !Number.isFinite(Date.parse(plan.valid_until)) || !['policy_change', 'add_access_lease'].includes(String(plan.change_kind)) || !Array.isArray(plan.gates)
    || plan.gates.some(gate => !gate || typeof gate !== 'object' || Array.isArray(gate) || typeof gate.gate_id !== 'string' || typeof gate.result !== 'string')
    || !Array.isArray(data.roles) || data.roles.some(role => typeof role !== 'string')
    || ![data.plan_hash, data.requirements_hash].every(hash => typeof hash === 'string' && /^sha256:[0-9a-f]{64}$/.test(hash))) {
    throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
  }
  const aggregation = data.aggregation === undefined ? undefined : record(data.aggregation);
  let currentSet: AuthorityApprovalSet | null | undefined;
  if (aggregation) {
    if (!['not_evaluated', 'authority_unavailable', 'pending', 'blocked_by_dissent', 'approved', 'stale'].includes(String(aggregation.state))) throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
    if (aggregation.state === 'approved') {
      const set = record(data.current_approval_set); const content = record(set.content); const ref = record(content.plan_ref);
      if (content.schema_version !== 'f.approval-set/v1' || content.kind !== 'human' || typeof content.approval_set_id !== 'string'
        || content.approval_set_id !== aggregation.approval_set_id || set.hash !== aggregation.approval_set_hash
        || typeof set.hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(set.hash)
        || typeof set.valid_until !== 'string' || !Number.isFinite(Date.parse(set.valid_until)) || set.valid_until !== content.valid_until
        || Date.parse(set.valid_until) > Date.parse(plan.valid_until) || typeof content.created_at !== 'string' || !Number.isFinite(Date.parse(content.created_at)) || Date.parse(content.created_at) >= Date.parse(set.valid_until)
        || content.org_id !== plan.org_id || content.project_id !== plan.project_id
        || ref.plan_id !== plan.plan_id || ref.plan_hash !== data.plan_hash || ref.plan_kind !== plan.change_kind
        || content.requirements_hash !== data.requirements_hash || content.authority_epoch !== plan.authority_epoch
        || content.role_policy_hash !== requirements.role_policy_hash || !Array.isArray(content.approvals) || !Number.isInteger(requirements.minimum_humans) || Number(requirements.minimum_humans) < 1
        || content.approvals.length < Number(requirements.minimum_humans) || content.approvals.length > 3
        || content.approvals.some(item => record(item).decision !== 'approve')) throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
      currentSet = { content, hash: set.hash, valid_until: set.valid_until };
    } else {
      if (data.current_approval_set !== null) throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
      currentSet = null;
    }
  } else if (data.current_approval_set !== undefined) throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
  const decisions = data.current_principal_decisions ?? [];
  if (!Array.isArray(decisions) || decisions.some(item => !item || typeof item.current_valid !== 'boolean' || !['approve', 'reject'].includes(String(record(item.approval).decision)))) throw new ApiError(0, 'AUTHORITY_RESPONSE_INVALID', '');
  const review = data.review === undefined || data.review === null || record(data.review).available !== true ? undefined : record(data.review);
  return { plan, requirements, plan_hash: data.plan_hash as string, requirements_hash: data.requirements_hash as string, roles: data.roles as string[],
    aggregation: aggregation as AuthorityAggregation | undefined, current_approval_set: currentSet, current_principal_decisions: decisions, review: review ? { before: record(review.before), after: record(review.after) } : undefined };
}

// One client belongs to one authority page. Neither this proof nor signed browser
// assertions enter persistent storage, URLs, controller requests or console logs.
export class AuthorityClient {
  private csrf: string | undefined;
  clearSession() { this.csrf = undefined; }
  async request<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    if (window.location.origin !== authorityOrigin) throw new ApiError(0, 'AUTHORITY_ORIGIN_REQUIRED', '');
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (this.csrf) headers['X-Authority-CSRF'] = this.csrf;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let response: Response;
    try {
      response = await fetch('/authority/v1' + path, { method: body === undefined ? 'GET' : 'POST', headers,
        body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store', signal });
    } catch (error) {
      if (signal?.aborted) throw error;
      throw new ApiError(0, 'NETWORK_ERROR', '');
    }
    const value: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const problem = value && typeof value === 'object' ? value as JsonRecord : {};
      throw new ApiError(response.status, typeof problem.error === 'string' ? problem.error : 'AUTHORITY_REQUEST_FAILED', typeof problem.reason === 'string' ? problem.reason.slice(0, 200) : '');
    }
    return value as T;
  }
  acceptSession(value: unknown): AuthoritySession {
    const session = record(value);
    if (typeof session.authenticated !== 'boolean' || typeof session.csrf_token !== 'string' || !session.csrf_token) throw new ApiError(0, 'AUTHORITY_SESSION_INVALID', '');
    if (session.authenticated && ![session.principal_id, session.org_id, session.project_id, session.expires_at].every(field => typeof field === 'string' && field)) throw new ApiError(0, 'AUTHORITY_SESSION_INVALID', '');
    this.csrf = session.csrf_token;
    return session as unknown as AuthoritySession;
  }
  async session(signal?: AbortSignal) { return this.acceptSession(await this.request('/session', undefined, signal)); }
  async plan(id: string) { return parseAuthorityPlan(await this.request('/plans/' + encodeURIComponent(id))); }
}
