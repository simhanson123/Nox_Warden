export type JsonRecord = Record<string, unknown>;
export interface ActionPermission { action_id: string; allowed: boolean; reason_code: string | null }
export interface ReadEnvelope<T> {
  data: T;
  server_time?: string;
  revision?: number;
  actions?: ActionPermission[];
  freshness?: { observed_at: string | null; stale: boolean; source: string; stale_after_seconds: number };
  next_cursor?: string | null;
}
export interface Session { authenticated: boolean; principal_id: string; org_id: string; project_id: string; csrf_token: string }
export interface ControllerStatus { mode: string; enforcement: boolean; version: string; telemetry_enabled?: boolean; [key: string]: unknown }
export interface AccessRequest {
  schema_version: 'f.access-request/v1'; idempotency_key: string;
  workflow_id: string; workload_binding_id: string;
  source_asset_ids: string[]; destination_asset_ids: string[];
  service_id: string; lease_seconds: number; purpose: string;
}
export class ApiError extends Error {
  constructor(public status: number, public code: string, public detail: string, public requestId?: string) {
    super(code); this.name = 'ApiError';
  }
}
let csrfToken: string | undefined;
export function setCsrfToken(token: string | undefined) { csrfToken = token; }
export async function api<T>(path: string, options: { body?: unknown; key?: string; signal?: AbortSignal } = {}): Promise<ReadEnvelope<T>> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Idempotency-Key'] = options.key ?? crypto.randomUUID();
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  }
  let response: Response;
  try {
    response = await fetch('/api/v1' + path, { method: options.body === undefined ? 'GET' : 'POST', headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: 'same-origin', cache: 'no-store', signal: options.signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(0, 'NETWORK_ERROR', '');
  }
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const problem = body && typeof body === 'object' ? body as JsonRecord : {};
    throw new ApiError(response.status, typeof problem.code === 'string' ? problem.code : `HTTP_${response.status}`,
      typeof problem.detail === 'string' ? problem.detail.slice(0, 2000) : '',
      typeof problem.request_id === 'string' ? problem.request_id : undefined);
  }
  if (body && typeof body === 'object' && 'data' in body) return body as ReadEnvelope<T>;
  return { data: body as T };
}
export function listData(envelope: ReadEnvelope<unknown>): JsonRecord[] {
  const data = envelope.data;
  const items: unknown = Array.isArray(data) ? data : data && typeof data === 'object' && 'items' in data ? data.items : null;
  if (!Array.isArray(items)) throw new ApiError(0, 'INVALID_RESPONSE', '');
  if (items.some(item => item === null || typeof item !== 'object' || Array.isArray(item))) throw new ApiError(0, 'INVALID_RESPONSE', '');
  return items as JsonRecord[];
}
export function recordValue(row: JsonRecord, ...keys: string[]): unknown {
  for (const key of keys) if (row[key] !== undefined && row[key] !== null) return row[key];
  for (const nested of ['body', 'request', 'payload', 'data']) {
    const value = row[nested];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const key of keys) if ((value as JsonRecord)[key] !== undefined) return (value as JsonRecord)[key];
    }
  }
  return null;
}
export function displayValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value).slice(0, 300);
  return String(value).slice(0, 300);
}
