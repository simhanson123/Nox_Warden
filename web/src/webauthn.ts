import { ApiError } from './api';

// Only the signed browser bytes are encoded here. The controller verifies the
// challenge, origin, user verification and credential; the UI cannot approve it.
export function encodeBase64Url(buffer: ArrayBuffer): string {
  if (buffer.byteLength > 32_768) throw new ApiError(0, 'PASSKEY_RESPONSE_TOO_LARGE', '');
  let text = '';
  for (const byte of new Uint8Array(buffer)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decodeBase64Url(value: unknown, maxBytes = 1024): ArrayBuffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maxBytes * 4 / 3)) {
    throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', '');
  }
  try {
    const text = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
    const bytes = Uint8Array.from(text, char => char.charCodeAt(0));
    if (bytes.length > maxBytes || encodeBase64Url(bytes.buffer) !== value) throw new Error();
    return bytes.buffer;
  } catch { throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', ''); }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', '');
  return value as Record<string, unknown>;
}

function descriptors(value: unknown): PublicKeyCredentialDescriptor[] {
  if (!Array.isArray(value) || value.length > 8) throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', '');
  return value.map(item => {
    const descriptor = object(item);
    if (descriptor.type !== 'public-key') throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', '');
    return { ...descriptor, type: 'public-key', id: decodeBase64Url(descriptor.id) } as PublicKeyCredentialDescriptor;
  });
}

function challenge(value: unknown): ArrayBuffer {
  const bytes = decodeBase64Url(value);
  if (bytes.byteLength < 32) throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', '');
  return bytes;
}

export function creationOptions(value: unknown): PublicKeyCredentialCreationOptions {
  const options = object(value);
  const user = object(options.user);
  const selection = object(options.authenticatorSelection);
  if (object(options.rp).id !== 'localhost' || selection.userVerification !== 'required') throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', '');
  return {
    ...options,
    challenge: challenge(options.challenge),
    user: { ...user, id: decodeBase64Url(user.id, 64) },
    excludeCredentials: options.excludeCredentials === undefined ? undefined : descriptors(options.excludeCredentials),
  } as PublicKeyCredentialCreationOptions;
}

export function requestOptions(value: unknown): PublicKeyCredentialRequestOptions {
  const options = object(value);
  if (options.rpId !== 'localhost' || options.userVerification !== 'required') throw new ApiError(0, 'PASSKEY_OPTIONS_INVALID', '');
  return { ...options, challenge: challenge(options.challenge), allowCredentials: descriptors(options.allowCredentials) } as PublicKeyCredentialRequestOptions;
}

export function passkeysSupported(): boolean {
  return window.isSecureContext && typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials?.create && !!navigator.credentials?.get;
}

function credential(value: Credential | null): PublicKeyCredential {
  if (!value || value.type !== 'public-key') throw new ApiError(0, 'PASSKEY_CANCELLED', '');
  const result = value as PublicKeyCredential;
  if (!(result.rawId instanceof ArrayBuffer) || encodeBase64Url(result.rawId) !== result.id) throw new ApiError(0, 'PASSKEY_RESPONSE_INVALID', '');
  return result;
}

export function passkeyError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  if (error instanceof DOMException && ['NotAllowedError', 'AbortError'].includes(error.name)) return new ApiError(0, 'PASSKEY_CANCELLED', '');
  if (error instanceof DOMException && error.name === 'InvalidStateError') return new ApiError(0, 'PASSKEY_ALREADY_REGISTERED', '');
  return new ApiError(0, 'PASSKEY_BROWSER_UNAVAILABLE', '');
}

export async function createPasskey(options: unknown, signal?: AbortSignal) {
  if (!passkeysSupported()) throw new ApiError(0, 'PASSKEY_BROWSER_UNAVAILABLE', '');
  const result = credential(await navigator.credentials.create({ publicKey: creationOptions(options), signal }));
  const response = result.response as AuthenticatorAttestationResponse;
  return {
    id: result.id, rawId: encodeBase64Url(result.rawId), type: 'public-key',
    response: { attestationObject: encodeBase64Url(response.attestationObject), clientDataJSON: encodeBase64Url(response.clientDataJSON), transports: response.getTransports?.() ?? [] },
    clientExtensionResults: result.getClientExtensionResults(),
  };
}

export async function getPasskey(options: unknown, signal?: AbortSignal) {
  if (!passkeysSupported()) throw new ApiError(0, 'PASSKEY_BROWSER_UNAVAILABLE', '');
  const result = credential(await navigator.credentials.get({ publicKey: requestOptions(options), signal }));
  const response = result.response as AuthenticatorAssertionResponse;
  return {
    id: result.id, rawId: encodeBase64Url(result.rawId), type: 'public-key',
    response: { authenticatorData: encodeBase64Url(response.authenticatorData), clientDataJSON: encodeBase64Url(response.clientDataJSON), signature: encodeBase64Url(response.signature), userHandle: response.userHandle === null ? null : encodeBase64Url(response.userHandle) },
    clientExtensionResults: result.getClientExtensionResults(),
  };
}
