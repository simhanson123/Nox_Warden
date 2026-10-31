import { ApiError } from './api';
import { creationOptions, createPasskey, decodeBase64Url, encodeBase64Url, getPasskey, passkeyError, requestOptions } from './webauthn';

const encoded = (value: number[]) => encodeBase64Url(Uint8Array.from(value).buffer);
const challenge = encoded(Array(32).fill(7));
const creation = { rp: { id: 'localhost', name: 'Warden' }, user: { id: encoded([1, 2]), name: 'owner', displayName: 'Owner' }, challenge, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { userVerification: 'required' }, excludeCredentials: [{ type: 'public-key', id: encoded([3, 4]) }] };
const request = { rpId: 'localhost', challenge, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: encoded([3, 4]) }] };
const originalCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
afterEach(() => {
  vi.unstubAllGlobals();
  if (originalCredentials) Object.defineProperty(navigator, 'credentials', originalCredentials);
  else Reflect.deleteProperty(navigator, 'credentials');
});

test('base64url conversion preserves bytes and rejects noncanonical or unbounded input', () => {
  const bytes = Uint8Array.from([0, 255, 254, 128, 1]);
  expect(new Uint8Array(decodeBase64Url(encodeBase64Url(bytes.buffer)))).toEqual(bytes);
  for (const invalid of ['', 'A', 'AB', 'AA==', 'AA+', 'AA/', 'A'.repeat(1400)]) expect(() => decodeBase64Url(invalid)).toThrow(ApiError);
});

test('browser options decode credential identifiers without altering the server challenge', () => {
  const options = creationOptions(creation);
  expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(Uint8Array.from(Array(32).fill(7)));
  expect(new Uint8Array(options.user.id as ArrayBuffer)).toEqual(Uint8Array.from([1, 2]));
  expect(new Uint8Array(options.excludeCredentials![0].id as ArrayBuffer)).toEqual(Uint8Array.from([3, 4]));
  expect(creation.challenge).toBe(challenge);
  expect(new Uint8Array(requestOptions(request).allowCredentials![0].id as ArrayBuffer)).toEqual(Uint8Array.from([3, 4]));
});

test('unsupported RP, weakened verification and short challenges never reach the browser', () => {
  expect(() => creationOptions({ ...creation, rp: { id: 'attacker.example' } })).toThrow(ApiError);
  expect(() => creationOptions({ ...creation, authenticatorSelection: { userVerification: 'preferred' } })).toThrow(ApiError);
  expect(() => requestOptions({ ...request, userVerification: 'discouraged' })).toThrow(ApiError);
  expect(() => requestOptions({ ...request, challenge: encoded([1, 2]) })).toThrow(ApiError);
});

function browser(response: Record<string, unknown>) {
  vi.stubGlobal('isSecureContext', true); vi.stubGlobal('PublicKeyCredential', class {});
  const credential = { id: encoded([3, 4]), rawId: Uint8Array.from([3, 4]).buffer, type: 'public-key', response, getClientExtensionResults: () => ({}) };
  const create = vi.fn().mockResolvedValue(credential); const get = vi.fn().mockResolvedValue(credential);
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create, get } });
  return { create, get };
}

test('registration sends the original signed clientDataJSON bytes with actual authenticator output', async () => {
  const raw = new TextEncoder().encode('{ "type" : "webauthn.create", "challenge":"original" }').buffer;
  const native = browser({ attestationObject: Uint8Array.from([0, 255, 1]).buffer, clientDataJSON: raw, getTransports: () => ['internal'] });
  const proof = await createPasskey(creation);
  expect(proof.response.clientDataJSON).toBe(encodeBase64Url(raw));
  expect(proof.response.attestationObject).toBe(encoded([0, 255, 1]));
  expect(proof.clientExtensionResults).toEqual({});
  expect(native.create).toHaveBeenCalledOnce(); expect(native.get).not.toHaveBeenCalled();
});

test('authentication encodes the signature and preserves a missing user handle as null', async () => {
  const native = browser({ authenticatorData: Uint8Array.from([9, 8]).buffer, clientDataJSON: Uint8Array.from([7, 6]).buffer, signature: Uint8Array.from([5, 4]).buffer, userHandle: null });
  expect(await getPasskey(request)).toMatchObject({ response: { authenticatorData: encoded([9, 8]), clientDataJSON: encoded([7, 6]), signature: encoded([5, 4]), userHandle: null } });
  expect(native.get).toHaveBeenCalledOnce(); expect(native.create).not.toHaveBeenCalled();
});

test('cancelled and unsupported ceremonies produce failures, never fabricated credentials', async () => {
  const native = browser({}); native.get.mockResolvedValue(null);
  await expect(getPasskey(request)).rejects.toMatchObject({ code: 'PASSKEY_CANCELLED' });
  expect(passkeyError(new DOMException('private browser detail', 'NotAllowedError'))).toMatchObject({ code: 'PASSKEY_CANCELLED', detail: '' });
  vi.stubGlobal('isSecureContext', false);
  await expect(createPasskey(creation)).rejects.toMatchObject({ code: 'PASSKEY_BROWSER_UNAVAILABLE' });
  expect(native.create).not.toHaveBeenCalled();
});
