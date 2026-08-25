const crypto = require('node:crypto');

const MAX_WEBAUTHN_BINARY_BYTES = 2 * 1024 * 1024;
const MAX_CBOR_DEPTH = 16;
const MAX_CBOR_CONTAINER_ITEMS = 1024;
const MAX_CBOR_TOTAL_ITEMS = 4096;

function b64url(buffer) { return Buffer.from(buffer).toString('base64url'); }
function fromB64url(value, maxBytes = MAX_WEBAUTHN_BINARY_BYTES) {
  const encoded = String(value || '');
  if (!/^[A-Za-z0-9_-]*$/.test(encoded)) throw new Error('WebAuthn data is not valid base64url.');
  if (encoded.length > Math.ceil(maxBytes * 4 / 3) + 4) throw new Error('WebAuthn data exceeds the accepted size limit.');
  const decoded = Buffer.from(encoded, 'base64url');
  if (decoded.length > maxBytes) throw new Error('WebAuthn data exceeds the accepted size limit.');
  return decoded;
}

function readLength(buffer, state, additional) {
  if (additional < 24) return additional;
  const sizes = { 24: 1, 25: 2, 26: 4, 27: 8 };
  const size = sizes[additional];
  if (!size || state.offset + size > buffer.length) throw new Error('Unsupported CBOR length.');
  let value = 0n;
  for (let index = 0; index < size; index += 1) value = (value << 8n) | BigInt(buffer[state.offset++]);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR integer is too large.');
  return Number(value);
}

function reserveCborItems(state, count) {
  if (count > MAX_CBOR_CONTAINER_ITEMS || state.items + count > MAX_CBOR_TOTAL_ITEMS) {
    throw new Error('CBOR container contains too many items.');
  }
  state.items += count;
}

function decodeCborValue(buffer, state, depth) {
  if (depth > MAX_CBOR_DEPTH) throw new Error('CBOR nesting is too deep.');
  if (state.offset >= buffer.length) throw new Error('Unexpected end of CBOR data.');
  const initial = buffer[state.offset++];
  const major = initial >> 5;
  const additional = initial & 31;
  if (additional === 31) throw new Error('Indefinite CBOR values are not supported.');
  const length = readLength(buffer, state, additional);
  if (major === 0) return length;
  if (major === 1) return -1 - length;
  if (major === 2 || major === 3) {
    if (state.offset + length > buffer.length) throw new Error('Truncated CBOR value.');
    const value = buffer.subarray(state.offset, state.offset + length);
    state.offset += length;
    return major === 2 ? Buffer.from(value) : value.toString('utf8');
  }
  if (major === 4) {
    reserveCborItems(state, length);
    const values = [];
    for (let index = 0; index < length; index += 1) values.push(decodeCborValue(buffer, state, depth + 1));
    return values;
  }
  if (major === 5) {
    reserveCborItems(state, length * 2);
    const map = new Map();
    for (let index = 0; index < length; index += 1) {
      const key = decodeCborValue(buffer, state, depth + 1);
      if (map.has(key)) throw new Error('CBOR map contains a duplicate key.');
      map.set(key, decodeCborValue(buffer, state, depth + 1));
    }
    return map;
  }
  if (major === 6) return decodeCborValue(buffer, state, depth + 1);
  if (major === 7) {
    if (additional === 20) return false;
    if (additional === 21) return true;
    if (additional === 22 || additional === 23) return null;
  }
  throw new Error('Unsupported CBOR value.');
}

function decodeCborPrefix(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  if (buffer.length > MAX_WEBAUTHN_BINARY_BYTES) throw new Error('CBOR data exceeds the accepted size limit.');
  const state = { offset: 0, items: 0 };
  const value = decodeCborValue(buffer, state, 0);
  return { value, bytesRead: state.offset };
}

function decodeCbor(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  const decoded = decodeCborPrefix(buffer);
  if (decoded.bytesRead !== buffer.length) throw new Error('CBOR data contains trailing bytes.');
  return decoded.value;
}

function sha256(value) { return crypto.createHash('sha256').update(value).digest(); }
function equal(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }

function parseClientData(raw, expectedType, challenge, allowedOrigins) {
  const bytes = fromB64url(raw);
  let data;
  try { data = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('WebAuthn client data is invalid.'); }
  if (data.type !== expectedType) throw new Error('WebAuthn operation type did not match.');
  if (!equal(fromB64url(data.challenge), fromB64url(challenge))) throw new Error('WebAuthn challenge did not match.');
  if (!allowedOrigins.includes(data.origin)) throw new Error('WebAuthn origin did not match this dashboard.');
  return { bytes, data };
}

function parseAuthenticatorData(buffer, rpId, requireAttested = false) {
  if (buffer.length < 37) throw new Error('Authenticator data is truncated.');
  if (!equal(buffer.subarray(0, 32), sha256(Buffer.from(rpId)))) throw new Error('Passkey RP ID did not match this dashboard.');
  const flags = buffer[32];
  if (!(flags & 0x01)) throw new Error('Passkey user presence was not verified.');
  if (!(flags & 0x04)) throw new Error('Passkey user verification is required.');
  const signCount = buffer.readUInt32BE(33);
  const result = { flags, signCount };
  if (requireAttested) {
    if (!(flags & 0x40) || buffer.length < 55) throw new Error('Passkey registration data is missing.');
    let offset = 53;
    const credentialLength = buffer.readUInt16BE(offset);
    offset += 2;
    if (offset + credentialLength > buffer.length) throw new Error('Passkey credential ID is truncated.');
    result.credentialId = buffer.subarray(offset, offset + credentialLength);
    offset += credentialLength;
    const credentialKey = decodeCborPrefix(buffer.subarray(offset));
    result.cose = credentialKey.value;
    offset += credentialKey.bytesRead;
    if (flags & 0x80) {
      const extensions = decodeCbor(buffer.subarray(offset));
      if (!(extensions instanceof Map)) throw new Error('Passkey authenticator extensions are invalid.');
      result.extensions = extensions;
    } else if (offset !== buffer.length) {
      throw new Error('Passkey authenticator data contains unexpected trailing bytes.');
    }
  }
  return result;
}

function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new Error('Passkey public key is invalid.');
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (kty === 2 && alg === -7 && cose.get(-1) === 1) {
    return { kty: 'EC', crv: 'P-256', x: b64url(cose.get(-2)), y: b64url(cose.get(-3)), alg: 'ES256', ext: true };
  }
  if (kty === 3 && alg === -257) {
    return { kty: 'RSA', n: b64url(cose.get(-1)), e: b64url(cose.get(-2)), alg: 'RS256', ext: true };
  }
  throw new Error('Passkey algorithm is not supported. Use an ES256 or RS256 authenticator.');
}

function registrationOptions({ user, rpId, rpName = 'SHAM', existing = [] }) {
  return {
    challenge: b64url(crypto.randomBytes(32)),
    rp: { id: rpId, name: rpName },
    user: { id: b64url(Buffer.from(String(user.id))), name: user.username, displayName: user.username },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    timeout: 60_000,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    excludeCredentials: existing.map((id) => ({ type: 'public-key', id }))
  };
}

function verifyRegistration({ response, challenge, rpId, origins }) {
  if (response?.type !== 'public-key') throw new Error('Passkey response type is invalid.');
  // Mirrors verifyAssertion below: without this, registration never checked
  // that clientDataJSON's type/challenge/origin matched what the server
  // issued, so a stale or cross-origin registration ceremony could complete.
  parseClientData(response.response?.clientDataJSON, 'webauthn.create', challenge, origins);
  const attestation = decodeCbor(fromB64url(response.response?.attestationObject));
  if (!(attestation instanceof Map) || attestation.get('fmt') !== 'none') throw new Error('Only privacy-preserving “none” passkey attestation is accepted.');
  const authData = attestation.get('authData');
  if (!Buffer.isBuffer(authData)) throw new Error('Passkey authenticator data is missing.');
  const parsed = parseAuthenticatorData(authData, rpId, true);
  return {
    credentialId: b64url(parsed.credentialId),
    publicKeyJwk: coseToJwk(parsed.cose),
    signCount: parsed.signCount,
    transports: Array.isArray(response.response?.transports) ? response.response.transports.slice(0, 10) : []
  };
}

function assertionOptions({ credentials }) {
  return {
    challenge: b64url(crypto.randomBytes(32)),
    timeout: 60_000,
    userVerification: 'required',
    allowCredentials: credentials.map((credential) => ({
      type: 'public-key', id: credential.credential_id,
      transports: (() => { try { return JSON.parse(credential.transports_json || '[]'); } catch { return []; } })()
    }))
  };
}

function verifyAssertion({ response, credential, challenge, rpId, origins }) {
  if (response?.type !== 'public-key' || response.id !== credential.credential_id) throw new Error('Passkey credential did not match.');
  const client = parseClientData(response.response?.clientDataJSON, 'webauthn.get', challenge, origins);
  const authData = fromB64url(response.response?.authenticatorData);
  const parsed = parseAuthenticatorData(authData, rpId, false);
  const signature = fromB64url(response.response?.signature);
  const signed = Buffer.concat([authData, sha256(client.bytes)]);
  const publicKey = crypto.createPublicKey({ key: JSON.parse(credential.public_key_jwk), format: 'jwk' });
  const valid = crypto.verify(credential.algorithm === 'RS256' ? 'RSA-SHA256' : 'sha256', signed, publicKey, signature);
  if (!valid) throw new Error('Passkey signature verification failed.');
  if (credential.sign_count > 0 && parsed.signCount > 0 && parsed.signCount <= credential.sign_count) {
    throw new Error('Passkey signature counter moved backwards; this credential may have been cloned.');
  }
  return { signCount: parsed.signCount };
}

module.exports = { b64url, fromB64url, decodeCbor, registrationOptions, verifyRegistration, assertionOptions, verifyAssertion };
