// unsea/src/subtle.js
//
// WebCrypto's SubtleCrypto, or a stand-in for the part of it unsea and the
// libraries built on it use, when a page has none.
//
// Browsers give crypto.subtle only to secure pages (https, or localhost). A
// page opened at a plain-http address, such as a dev server reached by its LAN
// IP from a phone, has crypto.getRandomValues but no crypto.subtle, and every
// hash, key derivation and AES-GCM call would throw. There, the same
// operations run on noble's audited implementations instead, and give the
// same bytes: a record or message made one way opens the other way.
//
// What the stand-in does:
//   digest        SHA-256
//   importKey     'raw' keys for AES-GCM (128, 192, 256 bits), HKDF, PBKDF2
//   exportKey     'raw', for keys made extractable
//   generateKey   AES-GCM
//   deriveBits    HKDF and PBKDF2, with SHA-256
//   deriveKey     HKDF and PBKDF2 to an AES-GCM key
//   encrypt       AES-GCM, 96-bit or other IV, additional data, 128-bit tag
//   decrypt       the same
// Anything else throws NotSupportedError, as a browser does for an algorithm
// it lacks. Its keys are opaque objects that only it accepts, as a native
// CryptoKey only works with native subtle; getSubtle() picks one or the other
// once, so the two never meet.

import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { gcm } from '@noble/ciphers/aes.js';

const RAW = Symbol('unsea.rawKey');
const AES_LENGTHS = [128, 192, 256];

class SubtleError extends Error {
  constructor(name, message) {
    super(message);
    this.name = name;
  }
}

const fail = (name, message) => { throw new SubtleError(name, message); };

/** BufferSource as a Uint8Array view (no copy). */
function bytesOf(data, what = 'data') {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  return fail('TypeError', `${what} must be an ArrayBuffer or a typed array`);
}

/** A fresh ArrayBuffer holding exactly these bytes, as WebCrypto returns. */
const bufferOf = (bytes) => bytes.slice().buffer;

const nameOf = (algorithm) => String(typeof algorithm === 'string' ? algorithm : algorithm?.name ?? '').toUpperCase();

function sha256Only(hash) {
  if (nameOf(hash) !== 'SHA-256') fail('NotSupportedError', `Only SHA-256 is supported here, not ${nameOf(hash) || 'no hash'}`);
}

function makeKey(raw, name, extractable, usages, extra = {}) {
  const key = { type: 'secret', extractable: !!extractable, algorithm: { name, ...extra }, usages: [...usages] };
  Object.defineProperty(key, RAW, { value: Uint8Array.from(raw), enumerable: false });
  return Object.freeze(key);
}

function rawOf(key, name, usage) {
  const raw = key?.[RAW];
  if (!raw) fail('InvalidAccessError', 'This key was not made by this SubtleCrypto');
  if (name && key.algorithm.name !== name) fail('InvalidAccessError', `This is a ${key.algorithm.name} key, not ${name}`);
  if (usage && !key.usages.includes(usage)) fail('InvalidAccessError', `This key's usages do not include ${usage}`);
  return raw;
}

function aesLength(bits) {
  if (!AES_LENGTHS.includes(bits)) fail('OperationError', 'AES keys are 128, 192 or 256 bits long');
  return bits;
}

function tagLength(algorithm) {
  if (algorithm.tagLength !== undefined && Number(algorithm.tagLength) !== 128) fail('NotSupportedError', 'Only a 128-bit AES-GCM tag is supported here');
}

async function deriveBitsNow(algorithm, baseKey, length) {
  const name = nameOf(algorithm);
  if (!Number.isInteger(length) || length <= 0 || length % 8) fail('OperationError', 'The length must be a positive multiple of 8 bits');
  if (name === 'PBKDF2') {
    sha256Only(algorithm.hash);
    const iterations = Number(algorithm.iterations);
    if (!Number.isInteger(iterations) || iterations < 1) fail('OperationError', 'PBKDF2 needs a positive iteration count');
    const raw = rawOf(baseKey, 'PBKDF2');
    return pbkdf2Async(sha256, raw, bytesOf(algorithm.salt, 'salt'), { c: iterations, dkLen: length / 8, asyncTick: 10 });
  }
  if (name === 'HKDF') {
    sha256Only(algorithm.hash);
    const raw = rawOf(baseKey, 'HKDF');
    return hkdf(sha256, raw, bytesOf(algorithm.salt, 'salt'), bytesOf(algorithm.info, 'info'), length / 8);
  }
  return fail('NotSupportedError', `Deriving with ${name} is not supported here`);
}

export const nobleSubtle = Object.freeze({
  async digest(algorithm, data) {
    sha256Only(algorithm);
    return bufferOf(sha256(bytesOf(data)));
  },

  async importKey(format, keyData, algorithm, extractable, usages = []) {
    if (format !== 'raw') fail('NotSupportedError', `Only raw keys are supported here, not ${format}`);
    const raw = bytesOf(keyData, 'keyData');
    const name = nameOf(algorithm);
    if (name === 'AES-GCM') return makeKey(raw, 'AES-GCM', extractable, usages, { length: aesLength(raw.length * 8) });
    if (name === 'HKDF' || name === 'PBKDF2') {
      if (extractable) fail('SyntaxError', `${name} keys cannot be extractable`);
      return makeKey(raw, name, false, usages);
    }
    return fail('NotSupportedError', `${name || 'That algorithm'} is not supported here`);
  },

  async exportKey(format, key) {
    if (format !== 'raw') fail('NotSupportedError', `Only raw keys are supported here, not ${format}`);
    const raw = rawOf(key);
    if (!key.extractable) fail('InvalidAccessError', 'This key is not extractable');
    return bufferOf(raw);
  },

  async generateKey(algorithm, extractable, usages = []) {
    if (nameOf(algorithm) !== 'AES-GCM') fail('NotSupportedError', `Making ${nameOf(algorithm)} keys is not supported here`);
    const bits = aesLength(Number(algorithm.length));
    const raw = globalThis.crypto.getRandomValues(new Uint8Array(bits / 8));
    return makeKey(raw, 'AES-GCM', extractable, usages, { length: bits });
  },

  async deriveBits(algorithm, baseKey, length) {
    rawOf(baseKey, undefined, 'deriveBits');
    return bufferOf(await deriveBitsNow(algorithm, baseKey, length));
  },

  async deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, usages = []) {
    rawOf(baseKey, undefined, 'deriveKey');
    if (nameOf(derivedKeyAlgorithm) !== 'AES-GCM') fail('NotSupportedError', `Deriving ${nameOf(derivedKeyAlgorithm)} keys is not supported here`);
    const bits = aesLength(Number(derivedKeyAlgorithm.length));
    const raw = await deriveBitsNow(algorithm, baseKey, bits);
    return makeKey(raw, 'AES-GCM', extractable, usages, { length: bits });
  },

  async encrypt(algorithm, key, data) {
    if (nameOf(algorithm) !== 'AES-GCM') fail('NotSupportedError', `Encrypting with ${nameOf(algorithm)} is not supported here`);
    tagLength(algorithm);
    const raw = rawOf(key, 'AES-GCM', 'encrypt');
    const aad = algorithm.additionalData === undefined ? undefined : bytesOf(algorithm.additionalData, 'additionalData');
    return bufferOf(gcm(raw, bytesOf(algorithm.iv, 'iv'), aad).encrypt(bytesOf(data)));
  },

  async decrypt(algorithm, key, data) {
    if (nameOf(algorithm) !== 'AES-GCM') fail('NotSupportedError', `Decrypting with ${nameOf(algorithm)} is not supported here`);
    tagLength(algorithm);
    const raw = rawOf(key, 'AES-GCM', 'decrypt');
    const aad = algorithm.additionalData === undefined ? undefined : bytesOf(algorithm.additionalData, 'additionalData');
    try {
      return bufferOf(gcm(raw, bytesOf(algorithm.iv, 'iv'), aad).decrypt(bytesOf(data)));
    } catch {
      // As WebCrypto: one error for a wrong key, a changed message or a changed tag.
      return fail('OperationError', 'The data could not be decrypted');
    }
  },
});

/** Whether this environment has WebCrypto's own SubtleCrypto. */
export function hasNativeSubtle() {
  return !!globalThis.crypto?.subtle;
}

/**
 * The SubtleCrypto to use here: WebCrypto's own when there is one, else the
 * noble stand-in above (a page on plain http). Give it to code that would call
 * crypto.subtle, so it works on either.
 */
export function getSubtle() {
  return hasNativeSubtle() ? globalThis.crypto.subtle : nobleSubtle;
}
