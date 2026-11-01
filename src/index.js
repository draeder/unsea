// unsea/src/index.js

import { p256 } from '@noble/curves/p256';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { get, set, del } from 'idb-keyval';

const LIB_VERSION = '3.0.0';

// Platform detection
const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined';

// Get WebCrypto subtle interface
let _subtle;
function getSubtle() {
  if (_subtle) return _subtle;

  if (isBrowser && window.crypto?.subtle) {
    _subtle = window.crypto.subtle;
  } else if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    _subtle = globalThis.crypto.subtle;
  } else {
    // For Node.js environments - will be handled by bundler
    if (typeof require !== 'undefined') {
      try {
        const { webcrypto } = require('crypto');
        _subtle = webcrypto.subtle;
      } catch (e) {
        throw new Error('WebCrypto not available in this environment');
      }
    } else {
      // ESM environment
      throw new Error('WebCrypto not available - ensure you are using Node.js 16+ or a modern browser');
    }
  }
  return _subtle;
}

// Get crypto random values
function getRandomValues(array) {
  if (isBrowser && window.crypto) {
    return window.crypto.getRandomValues(array);
  } else if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    return globalThis.crypto.getRandomValues(array);
  } else {
    // For Node.js environments
    if (typeof require !== 'undefined') {
      try {
        const { webcrypto } = require('crypto');
        return webcrypto.getRandomValues(array);
      } catch (e) {
        throw new Error('Crypto random values not available in this environment');
      }
    } else {
      throw new Error('Crypto random values not available - ensure you are using Node.js 16+ or a modern browser');
    }
  }
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

// Messages are signed and encrypted exactly as given. Up to 1.x they were
// NFC-normalized and trimmed first, so a signature on "pay bob 100" also
// verified "  pay bob 100\n", and decrypted text could differ from what was sent.
function messageBytes(s) {
  if (typeof s !== 'string') {
    throw new Error('Input must be a string');
  }
  return TEXT_ENCODER.encode(s);
}

function validatePrivateKey(privB64) {
  if (typeof privB64 !== 'string') {
    throw new Error('Private key must be a string');
  }
  let key;
  try {
    key = b64UrlToBuf(privB64);
  } catch (error) {
    throw new Error(`Invalid private key format: ${error.message}`);
  }
  if (key.length !== 32) {
    throw new Error('Invalid private key format: Invalid private key length for P-256 (expected 32 bytes)');
  }
  if (!p256.utils.isValidPrivateKey(key)) {
    throw new Error('Invalid private key: not a valid P-256 scalar');
  }
  return key;
}

function validatePublicKey(pubJwk) {
  if (typeof pubJwk !== 'string') {
    throw new Error('Public key must be a string');
  }
  if (!pubJwk.includes('.')) {
    throw new Error('Public key must be in JWK format (x.y)');
  }
  let x;
  let y;
  try {
    const parts = pubJwk.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new Error('Invalid JWK format: missing x or y component');
    }
    x = b64UrlToBuf(parts[0]);
    y = b64UrlToBuf(parts[1]);
  } catch (error) {
    throw new Error(`Invalid public key format: ${error.message}`);
  }
  if (x.length !== 32 || y.length !== 32) {
    throw new Error('Invalid public key format: Invalid public key coordinates length for P-256');
  }
  // The point must be on the curve (and not the point at infinity).
  try {
    p256.ProjectivePoint.fromHex(new Uint8Array([4, ...x, ...y])).assertValidity();
  } catch (error) {
    throw new Error('Invalid public key: not a point on P-256');
  }
  return { x, y };
}

// Constant-time comparison to prevent timing attacks
function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

function bufToB64Url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64UrlToBuf(b64url) {
  if (typeof b64url !== 'string' || !/^[A-Za-z0-9_-]*$/.test(b64url)) {
    throw new Error('Invalid base64url data');
  }
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/**
 * Compute a SHA-256 digest for text or binary input.
 *
 * @param {string|ArrayBuffer|ArrayBufferView} input Data to hash. Strings are
 * encoded as UTF-8 without normalization so every byte remains significant.
 * @param {'hex'|'base64url'|'bytes'} [output='hex'] Digest output format.
 * @returns {Promise<string|Uint8Array>}
 */
export async function sha256(input, output = 'hex') {
  let bytes;

  if (typeof input === 'string') {
    bytes = TEXT_ENCODER.encode(input);
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else if (ArrayBuffer.isView(input)) {
    bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  } else {
    throw new Error('SHA-256 input must be a string, ArrayBuffer, or ArrayBuffer view');
  }

  const digest = new Uint8Array(await getSubtle().digest('SHA-256', bytes));

  if (output === 'bytes') return digest;
  if (output === 'base64url') return bufToB64Url(digest);
  if (output === 'hex') {
    return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  throw new Error("SHA-256 output must be 'hex', 'base64url', or 'bytes'");
}

function keyToJWK(pubBuf) {
  if (pubBuf[0] !== 4) throw new Error('Expected uncompressed key');
  const x = pubBuf.slice(1, 33);
  const y = pubBuf.slice(33, 65);
  return `${bufToB64Url(x)}.${bufToB64Url(y)}`;
}

function jwkToKey(jwk) {
  const [x, y] = jwk.split('.');
  return new Uint8Array([4, ...b64UrlToBuf(x), ...b64UrlToBuf(y)]);
}

function publicJwkOf(priv) {
  return keyToJWK(p256.getPublicKey(priv, false));
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Post-quantum keys (3.0)
//
// A key pair can carry, next to its P-256 keys:
//   qpub / qpriv  ML-DSA-65 (FIPS 204) signing key: the public key, and the
//                 32-byte seed it is generated from
//   kpub / kpriv  ML-KEM-768 (FIPS 203) encryption key: the public key, and
//                 its 64-byte seed
// Only seeds are stored; the full secret keys are regenerated from them (and
// kept in a small cache). They are always used together with the P-256 keys
// (hybrid), so a pair stays as strong as the stronger of the two.

const ML_DSA_SEED_BYTES = 32;
const ML_KEM_SEED_BYTES = 64;
const ML_DSA_PUBLIC_BYTES = 1952;
const ML_KEM_PUBLIC_BYTES = 1184;
const ML_KEM_CIPHERTEXT_BYTES = 1088;
const HYBRID_SIGNATURE_PREFIX = 'pq1.';
const HYBRID_CONTEXT = TEXT_ENCODER.encode('unsea/v3/hybrid');

const pqKeyCache = new Map();
function cachedKeygen(kind, seed) {
  const id = `${kind}:${bufToB64Url(seed)}`;
  let keys = pqKeyCache.get(id);
  if (!keys) {
    keys = kind === 'dsa' ? ml_dsa65.keygen(seed) : ml_kem768.keygen(seed);
    if (pqKeyCache.size >= 16) pqKeyCache.delete(pqKeyCache.keys().next().value);
    pqKeyCache.set(id, keys);
  }
  return keys;
}

function seedOf(value, length, what) {
  if (typeof value !== 'string') throw new Error(`${what} must be a string`);
  const seed = b64UrlToBuf(value);
  if (seed.length !== length) throw new Error(`Invalid ${what} length (expected ${length} bytes)`);
  return seed;
}

function pqPublicOf(value, length, what) {
  if (typeof value !== 'string') throw new Error(`${what} must be a string`);
  const key = b64UrlToBuf(value);
  if (key.length !== length) throw new Error(`Invalid ${what} length (expected ${length} bytes)`);
  return key;
}

function pqKeysFromSeeds(dsaSeed, kemSeed) {
  return {
    qpub: bufToB64Url(cachedKeygen('dsa', dsaSeed).publicKey),
    qpriv: bufToB64Url(dsaSeed),
    kpub: bufToB64Url(cachedKeygen('kem', kemSeed).publicKey),
    kpriv: bufToB64Url(kemSeed),
  };
}

/** Whether a key pair (or its public half) carries post-quantum keys. */
export function hasPostQuantumKeys(pair) {
  return !!(pair && typeof pair === 'object' && typeof pair.qpub === 'string' && typeof pair.kpub === 'string');
}

/**
 * A key pair with post-quantum keys added (new, random ones) if it has none.
 * Its P-256 keys are kept, so its identity (pub) is unchanged.
 */
export function upgradePair(pair) {
  if (!pair || typeof pair !== 'object' || typeof pair.priv !== 'string') {
    throw new Error('upgradePair needs a key pair with priv');
  }
  if (typeof pair.qpriv === 'string' && typeof pair.kpriv === 'string') return { ...pair, ...pqKeysFromSeeds(seedOf(pair.qpriv, ML_DSA_SEED_BYTES, 'qpriv'), seedOf(pair.kpriv, ML_KEM_SEED_BYTES, 'kpriv')) };
  return {
    ...pair,
    ...pqKeysFromSeeds(getRandomValues(new Uint8Array(ML_DSA_SEED_BYTES)), getRandomValues(new Uint8Array(ML_KEM_SEED_BYTES))),
  };
}

/** The public half of a key pair: what to give others. */
export function publicKeysOf(pair) {
  if (!pair || typeof pair !== 'object') throw new Error('Key pair must be an object');
  const out = { pub: pair.pub, epub: pair.epub };
  if (hasPostQuantumKeys(pair)) {
    out.qpub = pair.qpub;
    out.kpub = pair.kpub;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Deterministic key pairs from a password

const DERIVE_ITERATIONS = 600_000;       // OWASP 2023 guidance for PBKDF2-SHA256
const LEGACY_DERIVE_ITERATIONS = 300_000;
const MIN_PASSWORD_BYTES = 16;

async function stretchKey(input, salt, iterations) {
  const subtle = getSubtle();
  const baseKey = await subtle.importKey('raw', input, { name: 'PBKDF2' }, false, ['deriveBits']);
  const keyBits = await subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, baseKey, 256);
  return new Uint8Array(keyBits);
}

/**
 * Derive a signing and an encryption key pair from a password and a per-user
 * salt (for example the user's alias or account id).
 *
 * The salt is required. Up to 1.x the salt was the same fixed string for
 * everyone, so the same password gave every user the same keys, and an
 * attacker who saw any public key could test password guesses offline against
 * every user at once. With a per-user salt each guess tests one user only.
 *
 * Keys derived by 1.x (no salt) can still be reproduced with
 * `derivePair(password, { legacyUnsalted: true })`, to migrate them.
 *
 * @param {string} pwd at least 16 bytes; use a high-entropy passphrase
 * @param {string|Uint8Array} salt a value unique to this user
 * @param {{ iterations?: number }} [options]
 */
export async function derivePair(pwd, salt, options = {}) {
  if (salt !== null && typeof salt === 'object' && !(salt instanceof Uint8Array)) {
    options = salt;
    salt = undefined;
  }
  if (typeof pwd !== 'string') {
    throw new Error('Password must be a string');
  }

  const unsalted = salt === undefined || salt === null || salt === '';
  if (unsalted && !options.legacyUnsalted) {
    throw new Error('derivePair needs a per-user salt, such as the user\'s alias: derivePair(password, salt). Keys from unsea 1.x can be reproduced with { legacyUnsalted: true }.');
  }

  const legacy = unsalted;
  const entropy = TEXT_ENCODER.encode(legacy ? pwd.normalize('NFC').trim() : pwd.normalize('NFC'));
  if (entropy.length < MIN_PASSWORD_BYTES) {
    throw new Error(`Insufficient input entropy (${entropy.length})`);
  }

  const saltSuffix = legacy ? null
    : (salt instanceof Uint8Array ? salt : TEXT_ENCODER.encode(String(salt).normalize('NFC')));
  const iterations = legacy
    ? LEGACY_DERIVE_ITERATIONS
    : Math.max(DERIVE_ITERATIONS, Math.floor(Number(options.iterations) || 0));

  const labels = ['signing', 'encryption'];
  const [signingKeys, encryptionKeys] = await Promise.all(labels.map(async (label) => {
    const saltBytes = legacy
      ? TEXT_ENCODER.encode(`${label}-v1`)
      : concatBytes(TEXT_ENCODER.encode(`unsea/v2/${label}|`), saltSuffix);
    const privateKey = await stretchKey(entropy, saltBytes, iterations);

    if (!p256.utils.isValidPrivateKey(privateKey)) {
      throw new Error(`Invalid private key for ${label}`);
    }

    const publicKey = p256.getPublicKey(privateKey, false);
    return {
      pub: keyToJWK(publicKey),
      priv: bufToB64Url(privateKey)
    };
  }));

  const pair = {
    pub: signingKeys.pub,
    priv: signingKeys.priv,
    epub: encryptionKeys.pub,
    epriv: encryptionKeys.priv
  };
  // Keys reproduced from 1.x stay as they were (upgradePair adds random
  // post-quantum keys to them). New derivations get post-quantum keys from the
  // password too, stretched separately from the P-256 keys.
  if (legacy) return pair;
  const [dsaSeed, kemSeedA, kemSeedB] = await Promise.all(['pq-signing', 'pq-encryption-a', 'pq-encryption-b'].map((label) => (
    stretchKey(entropy, concatBytes(TEXT_ENCODER.encode(`unsea/v3/${label}|`), saltSuffix), iterations)
  )));
  return { ...pair, ...pqKeysFromSeeds(dsaSeed, concatBytes(kemSeedA, kemSeedB)) };
}

/**
 * A new random key pair: P-256 signing and encryption keys, and (unless
 * { postQuantum: false }) ML-DSA-65 and ML-KEM-768 keys for hybrid use.
 */
export async function generateRandomPair(options = {}) {
  const signingPriv = p256.utils.randomPrivateKey();
  const encryptionPriv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(signingPriv, false);
  const epub = p256.getPublicKey(encryptionPriv, false);
  const pair = {
    pub: keyToJWK(pub),
    priv: bufToB64Url(signingPriv),
    epub: keyToJWK(epub),
    epriv: bufToB64Url(encryptionPriv)
  };
  return options?.postQuantum === false ? pair : upgradePair(pair);
}

// ---------------------------------------------------------------------------
// Signatures

async function signBytes(bytes, priv) {
  const hash = new Uint8Array(await getSubtle().digest('SHA-256', bytes));
  return bufToB64Url(p256.sign(hash, priv, { lowS: true }).toCompactRawBytes());
}

async function verifyBytes(bytes, sigB64, pubJwk) {
  const hash = new Uint8Array(await getSubtle().digest('SHA-256', bytes));
  validatePublicKey(pubJwk);
  const pub = jwkToKey(pubJwk);
  try {
    const sig = b64UrlToBuf(sigB64);
    // Exactly the 64-byte compact form signMessage produces (no DER
    // alternative), with low S, so each message has one valid encoding.
    if (sig.length !== 64) return false;
    return p256.verify(sig, hash, pub, { lowS: true, format: 'compact' });
  } catch (error) {
    // Return false instead of throwing for invalid signatures
    return false;
  }
}

// Hybrid signatures (3.0): "pq1.<ECDSA>.<ML-DSA-65>". Both halves sign the
// same bytes: a hybrid prefix, a digest of both public keys, then the
// message. So the ECDSA half is not a valid plain signature on its own, and
// neither half can be paired with another key's half; both must verify. A
// verifier given the signer's qpub accepts only hybrid signatures, so a
// signer's post-quantum key cannot be stripped.

async function hybridBytes(bytes, pub, qpub) {
  const keys = new Uint8Array(await getSubtle().digest('SHA-256', TEXT_ENCODER.encode(`${pub}|${qpub}`)));
  return concatBytes(HYBRID_CONTEXT, new Uint8Array([0]), keys, bytes);
}

/** Whether a signature is a hybrid (ECDSA + ML-DSA) one. */
export function isHybridSignature(sig) {
  return typeof sig === 'string' && sig.startsWith(HYBRID_SIGNATURE_PREFIX);
}

/**
 * Sign a message. With a private key string: ECDSA P-256. With a key pair
 * that has post-quantum keys ({ priv, qpriv }): a hybrid ECDSA + ML-DSA-65
 * signature.
 */
export async function signMessage(msg, privOrPair) {
  const bytes = messageBytes(msg);
  if (privOrPair && typeof privOrPair === 'object') {
    const priv = validatePrivateKey(privOrPair.priv);
    if (typeof privOrPair.qpriv !== 'string') return signBytes(bytes, priv);
    const { secretKey, publicKey } = cachedKeygen('dsa', seedOf(privOrPair.qpriv, ML_DSA_SEED_BYTES, 'qpriv'));
    const signed = await hybridBytes(bytes, publicJwkOf(priv), bufToB64Url(publicKey));
    const classic = await signBytes(signed, priv);
    const quantum = ml_dsa65.sign(signed, secretKey, { context: HYBRID_CONTEXT });
    return `${HYBRID_SIGNATURE_PREFIX}${classic}.${bufToB64Url(quantum)}`;
  }
  return signBytes(bytes, validatePrivateKey(privOrPair));
}

/**
 * Verify a signature. Given a public key string, only plain ECDSA
 * signatures verify. Given public keys with qpub ({ pub, qpub }), only hybrid
 * signatures verify, and both halves must be valid.
 */
export async function verifyMessage(msg, sigB64, pubOrKeys) {
  if (typeof sigB64 !== 'string') {
    throw new Error('Signature must be a string');
  }
  const bytes = messageBytes(msg);
  const keys = pubOrKeys && typeof pubOrKeys === 'object' ? pubOrKeys : { pub: pubOrKeys };
  if (typeof keys.qpub === 'string') {
    if (!isHybridSignature(sigB64)) return false;
    const parts = sigB64.slice(HYBRID_SIGNATURE_PREFIX.length).split('.');
    if (parts.length !== 2) return false;
    if (typeof keys.pub !== 'string') throw new Error('Public key must be a string');
    const signed = await hybridBytes(bytes, keys.pub, keys.qpub);
    let quantumOk = false;
    try {
      const qpub = pqPublicOf(keys.qpub, ML_DSA_PUBLIC_BYTES, 'qpub');
      quantumOk = ml_dsa65.verify(b64UrlToBuf(parts[1]), signed, qpub, { context: HYBRID_CONTEXT });
    } catch {
      return false;
    }
    const classicOk = await verifyBytes(signed, parts[0], keys.pub);
    return quantumOk && classicOk;
  }
  if (isHybridSignature(sigB64)) return false;
  return verifyBytes(bytes, sigB64, keys.pub);
}

// ---------------------------------------------------------------------------
// Encryption
//
// Version 2 (written by 2.x): the AES-GCM key comes from HKDF-SHA256 over the
// ECDH shared secret, with both public keys in its info, and the metadata
// (sender, recipient, timestamp) is authenticated as AES-GCM additional data.
// Version 1 (unsea 1.x) used SHA-256(shared secret) as the key and left the
// metadata unauthenticated; it is still decrypted, so messages from peers on
// 1.x keep working, but its timestamp cannot be trusted.

const HKDF_SALT = TEXT_ENCODER.encode('unsea/v2/hkdf');

async function hkdfAesKey(sharedX, info, usages) {
  const subtle = getSubtle();
  const ikm = await subtle.importKey('raw', sharedX, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: TEXT_ENCODER.encode(info) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

async function legacyAesKey(sharedX, usages) {
  const subtle = getSubtle();
  const keyMat = await subtle.digest('SHA-256', sharedX);
  return subtle.importKey('raw', keyMat, { name: 'AES-GCM' }, false, usages);
}

function metaContext(sender, recipient, timestamp) {
  return `unsea/v2/meta|${sender}|${recipient}|${timestamp}`;
}

function pairContext(senderEpub, receiverEpub) {
  return `unsea/v2/pair|${senderEpub}|${receiverEpub}`;
}

function payloadVersion(payload) {
  if (payload.v === undefined) return 1;
  if (payload.v === 2 || payload.v === 3) return payload.v;
  throw new Error(`Unsupported payload version: ${payload.v}`);
}

// Version 3 (3.0, when the recipient has a kpub): hybrid. An ML-KEM-768
// shared secret is combined with the ECDH one in the HKDF input, so the key is
// safe while either holds; the ML-KEM public key and ciphertext are bound
// into the authenticated context.
async function hybridKeyMaterial(ecdhShared, kemShared) {
  return concatBytes(ecdhShared, kemShared);
}

async function kemBinding(kpubBytes, kemCiphertext) {
  const digest = new Uint8Array(await getSubtle().digest('SHA-256', concatBytes(kpubBytes, kemCiphertext)));
  return bufToB64Url(digest);
}

function kemPrivateOf(keys) {
  if (!keys || typeof keys !== 'object' || typeof keys.kpriv !== 'string') {
    throw new Error('This message is post-quantum encrypted: decrypting it needs the key pair with kpriv');
  }
  return cachedKeygen('kem', seedOf(keys.kpriv, ML_KEM_SEED_BYTES, 'kpriv'));
}

function eprivOf(privOrPair) {
  return privOrPair && typeof privOrPair === 'object' ? privOrPair.epriv : privOrPair;
}

/**
 * Encrypt a message to a recipient's keys ({ epub }, or { epub, kpub } for a
 * post-quantum hybrid).
 */
export async function encryptMessageWithMeta(msg, recipient) {
  if (!recipient || typeof recipient !== 'object') {
    throw new Error('Recipient must be a key object with epub property');
  }
  if (!recipient.epub) {
    throw new Error('Recipient must have an encryption public key (epub)');
  }
  const msgBuf = messageBytes(msg);

  // Validate recipient's public key
  validatePublicKey(recipient.epub);
  const pub = jwkToKey(recipient.epub);

  const ephPriv = p256.utils.randomPrivateKey();
  const sender = keyToJWK(p256.getPublicKey(ephPriv, false));
  const shared = p256.getSharedSecret(ephPriv, pub).slice(1);
  const timestamp = Date.now();
  if (typeof recipient.kpub === 'string') {
    const kpub = pqPublicOf(recipient.kpub, ML_KEM_PUBLIC_BYTES, 'kpub');
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(kpub);
    const context = `unsea/v3/meta|${sender}|${recipient.epub}|${await kemBinding(kpub, cipherText)}|${timestamp}`;
    const key = await hkdfAesKey(await hybridKeyMaterial(shared, sharedSecret), context, ['encrypt']);
    const iv = getRandomValues(new Uint8Array(12));
    const ct = await getSubtle().encrypt({ name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) }, key, msgBuf);
    return { v: 3, ciphertext: bufToB64Url(ct), iv: bufToB64Url(iv), sender, kem: bufToB64Url(cipherText), timestamp };
  }
  const context = metaContext(sender, recipient.epub, timestamp);
  const key = await hkdfAesKey(shared, context, ['encrypt']);
  const iv = getRandomValues(new Uint8Array(12));
  const ct = await getSubtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) },
    key,
    msgBuf,
  );
  return {
    v: 2,
    ciphertext: bufToB64Url(ct),
    iv: bufToB64Url(iv),
    sender,
    timestamp
  };
}

/**
 * Decrypt a message. Pass the key pair ({ epriv, kpriv }) for post-quantum
 * messages; the encryption private key string (epriv) still opens the others.
 */
export async function decryptMessageWithMeta(payload, privOrPair) {
  const privB64 = eprivOf(privOrPair);
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be an encrypted message object');
  }
  if (!payload.ciphertext || !payload.iv || !payload.sender) {
    throw new Error('Payload must contain ciphertext, iv, and sender');
  }
  const version = payloadVersion(payload);

  // Validate sender's ephemeral public key
  validatePublicKey(payload.sender);
  const ephPub = jwkToKey(payload.sender);
  const priv = validatePrivateKey(privB64);
  const shared = p256.getSharedSecret(priv, ephPub).slice(1);

  try {
    const iv = b64UrlToBuf(payload.iv);
    const ct = b64UrlToBuf(payload.ciphertext);
    let pt;
    if (version === 3) {
      if (!Number.isSafeInteger(payload.timestamp)) throw new Error('Payload timestamp must be an integer');
      const kem = kemPrivateOf(privOrPair);
      const kemCt = b64UrlToBuf(String(payload.kem ?? ''));
      if (kemCt.length !== ML_KEM_CIPHERTEXT_BYTES) throw new Error('Invalid post-quantum ciphertext');
      const context = `unsea/v3/meta|${payload.sender}|${publicJwkOf(priv)}|${await kemBinding(kem.publicKey, kemCt)}|${payload.timestamp}`;
      const key = await hkdfAesKey(await hybridKeyMaterial(shared, ml_kem768.decapsulate(kemCt, kem.secretKey)), context, ['decrypt']);
      pt = await getSubtle().decrypt({ name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) }, key, ct);
    } else if (version === 2) {
      if (!Number.isSafeInteger(payload.timestamp)) throw new Error('Payload timestamp must be an integer');
      const context = metaContext(payload.sender, publicJwkOf(priv), payload.timestamp);
      const key = await hkdfAesKey(shared, context, ['decrypt']);
      pt = await getSubtle().decrypt({ name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) }, key, ct);
    } else {
      const key = await legacyAesKey(shared, ['decrypt']);
      pt = await getSubtle().decrypt({ name: 'AES-GCM', iv }, key, ct);
    }
    return TEXT_DECODER.decode(pt);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

// Asymmetric encryption for private chat: epriv1 + epub2 = epriv2 + epub1 (the
// same shared secret). Version 2 derives a different key for each direction, so
// a message cannot be bounced back to its sender as if the other side wrote it.
export async function encryptBySenderForReceiver(msg, senderEpriv, receiver) {
  const receiverEpub = receiver && typeof receiver === 'object' ? receiver.epub : receiver;
  const receiverKpub = receiver && typeof receiver === 'object' && typeof receiver.kpub === 'string' ? receiver.kpub : null;
  if (typeof msg !== 'string') {
    throw new Error('Message must be a string');
  }
  if (typeof senderEpriv !== 'string') {
    throw new Error('Sender private key must be a string');
  }
  if (typeof receiverEpub !== 'string') {
    throw new Error('Receiver public key must be a string');
  }

  const senderPriv = validatePrivateKey(senderEpriv);
  validatePublicKey(receiverEpub);
  const receiverPub = jwkToKey(receiverEpub);

  const shared = p256.getSharedSecret(senderPriv, receiverPub).slice(1);
  if (receiverKpub) {
    const kpub = pqPublicOf(receiverKpub, ML_KEM_PUBLIC_BYTES, 'kpub');
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(kpub);
    const context = `unsea/v3/pair|${publicJwkOf(senderPriv)}|${receiverEpub}|${await kemBinding(kpub, cipherText)}`;
    const key = await hkdfAesKey(await hybridKeyMaterial(shared, sharedSecret), context, ['encrypt']);
    const iv = getRandomValues(new Uint8Array(12));
    const ct = await getSubtle().encrypt({ name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) }, key, messageBytes(msg));
    return { v: 3, ciphertext: bufToB64Url(ct), iv: bufToB64Url(iv), kem: bufToB64Url(cipherText) };
  }
  const context = pairContext(publicJwkOf(senderPriv), receiverEpub);
  const key = await hkdfAesKey(shared, context, ['encrypt']);
  const iv = getRandomValues(new Uint8Array(12));
  const ct = await getSubtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) },
    key,
    messageBytes(msg),
  );

  return {
    v: 2,
    ciphertext: bufToB64Url(ct),
    iv: bufToB64Url(iv)
  };
}

export async function decryptBySenderForReceiver(payload, senderEpub, receiverEprivOrPair) {
  const receiverEpriv = eprivOf(receiverEprivOrPair);
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be an encrypted message object');
  }
  if (!payload.ciphertext || !payload.iv) {
    throw new Error('Payload must contain ciphertext and iv');
  }
  if (typeof senderEpub !== 'string') {
    throw new Error('Sender public key must be a string');
  }
  if (typeof receiverEpriv !== 'string') {
    throw new Error('Receiver private key must be a string');
  }
  const version = payloadVersion(payload);

  validatePublicKey(senderEpub);
  const senderPub = jwkToKey(senderEpub);
  const receiverPriv = validatePrivateKey(receiverEpriv);
  const shared = p256.getSharedSecret(receiverPriv, senderPub).slice(1);

  try {
    const iv = b64UrlToBuf(payload.iv);
    const ct = b64UrlToBuf(payload.ciphertext);
    let pt;
    if (version === 3) {
      const kem = kemPrivateOf(receiverEprivOrPair);
      const kemCt = b64UrlToBuf(String(payload.kem ?? ''));
      if (kemCt.length !== ML_KEM_CIPHERTEXT_BYTES) throw new Error('Invalid post-quantum ciphertext');
      const context = `unsea/v3/pair|${senderEpub}|${publicJwkOf(receiverPriv)}|${await kemBinding(kem.publicKey, kemCt)}`;
      const key = await hkdfAesKey(await hybridKeyMaterial(shared, ml_kem768.decapsulate(kemCt, kem.secretKey)), context, ['decrypt']);
      pt = await getSubtle().decrypt({ name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) }, key, ct);
    } else if (version === 2) {
      const context = pairContext(senderEpub, publicJwkOf(receiverPriv));
      const key = await hkdfAesKey(shared, context, ['decrypt']);
      pt = await getSubtle().decrypt({ name: 'AES-GCM', iv, additionalData: TEXT_ENCODER.encode(context) }, key, ct);
    } else {
      const key = await legacyAesKey(shared, ['decrypt']);
      pt = await getSubtle().decrypt({ name: 'AES-GCM', iv }, key, ct);
    }
    return TEXT_DECODER.decode(pt);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

// ---------------------------------------------------------------------------
// Key export and import

export async function exportToJWK(privB64) {
  const priv = validatePrivateKey(privB64);
  const [x, y] = publicJwkOf(priv).split('.');
  return {
    kty: 'EC',
    crv: 'P-256',
    x,
    y,
    d: bufToB64Url(priv),
    use: 'sig',
    key_ops: ['sign']
  };
}

export async function importFromJWK(jwk) {
  if (!jwk || typeof jwk !== 'object') {
    throw new Error('JWK must be an object');
  }
  if (jwk.kty !== 'EC') {
    throw new Error('JWK must be an EC key');
  }
  if (jwk.crv !== 'P-256') {
    throw new Error('JWK must use P-256 curve');
  }
  if (!jwk.d) {
    throw new Error('JWK must contain private key component (d)');
  }
  const priv = validatePrivateKey(jwk.d);
  if (jwk.x !== undefined || jwk.y !== undefined) {
    if (`${jwk.x}.${jwk.y}` !== publicJwkOf(priv)) {
      throw new Error('JWK public key (x, y) does not match its private key (d)');
    }
  }
  return jwk.d;
}

const OID_EC_PUBLIC_KEY = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

export async function exportToPEM(privB64) {
  const raw = validatePrivateKey(privB64);

  // PKCS#8 PrivateKeyInfo wrapping an RFC 5915 ECPrivateKey with its public key,
  // the same layout WebCrypto exports.
  const pkcs8Header = new Uint8Array([
    0x30, 0x81, 0x87, // SEQUENCE (135 bytes)
    0x02, 0x01, 0x00, // INTEGER version (0)
    0x30, 0x13, // SEQUENCE AlgorithmIdentifier
    0x06, 0x07, ...OID_EC_PUBLIC_KEY,
    0x06, 0x08, ...OID_P256,
    0x04, 0x6d, // OCTET STRING (109 bytes)
    0x30, 0x6b, // SEQUENCE ECPrivateKey
    0x02, 0x01, 0x01, // INTEGER version (1)
    0x04, 0x20 // OCTET STRING privateKey (32 bytes)
  ]);
  const pkcs8Suffix = new Uint8Array([
    0xa1, 0x44, 0x03, 0x42, 0x00 // [1] publicKey: BIT STRING (66 bytes, no unused bits)
  ]);
  const pubKey = p256.getPublicKey(raw, false);

  const pkcs8Data = concatBytes(pkcs8Header, raw, pkcs8Suffix, pubKey);
  const b64 = btoa(String.fromCharCode(...pkcs8Data));
  return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
}

// A minimal DER reader: enough to walk a P-256 PKCS#8 structure and refuse
// anything else.
function derElement(buf, pos, expectedTag) {
  if (pos + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[pos];
  if (expectedTag !== undefined && tag !== expectedTag) {
    throw new Error(`unexpected DER tag 0x${tag.toString(16)} (expected 0x${expectedTag.toString(16)})`);
  }
  let len = buf[pos + 1];
  let header = 2;
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count < 1 || count > 2) throw new Error('unsupported DER length');
    len = 0;
    for (let i = 0; i < count; i++) len = (len << 8) | buf[pos + 2 + i];
    header += count;
  }
  const start = pos + header;
  const end = start + len;
  if (end > buf.length) throw new Error('truncated DER');
  return { tag, start, end };
}

function sameBytes(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function parseP256Pkcs8(der) {
  const outer = derElement(der, 0, 0x30);
  if (outer.end !== der.length) throw new Error('trailing data after PrivateKeyInfo');

  const version = derElement(der, outer.start, 0x02);
  if (!sameBytes(der.subarray(version.start, version.end), [0x00])) throw new Error('unsupported PKCS#8 version');

  const algorithm = derElement(der, version.end, 0x30);
  const algOid = derElement(der, algorithm.start, 0x06);
  if (!sameBytes(der.subarray(algOid.start, algOid.end), OID_EC_PUBLIC_KEY)) throw new Error('not an EC key');
  const curveOid = derElement(der, algOid.end, 0x06);
  if (!sameBytes(der.subarray(curveOid.start, curveOid.end), OID_P256)) throw new Error('not a P-256 key');
  if (curveOid.end !== algorithm.end) throw new Error('unexpected AlgorithmIdentifier contents');

  const wrapped = derElement(der, algorithm.end, 0x04);
  if (wrapped.end !== outer.end) throw new Error('unexpected PrivateKeyInfo contents');

  const ecKey = derElement(der, wrapped.start, 0x30);
  if (ecKey.end !== wrapped.end) throw new Error('unexpected ECPrivateKey length');
  const ecVersion = derElement(der, ecKey.start, 0x02);
  if (!sameBytes(der.subarray(ecVersion.start, ecVersion.end), [0x01])) throw new Error('unsupported ECPrivateKey version');
  const privOctets = derElement(der, ecVersion.end, 0x04);
  const priv = der.slice(privOctets.start, privOctets.end);
  if (priv.length !== 32) throw new Error('private key is not 32 bytes');
  if (!p256.utils.isValidPrivateKey(priv)) throw new Error('private key is not a valid P-256 scalar');

  let pos = privOctets.end;
  if (pos < ecKey.end && der[pos] === 0xa0) {
    const params = derElement(der, pos, 0xa0);
    const paramOid = derElement(der, params.start, 0x06);
    if (!sameBytes(der.subarray(paramOid.start, paramOid.end), OID_P256)) throw new Error('ECPrivateKey parameters are not P-256');
    pos = params.end;
  }
  if (pos < ecKey.end && der[pos] === 0xa1) {
    const pubWrap = derElement(der, pos, 0xa1);
    const bits = derElement(der, pubWrap.start, 0x03);
    const point = der.subarray(bits.start, bits.end);
    if (point[0] !== 0x00) throw new Error('public key BIT STRING has unused bits');
    if (!sameBytes(point.subarray(1), p256.getPublicKey(priv, false))) {
      throw new Error('embedded public key does not match the private key');
    }
    pos = pubWrap.end;
  }
  if (pos !== ecKey.end) throw new Error('unexpected ECPrivateKey contents');
  return priv;
}

export async function importFromPEM(pem) {
  if (typeof pem !== 'string' || !pem.includes('-----BEGIN PRIVATE KEY-----') || !pem.includes('-----END PRIVATE KEY-----')) {
    throw new Error('Invalid PEM format: must contain BEGIN PRIVATE KEY and END PRIVATE KEY lines');
  }

  const body = pem.slice(pem.indexOf('-----BEGIN PRIVATE KEY-----') + 27, pem.indexOf('-----END PRIVATE KEY-----'));
  const b64 = body.replace(/\s+/g, '');
  if (!b64) {
    throw new Error('Invalid PEM format: no data found');
  }

  try {
    const bin = atob(b64);
    const der = Uint8Array.from(bin, c => c.charCodeAt(0));
    return bufToB64Url(parseP256Pkcs8(der));
  } catch (error) {
    throw new Error(`Failed to parse PEM: ${error.message}`);
  }
}

// ---------------------------------------------------------------------------
// Key storage

const STORAGE_ITERATIONS = 600_000;       // OWASP 2023 guidance for PBKDF2-SHA256
const LEGACY_STORAGE_ITERATIONS = 100_000; // records written by 1.x carry no count

async function deriveStorageKey(password, salt, iterations) {
  const subtle = getSubtle();
  const keyMaterial = await subtle.importKey(
    'raw',
    TEXT_ENCODER.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Version 3 (3.0): Argon2id (memory-hard, OWASP's minimum: 19 MiB, 2 passes),
// so each password guess against a stolen or published record costs memory
// as well as time. Versions 1 and 2 (PBKDF2) still open.
export const ARGON2ID_PARAMS = Object.freeze({ m: 19456, t: 2, p: 1 });
const MAX_ARGON2ID_MEMORY_KIB = 262144;

async function argon2Key(password, salt, params) {
  const bits = await argon2idAsync(TEXT_ENCODER.encode(password), salt, { ...params, dkLen: 32, asyncTick: 10 });
  return getSubtle().importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt any JSON value with a password (Argon2id, then AES-256-GCM). The
 * result is a plain object safe to store or publish; open it with
 * decryptWithPassword.
 */
export async function encryptWithPassword(value, password) {
  if (typeof password !== 'string' || !password) throw new Error('Password must be a non-empty string');
  return sealWithPassword(value, password);
}

/** Open what encryptWithPassword (or saveKeys) sealed; throws on a wrong password. */
export async function decryptWithPassword(record, password) {
  if (!record || typeof record !== 'object') throw new Error('Encrypted record must be an object');
  return openWithPassword(record, password);
}

async function sealWithPassword(value, password) {
  const salt = getRandomValues(new Uint8Array(16));
  const iv = getRandomValues(new Uint8Array(12));
  const storageKey = await argon2Key(password, salt, ARGON2ID_PARAMS);
  const data = await getSubtle().encrypt(
    { name: 'AES-GCM', iv },
    storageKey,
    TEXT_ENCODER.encode(JSON.stringify(value)),
  );
  return {
    encrypted: true,
    v: 3,
    kdf: 'argon2id',
    ...ARGON2ID_PARAMS,
    salt: bufToB64Url(salt),
    iv: bufToB64Url(iv),
    data: bufToB64Url(data)
  };
}

async function openWithPassword(record, password) {
  if (record.kdf === 'argon2id') {
    const params = { m: record.m, t: record.t, p: record.p };
    if (!Number.isSafeInteger(params.m) || !Number.isSafeInteger(params.t) || !Number.isSafeInteger(params.p)
      || params.m < ARGON2ID_PARAMS.m || params.t < 1 || params.p < 1 || params.m > MAX_ARGON2ID_MEMORY_KIB || params.t > 16 || params.p > 4) {
      throw new Error('stored Argon2id parameters are out of range');
    }
    const storageKey = await argon2Key(password, b64UrlToBuf(record.salt), params);
    const plain = await getSubtle().decrypt({ name: 'AES-GCM', iv: b64UrlToBuf(record.iv) }, storageKey, b64UrlToBuf(record.data));
    return JSON.parse(TEXT_DECODER.decode(plain));
  }
  const iterations = Number.isSafeInteger(record.iterations) ? record.iterations : LEGACY_STORAGE_ITERATIONS;
  if (iterations < LEGACY_STORAGE_ITERATIONS) throw new Error('stored iteration count is too low');
  const storageKey = await deriveStorageKey(password, b64UrlToBuf(record.salt), iterations);
  const plain = await getSubtle().decrypt({ name: 'AES-GCM', iv: b64UrlToBuf(record.iv) }, storageKey, b64UrlToBuf(record.data));
  return JSON.parse(TEXT_DECODER.decode(plain));
}

function requirePassword(password, options, what) {
  if (password) {
    if (typeof password !== 'string') throw new Error('Password must be a string');
    return true;
  }
  if (options.allowUnencrypted) return false;
  throw new Error(`${what} needs a password: private keys are not stored unencrypted. Pass { allowUnencrypted: true } to store them in plain text anyway.`);
}

/**
 * Save keys to IndexedDB, encrypted with a password (Argon2id, then
 * AES-256-GCM; see encryptWithPassword). Storing them unencrypted needs
 * `{ allowUnencrypted: true }`.
 */
export async function saveKeys(name, keys, password = null, options = {}) {
  if (!requirePassword(password, options, 'saveKeys')) {
    return set(name, { encrypted: false, data: keys });
  }
  try {
    return set(name, await sealWithPassword(keys, password));
  } catch (error) {
    throw new Error(`Failed to encrypt and save keys: ${error.message}`);
  }
}

export async function loadKeys(name, password = null, options = {}) {
  const stored = await get(name);

  if (!stored) {
    return undefined;
  }

  if (!stored.encrypted) {
    if (!options.allowUnencrypted) {
      throw new Error('Stored keys are unencrypted; pass { allowUnencrypted: true } to read them, then save them again with a password');
    }
    return stored.data;
  }

  if (!password) {
    throw new Error('Password required to decrypt stored keys');
  }

  try {
    return await openWithPassword(stored, password);
  } catch (error) {
    throw new Error(`Failed to decrypt keys: ${error.message}`);
  }
}

export async function clearKeys(name) {
  return del(name);
}

// Session storage for UnSEA key pairs (browser only), like Gun's SEA
// user.recall(). Key pairs are encrypted with a password, as with saveKeys:
// sessionStorage is readable by every script on the page.

/**
 * Save a key pair to session storage, encrypted with a password.
 * @param {Object} keypair UnSEA key pair {pub, priv, ...}
 * @param {string} [alias='user']
 * @param {string} password
 * @param {{ allowUnencrypted?: boolean }} [options]
 * @returns {Promise<Object|null>} the key pair, or null outside a browser or on failure
 */
export async function save(keypair, alias = 'user', password = null, options = {}) {
  if (typeof window === 'undefined' || !window.sessionStorage) return null;
  if (!keypair || !keypair.pub || !keypair.priv) {
    throw new Error('Invalid keypair: must have pub and priv properties');
  }
  const encrypt = requirePassword(password, options, 'save');
  const record = encrypt ? await sealWithPassword(keypair, password) : { encrypted: false, data: keypair };
  try {
    sessionStorage.setItem(`unsea.${alias}`, JSON.stringify(record));
    return keypair;
  } catch (error) {
    console.warn('Failed to save keypair to session storage:', error.message);
    return null;
  }
}

/**
 * Recall a key pair from session storage.
 * @param {string} [alias='user']
 * @param {string} password
 * @param {{ allowUnencrypted?: boolean }} [options]
 * @returns {Promise<Object|null>} the key pair, or null if none is stored
 */
export async function recall(alias = 'user', password = null, options = {}) {
  if (typeof window === 'undefined' || !window.sessionStorage) return null;
  const data = sessionStorage.getItem(`unsea.${alias}`);
  if (data === null) return null;

  let record;
  try {
    record = JSON.parse(data);
  } catch {
    console.warn('Invalid keypair found in session storage');
    return null;
  }

  let keypair;
  if (record && record.encrypted === true) {
    if (!password) throw new Error('Password required to recall this key pair');
    try {
      keypair = await openWithPassword(record, password);
    } catch (error) {
      throw new Error(`Failed to decrypt key pair: ${error.message}`);
    }
  } else {
    // Unencrypted: written by save() with allowUnencrypted, or by unsea 1.x
    // (which stored the bare key pair).
    if (!options.allowUnencrypted) {
      throw new Error('This key pair is stored unencrypted; pass { allowUnencrypted: true } to read it, then save it again with a password');
    }
    keypair = record && record.encrypted === false ? record.data : record;
  }

  if (!keypair || !keypair.pub || !keypair.priv) {
    console.warn('Invalid keypair found in session storage');
    return null;
  }
  return keypair;
}

/**
 * Clear UnSEA keypair from session storage (browser only)
 * @param {string} [alias='user'] - User alias/name to clear, or null to clear all UnSEA data
 */
export function clear(alias = 'user') {
  if (typeof window !== 'undefined' && window.sessionStorage) {
    try {
      if (alias === null) {
        // Clear all UnSEA session data
        const keys = Object.keys(sessionStorage);
        keys.forEach(key => {
          if (key.startsWith('unsea.')) {
            sessionStorage.removeItem(key);
          }
        });
      } else {
        const sessionKey = `unsea.${alias}`;
        sessionStorage.removeItem(sessionKey);
      }
      return true;
    } catch (error) {
      console.warn('Failed to clear keypair from session storage:', error.message);
      return false;
    }
  }
  return false; // Not in browser environment
}

// ---------------------------------------------------------------------------
// Proof of work

const DEFAULT_POW_DIFFICULTY = 4;
const MAX_POW_DIFFICULTY = 64; // hex digits of a SHA-256 hash

function checkDifficulty(difficulty) {
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > MAX_POW_DIFFICULTY) {
    throw new Error(`Difficulty must be an integer from 1 to ${MAX_POW_DIFFICULTY}`);
  }
}

async function workHash(data, nonce) {
  const hashBuf = await getSubtle().digest('SHA-256', TEXT_ENCODER.encode(`${data}:${nonce}`));
  const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return { hash: bufToB64Url(hashBuf), hashHex };
}

export async function generateWork(data, difficulty = DEFAULT_POW_DIFFICULTY, maxIterations = 1000000) {
  checkDifficulty(difficulty);
  const target = '0'.repeat(difficulty);
  const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

  let nonce = 0;
  let hash;
  let hashHex;

  const startTime = Date.now();

  while (nonce < maxIterations) {
    ({ hash, hashHex } = await workHash(dataStr, nonce));
    if (hashHex.startsWith(target)) break;
    nonce++;
  }

  const endTime = Date.now();
  const duration = endTime - startTime;

  if (nonce >= maxIterations) {
    throw new Error(`Failed to find proof of work within ${maxIterations} iterations`);
  }

  return {
    data: dataStr,
    nonce,
    hash,
    hashHex,
    difficulty,
    timestamp: endTime,
    duration,
    hashRate: Math.round(nonce / Math.max(duration / 1000, 0.001))
  };
}

/**
 * Check a proof of work. The verifier decides how much work it requires:
 * `minDifficulty` (default 4). The difficulty written in the proof only says
 * what the prover claims; up to 1.x it was all that was checked, so a proof
 * claiming difficulty 0 took no work and passed.
 *
 * @param {Object} proof from generateWork
 * @param {{ minDifficulty?: number, maxAgeMs?: number, now?: number }} [options]
 *   maxAgeMs: also reject proofs whose timestamp is older than this (or in the future)
 */
export async function verifyWork(proof, options = {}) {
  if (!proof || typeof proof !== 'object') {
    throw new Error('Proof must be an object');
  }
  if (typeof proof.data !== 'string' || typeof proof.nonce !== 'number' ||
    typeof proof.difficulty !== 'number' || !proof.hash || !proof.hashHex) {
    throw new Error('Proof must contain data, nonce, difficulty, hash, and hashHex');
  }
  const minDifficulty = options.minDifficulty ?? DEFAULT_POW_DIFFICULTY;
  checkDifficulty(minDifficulty);

  const wellFormed = Number.isSafeInteger(proof.nonce) && proof.nonce >= 0
    && Number.isInteger(proof.difficulty) && proof.difficulty >= 1 && proof.difficulty <= MAX_POW_DIFFICULTY;
  const { hash: hashB64, hashHex } = await workHash(proof.data, proof.nonce);

  const validHashB64 = constantTimeEqual(TEXT_ENCODER.encode(String(proof.hash)), TEXT_ENCODER.encode(hashB64));
  const validHashHex = constantTimeEqual(TEXT_ENCODER.encode(String(proof.hashHex)), TEXT_ENCODER.encode(hashHex));
  const validHash = validHashB64 && validHashHex;
  const validDifficulty = wellFormed && hashHex.startsWith('0'.repeat(proof.difficulty));
  const meetsMinimum = wellFormed && proof.difficulty >= minDifficulty;

  let fresh = true;
  if (options.maxAgeMs !== undefined) {
    const now = options.now ?? Date.now();
    fresh = Number.isSafeInteger(proof.timestamp)
      && proof.timestamp <= now + 60_000
      && now - proof.timestamp <= options.maxAgeMs;
  }

  return {
    valid: validHash && validDifficulty && meetsMinimum && fresh,
    hashMatches: validHash,
    difficultyMatches: validDifficulty,
    meetsMinimum,
    fresh,
    computedHash: hashB64,
    computedHashHex: hashHex,
    expectedDifficulty: '0'.repeat(Math.max(minDifficulty, wellFormed ? proof.difficulty : 0))
  };
}

// What a signed proof's signature covers: every field of the proof, under a
// label so the signature cannot be passed off as a signed message.
function workSigningPayload(work) {
  return `unsea/v2/work|${JSON.stringify([work.data, work.nonce, work.hash, work.difficulty, work.timestamp])}`;
}

export async function generateSignedWork(data, privKey, difficulty = DEFAULT_POW_DIFFICULTY, maxIterations = 1000000) {
  const work = await generateWork(data, difficulty, maxIterations);
  const signedPayload = workSigningPayload(work);
  const signature = await signMessage(signedPayload, privKey);
  return {
    ...work,
    signature,
    signedPayload
  };
}

/**
 * Check a signed proof of work: the work (as verifyWork, with the same
 * options) and a signature over that same proof. Up to 1.x the signature was
 * checked over `signedPayload` as given, which nothing tied to the proof, so a
 * valid signature could be attached to someone else's proof.
 */
export async function verifySignedWork(signedWork, pubKey, options = {}) {
  const workVerification = await verifyWork(signedWork, options);

  if (!workVerification.valid) {
    return {
      valid: false,
      workValid: false,
      signatureValid: false,
      reason: 'Invalid proof of work',
      workVerification
    };
  }

  const expected = workSigningPayload(signedWork);
  if (signedWork.signedPayload !== undefined && signedWork.signedPayload !== expected) {
    return {
      valid: false,
      workValid: true,
      signatureValid: false,
      reason: 'Signed payload does not match the proof',
      workVerification
    };
  }

  const signatureValid = typeof signedWork.signature === 'string'
    && await verifyMessage(expected, signedWork.signature, pubKey);

  return {
    valid: signatureValid,
    workValid: true,
    signatureValid,
    ...(signatureValid ? {} : { reason: 'Invalid signature' }),
    workVerification
  };
}

// Security configuration and utilities
export const SECURITY_CONFIG = {
  STORAGE_KDF: 'argon2id',
  ARGON2ID: ARGON2ID_PARAMS,
  POST_QUANTUM: { signing: 'ML-DSA-65', encryption: 'ML-KEM-768', mode: 'hybrid with P-256' },
  PBKDF2_ITERATIONS: STORAGE_ITERATIONS,
  DERIVE_ITERATIONS,
  AES_KEY_LENGTH: 256,
  CURVE: 'P-256',
  HASH_ALGORITHM: 'SHA-256',
  SUPPORTED_FORMATS: ['JWK', 'PEM'],
  MIN_POW_DIFFICULTY: 1,
  DEFAULT_POW_DIFFICULTY,
  MAX_POW_DIFFICULTY
};

// Utility function to get library version and security info
export function getSecurityInfo() {
  return {
    version: LIB_VERSION,
    securityEnhancements: [
      'Messages are signed and encrypted exactly as given (no trimming or normalization)',
      'ECDH keys derived with HKDF-SHA256 bound to both public keys; metadata authenticated as AES-GCM additional data',
      'Direction-bound keys for private chat',
      'derivePair requires a per-user salt (PBKDF2-SHA256, 600,000 iterations)',
      'Key storage requires a password (Argon2id, 19 MiB, 2 passes, then AES-256-GCM)',
      'Post-quantum hybrid keys: ML-DSA-65 signatures and ML-KEM-768 encryption alongside P-256; both must hold',
      'Signed proofs of work bind the signature to the proof; verifiers set the minimum difficulty',
      'Strict PKCS#8 parsing; public keys checked to be on P-256; one signature encoding (compact, low S)'
    ],
    algorithms: {
      signing: 'ECDSA with P-256 and SHA-256; hybrid with ML-DSA-65 for key pairs that have post-quantum keys',
      encryption: 'ECDH (P-256) + HKDF-SHA256 + AES-256-GCM; hybrid with ML-KEM-768 for recipients that have a kpub',
      keyDerivation: 'Argon2id for stored keys; PBKDF2-SHA256 for derivePair',
      proofOfWork: 'SHA-256 based mining'
    },
    warnings: [
      'Version 1 encrypted payloads (unsea 1.x) are still decrypted; their timestamp is not authenticated',
      'A password-derived key pair is only as strong as the password',
      'Dependencies are bundled at build time - verify bundle integrity'
    ]
  };
}
