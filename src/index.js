// unsea/src/index.js

import { p256 } from '@noble/curves/p256';
import { get, set, del } from 'idb-keyval';

const LIB_VERSION = '2.0.0';

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

  return {
    pub: signingKeys.pub,
    priv: signingKeys.priv,
    epub: encryptionKeys.pub,
    epriv: encryptionKeys.priv
  };
}

export async function generateRandomPair() {
  const signingPriv = p256.utils.randomPrivateKey();
  const encryptionPriv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(signingPriv, false);
  const epub = p256.getPublicKey(encryptionPriv, false);
  return {
    pub: keyToJWK(pub),
    priv: bufToB64Url(signingPriv),
    epub: keyToJWK(epub),
    epriv: bufToB64Url(encryptionPriv)
  };
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

export async function signMessage(msg, privB64) {
  const bytes = messageBytes(msg);
  const priv = validatePrivateKey(privB64);
  return signBytes(bytes, priv);
}

export async function verifyMessage(msg, sigB64, pubJwk) {
  if (typeof sigB64 !== 'string') {
    throw new Error('Signature must be a string');
  }
  const bytes = messageBytes(msg);
  return verifyBytes(bytes, sigB64, pubJwk);
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
  if (payload.v === 2) return 2;
  throw new Error(`Unsupported payload version: ${payload.v}`);
}

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

export async function decryptMessageWithMeta(payload, privB64) {
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
    if (version === 2) {
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
export async function encryptBySenderForReceiver(msg, senderEpriv, receiverEpub) {
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

export async function decryptBySenderForReceiver(payload, senderEpub, receiverEpriv) {
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
    if (version === 2) {
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

async function sealWithPassword(value, password) {
  const salt = getRandomValues(new Uint8Array(16));
  const iv = getRandomValues(new Uint8Array(12));
  const storageKey = await deriveStorageKey(password, salt, STORAGE_ITERATIONS);
  const data = await getSubtle().encrypt(
    { name: 'AES-GCM', iv },
    storageKey,
    TEXT_ENCODER.encode(JSON.stringify(value)),
  );
  return {
    encrypted: true,
    v: 2,
    iterations: STORAGE_ITERATIONS,
    salt: bufToB64Url(salt),
    iv: bufToB64Url(iv),
    data: bufToB64Url(data)
  };
}

async function openWithPassword(record, password) {
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
 * Save keys to IndexedDB, encrypted with a password (PBKDF2-SHA256, 600,000
 * iterations, then AES-GCM). Storing them unencrypted needs
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
      'Key storage requires a password (PBKDF2-SHA256, 600,000 iterations, AES-GCM)',
      'Signed proofs of work bind the signature to the proof; verifiers set the minimum difficulty',
      'Strict PKCS#8 parsing; public keys checked to be on P-256; one signature encoding (compact, low S)'
    ],
    algorithms: {
      signing: 'ECDSA with P-256 and SHA-256',
      encryption: 'ECDH (P-256) + HKDF-SHA256 + AES-256-GCM',
      keyDerivation: 'PBKDF2 with SHA-256',
      proofOfWork: 'SHA-256 based mining'
    },
    warnings: [
      'Version 1 encrypted payloads (unsea 1.x) are still decrypted; their timestamp is not authenticated',
      'A password-derived key pair is only as strong as the password',
      'Dependencies are bundled at build time - verify bundle integrity'
    ]
  };
}
