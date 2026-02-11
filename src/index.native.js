import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha2';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { gcm } from '@noble/ciphers/aes.js';
import * as SecureStore from 'expo-secure-store';
import { getRandomBytes } from 'expo-random';

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function bufToB64Url(buf) {
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64UrlToBuf(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function normalize(s) {
  if (typeof s !== 'string') {
    throw new Error('Input must be a string');
  }
  return s.normalize('NFC').trim();
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
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

function validatePrivateKey(privB64) {
  if (typeof privB64 !== 'string') throw new Error('Private key must be a string');
  const key = b64UrlToBuf(privB64);
  if (key.length !== 32) throw new Error('Invalid private key length for P-256 (expected 32 bytes)');
  return key;
}

function validatePublicKey(pubJwk) {
  if (typeof pubJwk !== 'string') throw new Error('Public key must be a string');
  if (!pubJwk.includes('.')) throw new Error('Public key must be in JWK format (x.y)');
  const [x, y] = pubJwk.split('.');
  if (!x || !y) throw new Error('Invalid JWK format: missing x or y component');
  const xBuf = b64UrlToBuf(x);
  const yBuf = b64UrlToBuf(y);
  if (xBuf.length !== 32 || yBuf.length !== 32) throw new Error('Invalid public key coordinates length for P-256');
  return { x: xBuf, y: yBuf };
}

function randomBytes(len) {
  const out = getRandomBytes(len);
  return out instanceof Uint8Array ? out : Uint8Array.from(out);
}

function sha256Digest(bytes) {
  return sha256(bytes);
}

function deriveKeyPBKDF2(input, salt, iterations = 100000) {
  return pbkdf2(sha256, input, salt, { c: iterations, dkLen: 32 });
}

export async function derivePair(pwd) {
  const entropy = TEXT_ENCODER.encode(pwd.normalize('NFC').trim());
  const entropyUint8 = new Uint8Array(entropy.length);
  entropyUint8.set(entropy);
  if (entropyUint8.length < 16) throw new Error(`Insufficient input entropy (${entropyUint8.length})`);
  const version = 'v1';
  const salts = [
    { label: 'signing', type: 'pub/priv' },
    { label: 'encryption', type: 'epub/epriv' }
  ];
  const results = await Promise.all(salts.map(async ({ label }) => {
    const salt = TEXT_ENCODER.encode(`${label}-${version}`);
    const privateKey = deriveKeyPBKDF2(entropyUint8, salt, 300000);
    if (!p256.utils.isValidPrivateKey(privateKey)) throw new Error(`Invalid private key for ${label}`);
    const publicKey = p256.getPublicKey(privateKey, false);
    return { pub: keyToJWK(publicKey), priv: bufToB64Url(privateKey) };
  }));
  return { pub: results[0].pub, priv: results[0].priv, epub: results[1].pub, epriv: results[1].priv };
}

export async function generateRandomPair() {
  let signingPriv = randomBytes(32);
  while (!p256.utils.isValidPrivateKey(signingPriv)) signingPriv = randomBytes(32);
  let encryptionPriv = randomBytes(32);
  while (!p256.utils.isValidPrivateKey(encryptionPriv)) encryptionPriv = randomBytes(32);
  const pub = p256.getPublicKey(signingPriv, false);
  const epub = p256.getPublicKey(encryptionPriv, false);
  return {
    pub: keyToJWK(pub),
    priv: bufToB64Url(signingPriv),
    epub: keyToJWK(epub),
    epriv: bufToB64Url(encryptionPriv)
  };
}

export async function signMessage(msg, privB64) {
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const hash = sha256Digest(msgBuf);
  const priv = validatePrivateKey(privB64);
  const sig = p256.sign(hash, priv);
  return bufToB64Url(sig.toCompactRawBytes());
}

export async function verifyMessage(msg, sigB64, pubJwk) {
  if (typeof sigB64 !== 'string') throw new Error('Signature must be a string');
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const hash = sha256Digest(msgBuf);
  validatePublicKey(pubJwk);
  const pub = jwkToKey(pubJwk);
  try {
    const sig = b64UrlToBuf(sigB64);
    return p256.verify(sig, hash, pub);
  } catch {
    return false;
  }
}

function aesGcmEncrypt(keyBytes, ivBytes, dataBytes) {
  const cipher = gcm(keyBytes, ivBytes);
  return cipher.encrypt(dataBytes);
}

function aesGcmDecrypt(keyBytes, ivBytes, ctBytes) {
  const cipher = gcm(keyBytes, ivBytes);
  return cipher.decrypt(ctBytes);
}

export async function encryptMessageWithMeta(msg, recipient) {
  if (!recipient || typeof recipient !== 'object') throw new Error('Recipient must be a key object with epub property');
  if (!recipient.epub) throw new Error('Recipient must have an encryption public key (epub)');
  validatePublicKey(recipient.epub);
  const pub = jwkToKey(recipient.epub);
  const ephPriv = randomBytes(32);
  const ephPub = p256.getPublicKey(ephPriv, false);
  const shared = p256.getSharedSecret(ephPriv, pub).slice(1);
  const keyMat = sha256Digest(shared);
  const iv = randomBytes(12);
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const ct = aesGcmEncrypt(keyMat, iv, msgBuf);
  return {
    ciphertext: bufToB64Url(ct),
    iv: bufToB64Url(iv),
    sender: keyToJWK(ephPub),
    timestamp: Date.now()
  };
}

export async function decryptMessageWithMeta(payload, privB64) {
  if (!payload || typeof payload !== 'object') throw new Error('Payload must be an encrypted message object');
  if (!payload.ciphertext || !payload.iv || !payload.sender) throw new Error('Payload must contain ciphertext, iv, and sender');
  validatePublicKey(payload.sender);
  const ephPub = jwkToKey(payload.sender);
  const priv = validatePrivateKey(privB64);
  const shared = p256.getSharedSecret(priv, ephPub).slice(1);
  const keyMat = sha256Digest(shared);
  try {
    const iv = b64UrlToBuf(payload.iv);
    const ct = b64UrlToBuf(payload.ciphertext);
    const pt = aesGcmDecrypt(keyMat, iv, ct);
    return TEXT_DECODER.decode(pt);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

export async function encryptBySenderForReceiver(msg, senderEpriv, receiverEpub) {
  if (typeof msg !== 'string') throw new Error('Message must be a string');
  if (typeof senderEpriv !== 'string') throw new Error('Sender private key must be a string');
  if (typeof receiverEpub !== 'string') throw new Error('Receiver public key must be a string');
  const senderPriv = validatePrivateKey(senderEpriv);
  validatePublicKey(receiverEpub);
  const receiverPub = jwkToKey(receiverEpub);
  const shared = p256.getSharedSecret(senderPriv, receiverPub).slice(1);
  const keyMat = sha256Digest(shared);
  const iv = randomBytes(12);
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const ct = aesGcmEncrypt(keyMat, iv, msgBuf);
  return { ciphertext: bufToB64Url(ct), iv: bufToB64Url(iv) };
}

export async function decryptBySenderForReceiver(payload, senderEpub, receiverEpriv) {
  if (!payload || typeof payload !== 'object') throw new Error('Payload must be an encrypted message object');
  if (!payload.ciphertext || !payload.iv) throw new Error('Payload must contain ciphertext and iv');
  if (typeof senderEpub !== 'string') throw new Error('Sender public key must be a string');
  if (typeof receiverEpriv !== 'string') throw new Error('Receiver private key must be a string');
  validatePublicKey(senderEpub);
  const senderPub = jwkToKey(senderEpub);
  const receiverPriv = validatePrivateKey(receiverEpriv);
  const shared = p256.getSharedSecret(receiverPriv, senderPub).slice(1);
  const keyMat = sha256Digest(shared);
  try {
    const iv = b64UrlToBuf(payload.iv);
    const ct = b64UrlToBuf(payload.ciphertext);
    const pt = aesGcmDecrypt(keyMat, iv, ct);
    return TEXT_DECODER.decode(pt);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

export async function exportToJWK(privB64) {
  const priv = b64UrlToBuf(privB64);
  if (priv.length !== 32) throw new Error('Invalid private key length for P-256');
  return { kty: 'EC', crv: 'P-256', d: bufToB64Url(priv), use: 'sig', key_ops: ['sign'] };
}

export async function importFromJWK(jwk) {
  if (jwk.kty !== 'EC') throw new Error('JWK must be an EC key');
  if (jwk.crv !== 'P-256') throw new Error('JWK must use P-256 curve');
  if (!jwk.d) throw new Error('JWK must contain private key component (d)');
  return jwk.d;
}

export async function exportToPEM(privB64) {
  const raw = b64UrlToBuf(privB64);
  if (raw.length !== 32) throw new Error('Invalid private key length for P-256');
  const pkcs8Header = new Uint8Array([0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20]);
  const pkcs8Suffix = new Uint8Array([0xa1, 0x44, 0x03, 0x42, 0x00, 0x04]);
  const pubKey = p256.getPublicKey(raw, false);
  const pkcs8Data = new Uint8Array(pkcs8Header.length + raw.length + pkcs8Suffix.length + pubKey.length);
  pkcs8Data.set(pkcs8Header, 0);
  pkcs8Data.set(raw, pkcs8Header.length);
  pkcs8Data.set(pkcs8Suffix, pkcs8Header.length + raw.length);
  pkcs8Data.set(pubKey, pkcs8Header.length + raw.length + pkcs8Suffix.length);
  const b64 = btoa(String.fromCharCode(...pkcs8Data));
  return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
}

export async function importFromPEM(pem) {
  if (!pem.includes('-----BEGIN PRIVATE KEY-----')) throw new Error('Invalid PEM format: must contain BEGIN PRIVATE KEY header');
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const data = Uint8Array.from([...bin].map(c => c.charCodeAt(0)));
  for (let i = 0; i < data.length - 34; i++) {
    if (data[i] === 0x04 && data[i + 1] === 0x20) {
      const privateKey = data.slice(i + 2, i + 34);
      if (privateKey.length === 32) return bufToB64Url(privateKey);
    }
  }
  throw new Error('Could not extract private key from PKCS#8 structure');
}

async function secureSet(key, value) {
  const str = typeof value === 'string' ? value : JSON.stringify(value);
  await SecureStore.setItemAsync(String(key), str);
}
async function secureGet(key) {
  const str = await SecureStore.getItemAsync(String(key));
  if (str == null) return undefined;
  try {
    return JSON.parse(str);
  } catch {
    return str;
  }
}
async function secureDel(key) {
  await SecureStore.deleteItemAsync(String(key));
}

export async function saveKeys(name, keys, password = null) {
  if (!password) {
    await secureSet(name, { encrypted: false, data: keys });
    return;
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const storageKey = deriveKeyPBKDF2(TEXT_ENCODER.encode(password), salt, 100000);
  const keyData = TEXT_ENCODER.encode(JSON.stringify(keys));
  const encryptedData = aesGcmEncrypt(storageKey, iv, keyData);
  await secureSet(name, { encrypted: true, salt: bufToB64Url(salt), iv: bufToB64Url(iv), data: bufToB64Url(encryptedData) });
}

export async function loadKeys(name, password = null) {
  const stored = await secureGet(name);
  if (!stored) return undefined;
  if (!stored.encrypted) return stored.data;
  if (!password) throw new Error('Password required to decrypt stored keys');
  const salt = b64UrlToBuf(stored.salt);
  const iv = b64UrlToBuf(stored.iv);
  const encryptedData = b64UrlToBuf(stored.data);
  const storageKey = deriveKeyPBKDF2(TEXT_ENCODER.encode(password), salt, 100000);
  const decryptedData = aesGcmDecrypt(storageKey, iv, encryptedData);
  const keyData = TEXT_DECODER.decode(decryptedData);
  return JSON.parse(keyData);
}

export async function clearKeys(name) {
  await secureDel(name);
}

export function save(keypair, alias = 'user') {
  const sessionKey = `unsea.${alias}`;
  return secureSet(sessionKey, keypair).then(() => keypair).catch(() => null);
}

export async function recall(alias = 'user') {
  const sessionKey = `unsea.${alias}`;
  const kp = await secureGet(sessionKey);
  if (!kp || !kp.pub || !kp.priv) return null;
  return kp;
}

export async function clear(alias = 'user') {
  const sessionKey = `unsea.${alias}`;
  await secureDel(sessionKey);
  return true;
}

export const SECURITY_CONFIG = {
  PBKDF2_ITERATIONS: 100000,
  AES_KEY_LENGTH: 256,
  CURVE: 'P-256',
  HASH_ALGORITHM: 'SHA-256',
  SUPPORTED_FORMATS: ['JWK', 'PEM'],
  MIN_POW_DIFFICULTY: 1,
  MAX_POW_DIFFICULTY: 8
};

export function getSecurityInfo() {
  return {
    version: '1.1.3-native',
    securityEnhancements: [
      'React Native-compatible crypto primitives',
      'Encrypted key storage via expo-secure-store',
      'Input validation and constant-time comparisons'
    ],
    algorithms: {
      signing: 'ECDSA with P-256 and SHA-256',
      encryption: 'ECDH + AES-GCM',
      keyDerivation: 'PBKDF2 with SHA-256'
    }
  };
}
