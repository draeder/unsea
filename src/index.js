// crypto-utils-p256/src/index.js

import { p256 } from '@noble/curves/p256';
import { get, set, del } from 'idb-keyval';

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

function normalize(s) {
  if (typeof s !== 'string') {
    throw new Error('Input must be a string');
  }
  return s.normalize('NFC').trim()
}

function validatePrivateKey(privB64) {
  if (typeof privB64 !== 'string') {
    throw new Error('Private key must be a string');
  }
  try {
    const key = b64UrlToBuf(privB64);
    if (key.length !== 32) {
      throw new Error('Invalid private key length for P-256 (expected 32 bytes)');
    }
    return key;
  } catch (error) {
    throw new Error(`Invalid private key format: ${error.message}`);
  }
}

function validatePublicKey(pubJwk) {
  if (typeof pubJwk !== 'string') {
    throw new Error('Public key must be a string');
  }
  if (!pubJwk.includes('.')) {
    throw new Error('Public key must be in JWK format (x.y)');
  }
  try {
    const [x, y] = pubJwk.split('.');
    if (!x || !y) {
      throw new Error('Invalid JWK format: missing x or y component');
    }
    const xBuf = b64UrlToBuf(x);
    const yBuf = b64UrlToBuf(y);
    if (xBuf.length !== 32 || yBuf.length !== 32) {
      throw new Error('Invalid public key coordinates length for P-256');
    }
    return { x: xBuf, y: yBuf };
  } catch (error) {
    throw new Error(`Invalid public key format: ${error.message}`);
  }
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
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64UrlToBuf(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
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


async function stretchKey(input, salt, iterations = 300_000) {
  const baseKey = await crypto.subtle.importKey('raw', input, { name: 'PBKDF2' }, false, ['deriveBits']);
  const keyBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, baseKey, 256);
  return new Uint8Array(keyBits);
}

// Internal function to derive a keypair from a passphrase
async function derivePair(pwd) {
  const entropy = TEXT_ENCODER.encode(pwd.normalize('NFC').trim());

  const entropyUint8 = new Uint8Array(entropy.length);
  entropyUint8.set(entropy);

  if (entropyUint8.length < 16) {
    throw new Error(`Insufficient input entropy (${entropyUint8.length})`);
  }

  const version = 'v1';
  const salts = [
    { label: 'signing', type: 'pub/priv' },
    { label: 'encryption', type: 'epub/epriv' }
  ];

  const [signingKeys, encryptionKeys] = await Promise.all(salts.map(async ({ label }) => {
    const salt = TEXT_ENCODER.encode(`${label}-${version}`);
    const privateKey = await stretchKey(entropyUint8, salt);

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

// Internal function to generate a random keypair
async function generateRandomPair() {
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

// Simplified API: Generate random keypair or derive from passphrase
export async function pair(passphrase = null) {
  if (passphrase) {
    return await derivePair(passphrase);
  }
  return await generateRandomPair();
}

// Simplified API: Derive keypair from passphrase
export async function derive(passphrase) {
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('Passphrase must be a non-empty string');
  }
  return await derivePair(passphrase);
}

// Simplified API: Sign a message
export async function sign(msg, privKey) {
  const subtle = getSubtle();
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const hash = await subtle.digest('SHA-256', msgBuf);
  const priv = validatePrivateKey(privKey);
  const sig = p256.sign(new Uint8Array(hash), priv);
  return bufToB64Url(sig.toCompactRawBytes());
}

// Simplified API: Verify a message signature
export async function verify(msg, signature, pubKey) {
  if (typeof signature !== 'string') {
    throw new Error('Signature must be a string');
  }

  const subtle = getSubtle();
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const hash = await subtle.digest('SHA-256', msgBuf);

  // Validate public key
  validatePublicKey(pubKey);
  const pub = jwkToKey(pubKey);

  try {
    const sig = b64UrlToBuf(signature);
    return p256.verify(sig, new Uint8Array(hash), pub);
  } catch (error) {
    // Return false instead of throwing for invalid signatures
    return false;
  }
}

// Simplified API: Unified encryption function
export async function encrypt(msg, recipientKey, senderKey = null) {
  if (typeof msg !== 'string') {
    throw new Error('Message must be a string');
  }

  if (senderKey) {
    // Authenticated encryption between known parties
    if (typeof senderKey !== 'string') {
      throw new Error('Sender private key must be a string');
    }
    if (typeof recipientKey !== 'string') {
      throw new Error('Recipient public key must be a string');
    }
    
    const subtle = getSubtle();
    
    // Validate sender's private key and recipient's public key
    const senderPriv = validatePrivateKey(senderKey);
    validatePublicKey(recipientKey);
    const recipientPub = jwkToKey(recipientKey);
    
    // Derive shared secret: senderEpriv + recipientEpub
    const shared = p256.getSharedSecret(senderPriv, recipientPub).slice(1);
    const keyMat = await subtle.digest('SHA-256', shared);
    const iv = getRandomValues(new Uint8Array(12));
    const key = await subtle.importKey('raw', keyMat, { name: 'AES-GCM' }, false, ['encrypt']);
    const msgBuf = TEXT_ENCODER.encode(normalize(msg));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, msgBuf);
    
    return {
      ciphertext: bufToB64Url(ct),
      iv: bufToB64Url(iv),
      mode: 'authenticated'
    };
  } else {
    // Ephemeral encryption with metadata
    if (typeof recipientKey !== 'string') {
      throw new Error('Recipient public key must be a string');
    }

    const subtle = getSubtle();

    // Validate recipient's public key
    validatePublicKey(recipientKey);
    const pub = jwkToKey(recipientKey);

    const ephPriv = p256.utils.randomPrivateKey();
    const ephPub = p256.getPublicKey(ephPriv, false);
    const shared = p256.getSharedSecret(ephPriv, pub).slice(1);
    const keyMat = await subtle.digest('SHA-256', shared);
    const iv = getRandomValues(new Uint8Array(12));
    const key = await subtle.importKey('raw', keyMat, { name: 'AES-GCM' }, false, ['encrypt']);
    const msgBuf = TEXT_ENCODER.encode(normalize(msg));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, msgBuf);
    
    return {
      ciphertext: bufToB64Url(ct),
      iv: bufToB64Url(iv),
      sender: keyToJWK(ephPub),
      timestamp: Date.now(),
      mode: 'ephemeral'
    };
  }
}

// Simplified API: Unified decryption function
export async function decrypt(payload, recipientKey, senderKey = null) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be an encrypted message object');
  }
  if (!payload.ciphertext || !payload.iv) {
    throw new Error('Payload must contain ciphertext and iv');
  }

  const subtle = getSubtle();

  if (payload.mode === 'authenticated' || senderKey) {
    // Authenticated decryption between known parties
    if (!senderKey) {
      throw new Error('Sender public key required for authenticated decryption');
    }
    if (typeof senderKey !== 'string') {
      throw new Error('Sender public key must be a string');
    }
    if (typeof recipientKey !== 'string') {
      throw new Error('Recipient private key must be a string');
    }
    
    // Validate sender's public key and recipient's private key
    validatePublicKey(senderKey);
    const senderPub = jwkToKey(senderKey);
    const recipientPriv = validatePrivateKey(recipientKey);
    
    // Derive shared secret: recipientEpriv + senderEpub (same as senderEpriv + recipientEpub)
    const shared = p256.getSharedSecret(recipientPriv, senderPub).slice(1);
    const keyMat = await subtle.digest('SHA-256', shared);
    const key = await subtle.importKey('raw', keyMat, { name: 'AES-GCM' }, false, ['decrypt']);
    
    try {
      const iv = b64UrlToBuf(payload.iv);
      const ct = b64UrlToBuf(payload.ciphertext);
      const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      return TEXT_DECODER.decode(pt);
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  } else {
    // Ephemeral decryption with metadata
    if (!payload.sender) {
      throw new Error('Payload must contain sender for ephemeral decryption');
    }

    // Validate sender's ephemeral public key
    validatePublicKey(payload.sender);
    const ephPub = jwkToKey(payload.sender);

    const priv = validatePrivateKey(recipientKey);
    const shared = p256.getSharedSecret(priv, ephPub).slice(1);
    const keyMat = await subtle.digest('SHA-256', shared);
    const key = await subtle.importKey('raw', keyMat, { name: 'AES-GCM' }, false, ['decrypt']);

    try {
      const iv = b64UrlToBuf(payload.iv);
      const ct = b64UrlToBuf(payload.ciphertext);
      const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      return TEXT_DECODER.decode(pt);
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
}

// Simplified API: Export keys in various formats
async function exportKey(privKey, format = 'jwk') {
  if (format.toLowerCase() === 'pem') {
    const raw = b64UrlToBuf(privKey);
    if (raw.length !== 32) {
      throw new Error('Invalid private key length for P-256');
    }

    // Create proper PKCS#8 structure for P-256 private key
    const pkcs8Header = new Uint8Array([
      0x30, 0x81, 0x87, // SEQUENCE (135 bytes)
      0x02, 0x01, 0x00, // INTEGER version (0)
      0x30, 0x13, // SEQUENCE AlgorithmIdentifier
      0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID secp256r1
      0x04, 0x6d, // OCTET STRING (109 bytes)
      0x30, 0x6b, // SEQUENCE ECPrivateKey
      0x02, 0x01, 0x01, // INTEGER version (1)
      0x04, 0x20 // OCTET STRING privateKey (32 bytes)
    ]);

    const pkcs8Suffix = new Uint8Array([
      0xa1, 0x44, 0x03, 0x42, 0x00, 0x04 // publicKey context tag + BIT STRING + uncompressed point indicator
    ]);

    // Generate corresponding public key
    const pubKey = p256.getPublicKey(raw, false);

    // Combine all parts
    const pkcs8Data = new Uint8Array(pkcs8Header.length + raw.length + pkcs8Suffix.length + pubKey.length);
    pkcs8Data.set(pkcs8Header, 0);
    pkcs8Data.set(raw, pkcs8Header.length);
    pkcs8Data.set(pkcs8Suffix, pkcs8Header.length + raw.length);
    pkcs8Data.set(pubKey, pkcs8Header.length + raw.length + pkcs8Suffix.length);

    const b64 = btoa(String.fromCharCode(...pkcs8Data));
    return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
  } else {
    // Default to JWK format
    const priv = b64UrlToBuf(privKey);
    if (priv.length !== 32) {
      throw new Error('Invalid private key length for P-256');
    }
    return {
      kty: 'EC',
      crv: 'P-256',
      d: bufToB64Url(priv),
      use: 'sig',
      key_ops: ['sign']
    };
  }
}

// Simplified API: Import keys from various formats
async function importKey(keyData) {
  if (typeof keyData === 'string') {
    if (keyData.includes('-----BEGIN PRIVATE KEY-----')) {
      // PEM format
      const b64 = keyData.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
      if (!b64) {
        throw new Error('Invalid PEM format: no data found');
      }

      try {
        const bin = atob(b64);
        const data = Uint8Array.from([...bin].map(c => c.charCodeAt(0)));

        // Extract the 32-byte private key from PKCS#8 structure
        for (let i = 0; i < data.length - 34; i++) {
          if (data[i] === 0x04 && data[i + 1] === 0x20) {
            const privateKey = data.slice(i + 2, i + 34);
            if (privateKey.length === 32) {
              return bufToB64Url(privateKey);
            }
          }
        }

        throw new Error('Could not extract private key from PKCS#8 structure');
      } catch (error) {
        throw new Error(`Failed to parse PEM: ${error.message}`);
      }
    } else {
      // Assume it's already a base64url string
      return keyData;
    }
  } else if (typeof keyData === 'object' && keyData.kty === 'EC') {
    // JWK format
    if (keyData.crv !== 'P-256') {
      throw new Error('JWK must use P-256 curve');
    }
    if (!keyData.d) {
      throw new Error('JWK must contain private key component (d)');
    }
    return keyData.d;
  } else {
    throw new Error('Unsupported key format');
  }
}

// Export the functions with the simplified names
export { exportKey as export, importKey as import };

// Helper function for encrypted storage
async function deriveStorageKey(password, salt) {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const keyMaterial = await subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Simplified API: Save keys (both session storage and encrypted persistent storage)
export async function save(keys, name = 'user', password = null) {
  if (typeof name === 'string' && name.length > 0 && !password) {
    // Session storage mode (browser only)
    if (typeof window !== 'undefined' && window.sessionStorage) {
      try {
        if (!keys || !keys.pub || !keys.priv) {
          throw new Error('Invalid keypair: must have pub and priv properties');
        }

        const sessionKey = `unsea.${name}`;
        sessionStorage.setItem(sessionKey, JSON.stringify(keys));
        return keys;
      } catch (error) {
        console.warn('Failed to save keypair to session storage:', error.message);
        return null;
      }
    }
    return null; // Not in browser environment
  } else {
    // Persistent storage mode (encrypted)
    if (!password) {
      console.warn('⚠️ WARNING: Keys are being stored unencrypted. Consider providing a password for better security.');
      return set(name, { encrypted: false, data: keys });
    }

    try {
      const subtle = getSubtle();
      const salt = getRandomValues(new Uint8Array(16));
      const iv = getRandomValues(new Uint8Array(12));

      const storageKey = await deriveStorageKey(password, salt);
      const keyData = TEXT_ENCODER.encode(JSON.stringify(keys));
      const encryptedData = await subtle.encrypt({ name: 'AES-GCM', iv }, storageKey, keyData);

      return set(name, {
        encrypted: true,
        salt: bufToB64Url(salt),
        iv: bufToB64Url(iv),
        data: bufToB64Url(encryptedData)
      });
    } catch (error) {
      throw new Error(`Failed to encrypt and save keys: ${error.message}`);
    }
  }
}

// Simplified API: Load keys (both session storage and encrypted persistent storage)
export async function load(name = 'user', password = null) {
  // Try session storage first (browser only)
  if (typeof window !== 'undefined' && window.sessionStorage && !password) {
    try {
      const sessionKey = `unsea.${name}`;
      const data = sessionStorage.getItem(sessionKey);
      if (data !== null) {
        const keypair = JSON.parse(data);
        // Validate it's a proper keypair
        if (keypair && keypair.pub && keypair.priv) {
          return keypair;
        }
      }
    } catch (error) {
      console.warn('Failed to load keypair from session storage:', error.message);
    }
  }

  // Try persistent storage
  const stored = await get(name);
  if (!stored) {
    return undefined;
  }

  if (!stored.encrypted) {
    return stored.data;
  }

  if (!password) {
    throw new Error('Password required to decrypt stored keys');
  }

  try {
    const subtle = getSubtle();
    const salt = b64UrlToBuf(stored.salt);
    const iv = b64UrlToBuf(stored.iv);
    const encryptedData = b64UrlToBuf(stored.data);

    const storageKey = await deriveStorageKey(password, salt);
    const decryptedData = await subtle.decrypt({ name: 'AES-GCM', iv }, storageKey, encryptedData);
    const keyData = TEXT_DECODER.decode(decryptedData);

    return JSON.parse(keyData);
  } catch (error) {
    throw new Error(`Failed to decrypt keys: ${error.message}`);
  }
}

// Simplified API: Clear keys (both session storage and encrypted persistent storage)
export async function clear(name = 'user') {
  let cleared = false;

  // Clear from session storage (browser only)
  if (typeof window !== 'undefined' && window.sessionStorage) {
    try {
      if (name === null) {
        // Clear all UnSEA session data
        const keys = Object.keys(sessionStorage);
        keys.forEach(key => {
          if (key.startsWith('unsea.')) {
            sessionStorage.removeItem(key);
          }
        });
        cleared = true;
      } else {
        const sessionKey = `unsea.${name}`;
        sessionStorage.removeItem(sessionKey);
        cleared = true;
      }
    } catch (error) {
      console.warn('Failed to clear keypair from session storage:', error.message);
    }
  }

  // Clear from persistent storage
  try {
    await del(name);
    cleared = true;
  } catch (error) {
    console.warn('Failed to clear keypair from persistent storage:', error.message);
  }

  return cleared;
}

// Simplified API: Recall keys from session storage (browser only)
export function recall(name = 'user') {
  if (typeof window !== 'undefined' && window.sessionStorage) {
    try {
      const sessionKey = `unsea.${name}`;
      const data = sessionStorage.getItem(sessionKey);
      if (data === null) return null;

      const keypair = JSON.parse(data);

      // Validate it's a proper keypair
      if (!keypair || !keypair.pub || !keypair.priv) {
        console.warn('Invalid keypair found in session storage');
        return null;
      }

      return keypair;
    } catch (error) {
      console.warn('Failed to recall keypair from session storage:', error.message);
      return null;
    }
  }
  return null; // Not in browser environment
}

// Simplified API: Unified proof-of-work functionality
export async function work(data, options = {}) {
  const {
    difficulty = 4,
    maxIterations = 1000000,
    privKey = null,
    pubKey = null,
    verify: shouldVerify = false,
    proof = null
  } = options;

  if (shouldVerify || proof) {
    // Verification mode
    const proofToVerify = proof || data;
    if (!proofToVerify || typeof proofToVerify !== 'object') {
      throw new Error('Proof must be an object for verification');
    }

    if (proofToVerify.signature && pubKey) {
      // Verify signed proof of work
      const workVerification = await verifyWork(proofToVerify);
      if (!workVerification.valid) {
        return {
          valid: false,
          workValid: false,
          signatureValid: false,
          reason: 'Invalid proof of work'
        };
      }

      const signatureValid = await verify(
        proofToVerify.signedPayload,
        proofToVerify.signature,
        pubKey
      );

      return {
        valid: workVerification.valid && signatureValid,
        workValid: workVerification.valid,
        signatureValid,
        workVerification
      };
    } else {
      // Verify regular proof of work
      return await verifyWork(proofToVerify);
    }
  } else {
    // Generation mode
    const workResult = await generateWork(data, difficulty, maxIterations);

    if (privKey) {
      // Generate signed proof of work
      const workPayload = JSON.stringify({
        data: workResult.data,
        nonce: workResult.nonce,
        hash: workResult.hash,
        difficulty: workResult.difficulty,
        timestamp: workResult.timestamp
      });

      const signature = await sign(workPayload, privKey);

      return {
        ...workResult,
        signature,
        signedPayload: workPayload
      };
    } else {
      // Generate regular proof of work
      return workResult;
    }
  }
}

// Internal proof-of-work generation function
async function generateWork(data, difficulty = 4, maxIterations = 1000000) {
  const subtle = getSubtle();
  const target = '0'.repeat(difficulty);
  const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

  let nonce = 0;
  let hash;
  let hashHex;

  const startTime = Date.now();

  while (nonce < maxIterations) {
    const payload = `${dataStr}:${nonce}`;
    const payloadBuf = TEXT_ENCODER.encode(payload);
    const hashBuf = await subtle.digest('SHA-256', payloadBuf);
    const hashArray = new Uint8Array(hashBuf);

    // Convert to hex string
    hashHex = Array.from(hashArray)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (hashHex.startsWith(target)) {
      hash = bufToB64Url(hashBuf);
      break;
    }

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
    hashRate: Math.round(nonce / (duration / 1000))
  };
}

// Internal proof-of-work verification function
async function verifyWork(proof) {
  if (!proof || typeof proof !== 'object') {
    throw new Error('Proof must be an object');
  }
  if (typeof proof.data !== 'string' || typeof proof.nonce !== 'number' ||
    typeof proof.difficulty !== 'number' || !proof.hash || !proof.hashHex) {
    throw new Error('Proof must contain data, nonce, difficulty, hash, and hashHex');
  }

  const subtle = getSubtle();
  const target = '0'.repeat(proof.difficulty);

  // Reconstruct the payload
  const payload = `${proof.data}:${proof.nonce}`;
  const payloadBuf = TEXT_ENCODER.encode(payload);
  const hashBuf = await subtle.digest('SHA-256', payloadBuf);
  const hashArray = new Uint8Array(hashBuf);

  // Convert to hex and base64url
  const hashHex = Array.from(hashArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  const hashB64 = bufToB64Url(hashBuf);

  // Use constant-time comparison for hash verification
  const expectedHashB64 = TEXT_ENCODER.encode(proof.hash);
  const computedHashB64 = TEXT_ENCODER.encode(hashB64);
  const expectedHashHex = TEXT_ENCODER.encode(proof.hashHex);
  const computedHashHex = TEXT_ENCODER.encode(hashHex);

  const validHashB64 = constantTimeEqual(expectedHashB64, computedHashB64);
  const validHashHex = constantTimeEqual(expectedHashHex, computedHashHex);
  const validHash = validHashB64 && validHashHex;
  const validDifficulty = hashHex.startsWith(target);

  return {
    valid: validHash && validDifficulty,
    hashMatches: validHash,
    difficultyMatches: validDifficulty,
    computedHash: hashB64,
    computedHashHex: hashHex,
    expectedDifficulty: target
  };
}

// Simplified API: Get library information and security details
export function info() {
  return {
    version: '2.0.0',
    securityEnhancements: [
      'Bundled dependencies with static imports',
      'Proper PKCS#8 PEM encoding/decoding',
      'Encrypted key storage with PBKDF2',
      'Input validation and sanitization',
      'Constant-time comparisons',
      'Enhanced error handling',
      'Simplified unified API',
      'Multiple output formats for compatibility'
    ],
    algorithms: {
      signing: 'ECDSA with P-256 and SHA-256',
      encryption: 'ECDH + AES-GCM',
      keyDerivation: 'PBKDF2 with SHA-256',
      proofOfWork: 'SHA-256 based mining'
    },
    api: {
      pair: 'Generate random keypair or derive from passphrase',
      derive: 'Derive keypair from passphrase',
      sign: 'Sign message with private key',
      verify: 'Verify message signature',
      encrypt: 'Encrypt message (ephemeral or authenticated)',
      decrypt: 'Decrypt message',
      export: 'Export key to JWK or PEM format',
      import: 'Import key from various formats',
      save: 'Save keys to session or persistent storage',
      load: 'Load keys from storage',
      clear: 'Clear keys from storage',
      recall: 'Recall keys from session storage',
      work: 'Generate or verify proof-of-work',
      info: 'Get library information'
    },
    warnings: [
      'Keys stored without password are unencrypted',
      'PEM format uses simplified PKCS#8 structure',
      'Proof of work verification uses constant-time comparison for hashes only',
      'Dependencies are bundled at build time - verify bundle integrity'
    ]
  };
}
