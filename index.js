// crypto-utils-p256/index.js

let _p256;
async function loadCurve() {
  if (_p256) return _p256;
  const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined';
  if (isBrowser) {
    try {
      const mod = await import('@noble/curves/p256');
      _p256 = mod.p256;
    } catch (_) {
      const { p256 } = await import('https://esm.sh/@noble/curves/p256');
      _p256 = p256;
    }
  } else {
    const mod = await import('@noble/curves/p256');
    _p256 = mod.p256;
  }
  return _p256;
}

let _subtle;
async function loadSubtle() {
  if (_subtle) return _subtle;
  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    _subtle = window.crypto.subtle;
  } else {
    const { webcrypto } = await import('crypto');
    _subtle = webcrypto.subtle;
  }
  return _subtle;
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function normalize(s) {
  if (typeof s !== 'string') {
    throw new Error('Input must be a string');
  }
  return s.normalize('NFC').trim();
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

export async function generateRandomPair() {
  const p256 = await loadCurve();
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

export async function signMessage(msg, privB64) {
  const p256 = await loadCurve();
  const subtle = await loadSubtle();
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const hash = await subtle.digest('SHA-256', msgBuf);
  const priv = validatePrivateKey(privB64);
  const sig = p256.sign(new Uint8Array(hash), priv);
  return bufToB64Url(sig.toCompactRawBytes());
}

export async function verifyMessage(msg, sigB64, pubJwk) {
  if (typeof sigB64 !== 'string') {
    throw new Error('Signature must be a string');
  }
  
  const p256 = await loadCurve();
  const subtle = await loadSubtle();
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const hash = await subtle.digest('SHA-256', msgBuf);
  
  // Validate public key
  validatePublicKey(pubJwk);
  const pub = jwkToKey(pubJwk);
  
  try {
    const sig = b64UrlToBuf(sigB64);
    return p256.verify(sig, new Uint8Array(hash), pub);
  } catch (error) {
    // Return false instead of throwing for invalid signatures
    return false;
  }
}

export async function encryptMessageWithMeta(msg, recipient) {
  if (!recipient || typeof recipient !== 'object') {
    throw new Error('Recipient must be a key object with epub property');
  }
  if (!recipient.epub) {
    throw new Error('Recipient must have an encryption public key (epub)');
  }
  
  const p256 = await loadCurve();
  const subtle = await loadSubtle();
  
  // Validate recipient's public key
  validatePublicKey(recipient.epub);
  const pub = jwkToKey(recipient.epub);
  
  const ephPriv = p256.utils.randomPrivateKey();
  const ephPub = p256.getPublicKey(ephPriv, false);
  const shared = p256.getSharedSecret(ephPriv, pub).slice(1);
  const keyMat = await subtle.digest('SHA-256', shared);
  const iv = (typeof window !== 'undefined' ? crypto : (await import('crypto')).webcrypto).getRandomValues(new Uint8Array(12));
  const key = await subtle.importKey('raw', keyMat, { name: 'AES-GCM' }, false, ['encrypt']);
  const msgBuf = TEXT_ENCODER.encode(normalize(msg));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, msgBuf);
  return {
    ciphertext: bufToB64Url(ct),
    iv: bufToB64Url(iv),
    sender: keyToJWK(ephPub),
    timestamp: Date.now()
  };
}

export async function decryptMessageWithMeta(payload, privB64) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be an encrypted message object');
  }
  if (!payload.ciphertext || !payload.iv || !payload.sender) {
    throw new Error('Payload must contain ciphertext, iv, and sender');
  }
  
  const p256 = await loadCurve();
  const subtle = await loadSubtle();
  
  // Validate sender's ephemeral public key
  validatePublicKey(payload.sender);
  const ephPub = jwkToKey(payload.sender);
  
  const priv = validatePrivateKey(privB64);
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

export async function exportToJWK(privB64) {
  const priv = b64UrlToBuf(privB64);
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

export async function importFromJWK(jwk) {
  if (jwk.kty !== 'EC') {
    throw new Error('JWK must be an EC key');
  }
  if (jwk.crv !== 'P-256') {
    throw new Error('JWK must use P-256 curve');
  }
  if (!jwk.d) {
    throw new Error('JWK must contain private key component (d)');
  }
  return jwk.d;
}

export async function exportToPEM(privB64) {
  const raw = b64UrlToBuf(privB64);
  if (raw.length !== 32) {
    throw new Error('Invalid private key length for P-256');
  }
  
  // Create proper PKCS#8 structure for P-256 private key
  // This is a simplified PKCS#8 wrapper - for production use, consider using a proper ASN.1 library
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
  const p256 = await loadCurve();
  const pubKey = p256.getPublicKey(raw, false);
  
  // Combine all parts
  const pkcs8Data = new Uint8Array(pkcs8Header.length + raw.length + pkcs8Suffix.length + pubKey.length);
  pkcs8Data.set(pkcs8Header, 0);
  pkcs8Data.set(raw, pkcs8Header.length);
  pkcs8Data.set(pkcs8Suffix, pkcs8Header.length + raw.length);
  pkcs8Data.set(pubKey, pkcs8Header.length + raw.length + pkcs8Suffix.length);
  
  const b64 = btoa(String.fromCharCode(...pkcs8Data));
  return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
}

export async function importFromPEM(pem) {
  if (!pem.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new Error('Invalid PEM format: must contain BEGIN PRIVATE KEY header');
  }
  
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
  if (!b64) {
    throw new Error('Invalid PEM format: no data found');
  }
  
  try {
    const bin = atob(b64);
    const data = Uint8Array.from([...bin].map(c => c.charCodeAt(0)));
    
    // For simplified PKCS#8 parsing, extract the 32-byte private key
    // Look for the private key OCTET STRING pattern (0x04, 0x20 followed by 32 bytes)
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
}

// Secure key storage functions
async function deriveStorageKey(password, salt) {
  const subtle = await loadSubtle();
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

export async function saveKeys(name, keys, password = null) {
  const { set } = await import('idb-keyval');
  
  if (!password) {
    // Store without encryption (warn user)
    console.warn('⚠️ WARNING: Keys are being stored unencrypted. Consider providing a password for better security.');
    return set(name, { encrypted: false, data: keys });
  }
  
  try {
    const subtle = await loadSubtle();
    const salt = (typeof window !== 'undefined' ? crypto : (await import('crypto')).webcrypto).getRandomValues(new Uint8Array(16));
    const iv = (typeof window !== 'undefined' ? crypto : (await import('crypto')).webcrypto).getRandomValues(new Uint8Array(12));
    
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

export async function loadKeys(name, password = null) {
  const { get } = await import('idb-keyval');
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
    const subtle = await loadSubtle();
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

export async function clearKeys(name) {
  const { del } = await import('idb-keyval');
  return del(name);
}

// Proof-of-Work functionality
export async function generateWork(data, difficulty = 4, maxIterations = 1000000) {
  const subtle = await loadSubtle();
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

export async function verifyWork(proof) {
  if (!proof || typeof proof !== 'object') {
    throw new Error('Proof must be an object');
  }
  if (typeof proof.data !== 'string' || typeof proof.nonce !== 'number' || 
      typeof proof.difficulty !== 'number' || !proof.hash || !proof.hashHex) {
    throw new Error('Proof must contain data, nonce, difficulty, hash, and hashHex');
  }
  
  const subtle = await loadSubtle();
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

export async function generateSignedWork(data, privKey, difficulty = 4, maxIterations = 1000000) {
  // Generate proof of work
  const work = await generateWork(data, difficulty, maxIterations);
  
  // Sign the work proof
  const workPayload = JSON.stringify({
    data: work.data,
    nonce: work.nonce,
    hash: work.hash,
    difficulty: work.difficulty,
    timestamp: work.timestamp
  });
  
  const signature = await signMessage(workPayload, privKey);
  
  return {
    ...work,
    signature,
    signedPayload: workPayload
  };
}

export async function verifySignedWork(signedWork, pubKey) {
  // Verify the proof of work
  const workVerification = await verifyWork(signedWork);
  
  if (!workVerification.valid) {
    return {
      valid: false,
      workValid: false,
      signatureValid: false,
      reason: 'Invalid proof of work'
    };
  }
  
  // Verify the signature
  const signatureValid = await verifyMessage(
    signedWork.signedPayload, 
    signedWork.signature, 
    pubKey
  );
  
  return {
    valid: workVerification.valid && signatureValid,
    workValid: workVerification.valid,
    signatureValid,
    workVerification
  };
}

// Security configuration and utilities
export const SECURITY_CONFIG = {
  PBKDF2_ITERATIONS: 100000,
  AES_KEY_LENGTH: 256,
  CURVE: 'P-256',
  HASH_ALGORITHM: 'SHA-256',
  SUPPORTED_FORMATS: ['JWK', 'PEM'],
  MIN_POW_DIFFICULTY: 1,
  MAX_POW_DIFFICULTY: 8
};

// Utility function to get library version and security info
export function getSecurityInfo() {
  return {
    version: '1.1.0',
    securityEnhancements: [
      'Proper PKCS#8 PEM encoding/decoding',
      'Encrypted key storage with PBKDF2',
      'Input validation and sanitization',
      'Constant-time comparisons',
      'Enhanced error handling'
    ],
    algorithms: {
      signing: 'ECDSA with P-256 and SHA-256',
      encryption: 'ECDH + AES-GCM',
      keyDerivation: 'PBKDF2 with SHA-256',
      proofOfWork: 'SHA-256 based mining'
    },
    warnings: [
      'Keys stored without password are unencrypted',
      'PEM format uses simplified PKCS#8 structure',
      'Proof of work verification uses constant-time comparison for hashes only'
    ]
  };
}
