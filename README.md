# Unsea

> Platform-agnostic cryptographic utility toolkit for ephemeral identity, secure messaging, and portable key management — built on WebCrypto + noble-curves.

## 🔐 Features

- 🔑 Deterministic or random P-256 keypair generation
- ✍️ Message signing and verification (ECDSA)
- 🔒 Message encryption and decryption (ECDH + AES-GCM)
- 📦 Encrypted message metadata: sender pubkey and timestamp
- 🔁 Export/import keys to JWK and PEM formats (PKCS#8 compliant)
- 💾 Encrypted IndexedDB persistence with password protection
- ⛏️ Proof-of-work generation and verification (SHA-256 based mining)
- 📝 Signed proof-of-work with cryptographic attestation
- 🛡️ Enhanced security: input validation, constant-time operations, proper error handling
- ⚙️ Compatible with both Node.js and modern browsers via dynamic import fallback

---

## 📦 Installation

```bash
npm install unsea
```

Or use directly in the browser via CDN:

```html
<script type="module">
  import * as unsea from 'https://cdn.skypack.dev/unsea';

  const keys = await unsea.generateRandomPair();
  console.log(keys);
</script>
```

---

## 🚀 Quick Start

```bash
# Install the package
npm install unsea

# Run the example
npm run example

# Run tests
npm test
```

---

## 🧪 Example Usage

```js
import {
  generateRandomPair,
  signMessage,
  verifyMessage,
  encryptMessageWithMeta,
  decryptMessageWithMeta,
  exportToPEM,
  importFromPEM,
  exportToJWK,
  importFromJWK,
  saveKeys,
  loadKeys,
  clearKeys,
  generateWork,
  verifyWork,
  generateSignedWork,
  verifySignedWork,
  getSecurityInfo
} from 'unsea';

const keys = await generateRandomPair();
// Secure encrypted storage
await saveKeys('default', keys, 'your-strong-password');

const msg = 'Hello, Unsea!';
const sig = await signMessage(msg, keys.priv);
const valid = await verifyMessage(msg, sig, keys.pub);

const encrypted = await encryptMessageWithMeta(msg, keys);
const decrypted = await decryptMessageWithMeta(encrypted, keys.epriv);

// Get security information
console.log(getSecurityInfo());

console.log({ valid, decrypted });
```

---

## 🔁 Export / Import Keys

```js
const pem = await exportToPEM(keys.priv);
const restoredPriv = await importFromPEM(pem);

const jwk = await exportToJWK(keys.priv);
const restoredFromJwk = await importFromJWK(jwk);
```

---

## 💾 Key Persistence (Browser Only)

```js
await saveKeys('profile1', keys);
const loaded = await loadKeys('profile1');
await clearKeys('profile1');
```

---

## 🧩 Message Metadata Format

```json
{
  "ciphertext": "...",
  "iv": "...",
  "sender": "base64url(x.y)",
  "timestamp": 1723981192738
}
```

---

## ⛏️ Proof of Work

```js
// Generate proof of work (for rate limiting, anti-spam, etc.)
const data = { challenge: 'computational_proof', user: 'alice' };
const work = await generateWork(data, difficulty = 4, maxIterations = 1000000);
console.log(work);
// {
//   data: '{"challenge":"computational_proof","user":"alice"}',
//   nonce: 12847,
//   hash: 'ABC123...',
//   hashHex: '0000a1b2c3...',
//   difficulty: 4,
//   timestamp: 1723981192738,
//   duration: 2341,
//   hashRate: 5489
// }

// Verify proof of work
const verification = await verifyWork(work);
console.log(verification.valid); // true

// Generate signed proof of work (authenticated computational proof)
const keys = await generateRandomPair();
const signedWork = await generateSignedWork(data, keys.priv, difficulty = 4);
console.log(signedWork.signature);

// Verify signed proof of work
const signedVerification = await verifySignedWork(signedWork, keys.pub);
console.log(signedVerification.valid); // true
```

---

## 📁 Project Structure

```
unsea/
├── index.js              # Main library
├── example/
│   └── example.js        # Usage examples and demos
├── test/
│   └── test.js          # Comprehensive test suite
├── README.md
├── package.json
└── LICENSE
```

Run `npm run example` to see all features in action!

---

## ⚙️ Internals

- Uses dynamic `import()` for browser/Node compatibility
- WebCrypto `subtle` for hashing + AES
- `@noble/curves/p256` for EC operations
- Base64url encoding utilities for compact key/IV/sig serialization

---

## 🛡️ Security

This library implements several security best practices:

- **Encrypted Key Storage**: Keys can be encrypted with PBKDF2 before storage
- **Input Validation**: All inputs are validated and sanitized
- **Constant-Time Operations**: Hash comparisons use constant-time algorithms
- **Proper Error Handling**: No sensitive data leaked in error messages
- **PKCS#8 Compliance**: PEM format follows cryptographic standards

For detailed security information, see [SECURITY.md](SECURITY.md).

---

## 🔁 Secure Key Storage

```js
// Encrypted storage (recommended)
const password = 'your-strong-password';
await saveKeys('profile', keys, password);
const loadedKeys = await loadKeys('profile', password);

// Unencrypted storage (shows warning)
await saveKeys('profile', keys);
const loadedKeys = await loadKeys('profile');
```

---
## License

MIT © 2025