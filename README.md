# Unsea

> Platform-agnostic cryptograFor ES modules in the browser:
```html
<script type="module">
  import * as unsea from 'https://unpkg.com/unsea/dist/unsea.mjs';
  
  const keys = await unsea.generateRandomPair();
  console.log(keys);
</script>
```

### Local Development
```bash
# Clone and setup
git clone https://github.com/draeder/unsea.git
cd unsea
npm install

# Setup development environment (configures git hooks, etc.)
npm run ci:setup

# Development server (for testing in browser)
npm run dev
# Opens http://localhost:5173/ with live testing interface

# Build the library
npm run build

# Run examples and tests
npm run example
npm test

# Security audit
npm run security:audit
```

### Contributing

This project uses a comprehensive CI/CD pipeline to ensure code quality and security:

- 🔍 **Automated Security Scanning**: Every commit is scanned for vulnerabilities
- 🧪 **Multi-Platform Testing**: Tests run on Linux, Windows, and macOS
- 🌐 **Browser Compatibility**: Automated browser testing with multiple engines
- 📦 **Package Integrity**: Validates package installation and imports
- 🚦 **Pre-commit Hooks**: Local validation before commits
- 👥 **Required Reviews**: All changes must be reviewed before merging

See [CI/CD Documentation](.github/CICD_README.md) for detailed information.

---ity toolkit for ephemeral identity, secure messaging, and portable key management — built on WebCrypto + noble-curves.

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
- 📦 Bundled with Vite for optimal performance and security
- ⚙️ Multiple formats: ES modules (.mjs), CommonJS (.cjs), and UMD (.js) for maximum compatibility
- 🌐 Cross-platform: Works seamlessly in Node.js 20+ and modern browsers

---

## 📦 Installation

```bash
npm install unsea
```

Or use directly in the browser via CDN:

```html
<script src="https://cdn.jsdelivr.net/npm/unsea/dist/unsea.umd.js"></script>
<script>
  // UMD version exposes Unsea globally
  const keys = await Unsea.generateRandomPair();
  console.log(keys);
</script>
```

For ES modules in the browser:
```html
<script type="module">
  import * as unsea from 'https://cdn.jsdelivr.net/npm/unsea/dist/unsea.mjs';
  
  const keys = await unsea.generateRandomPair();
  console.log(keys);
</script>
```

---

## � Build Architecture

Unsea uses Vite for modern bundling with multiple output formats:

| Format | File | Environment | Usage |
|--------|------|-------------|-------|
| ES Modules | `dist/unsea.mjs` | Modern Node.js, browsers | `import * as unsea from 'unsea'` |
| CommonJS | `dist/unsea.cjs` | Traditional Node.js | `const unsea = require('unsea')` |
| UMD | `dist/unsea.umd.js` | Browsers (global) | `<script src="...">` → `Unsea.generateRandomPair()` |

### Benefits of Bundled Approach
- 🚀 **Faster loading** - No dynamic imports at runtime
- 🔒 **Better security** - All dependencies statically analyzed
- 📦 **Smaller bundles** - Tree-shaking removes unused code
- ⚡ **Reliable** - No network dependencies or import failures
- 🌐 **Universal** - Works consistently across all environments

### Development Mode
For development and testing, you can use the built-in development server:

```bash
npm run dev
```

This starts a Vite development server with:
- 🔄 **Hot reload** - Automatic updates when source code changes
- 🧪 **Live testing interface** - Interactive browser testing environment
- 🐛 **Source maps** - Debug directly in the original source code
- ⚡ **Fast compilation** - Near-instant updates during development

The development server serves the library directly from `src/index.js` without bundling, making it perfect for rapid development and testing.

---

## �🚀 Quick Start

```bash
# Install the package
npm install unsea

# Build the library
npm run build

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
├── src/
│   └── index.js          # Main library source code
├── dist/                 # Built library files (generated)
│   ├── unsea.mjs         # ES modules
│   ├── unsea.cjs         # CommonJS
│   └── unsea.umd.js      # UMD for browsers
├── example/
│   └── example.js        # Usage examples and demos
├── test/
│   └── test.js          # Comprehensive test suite  
├── index.html            # Development server interface
├── vite.config.js        # Build configuration
├── README.md
├── SECURITY.md
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

- **Bundled Dependencies**: Static imports eliminate runtime dependency risks
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