# Unsea

> Platform-agnostic cryptographic utility toolkit for ephemeral identity, secure messaging, and portable key management — built on WebCrypto + noble-curves.

```html
<script type="module">
	import * as unsea from "https://unpkg.com/unsea/dist/unsea.mjs";

	const keys = await unsea.pair();
	console.log(keys);
</script>
```

### Local Development

```bash
# Clone and setup
git clone https://githu```

---/draeder/unsea.git
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
- � **CodeQL Analysis**: Manual security scanning available with `npm run codeql:quick`
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

Or import directly from a CDN:

```html
<script type="module">
	import * as unsea from "https://esm.sh/unsea/dist/unsea.mjs";

	const keys = await unsea.pair();
	console.log(keys);
</script>
```

You can have a global `Unsea` object with UMD in the browser:

```html
<script src="https://cdn.jsdelivr.net/npm/unsea/dist/unsea.umd.js"></script>
<script>
	// UMD version exposes Unsea globally
	const keys = await Unsea.pair();
	console.log(keys);
</script>
```

---

## � Build Architecture

Unsea uses Vite for modern bundling with multiple output formats:

| Format     | File                | Environment              | Usage                                               |
| ---------- | ------------------- | ------------------------ | --------------------------------------------------- |
| ES Modules | `dist/unsea.mjs`    | Modern Node.js, browsers | `import * as unsea from 'unsea'`                    |
| CommonJS   | `dist/unsea.cjs`    | Traditional Node.js      | `const unsea = require('unsea')`                    |
| UMD        | `dist/unsea.umd.js` | Browsers (global)        | `<script src="...">` → `Unsea.generateRandomPair()` |

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
- 🧪 **Comprehensive testing interface** - Access via `http://localhost:5173/example/browser.html`
- 🐛 **Source maps** - Debug directly in the original source code
- ⚡ **Fast compilation** - Near-instant updates during development
- 🌐 **Global API access** - All functions available via `window.unsea` for console debugging

The comprehensive testing interface includes 8 complete test suites: cryptographic tests, session storage, key derivation, and more - all using the bundled library for production-accurate testing.

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
	pair,
	derive,
	sign,
	verify,
	encrypt,
	decrypt,
	export,
	import,
	save,
	load,
	clear,
	recall,
	work,
	info,
} from "unsea";

// Generate random keypair or derive from passphrase
const keys = await pair(); // Random generation
// OR
const deterministicKeys = await pair("your-long-and-high-entropy-passphrase");
// OR (explicit derivation)
const derivedKeys = await derive("your-long-and-high-entropy-passphrase");

// Secure encrypted storage
await save(keys, "default", "your-strong-password");

const msg = "Hello, Unsea!";
const sig = await sign(msg, keys.priv);
const valid = await verify(msg, sig, keys.pub);

// Ephemeral encryption (includes metadata)
const encrypted = await encrypt(msg, keys.epub);
const decrypted = await decrypt(encrypted, keys.epriv);

// Authenticated encryption (between known parties)
const authEncrypted = await encrypt(msg, keys.epub, keys.epriv);
const authDecrypted = await decrypt(authEncrypted, keys.epriv, keys.epub);

// Get security information
console.log(info());

console.log({ valid, decrypted });
```

const encrypted = await encryptMessageWithMeta(msg, keys);
const decrypted = await decryptMessageWithMeta(encrypted, keys.epriv);

// Get security information
console.log(getSecurityInfo());

console.log({ valid, decrypted });
```

---

## 💬 Private Chat Encryption

For authenticated private messaging between known parties (baseline asymmetric encryption):

```js
const alice = await pair();
const bob = await pair();

// Alice encrypts for Bob using her private key + Bob's public key
const encrypted = await encrypt(
  'Secret message', 
  bob.epub,    // Bob's public key (recipient)
  alice.epriv  // Alice's private key (sender)
);

// Bob decrypts using Alice's public key + his private key
// (epriv1 + epub2 = epriv2 + epub1 - same shared secret)
const decrypted = await decrypt(
  encrypted, 
  bob.epriv,   // Bob's private key (recipient)
  alice.epub   // Alice's public key (sender)
);
```

**Key differences:**
- 🔒 **Authenticated**: Both parties know who sent/received the message
- 🚀 **Deterministic**: Same shared secret for ongoing conversations
- 💬 **Perfect for**: Private chat, secure messaging between known identities
- 🆚 **vs ephemeral encryption**: No ephemeral keys, no metadata, smaller payload

---

## 🔁 Export / Import Keys

```js
// Export to PEM format
const pem = await export(keys.priv, 'pem');
const restoredPriv = await import(pem);

// Export to JWK format (default)
const jwk = await export(keys.priv);
const restoredFromJwk = await import(jwk);
```

---

## 📦 Session Storage (Browser Only)

Similar to Gun's SEA `user.recall()` functionality - stores keypairs in browser session storage for persistence across page refreshes:

```js
// Generate keypairs
const alice = await pair();
const bob = await pair();

// Save keypairs to session storage (browser only)
save(alice, "alice"); // Save Alice's keypair
save(bob, "bob"); // Save Bob's keypair

// Recall keypairs (like Gun's user.recall())
const recalledAlice = recall("alice"); // Returns {pub, priv} or null
const recalledBob = recall("bob");

// Use recalled keypairs for crypto operations
if (recalledAlice) {
	const signature = await sign("hello", recalledAlice.priv);
	const isValid = await verify("hello", signature, recalledAlice.pub);
}

// Clear session data
clear("alice"); // Clear specific user
clear(null); // Clear all UnSEA session data
```

**Features:**

- ✅ Persists across page refreshes (until browser tab closes)
- ✅ Browser-only (gracefully fails in Node.js)
- ✅ Validates keypair structure
- ✅ Namespaced with `unsea.` prefix to avoid conflicts

---

## 💾 Persistent Key Storage

```js
// Save with encryption (recommended)
await save(keys, "profile1", "your-strong-password");
const loaded = await load("profile1", "your-strong-password");

// Save without encryption (shows warning)
await save(keys, "profile1");
const loaded = await load("profile1");

// Clear stored keys
await clear("profile1");
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
const data = { challenge: "computational_proof", user: "alice" };
const proof = await work(data, { difficulty: 4, maxIterations: 1000000 });
console.log(proof);
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
const verification = await work(proof, { verify: true });
console.log(verification.valid); // true

// Generate signed proof of work (authenticated computational proof)
const keys = await pair();
const signedProof = await work(data, { difficulty: 4, privKey: keys.priv });
console.log(signedProof.signature);

// Verify signed proof of work
const signedVerification = await work(signedProof, { verify: true, pubKey: keys.pub });
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
│   ├── browser.html      # Browser example (legacy)
│   └── example.js        # Node.js usage examples and demos
├── test/
│   └── test.js          # Comprehensive test suite
├── index.html            # Main browser interface with comprehensive testing
├── vite.config.js        # Build configuration
├── README.md
├── SECURITY.md
├── package.json
└── LICENSE
```

Run `npm run example` to see all features in action!

---

## ⚙️ Internals

- Uses static imports via vite for security and browser/Node compatibility
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
const password = "your-strong-password";
await save(keys, "profile", password);
const loadedKeys = await load("profile", password);

// Unencrypted storage (shows warning)
await save(keys, "profile");
const loadedKeys = await load("profile");
```
const loadedKeys = await loadKeys("profile", password);

// Unencrypted storage (shows warning)
await saveKeys("profile", keys);
const loadedKeys = await loadKeys("profile");
```

---

## License

MIT © 2025
