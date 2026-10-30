# Unsea

> Platform-agnostic cryptographic utility toolkit for ephemeral identity, secure messaging, and portable key management — built on WebCrypto + noble-curves.

```html
<script type="module">
	import * as unsea from "https://unpkg.com/unsea/dist/unsea.mjs";

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
# Opens comprehensive testing interface at http://localhost:5173/

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
- #️⃣ SHA-256 hashing for text and binary input with hex, base64url, or byte output
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

	const keys = await unsea.generateRandomPair();
	console.log(keys);
</script>
```

You can have a global `Unsea` object with UMD in the browser:

```html
<script src="https://cdn.jsdelivr.net/npm/unsea/dist/unsea.umd.js"></script>
<script>
	// UMD version exposes Unsea globally
	const keys = await Unsea.generateRandomPair();
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
- 🧪 **Comprehensive testing interface** - Access directly at `http://localhost:5173/`
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
	sha256,
	generateRandomPair,
	derivePair,
	signMessage,
	verifyMessage,
	encryptMessageWithMeta,
	decryptMessageWithMeta,
	encryptBySenderForReceiver,    // NEW: Private chat encryption
	decryptBySenderForReceiver,    // NEW: Private chat decryption
	exportToPEM,
	importFromPEM,
	exportToJWK,
	importFromJWK,
	saveKeys,
	loadKeys,
	clearKeys,
	save, // Session storage
	recall, // Session storage
	clear, // Session storage
	generateWork,
	verifyWork,
	generateSignedWork,
	verifySignedWork,
	getSecurityInfo,
} from "unsea";

const routingKey = await sha256("freertc:network:room");

const keys = await generateRandomPair();
// OR
const deterministicKeys = await derivePair(
	"your-long-and-high-entropy-passphrase",
	"alice" // per-user salt, such as the user's alias (required)
);

// Secure encrypted storage
await saveKeys("default", keys, "your-strong-password");

const msg = "Hello, Unsea!";
const sig = await signMessage(msg, keys.priv);
const valid = await verifyMessage(msg, sig, keys.pub);

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
const alice = await generateRandomPair();
const bob = await generateRandomPair();

// Alice encrypts for Bob using her private key + Bob's public key
const encrypted = await encryptBySenderForReceiver(
  'Secret message', 
  alice.epriv, 
  bob.epub
);

// Bob decrypts using Alice's public key + his private key
// (epriv1 + epub2 = epriv2 + epub1 - same shared secret)
const decrypted = await decryptBySenderForReceiver(
  encrypted, 
  alice.epub, 
  bob.epriv
);
```

**Key differences:**
- 🔒 **Authenticated**: Both parties know who sent/received the message
- 🚀 **Deterministic**: Same shared secret for ongoing conversations
- 💬 **Perfect for**: Private chat, secure messaging between known identities
- 🆚 **vs encryptMessageWithMeta**: No ephemeral keys, no metadata, smaller payload

---

## 🔁 Export / Import Keys

```js
const pem = await exportToPEM(keys.priv);
const restoredPriv = await importFromPEM(pem);

const jwk = await exportToJWK(keys.priv);
const restoredFromJwk = await importFromJWK(jwk);
```

---

## � Session Storage (Browser Only)

Similar to Gun's SEA `user.recall()` functionality - stores keypairs in browser session storage for persistence across page refreshes:

```js
// Generate keypairs
const alice = await generateRandomPair();
const bob = await generateRandomPair();

// Save keypairs to session storage (browser only), encrypted with a password
await save(alice, "alice", "alice-password");
await save(bob, "bob", "bob-password");

// Recall keypairs (like Gun's user.recall())
const recalledAlice = await recall("alice", "alice-password"); // {pub, priv, ...} or null
const recalledBob = await recall("bob", "bob-password");

// Use recalled keypairs for crypto operations
if (recalledAlice) {
	const signature = await signMessage("hello", recalledAlice.priv);
	const isValid = await verifyMessage("hello", signature, recalledAlice.pub);
}

// Clear session data
clear("alice"); // Clear specific user
clear(null); // Clear all UnSEA session data
```

**Features:**

- ✅ Persists across page refreshes (until browser tab closes)
- ✅ Encrypted with a password (PBKDF2-SHA256, 600,000 iterations, AES-GCM): sessionStorage is readable by every script on the page. Plain-text storage needs `{ allowUnencrypted: true }`
- ✅ Browser-only (returns null in Node.js)
- ✅ Validates keypair structure
- ✅ Namespaced with `unsea.` prefix to avoid conflicts

---

## �💾 Key Persistence (Browser Only)

```js
await saveKeys("profile1", keys, "your-strong-password");
const loaded = await loadKeys("profile1", "your-strong-password");
await clearKeys("profile1");
```

---

## 🧩 Message Metadata Format

```json
{
	"v": 2,
	"ciphertext": "...",
	"iv": "...",
	"sender": "base64url(x.y)",
	"timestamp": 1723981192738
}
```

The key comes from HKDF-SHA256 over the ECDH shared secret, bound to the sender's
and the recipient's public keys, and `sender` and `timestamp` are authenticated as
AES-GCM additional data: changing either makes decryption fail. Payloads without
`v` come from unsea 1.x; they still decrypt, but their timestamp is not authenticated.

---

## ⛏️ Proof of Work

```js
// Generate proof of work (for rate limiting, anti-spam, etc.)
const data = { challenge: "computational_proof", user: "alice" };
const work = await generateWork(
	data,
	(difficulty = 4),
	(maxIterations = 1000000)
);
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

// Verify proof of work. The verifier sets the minimum difficulty (default 4);
// the difficulty written in the proof is only what the prover claims.
const verification = await verifyWork(work, { minDifficulty: 4, maxAgeMs: 60_000 });
console.log(verification.valid); // true

// Generate signed proof of work (authenticated computational proof)
const keys = await generateRandomPair();
const signedWork = await generateSignedWork(data, keys.priv, (difficulty = 4));
console.log(signedWork.signature);

// Verify signed proof of work: the signature must cover this exact proof
const signedVerification = await verifySignedWork(signedWork, keys.pub, { minDifficulty: 4 });
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
│   ├── index.html        # Comprehensive browser testing interface
│   └── example.js        # Node.js usage examples and demos
├── test/
│   └── test.js          # Comprehensive test suite
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

- **Exact messages**: messages are signed and encrypted byte for byte, with no trimming or normalization
- **Authenticated encryption metadata**: HKDF-SHA256 keys bound to both public keys; sender and timestamp authenticated by AES-GCM; private-chat keys differ per direction
- **Salted password-derived keys**: `derivePair` needs a per-user salt (PBKDF2-SHA256, 600,000 iterations)
- **Encrypted key storage by default**: `saveKeys` and `save` need a password (PBKDF2-SHA256, 600,000 iterations)
- **Proofs of work the verifier controls**: the verifier sets the minimum difficulty, and a signed proof's signature covers that exact proof
- **Strict key handling**: real PKCS#8 parsing, public keys checked to be on P-256, one signature encoding (compact, low S)
- **Bundled Dependencies**: Static imports eliminate runtime dependency risks

For detailed security information, see [SECURITY.md](SECURITY.md).

---

## 🔁 Secure Key Storage

```js
// Encrypted storage (recommended)
const password = "your-strong-password";
await saveKeys("profile", keys, password);
const loadedKeys = await loadKeys("profile", password);

// Unencrypted storage must be asked for explicitly
await saveKeys("profile", keys, null, { allowUnencrypted: true });
const loadedKeys = await loadKeys("profile", null, { allowUnencrypted: true });
```

---

## ⬆️ Upgrading from 1.x

2.0.0 fixes several security problems, and some fixes change behaviour:

| Change | What to do |
| --- | --- |
| `derivePair(password)` needs a salt | Pass a per-user salt: `derivePair(password, alias)`. This gives new keys; to reproduce 1.x keys (to migrate), use `derivePair(password, { legacyUnsalted: true })` |
| Messages are no longer trimmed or NFC-normalized before signing or encrypting | Signatures made by 1.x over text with leading or trailing whitespace, or non-NFC text, no longer verify; sign the exact text |
| Encrypted payloads are version 2 (`v: 2`) | 2.x decrypts 1.x payloads; 1.x cannot decrypt 2.x payloads, so upgrade every party that decrypts |
| `verifyWork` / `verifySignedWork` enforce a minimum difficulty (default 4) | Pass `{ minDifficulty }` for lower difficulties; signed proofs from 1.x no longer verify |
| `saveKeys`, `save` need a password; `loadKeys`, `recall` refuse unencrypted records | Pass a password, or `{ allowUnencrypted: true }` to read old records and save them again encrypted |
| `save` and `recall` are async | `await` them |
| `importFromPEM` only accepts well-formed P-256 PKCS#8 | Keys exported by unsea or WebCrypto import as before |
| Signatures must be the 64-byte compact form with low S | Signatures from `signMessage` are already in that form |

---

## License

MIT © 2025
