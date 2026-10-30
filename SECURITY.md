# Security Guidelines for Unsea

## Security fixes in 2.0.0

A review of 1.1.3 found these problems; each is fixed and has a regression test
in `test/test.js` (the tests fail against 1.1.3).

| Severity | Problem in 1.x | Fix in 2.0.0 |
| --- | --- | --- |
| High | `verifySignedWork` checked the signature over `signedPayload` as given, which nothing tied to the proof: a valid signature could be attached to someone else's proof | The signature covers a payload rebuilt from the proof's own fields (`unsea/v2/work|…`); a `signedPayload` that differs is refused |
| High | `verifyWork` trusted the difficulty written in the proof; a proof claiming difficulty 0 took no work and passed | The verifier sets `minDifficulty` (default 4); optional `maxAgeMs` rejects old proofs |
| High | `derivePair` used the same fixed salt for everyone, so the same password gave everyone the same keys, and a password guess could be tested against every user at once | A per-user salt is required; 600,000 PBKDF2 iterations. 1.x keys can be reproduced with `{ legacyUnsalted: true }` to migrate |
| Medium | Messages were NFC-normalized and trimmed before signing and encrypting: a signature on "pay bob 100" also verified "  pay bob 100\n" | Messages are signed and encrypted exactly as given |
| Medium | Encryption keys were SHA-256(shared secret); `sender` and `timestamp` were not authenticated; private-chat used one key for both directions, so a message could be bounced back to its sender | HKDF-SHA256 bound to both public keys; metadata authenticated as AES-GCM additional data; private-chat keys differ per direction. Version 1 payloads still decrypt |
| Medium | Keys were stored unencrypted by default (`saveKeys`, and always in session storage by `save`); storage used 100,000 PBKDF2 iterations | A password is required unless `{ allowUnencrypted: true }`; 600,000 iterations (old records still open) |
| Low | `importFromPEM` took the first `04 20` byte pair anywhere in the data as the key | Real DER parsing of P-256 PKCS#8; the embedded public key, if present, must match |
| Low | Public keys were only length-checked; DER and high-S signatures were also accepted | Public keys must be points on P-256; signatures must be 64-byte compact, low S |
| Low | `exportToJWK` left out `x` and `y`; `getSecurityInfo()` reported an old version | Complete JWK; version comes from the release |
| Dev only | `vite` 6.3.5 (dev server) had two high-severity advisories | Updated to 6.4.5 |

See "Upgrading from 1.x" in the README for what changes for callers.

## Security Enhancements (v1.1.2)

This document outlines the security improvements implemented to address potential vulnerabilities in the Unsea cryptographic library.

### ✅ Implemented Security Fixes

#### 1. **Bundled Dependencies with Vite**
- **Issue**: Dynamic imports created security and reliability risks
- **Fix**: Static imports with Vite bundling for all dependencies
- **Impact**: No runtime dependency loading, improved security posture
- **Benefits**: Eliminates supply chain attacks via dynamic imports

#### 2. **Proper PKCS#8 PEM Format**
- **Issue**: Previous PEM implementation was overly simplified
- **Fix**: Implemented proper PKCS#8 ASN.1 structure for P-256 private keys
- **Impact**: Better compatibility with standard cryptographic tools

#### 3. **Encrypted Key Storage**
- **Issue**: Private keys stored in IndexedDB were unencrypted
- **Fix**: Added optional password-based encryption using PBKDF2 + AES-GCM
- **Usage**: `saveKeys(name, keys, password)` and `loadKeys(name, password)`
- **Security**: 100,000 PBKDF2 iterations with SHA-256

#### 4. **Input Validation & Sanitization**
- **Issue**: Limited validation of cryptographic inputs
- **Fix**: Comprehensive validation for all key formats and parameters
- **Features**:
  - Private key length validation (32 bytes for P-256)
  - Public key format validation (JWK x.y format)
  - Message type validation (must be string)
  - Graceful error handling for invalid signatures

#### 5. **Constant-Time Operations**
- **Issue**: Potential timing attacks in proof-of-work verification
- **Fix**: Implemented constant-time comparison for hash verification
- **Function**: `constantTimeEqual()` for secure comparisons

#### 6. **Enhanced Error Handling**
- **Issue**: Insufficient error messages and edge case handling
- **Fix**: Detailed error messages with security context
- **Benefit**: Better debugging while maintaining security

### 🔒 Security Best Practices

#### Key Storage
```javascript
// Secure (encrypted)
await saveKeys('profile', keys, 'strong-password-123');
const keys = await loadKeys('profile', 'strong-password-123');

// Insecure (unencrypted) - shows warning
await saveKeys('profile', keys);
```

#### Input Validation
- All functions now validate inputs before processing
- Invalid signatures return `false` instead of throwing errors
- Malformed data throws descriptive errors

#### Error Handling
- Cryptographic operations fail securely
- No sensitive data leaked in error messages
- Proper exception handling for all edge cases

### ⚠️ Security Considerations

#### Current Limitations
1. **PEM Format**: Uses simplified PKCS#8 structure (not full standard)
2. **Browser Storage**: IndexedDB is accessible to other scripts in same origin
3. **Proof of Work**: Constant-time comparison only for hash verification
4. **No HSM Support**: Private keys stored in memory/storage
5. **Bundle Security**: Dependencies are bundled at build time (requires trusted build environment)

#### Recommendations for Production
1. **Use strong passwords** for key encryption (12+ characters, mixed case, numbers, symbols)
2. **Implement key rotation** for long-term applications
3. **Use HTTPS** for all network communications
4. **Consider HSM** or hardware security modules for high-value keys
5. **Regular security audits** of your implementation
6. **Verify bundle integrity** in production deployments
7. **Use trusted build environments** for creating production bundles

### 🛡️ Cryptographic Algorithms

| Component | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Digital Signatures | ECDSA with P-256 | 256-bit | SHA-256 hash |
| Key Agreement | ECDH with P-256 | 256-bit | Ephemeral keys |
| Encryption | AES-GCM | 256-bit | Authenticated encryption |
| Key Derivation | PBKDF2 | 256-bit | 100k iterations, SHA-256 |
| Proof of Work | SHA-256 | N/A | Mining-style difficulty |

### 🔍 Security Testing

The library includes comprehensive security tests:
- Input validation tests
- Cryptographic functionality tests  
- Edge case handling
- Error condition testing
- Constant-time operation verification
- Bundle integrity verification

Build and run security tests:
```bash
npm run build
npm test
```

### 📞 Security Contact

If you discover a security vulnerability, please:
1. **Do NOT** create a public GitHub issue
2. Email the maintainer directly
3. Provide detailed reproduction steps
4. Allow time for fixes before disclosure

### 📄 Security Configuration

```javascript
import { getSecurityInfo, SECURITY_CONFIG } from 'unsea';

console.log(getSecurityInfo());
console.log(SECURITY_CONFIG);
```

## Version History

- **v1.1.2**: Bundling and security improvements
  - Static imports with Vite bundling
  - Multiple output formats (ES, CJS, UMD)
  - Enhanced cross-platform compatibility
  - Eliminated dynamic import security risks
  - Updated dependencies and fixed vulnerabilities

- **v1.1.0**: Major security enhancements
  - PKCS#8 PEM format
  - Encrypted key storage  
  - Input validation
  - Constant-time operations
  - Enhanced error handling

- **v1.0.0**: Initial release
  - Basic cryptographic functions
  - Simple key export/import
  - Proof of work functionality
