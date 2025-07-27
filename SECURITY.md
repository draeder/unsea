# Security Guidelines for Unsea

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
