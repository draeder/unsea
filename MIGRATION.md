# UnSEA v2.0 Migration Guide

UnSEA v2.0 introduces a **simplified, unified API** that reduces the number of function names while maintaining all existing functionality. This is a **breaking change** that requires updating your import statements and function calls.

## 🎯 Key Changes

### Simplified API
- **14 functions** instead of 20+ 
- **Consistent naming** with intuitive method names
- **Unified functions** that handle multiple modes
- **Reserved keyword handling** for `export`/`import`

## 📋 Migration Table

| v1.x Function | v2.0 Function | Notes |
|---------------|---------------|-------|
| `generateRandomPair()` | `pair()` | Generate random keypair |
| `derivePair(passphrase)` | `pair(passphrase)` or `derive(passphrase)` | Derive from passphrase |
| `signMessage(msg, key)` | `sign(msg, key)` | Sign message |
| `verifyMessage(msg, sig, key)` | `verify(msg, sig, key)` | Verify signature |
| `encryptMessageWithMeta(msg, key)` | `encrypt(msg, key)` | Ephemeral encryption |
| `decryptMessageWithMeta(payload, key)` | `decrypt(payload, key)` | Ephemeral decryption |
| `encryptBySenderForReceiver(msg, rkey, skey)` | `encrypt(msg, rkey, skey)` | Authenticated encryption |
| `decryptBySenderForReceiver(payload, skey, rkey)` | `decrypt(payload, rkey, skey)` | Authenticated decryption |
| `exportToPEM(key)` | `export(key, 'pem')` | Export to PEM |
| `exportToJWK(key)` | `export(key, 'jwk')` | Export to JWK |
| `importFromPEM(pem)` | `import(pem)` | Import from PEM |
| `importFromJWK(jwk)` | `import(jwk)` | Import from JWK |
| `saveKeys(name, keys, pwd)` | `save(keys, name, pwd)` | Save with encryption |
| `loadKeys(name, pwd)` | `load(name, pwd)` | Load with decryption |
| `clearKeys(name)` | `clear(name)` | Clear persistent storage |
| `save(keys, alias)` | `save(keys, alias)` | Session storage (unchanged) |
| `recall(alias)` | `recall(alias)` | Session recall (unchanged) |
| `clear(alias)` | `clear(alias)` | Session clear (unchanged) |
| `generateWork(...)` | `work(data, options)` | Generate proof of work |
| `verifyWork(proof)` | `work(proof, {verify: true})` | Verify proof of work |
| `generateSignedWork(...)` | `work(data, {privKey})` | Generate signed proof |
| `verifySignedWork(...)` | `work(proof, {verify: true, pubKey})` | Verify signed proof |
| `getSecurityInfo()` | `info()` | Get library information |

## 🔧 Migration Examples

### Basic Key Generation
```js
// v1.x
import { generateRandomPair, derivePair } from 'unsea';
const keys1 = await generateRandomPair();
const keys2 = await derivePair('passphrase');

// v2.0
import { pair, derive } from 'unsea';
const keys1 = await pair();
const keys2 = await pair('passphrase'); // or derive('passphrase')
```

### Message Signing
```js
// v1.x
import { signMessage, verifyMessage } from 'unsea';
const sig = await signMessage('hello', keys.priv);
const valid = await verifyMessage('hello', sig, keys.pub);

// v2.0
import { sign, verify } from 'unsea';
const sig = await sign('hello', keys.priv);
const valid = await verify('hello', sig, keys.pub);
```

### Encryption
```js
// v1.x - Ephemeral encryption
import { encryptMessageWithMeta, decryptMessageWithMeta } from 'unsea';
const encrypted = await encryptMessageWithMeta('secret', keys.epub);
const decrypted = await decryptMessageWithMeta(encrypted, keys.epriv);

// v2.0 - Ephemeral encryption  
import { encrypt, decrypt } from 'unsea';
const encrypted = await encrypt('secret', keys.epub);
const decrypted = await decrypt(encrypted, keys.epriv);

// v1.x - Authenticated encryption
import { encryptBySenderForReceiver, decryptBySenderForReceiver } from 'unsea';
const encrypted = await encryptBySenderForReceiver('secret', alice.epriv, bob.epub);
const decrypted = await decryptBySenderForReceiver(encrypted, alice.epub, bob.epriv);

// v2.0 - Authenticated encryption
import { encrypt, decrypt } from 'unsea';
const encrypted = await encrypt('secret', bob.epub, alice.epriv);
const decrypted = await decrypt(encrypted, bob.epriv, alice.epub);
```

### Export/Import
```js
// v1.x
import { exportToPEM, importFromPEM, exportToJWK, importFromJWK } from 'unsea';
const pem = await exportToPEM(keys.priv);
const restored1 = await importFromPEM(pem);
const jwk = await exportToJWK(keys.priv);  
const restored2 = await importFromJWK(jwk);

// v2.0
import { export as exportKey, import as importKey } from 'unsea';
// OR: import * as unsea from 'unsea'; const exportKey = unsea.export;
const pem = await exportKey(keys.priv, 'pem');
const restored1 = await importKey(pem);
const jwk = await exportKey(keys.priv, 'jwk');
const restored2 = await importKey(jwk);
```

### Proof of Work
```js
// v1.x
import { generateWork, verifyWork, generateSignedWork, verifySignedWork } from 'unsea';
const proof = await generateWork(data, 4);
const valid = await verifyWork(proof);
const signedProof = await generateSignedWork(data, keys.priv, 4);
const signedValid = await verifySignedWork(signedProof, keys.pub);

// v2.0
import { work } from 'unsea';
const proof = await work(data, { difficulty: 4 });
const valid = await work(proof, { verify: true });
const signedProof = await work(data, { difficulty: 4, privKey: keys.priv });
const signedValid = await work(signedProof, { verify: true, pubKey: keys.pub });
```

## 🚨 Breaking Changes

1. **Function names**: All function names have been simplified
2. **Import statements**: You need to update all import statements
3. **Parameter order**: Some functions have changed parameter order (notably `save()`)
4. **Unified functions**: `encrypt()`/`decrypt()` now handle both modes based on parameters
5. **Reserved keywords**: `export`/`import` require special handling in imports

## ✅ What Stays the Same

- **All functionality** is preserved
- **Security features** remain unchanged  
- **File formats** (PEM, JWK) are compatible
- **Encryption/decryption** produces identical results
- **Session storage** functions work identically
- **Package installation** remains `npm install unsea`

## 🎁 New Features in v2.0

1. **Simplified API**: Easier to learn and use
2. **Unified encryption**: One function handles both ephemeral and authenticated modes
3. **Flexible key generation**: `pair()` can generate random OR derive from passphrase
4. **Unified proof of work**: One function for generation and verification
5. **Better documentation**: Updated examples and clearer API

## 🔄 Migration Steps

1. **Update imports** to use new function names
2. **Update function calls** according to the migration table
3. **Test thoroughly** - especially encryption/decryption workflows
4. **Update documentation** and examples in your project
5. **Consider the new unified patterns** for cleaner code

## 📞 Support

If you encounter issues during migration:
- Check the [updated README](README.md) for examples
- Review the comprehensive test suite in `test/test.js`
- The old v1.x test file is preserved as `test/test-v1-old.js` for reference

The migration is straightforward - mostly renaming functions with a few parameter reorderings. The new API is more intuitive and consistent! 🎉
