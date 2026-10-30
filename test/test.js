#!/usr/bin/env node

import {
  sha256,
  generateRandomPair,
  signMessage,
  verifyMessage,
  encryptMessageWithMeta,
  decryptMessageWithMeta,
  encryptBySenderForReceiver,
  decryptBySenderForReceiver,
  exportToPEM,
  importFromPEM,
  exportToJWK,
  importFromJWK,
  generateWork,
  verifyWork,
  generateSignedWork,
  verifySignedWork,
  derivePair,
  saveKeys,
  getSecurityInfo
} from '../dist/unsea.mjs';
import { readFileSync } from 'node:fs';
import { p256 } from '@noble/curves/p256';

// Test utilities
let testCount = 0;
let passCount = 0;

function test(name, testFn) {
  testCount++;
  console.log(`\n🧪 Test ${testCount}: ${name}`);
  
  return testFn()
    .then(() => {
      passCount++;
      console.log(`✅ PASS`);
    })
    .catch((error) => {
      console.log(`❌ FAIL: ${error.message}`);
      console.error(error);
    });
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

// Main test suite
async function runTests() {
  console.log('🚀 Starting Unsea Test Suite\n');
  console.log('='.repeat(50));

  // SHA-256 digest API
  await test('SHA-256 Digest Formats and Binary Input', async () => {
    const expectedHex = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    const expectedBase64Url = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

    assert(await sha256('abc') === expectedHex, 'Default SHA-256 output should be lowercase hex');
    assert(await sha256('abc', 'hex') === expectedHex, 'Explicit hex output should match');
    assert(await sha256('abc', 'base64url') === expectedBase64Url, 'Base64url output should match');
    assert(await sha256(new Uint8Array([97, 98, 99])) === expectedHex, 'Uint8Array input should match text bytes');

    const bytes = await sha256('abc', 'bytes');
    assert(bytes instanceof Uint8Array, 'Byte output should be a Uint8Array');
    assert(bytes.length === 32, 'SHA-256 byte output should contain 32 bytes');

    try {
      await sha256({ value: 'abc' });
      assert(false, 'Should reject unsupported input');
    } catch (error) {
      assert(error.message.includes('SHA-256 input'), 'Should reject unsupported input types');
    }

    try {
      await sha256('abc', 'base64');
      assert(false, 'Should reject unsupported output formats');
    } catch (error) {
      assert(error.message.includes('SHA-256 output'), 'Should reject unsupported output formats');
    }
  });

  // Test 1: Key Generation
  await test('Generate Random Keypair', async () => {
    const keys = await generateRandomPair();
    
    assert(keys.pub, 'Public key should exist');
    assert(keys.priv, 'Private key should exist');
    assert(keys.epub, 'Encryption public key should exist');
    assert(keys.epriv, 'Encryption private key should exist');
    
    assert(keys.pub.includes('.'), 'Public key should be in JWK format (x.y)');
    assert(keys.epub.includes('.'), 'Encryption public key should be in JWK format (x.y)');
    
    console.log(`   Generated keys: pub=${keys.pub.slice(0, 20)}..., epub=${keys.epub.slice(0, 20)}...`);
  });

  // Test 2: Message Signing and Verification
  await test('Sign and Verify Message', async () => {
    const keys = await generateRandomPair();
    const message = 'Hello, Unsea! This is a test message.';
    
    const signature = await signMessage(message, keys.priv);
    assert(signature, 'Signature should be generated');
    
    const isValid = await verifyMessage(message, signature, keys.pub);
    assert(isValid === true, 'Signature should be valid');
    
    const isFalse = await verifyMessage('Different message', signature, keys.pub);
    assert(isFalse === false, 'Different message should not verify');
    
    console.log(`   Message: "${message}"`);
    console.log(`   Signature: ${signature.slice(0, 20)}...`);
    console.log(`   Verification: ${isValid}`);
  });

  // Test 3: Message Encryption and Decryption
  await test('Encrypt and Decrypt Message with Metadata', async () => {
    const keys = await generateRandomPair();
    const message = 'This is a secret message that should be encrypted!';
    
    const encrypted = await encryptMessageWithMeta(message, keys);
    assert(encrypted.ciphertext, 'Ciphertext should exist');
    assert(encrypted.iv, 'IV should exist');
    assert(encrypted.sender, 'Sender should exist');
    assert(encrypted.timestamp, 'Timestamp should exist');
    assert(typeof encrypted.timestamp === 'number', 'Timestamp should be a number');
    
    const decrypted = await decryptMessageWithMeta(encrypted, keys.epriv);
    assert(decrypted === message, 'Decrypted message should match original');
    
    console.log(`   Original: "${message}"`);
    console.log(`   Encrypted: ${encrypted.ciphertext.slice(0, 20)}...`);
    console.log(`   Decrypted: "${decrypted}"`);
    console.log(`   Timestamp: ${new Date(encrypted.timestamp).toISOString()}`);
  });

  // Test 4: Private Chat Encryption (epriv1+epub2=epriv2+epub1)
  await test('Private Chat Encryption (Baseline Asymmetric)', async () => {
    const alice = await generateRandomPair();
    const bob = await generateRandomPair();
    const message = 'Private chat message between Alice and Bob';
    
    // Alice encrypts for Bob using her private key + Bob's public key
    const encrypted = await encryptBySenderForReceiver(message, alice.epriv, bob.epub);
    assert(encrypted.ciphertext, 'Should have ciphertext');
    assert(encrypted.iv, 'Should have IV');
    assert(!encrypted.sender, 'Should not have sender (unlike encryptMessageWithMeta)');
    assert(!encrypted.timestamp, 'Should not have timestamp (unlike encryptMessageWithMeta)');
    
    // Bob decrypts using Alice's public key + his private key
    const decrypted = await decryptBySenderForReceiver(encrypted, alice.epub, bob.epriv);
    assert(decrypted === message, 'Decrypted message should match original');
    
    // Test bidirectional encryption
    const replyMessage = 'Reply from Bob to Alice';
    const replyEncrypted = await encryptBySenderForReceiver(replyMessage, bob.epriv, alice.epub);
    const replyDecrypted = await decryptBySenderForReceiver(replyEncrypted, bob.epub, alice.epriv);
    assert(replyDecrypted === replyMessage, 'Bidirectional encryption should work');
    
    console.log(`   Original: "${message}"`);
    console.log(`   Encrypted: ${encrypted.ciphertext.slice(0, 20)}...`);
    console.log(`   Decrypted: "${decrypted}"`);
    console.log(`   Bidirectional test: "${replyDecrypted}"`);
  });

  // Test 5: PEM Export and Import
  await test('Export and Import PEM Format', async () => {
    const keys = await generateRandomPair();
    
    const pem = await exportToPEM(keys.priv);
    assert(pem.includes('-----BEGIN PRIVATE KEY-----'), 'PEM should have correct header');
    assert(pem.includes('-----END PRIVATE KEY-----'), 'PEM should have correct footer');
    
    const importedPriv = await importFromPEM(pem);
    assert(importedPriv === keys.priv, 'Imported private key should match original');
    
    console.log(`   Original private key: ${keys.priv.slice(0, 20)}...`);
    console.log(`   PEM format: ${pem.split('\n')[1].slice(0, 20)}...`);
    console.log(`   Imported private key: ${importedPriv.slice(0, 20)}...`);
  });

  // Test 6: JWK Export and Import
  await test('Export and Import JWK Format', async () => {
    const keys = await generateRandomPair();
    
    const jwk = await exportToJWK(keys.priv);
    assert(jwk.kty === 'EC', 'JWK should have correct key type');
    assert(jwk.crv === 'P-256', 'JWK should have correct curve');
    assert(jwk.d, 'JWK should have private key component');
    
    const importedPriv = await importFromJWK(jwk);
    assert(importedPriv === keys.priv, 'Imported private key should match original');
    
    console.log(`   Original private key: ${keys.priv.slice(0, 20)}...`);
    console.log(`   JWK format: ${JSON.stringify(jwk)}`);
    console.log(`   Imported private key: ${importedPriv.slice(0, 20)}...`);
  });

  // Test 7: Cross-compatibility test
  await test('Cross-compatibility: Sign with one key, encrypt with another', async () => {
    const alice = await generateRandomPair();
    const bob = await generateRandomPair();
    const message = 'Cross-compatibility test message';
    
    // Alice signs a message
    const signature = await signMessage(message, alice.priv);
    
    // Bob verifies Alice's signature
    const isValid = await verifyMessage(message, signature, alice.pub);
    assert(isValid === true, 'Bob should be able to verify Alice\'s signature');
    
    // Alice encrypts a message for Bob
    const encrypted = await encryptMessageWithMeta(message, bob);
    
    // Bob decrypts Alice's message
    const decrypted = await decryptMessageWithMeta(encrypted, bob.epriv);
    assert(decrypted === message, 'Bob should be able to decrypt Alice\'s message');
    
    console.log(`   Alice -> Bob: Message signed and encrypted successfully`);
    console.log(`   Bob verified signature: ${isValid}`);
    console.log(`   Bob decrypted message: "${decrypted}"`);
  });

  // Test 8: Edge cases
  await test('Handle Edge Cases', async () => {
    const keys = await generateRandomPair();
    
    // Empty message
    const emptyMessage = '';
    const emptySig = await signMessage(emptyMessage, keys.priv);
    const emptyValid = await verifyMessage(emptyMessage, emptySig, keys.pub);
    assert(emptyValid === true, 'Empty message should sign and verify');
    
    // Unicode message
    const unicodeMessage = '🔐 Encryption test with émojis and àccénts! 测试';
    const unicodeSig = await signMessage(unicodeMessage, keys.priv);
    const unicodeValid = await verifyMessage(unicodeMessage, unicodeSig, keys.pub);
    assert(unicodeValid === true, 'Unicode message should sign and verify');
    
    const unicodeEncrypted = await encryptMessageWithMeta(unicodeMessage, keys);
    const unicodeDecrypted = await decryptMessageWithMeta(unicodeEncrypted, keys.epriv);
    assert(unicodeDecrypted === unicodeMessage, 'Unicode message should encrypt and decrypt');
    
    console.log(`   Empty message test: ${emptyValid}`);
    console.log(`   Unicode message: "${unicodeMessage}"`);
    console.log(`   Unicode test: ${unicodeValid && unicodeDecrypted === unicodeMessage}`);
  });

  // Test 9: Proof of Work
  await test('Generate and Verify Proof of Work', async () => {
    const data = 'Challenge data that needs computational proof';
    const difficulty = 3; // Use lower difficulty for faster testing
    
    const work = await generateWork(data, difficulty, 100000);
    assert(work.nonce !== undefined, 'Work should have a nonce');
    assert(work.hash, 'Work should have a hash');
    assert(work.hashHex, 'Work should have a hex hash');
    assert(work.difficulty === difficulty, 'Work should have correct difficulty');
    assert(work.hashHex.startsWith('0'.repeat(difficulty)), 'Hash should meet difficulty requirement');
    
    const verification = await verifyWork(work, { minDifficulty: difficulty });
    assert(verification.valid === true, 'Work should be valid');
    assert(verification.hashMatches === true, 'Hash should match');
    assert(verification.difficultyMatches === true, 'Difficulty should be met');
    
    console.log(`   Data: "${data}"`);
    console.log(`   Nonce: ${work.nonce}`);
    console.log(`   Hash: ${work.hashHex}`);
    console.log(`   Duration: ${work.duration}ms`);
    console.log(`   Hash Rate: ${work.hashRate} H/s`);
  });

  // Test 10: Signed Proof of Work
  await test('Generate and Verify Signed Proof of Work', async () => {
    const keys = await generateRandomPair();
    const data = { challenge: 'Rate limiting proof', user: 'alice', timestamp: Date.now() };
    const difficulty = 2; // Lower difficulty for testing
    
    const signedWork = await generateSignedWork(data, keys.priv, difficulty, 50000);
    assert(signedWork.signature, 'Signed work should have a signature');
    assert(signedWork.signedPayload, 'Signed work should have signed payload');
    
    const verification = await verifySignedWork(signedWork, keys.pub, { minDifficulty: difficulty });
    assert(verification.valid === true, 'Signed work should be valid');
    assert(verification.workValid === true, 'Work component should be valid');
    assert(verification.signatureValid === true, 'Signature component should be valid');
    
    // Test with wrong public key
    const wrongKeys = await generateRandomPair();
    const wrongVerification = await verifySignedWork(signedWork, wrongKeys.pub, { minDifficulty: difficulty });
    assert(wrongVerification.valid === false, 'Signed work should be invalid with wrong key');
    assert(wrongVerification.signatureValid === false, 'Signature should be invalid with wrong key');
    
    console.log(`   Data: ${JSON.stringify(data)}`);
    console.log(`   Nonce: ${signedWork.nonce}`);
    console.log(`   Hash: ${signedWork.hashHex}`);
    console.log(`   Signature valid: ${verification.signatureValid}`);
    console.log(`   Overall valid: ${verification.valid}`);
  });

  // Test 11: Proof of Work Edge Cases
  await test('Proof of Work Edge Cases', async () => {
    // Test with invalid proof
    const validWork = await generateWork('test data', 2, 10000);
    
    // Tamper with nonce
    const tamperedWork = { ...validWork, nonce: validWork.nonce + 1 };
    const tamperedVerification = await verifyWork(tamperedWork, { minDifficulty: 2 });
    assert(tamperedVerification.valid === false, 'Tampered work should be invalid');
    
    // Test with high difficulty (should fail quickly with low max iterations)
    try {
      await generateWork('difficult data', 6, 100); // Very high difficulty, low iterations
      assert(false, 'Should have thrown an error for impossible work');
    } catch (error) {
      assert(error.message.includes('Failed to find proof of work'), 'Should fail with appropriate error');
    }
    
    console.log(`   Tampered work detected: ${!tamperedVerification.valid}`);
    console.log(`   High difficulty handling: correct`);
  });

  // Test 12: Input Validation and Security
  await test('Input Validation and Security', async () => {
    const keys = await generateRandomPair();
    
    // Test invalid private key
    try {
      await signMessage('test', 'invalid-key');
      assert(false, 'Should have thrown error for invalid private key');
    } catch (error) {
      assert(error.message.includes('Invalid private key'), 'Should detect invalid private key');
    }
    
    // Test invalid public key
    try {
      await verifyMessage('test', 'signature', 'invalid-pubkey');
      assert(false, 'Should have thrown error for invalid public key');
    } catch (error) {
      assert(error.message.includes('Public key must be in JWK format'), 'Should detect invalid public key');
    }
    
    // Test invalid signature (should return false, not throw)
    const invalidSigResult = await verifyMessage('test message', 'invalid-signature', keys.pub);
    assert(invalidSigResult === false, 'Invalid signature should return false');
    
    // Test malformed encryption payload
    try {
      await decryptMessageWithMeta({ invalid: 'payload' }, keys.epriv);
      assert(false, 'Should have thrown error for malformed payload');
    } catch (error) {
      assert(error.message.includes('Payload must contain'), 'Should detect malformed payload');
    }
    
    // Test non-string message
    try {
      await signMessage(null, keys.priv);
      assert(false, 'Should have thrown error for null message');
    } catch (error) {
      assert(error.message.includes('Input must be a string'), 'Should detect non-string input');
    }
    
    console.log(`   Input validation: comprehensive checks passed`);
  });

  // Test 13: Enhanced PEM/JWK Security
  await test('Enhanced PEM/JWK Format Security', async () => {
    const keys = await generateRandomPair();
    
    // Test JWK validation
    const jwk = await exportToJWK(keys.priv);
    assert(jwk.kty === 'EC', 'JWK should have correct key type');
    assert(jwk.crv === 'P-256', 'JWK should have correct curve');
    assert(jwk.use === 'sig', 'JWK should have correct use');
    assert(Array.isArray(jwk.key_ops), 'JWK should have key operations');
    
    // Test invalid JWK import
    try {
      await importFromJWK({ kty: 'RSA', d: 'test' });
      assert(false, 'Should reject non-EC JWK');
    } catch (error) {
      assert(error.message.includes('JWK must be an EC key'), 'Should reject non-EC keys');
    }
    
    // Test PEM format improvement
    const pem = await exportToPEM(keys.priv);
    assert(pem.includes('-----BEGIN PRIVATE KEY-----'), 'PEM should have correct header');
    assert(pem.includes('-----END PRIVATE KEY-----'), 'PEM should have correct footer');
    
    // Test PEM import validation
    try {
      await importFromPEM('invalid pem data');
      assert(false, 'Should reject invalid PEM');
    } catch (error) {
      assert(error.message.includes('Invalid PEM format'), 'Should detect invalid PEM');
    }
    
    const importedKey = await importFromPEM(pem);
    assert(importedKey === keys.priv, 'Imported key should match original');
    
    console.log(`   Enhanced format validation: all checks passed`);
  });


  // ---- Security regressions (2.0.0) ----

  const subtle = globalThis.crypto.subtle;
  const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
  const LEGACY = {
    "keys": {
      "pub": "ge0zJeRnxCPDCvfEak8cEDUo_rK5uCrBR36NJUOSw3w.0LL-5UM_E1eK7w0dJi3d-n785q3zQUf05bKIVzV1Tf0",
      "priv": "CPITCHu8CZZk1Uzb7WfRHCJc1EQf3FWIYFGa5LmQ5-Q",
      "epub": "nGEZHxH3f5DSjpuSzeIsIYUqCYKc4sP2rpWNwx2VnHM.oqI8Gi-gKIwgIMZopHYU28FCLbnY_9jeetnTZ1QXg8I",
      "epriv": "9OC9OJq2w3sAG10LFuUXYorGb2fapNYNhobhTGxZau4"
    },
    "peerEpub": "6_90ze-HYsY4sKXc8WuyFQVEsiU4q4Ta-iPPEazf9SA.BbqXifl4VVbpiSWHznarTU5Xkw8EuKzwZbjho4VNk8Q",
    "meta": {
      "ciphertext": "Fe6tDM9aZ1Dg9P0e0p3IQx_aHIB8V5usjQYsrw",
      "iv": "cVqU6m6H9x4rUeX8",
      "sender": "uuRXXj-ikYrE3aQV4_hznZI5jv25gMAo4QaBicpX7-M.qhQpEjBIkuz0ynI5242OKvPaxQEhSius0eTsrWZknkg",
      "timestamp": 1793386106884
    },
    "pair": {
      "ciphertext": "hyBBe8xyx98-9IJvFLseI3mEJMLfAS4erJKq",
      "iv": "AZmpWjh90bxN2B4m"
    },
    "derivedPub": "zItFKYwa5ShiNjnS8C4bYljjrrP8M7dTy3EqdROEFD4.fT6PBnVzPakrnj9PyyGy59UNwerm8UBtehw31w9b5qI",
    "derivedEpub": "NXQDjX7rVWZGRo6XBUkp2hHDcwBTH7RRW2Hx-cTwk0Q.e6epjk-j6q3PTRtzOvof-cBD72_3WIbo2CbmuRD318Q"
  };

  await test('Security: a signed proof of work cannot carry someone else\'s data', async () => {
    const alice = await generateRandomPair();
    const signed = await generateSignedWork('alice says hi', alice.priv, 2, 100000);
    const mallory = await generateWork('mallory', 2, 100000);
    const forged = { ...signed, ...mallory, signature: signed.signature, signedPayload: signed.signedPayload };
    const result = await verifySignedWork(forged, alice.pub, { minDifficulty: 2 });
    assert(result.valid === false, 'A signature over one proof must not validate another proof');
    const noPayload = { ...forged };
    delete noPayload.signedPayload;
    assert((await verifySignedWork(noPayload, alice.pub, { minDifficulty: 2 })).valid === false, 'Dropping signedPayload must not help');
    const plainSig = await signMessage(JSON.stringify({ data: 'x' }), alice.priv);
    assert((await verifySignedWork({ ...mallory, signature: plainSig }, alice.pub, { minDifficulty: 2 })).valid === false, 'A message signature is not a work signature');
  });

  await test('Security: the verifier sets the minimum proof-of-work difficulty', async () => {
    const free = { data: 'spam', nonce: 0, difficulty: 0 };
    const probe = await verifyWork({ ...free, hash: 'x', hashHex: 'x' });
    const claimed = { ...free, hash: probe.computedHash, hashHex: probe.computedHashHex };
    assert((await verifyWork(claimed)).valid === false, 'Difficulty 0 must not pass');
    const cheap = await generateWork('cheap', 1, 100000);
    assert((await verifyWork(cheap)).valid === false, 'Difficulty below the default minimum (4) must not pass');
    assert((await verifyWork(cheap, { minDifficulty: 1 })).valid === true, 'An explicit minimum is honoured');
    assert((await verifyWork({ ...cheap, nonce: 1.5 }, { minDifficulty: 1 })).valid === false, 'A non-integer nonce must not pass');
    const old = { ...cheap, timestamp: Date.now() - 120_000 };
    assert((await verifyWork(old, { minDifficulty: 1, maxAgeMs: 60_000 })).valid === false, 'maxAgeMs rejects old proofs');
    assert((await verifyWork(cheap, { minDifficulty: 1, maxAgeMs: 60_000 })).valid === true, 'maxAgeMs accepts fresh proofs');
  });

  await test('Security: derivePair needs a per-user salt', async () => {
    const pwd = 'correct horse battery staple';
    let threw = false;
    try { await derivePair(pwd); } catch (error) { threw = /per-user salt/.test(error.message); }
    assert(threw, 'derivePair without a salt must refuse');
    const alice = await derivePair(pwd, 'alice');
    const bob = await derivePair(pwd, 'bob');
    const alice2 = await derivePair(pwd, 'alice');
    assert(alice.pub !== bob.pub && alice.epub !== bob.epub, 'The same password gives different users different keys');
    assert(alice.pub === alice2.pub && alice.priv === alice2.priv, 'Derivation is deterministic per user');
    const legacy = await derivePair(pwd, { legacyUnsalted: true });
    assert(legacy.pub === LEGACY.derivedPub && legacy.epub === LEGACY.derivedEpub, '1.x keys can still be reproduced');
    assert(legacy.pub !== alice.pub, 'Salted keys differ from 1.x keys');
  });

  await test('Security: messages are signed and encrypted exactly as given', async () => {
    const keys = await generateRandomPair();
    const sig = await signMessage('pay bob 100', keys.priv);
    assert(await verifyMessage('pay bob 100', sig, keys.pub) === true, 'The exact message verifies');
    assert(await verifyMessage('  pay bob 100\n', sig, keys.pub) === false, 'Whitespace changes must not verify');
    assert(await verifyMessage('pay bob 100'.normalize('NFD') + '́', sig, keys.pub) === false, 'A different string must not verify');
    const message = '  spaced and é not normalized \n';
    const decrypted = await decryptMessageWithMeta(await encryptMessageWithMeta(message, keys), keys.epriv);
    assert(decrypted === message, 'Encryption preserves the exact text');
  });

  await test('Security: one signature encoding (compact, low S)', async () => {
    const keys = await generateRandomPair();
    const sig = await signMessage('one encoding', keys.priv);
    const raw = Buffer.from(sig, 'base64url');
    const s = BigInt('0x' + raw.subarray(32).toString('hex'));
    const highS = p256.CURVE.n - s;
    const malleable = Buffer.concat([raw.subarray(0, 32), Buffer.from(highS.toString(16).padStart(64, '0'), 'hex')]);
    assert(await verifyMessage('one encoding', b64u(malleable), keys.pub) === false, 'The high-S twin must not verify');
    const der = p256.Signature.fromCompact(raw).toDERRawBytes();
    assert(await verifyMessage('one encoding', b64u(der), keys.pub) === false, 'The DER form must not verify');
  });

  await test('Security: public keys must be points on P-256', async () => {
    const keys = await generateRandomPair();
    const [x] = keys.pub.split('.');
    const offCurve = `${x}.${b64u(new Uint8Array(32).fill(7))}`;
    let threw = false;
    try { await verifyMessage('x', 'AAAA', offCurve); } catch (error) { threw = /not a point on P-256/.test(error.message); }
    assert(threw, 'An off-curve public key must be refused');
    threw = false;
    try { await encryptMessageWithMeta('x', { epub: offCurve }); } catch (error) { threw = /not a point on P-256/.test(error.message); }
    assert(threw, 'Encrypting to an off-curve key must be refused');
  });

  await test('Security: encrypted metadata is authenticated; 1.x payloads still decrypt', async () => {
    const keys = await generateRandomPair();
    const encrypted = await encryptMessageWithMeta('timestamped', keys);
    assert(encrypted.v === 2, 'New payloads are version 2');
    let failed = false;
    try { await decryptMessageWithMeta({ ...encrypted, timestamp: encrypted.timestamp + 1 }, keys.epriv); } catch { failed = true; }
    assert(failed, 'A changed timestamp must fail to decrypt');
    failed = false;
    const { v, ...stripped } = encrypted;
    try { await decryptMessageWithMeta(stripped, keys.epriv); } catch { failed = true; }
    assert(failed, 'A version 2 payload cannot be downgraded to version 1');
    const other = await generateRandomPair();
    failed = false;
    try { await decryptMessageWithMeta(encrypted, other.epriv); } catch { failed = true; }
    assert(failed, 'Another recipient cannot decrypt');
    assert(await decryptMessageWithMeta(LEGACY.meta, LEGACY.keys.epriv) === 'legacy hello', 'A 1.x payload still decrypts');
  });

  await test('Security: private chat keys are bound to the direction', async () => {
    const alice = await generateRandomPair();
    const bob = await generateRandomPair();
    const toBob = await encryptBySenderForReceiver('to bob', alice.epriv, bob.epub);
    assert(await decryptBySenderForReceiver(toBob, alice.epub, bob.epriv) === 'to bob', 'Bob decrypts');
    let failed = false;
    try { await decryptBySenderForReceiver(toBob, bob.epub, alice.epriv); } catch { failed = true; }
    assert(failed, 'Alice\'s message bounced back to her as if from Bob must fail');
    assert(await decryptBySenderForReceiver(LEGACY.pair, LEGACY.peerEpub, LEGACY.keys.epriv) === 'legacy pair', 'A 1.x pair payload still decrypts');
  });

  await test('Security: PEM import parses PKCS#8 and checks it', async () => {
    const pemOf = (der) => `-----BEGIN PRIVATE KEY-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
    const derOf = (pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
    // A key exported by WebCrypto imports, and gives the same private scalar.
    const wc = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const wcDer = new Uint8Array(await subtle.exportKey('pkcs8', wc.privateKey));
    const wcJwk = await subtle.exportKey('jwk', wc.privateKey);
    assert(await importFromPEM(pemOf(wcDer)) === wcJwk.d, 'WebCrypto PKCS#8 imports');
    // Our export imports into WebCrypto.
    const keys = await generateRandomPair();
    const ours = await exportToPEM(keys.priv);
    const back = await subtle.importKey('pkcs8', derOf(ours), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    assert((await subtle.exportKey('jwk', back)).d === keys.priv, 'Our PEM imports into WebCrypto');
    // Tampered structures are refused.
    const der = derOf(ours);
    const refuse = async (bytes, why) => {
      let threw = false;
      try { await importFromPEM(pemOf(bytes)); } catch { threw = true; }
      assert(threw, why);
    };
    const wrongPub = Uint8Array.from(der); wrongPub[wrongPub.length - 1] ^= 1;
    await refuse(wrongPub, 'A mismatched embedded public key must be refused');
    const wrongCurve = Uint8Array.from(der); wrongCurve[25] ^= 1;
    await refuse(wrongCurve, 'A different curve OID must be refused');
    await refuse(Uint8Array.from([...der, 0]), 'Trailing data must be refused');
    const junk = new Uint8Array(80); junk[10] = 0x04; junk[11] = 0x20; junk.fill(9, 12, 44);
    await refuse(junk, 'Bytes that merely contain 04 20 must be refused');
  });

  await test('Security: JWK export is a complete EC private key', async () => {
    const keys = await generateRandomPair();
    const jwk = await exportToJWK(keys.priv);
    assert(`${jwk.x}.${jwk.y}` === keys.pub, 'JWK carries the public key');
    const imported = await subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    assert(imported.type === 'private', 'WebCrypto imports the exported JWK');
    const other = await generateRandomPair();
    let threw = false;
    try { await importFromJWK({ ...jwk, x: other.pub.split('.')[0] }); } catch { threw = true; }
    assert(threw, 'A JWK whose x, y do not match d must be refused');
  });

  await test('Security: keys are not stored unencrypted by default', async () => {
    let threw = false;
    try { await saveKeys('k', await generateRandomPair()); } catch (error) { threw = /needs a password/.test(error.message); }
    assert(threw, 'saveKeys without a password must refuse');
  });

  await test('Library version matches the package', async () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
    assert(getSecurityInfo().version === pkg.version, `getSecurityInfo().version ${getSecurityInfo().version} != package ${pkg.version}`);
  });

  // Test Summary
  console.log('\n' + '='.repeat(50));
  console.log(`\n📊 Test Results: ${passCount}/${testCount} tests passed`);
  
  if (passCount === testCount) {
    console.log('🎉 All tests passed! Unsea is working correctly with enhanced security.');
    process.exit(0);
  } else {
    console.log(`💥 ${testCount - passCount} test(s) failed.`);
    process.exit(1);
  }
}

// Handle browser storage tests separately (will fail in Node.js)
async function testBrowserFeatures() {
  console.log('\n🌐 Browser-only features (will be skipped in Node.js):');
  
  try {
    const { saveKeys, loadKeys, clearKeys } = await import('../dist/unsea.mjs');
    const keys = await generateRandomPair();
    const testPassword = 'test-password-123';
    
    // Test encrypted storage
    await saveKeys('test-profile-encrypted', keys, testPassword);
    const loadedEncrypted = await loadKeys('test-profile-encrypted', testPassword);
    assert(loadedEncrypted.pub === keys.pub, 'Loaded encrypted keys should match saved keys');
    
    // Test unencrypted storage (with warning)
    await saveKeys('test-profile-plain', keys);
    const loadedPlain = await loadKeys('test-profile-plain');
    assert(loadedPlain.pub === keys.pub, 'Loaded unencrypted keys should match saved keys');
    
    // Test wrong password
    try {
      await loadKeys('test-profile-encrypted', 'wrong-password');
      assert(false, 'Should have failed with wrong password');
    } catch (error) {
      assert(error.message.includes('decrypt'), 'Should fail with decryption error');
    }
    
    // Clean up
    await clearKeys('test-profile-encrypted');
    await clearKeys('test-profile-plain');
    
    const cleared = await loadKeys('test-profile-encrypted', testPassword);
    assert(cleared === undefined, 'Cleared keys should be undefined');
    
    console.log('✅ IndexedDB storage tests passed (including encryption)');
  } catch (error) {
    console.log(`⏭️  IndexedDB tests skipped (Node.js environment): ${error.message}`);
  }
}

// Run all tests
runTests()
  .then(() => testBrowserFeatures())
  .catch((error) => {
    console.error('Test suite failed:', error);
    process.exit(1);
  });
