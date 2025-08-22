#!/usr/bin/env node

import {
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
  verifySignedWork
} from '../dist/unsea.mjs';

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
    
    const verification = await verifyWork(work);
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
    
    const verification = await verifySignedWork(signedWork, keys.pub);
    assert(verification.valid === true, 'Signed work should be valid');
    assert(verification.workValid === true, 'Work component should be valid');
    assert(verification.signatureValid === true, 'Signature component should be valid');
    
    // Test with wrong public key
    const wrongKeys = await generateRandomPair();
    const wrongVerification = await verifySignedWork(signedWork, wrongKeys.pub);
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
    const tamperedVerification = await verifyWork(tamperedWork);
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
