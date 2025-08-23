#!/usr/bin/env node

import * as unsea from '../dist/unsea.mjs';

// Extract simplified API functions
const {
  pair,
  derive,
  sign,
  verify,
  encrypt,
  decrypt,
  save,
  load,
  clear,
  recall,
  work,
  info
} = unsea;

// Note: export and import are reserved keywords, so we use the named functions
const exportKey = unsea.export;
const importKey = unsea.import;

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
  console.log('🚀 Starting Unsea v2.0 Test Suite\n');
  console.log('='.repeat(50));

  // Test 1: Key Generation
  await test('Generate Random Keypair', async () => {
    const keys = await pair();
    
    assert(keys.pub, 'Public key should exist');
    assert(keys.priv, 'Private key should exist');
    assert(keys.epub, 'Encryption public key should exist');
    assert(keys.epriv, 'Encryption private key should exist');
    
    assert(keys.pub.includes('.'), 'Public key should be in JWK format (x.y)');
    assert(keys.epub.includes('.'), 'Encryption public key should be in JWK format (x.y)');
    
    console.log(`   Generated keys: pub=${keys.pub.slice(0, 20)}..., epub=${keys.epub.slice(0, 20)}...`);
  });

  // Test 2: Deterministic Key Derivation
  await test('Derive Keypair from Passphrase', async () => {
    const passphrase = 'test-passphrase-with-sufficient-entropy-for-security';
    
    const keys1 = await derive(passphrase);
    const keys2 = await derive(passphrase);
    const keys3 = await pair(passphrase);
    
    assert(keys1.pub === keys2.pub, 'Derived keys should be deterministic');
    assert(keys1.priv === keys2.priv, 'Derived private keys should be deterministic');
    assert(keys1.pub === keys3.pub, 'pair(passphrase) should match derive()');
    
    console.log(`   Deterministic keys: pub=${keys1.pub.slice(0, 20)}...`);
  });

  // Test 3: Message Signing and Verification
  await test('Sign and Verify Message', async () => {
    const keys = await pair();
    const message = 'Hello, Unsea! This is a test message.';
    
    const signature = await sign(message, keys.priv);
    assert(signature, 'Signature should be generated');
    
    const isValid = await verify(message, signature, keys.pub);
    assert(isValid === true, 'Signature should be valid');
    
    const isFalse = await verify('Different message', signature, keys.pub);
    assert(isFalse === false, 'Different message should not verify');
    
    console.log(`   Message: "${message}"`);
    console.log(`   Signature: ${signature.slice(0, 20)}...`);
    console.log(`   Verification: ${isValid}`);
  });

  // Test 4: Ephemeral Encryption and Decryption
  await test('Encrypt and Decrypt Message - Ephemeral Mode', async () => {
    const keys = await pair();
    const message = 'This is a secret message that should be encrypted!';
    
    const encrypted = await encrypt(message, keys.epub);
    assert(encrypted.ciphertext, 'Ciphertext should exist');
    assert(encrypted.iv, 'IV should exist');
    assert(encrypted.sender, 'Sender should exist');
    assert(encrypted.timestamp, 'Timestamp should exist');
    assert(encrypted.mode === 'ephemeral', 'Should be ephemeral mode');
    assert(typeof encrypted.timestamp === 'number', 'Timestamp should be a number');
    
    const decrypted = await decrypt(encrypted, keys.epriv);
    assert(decrypted === message, 'Decrypted message should match original');
    
    console.log(`   Original: "${message}"`);
    console.log(`   Encrypted: ${encrypted.ciphertext.slice(0, 20)}...`);
    console.log(`   Decrypted: "${decrypted}"`);
    console.log(`   Timestamp: ${new Date(encrypted.timestamp).toISOString()}`);
  });

  // Test 5: Authenticated Encryption and Decryption
  await test('Encrypt and Decrypt Message - Authenticated Mode', async () => {
    const alice = await pair();
    const bob = await pair();
    const message = 'Private chat message between Alice and Bob';
    
    // Alice encrypts for Bob using her private key + Bob's public key
    const encrypted = await encrypt(message, bob.epub, alice.epriv);
    assert(encrypted.ciphertext, 'Should have ciphertext');
    assert(encrypted.iv, 'Should have IV');
    assert(encrypted.mode === 'authenticated', 'Should be authenticated mode');
    assert(!encrypted.sender, 'Should not have sender in authenticated mode');
    assert(!encrypted.timestamp, 'Should not have timestamp in authenticated mode');
    
    // Bob decrypts using Alice's public key + his private key
    const decrypted = await decrypt(encrypted, bob.epriv, alice.epub);
    assert(decrypted === message, 'Decrypted message should match original');
    
    // Test bidirectional communication
    const replyMessage = 'Reply from Bob to Alice';
    const replyEncrypted = await encrypt(replyMessage, alice.epub, bob.epriv);
    const replyDecrypted = await decrypt(replyEncrypted, alice.epriv, bob.epub);
    assert(replyDecrypted === replyMessage, 'Bidirectional encryption should work');
    
    console.log(`   Original: "${message}"`);
    console.log(`   Encrypted: ${encrypted.ciphertext.slice(0, 20)}...`);
    console.log(`   Decrypted: "${decrypted}"`);
    console.log(`   Bidirectional test: "${replyDecrypted}"`);
  });

  // Test 6: PEM Export and Import
  await test('Export and Import PEM Format', async () => {
    const keys = await pair();
    
    const pem = await exportKey(keys.priv, 'pem');
    assert(pem.includes('-----BEGIN PRIVATE KEY-----'), 'PEM should have correct header');
    assert(pem.includes('-----END PRIVATE KEY-----'), 'PEM should have correct footer');
    
    const importedPriv = await importKey(pem);
    assert(importedPriv === keys.priv, 'Imported private key should match original');
    
    console.log(`   Original private key: ${keys.priv.slice(0, 20)}...`);
    console.log(`   PEM format: ${pem.split('\n')[1].slice(0, 20)}...`);
    console.log(`   Imported private key: ${importedPriv.slice(0, 20)}...`);
  });

  // Test 7: JWK Export and Import
  await test('Export and Import JWK Format', async () => {
    const keys = await pair();
    
    const jwk = await exportKey(keys.priv, 'jwk');
    assert(jwk.kty === 'EC', 'JWK should have correct key type');
    assert(jwk.crv === 'P-256', 'JWK should have correct curve');
    assert(jwk.d, 'JWK should have private key component');
    
    const importedPriv = await importKey(jwk);
    assert(importedPriv === keys.priv, 'Imported private key should match original');
    
    console.log(`   Original private key: ${keys.priv.slice(0, 20)}...`);
    console.log(`   JWK format: ${JSON.stringify(jwk)}`);
    console.log(`   Imported private key: ${importedPriv.slice(0, 20)}...`);
  });

  // Test 8: Proof of Work
  await test('Generate and Verify Proof of Work', async () => {
    const data = { challenge: 'test_pow', user: 'alice' };
    
    const proof = await work(data, { difficulty: 2, maxIterations: 100000 });
    assert(proof.data, 'Should have data');
    assert(typeof proof.nonce === 'number', 'Should have nonce');
    assert(proof.hash, 'Should have hash');
    assert(proof.difficulty === 2, 'Should have correct difficulty');
    
    const verification = await work(proof, { verify: true });
    assert(verification.valid === true, 'Proof should be valid');
    
    console.log(`   Data: ${proof.data}`);
    console.log(`   Nonce: ${proof.nonce}`);
    console.log(`   Hash: ${proof.hashHex.slice(0, 20)}...`);
    console.log(`   Valid: ${verification.valid}`);
  });

  // Test 9: Signed Proof of Work
  await test('Generate and Verify Signed Proof of Work', async () => {
    const keys = await pair();
    const data = { challenge: 'signed_pow', user: 'bob' };
    
    const signedProof = await work(data, { difficulty: 2, privKey: keys.priv });
    assert(signedProof.signature, 'Should have signature');
    assert(signedProof.signedPayload, 'Should have signed payload');
    
    const verification = await work(signedProof, { verify: true, pubKey: keys.pub });
    assert(verification.valid === true, 'Signed proof should be valid');
    assert(verification.signatureValid === true, 'Signature should be valid');
    
    console.log(`   Signature: ${signedProof.signature.slice(0, 20)}...`);
    console.log(`   Work valid: ${verification.workValid}`);
    console.log(`   Signature valid: ${verification.signatureValid}`);
  });

  // Test 10: Edge Cases and Error Handling
  await test('Edge Cases and Error Handling', async () => {
    const keys = await pair();
    
    // Test empty message
    const emptyMessage = '';
    const emptySig = await sign(emptyMessage, keys.priv);
    const emptyValid = await verify(emptyMessage, emptySig, keys.pub);
    assert(emptyValid === true, 'Empty message should be signable');
    
    // Test Unicode message
    const unicodeMessage = '🔐 Hello, 世界! Привет мир! 🌍';
    const unicodeSig = await sign(unicodeMessage, keys.priv);
    const unicodeValid = await verify(unicodeMessage, unicodeSig, keys.pub);
    assert(unicodeValid === true, 'Unicode message should be signable');
    
    const unicodeEncrypted = await encrypt(unicodeMessage, keys.epub);
    const unicodeDecrypted = await decrypt(unicodeEncrypted, keys.epriv);
    assert(unicodeDecrypted === unicodeMessage, 'Unicode message should be encryptable');
    
    console.log(`   Empty message signature valid: ${emptyValid}`);
    console.log(`   Unicode message: "${unicodeMessage}"`);
    console.log(`   Unicode signature valid: ${unicodeValid}`);
  });

  // Test 11: Library Information
  await test('Library Information', async () => {
    const libInfo = info();
    
    assert(libInfo.version, 'Should have version');
    assert(libInfo.algorithms, 'Should have algorithms info');
    assert(libInfo.api, 'Should have API info');
    assert(libInfo.securityEnhancements, 'Should have security info');
    
    assert(libInfo.version === '2.0.0', 'Should be version 2.0.0');
    assert(Object.keys(libInfo.api).length === 14, 'Should have 14 API methods');
    
    console.log(`   Version: ${libInfo.version}`);
    console.log(`   API methods: ${Object.keys(libInfo.api).join(', ')}`);
    console.log(`   Security features: ${libInfo.securityEnhancements.length} enhancements`);
  });

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log(`🎯 Test Results: ${passCount}/${testCount} tests passed`);
  
  if (passCount === testCount) {
    console.log('🎉 All tests passed! UnSEA v2.0 is working correctly.');
    process.exit(0);
  } else {
    console.log('❌ Some tests failed. Please check the errors above.');
    process.exit(1);
  }
}

// Run the tests
runTests().catch(console.error);
