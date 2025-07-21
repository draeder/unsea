#!/usr/bin/env node

// Example usage of Unsea cryptographic toolkit
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
  generateWork,
  verifyWork,
  generateSignedWork,
  verifySignedWork
} from './index.js';

async function example() {
  console.log('🔐 Unsea Cryptographic Toolkit Example\n');

  // Generate keypairs
  console.log('1️⃣  Generating keypairs...');
  const alice = await generateRandomPair();
  const bob = await generateRandomPair();
  
  console.log(`   Alice's public key: ${alice.pub.slice(0, 30)}...`);
  console.log(`   Bob's public key: ${bob.pub.slice(0, 30)}...`);

  // Message signing and verification
  console.log('\n2️⃣  Message signing and verification...');
  const message = 'Hello from Alice! This message is digitally signed.';
  const signature = await signMessage(message, alice.priv);
  const isValid = await verifyMessage(message, signature, alice.pub);
  
  console.log(`   Message: "${message}"`);
  console.log(`   Signature: ${signature.slice(0, 30)}...`);
  console.log(`   Valid: ${isValid}`);

  // Message encryption and decryption
  console.log('\n3️⃣  Message encryption and decryption...');
  const secretMessage = 'This is a secret message from Alice to Bob! 🔒';
  const encrypted = await encryptMessageWithMeta(secretMessage, bob);
  const decrypted = await decryptMessageWithMeta(encrypted, bob.epriv);
  
  console.log(`   Original: "${secretMessage}"`);
  console.log(`   Encrypted: ${encrypted.ciphertext.slice(0, 30)}...`);
  console.log(`   Decrypted: "${decrypted}"`);
  console.log(`   Timestamp: ${new Date(encrypted.timestamp).toISOString()}`);

  // Key export and import
  console.log('\n4️⃣  Key export and import...');
  
  // PEM format
  const pemKey = await exportToPEM(alice.priv);
  const importedPemKey = await importFromPEM(pemKey);
  
  console.log(`   PEM export successful: ${pemKey.includes('BEGIN PRIVATE KEY')}`);
  console.log(`   PEM import matches: ${importedPemKey === alice.priv}`);
  
  // JWK format
  const jwkKey = await exportToJWK(alice.priv);
  const importedJwkKey = await importFromJWK(jwkKey);
  
  console.log(`   JWK export successful: ${jwkKey.kty === 'EC'}`);
  console.log(`   JWK import matches: ${importedJwkKey === alice.priv}`);

  // Proof of Work
  console.log('\n5️⃣  Proof of Work (Computational Proof)...');
  
  const challengeData = {
    challenge: 'Find a nonce that makes this hash start with zeros',
    user: 'alice',
    timestamp: Date.now()
  };
  
  console.log('   Computing proof of work (this may take a few seconds)...');
  const work = await generateWork(challengeData, 4, 100000); // difficulty 4
  const workVerification = await verifyWork(work);
  
  console.log(`   Challenge data: ${JSON.stringify(challengeData)}`);
  console.log(`   Nonce found: ${work.nonce}`);
  console.log(`   Hash: ${work.hashHex}`);
  console.log(`   Computing duration: ${work.duration}ms`);
  console.log(`   Hash rate: ${work.hashRate} H/s`);
  console.log(`   Verification: ${workVerification.valid}`);

  // Signed Proof of Work
  console.log('\n6️⃣  Signed Proof of Work (Authenticated Proof)...');
  
  const signedChallengeData = {
    challenge: 'Authenticated computational proof',
    participant: alice.pub.slice(0, 20) + '...',
    task: 'rate limiting or anti-spam proof',
    timestamp: Date.now()
  };
  
  console.log('   Computing and signing proof...');
  const signedWork = await generateSignedWork(signedChallengeData, alice.priv, 3, 50000);
  const signedVerification = await verifySignedWork(signedWork, alice.pub);
  
  console.log(`   Challenge data: ${JSON.stringify(signedChallengeData)}`);
  console.log(`   Nonce: ${signedWork.nonce}`);
  console.log(`   Hash: ${signedWork.hashHex}`);
  console.log(`   Computing duration: ${signedWork.duration}ms`);
  console.log(`   Signature valid: ${signedVerification.signatureValid}`);
  console.log(`   Work valid: ${signedVerification.workValid}`);
  console.log(`   Overall valid: ${signedVerification.valid}`);

  console.log('\n✅ Example completed successfully!');
  console.log('\n🌐 For browser usage with IndexedDB storage, see the README.md');
}

// Run the example
example().catch(console.error);
