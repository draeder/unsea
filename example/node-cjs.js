// Node.js CommonJS example using the bundled version
const unsea = require('../dist/unsea.cjs.js');

async function nodeExample() {
  console.log('🔐 Unsea Node.js CommonJS Example\n');

  try {
    // Generate keypairs
    console.log('1️⃣ Generating keypairs...');
    const alice = await unsea.generateRandomPair();
    const bob = await unsea.generateRandomPair();
    console.log(`   Alice's public key: ${alice.pub.substring(0, 30)}...`);
    console.log(`   Bob's public key: ${bob.pub.substring(0, 30)}...\n`);

    // Sign and verify message
    console.log('2️⃣ Message signing and verification...');
    const message = "Hello from Node.js CommonJS! This message is digitally signed.";
    const signature = await unsea.signMessage(message, alice.priv);
    const isValid = await unsea.verifyMessage(message, signature, alice.pub);
    console.log(`   Message: "${message}"`);
    console.log(`   Signature: ${signature.substring(0, 30)}...`);
    console.log(`   Valid: ${isValid}\n`);

    // Encrypt and decrypt
    console.log('3️⃣ Message encryption and decryption...');
    const secretMessage = "This is a secret message from Alice to Bob! 🔒";
    const encrypted = await unsea.encryptMessageWithMeta(secretMessage, bob.epub);
    const decrypted = await unsea.decryptMessageWithMeta(encrypted, bob.epriv);
    console.log(`   Original: "${secretMessage}"`);
    console.log(`   Encrypted: ${encrypted.ciphertext.substring(0, 30)}...`);
    console.log(`   Decrypted: "${decrypted}"`);
    console.log(`   Timestamp: ${new Date(encrypted.timestamp).toISOString()}\n`);

    // Proof of work
    console.log('4️⃣ Proof of Work (Computational Proof)...');
    const challengeData = {
      challenge: "Node.js CommonJS proof of work test",
      user: "alice",
      timestamp: Date.now()
    };
    console.log('   Computing proof of work...');
    const work = await unsea.generateWork(challengeData, 3, 10000);
    const workValid = await unsea.verifyWork(work);
    console.log(`   Challenge data: ${JSON.stringify(challengeData)}`);
    console.log(`   Nonce found: ${work.nonce}`);
    console.log(`   Hash: ${work.hashHex}`);
    console.log(`   Computing duration: ${work.duration}ms`);
    console.log(`   Hash rate: ${work.hashRate} H/s`);
    console.log(`   Verification: ${workValid.valid}\n`);

    // Key format conversion
    console.log('5️⃣ Key export and import...');
    const pemKey = await unsea.exportToPEM(alice.priv);
    const importedFromPem = await unsea.importFromPEM(pemKey);
    const jwkKey = await unsea.exportToJWK(alice.priv);
    const importedFromJwk = await unsea.importFromJWK(jwkKey);
    console.log(`   PEM export successful: ${pemKey.includes('BEGIN PRIVATE KEY')}`);
    console.log(`   PEM import matches: ${alice.priv === importedFromPem}`);
    console.log(`   JWK export successful: ${jwkKey.kty === 'EC'}`);
    console.log(`   JWK import matches: ${alice.priv === importedFromJwk}\n`);

    console.log('✅ Node.js CommonJS example completed successfully!');
    console.log('\n📚 This demonstrates that the bundled library works seamlessly in Node.js with CommonJS require()');

  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

// Run the example
nodeExample();
