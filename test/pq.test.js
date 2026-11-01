// Post-quantum hybrid keys (3.0): ML-DSA-65 + ECDSA signatures, ML-KEM-768 +
// ECDH encryption, Argon2id password encryption, and what still opens from
// before.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  generateRandomPair, upgradePair, publicKeysOf, hasPostQuantumKeys, derivePair,
  signMessage, verifyMessage, isHybridSignature,
  encryptMessageWithMeta, decryptMessageWithMeta,
  encryptBySenderForReceiver, decryptBySenderForReceiver,
  encryptWithPassword, decryptWithPassword,
} from '../dist/unsea.mjs';

test('new pairs carry post-quantum keys as small seeds', async () => {
  const pair = await generateRandomPair();
  assert.equal(hasPostQuantumKeys(pair), true);
  assert.equal(pair.qpriv.length, 43, '32-byte seed');
  assert.equal(pair.kpriv.length, 86, '64-byte seed');
  assert.equal(hasPostQuantumKeys(await generateRandomPair({ postQuantum: false })), false);
  const pub = publicKeysOf(pair);
  assert.deepEqual(Object.keys(pub).sort(), ['epub', 'kpub', 'pub', 'qpub']);
});

test('hybrid signatures need both halves, and cannot be downgraded', async () => {
  const pair = await generateRandomPair();
  const sig = await signMessage('move e2e4', pair);
  assert.equal(isHybridSignature(sig), true);
  assert.equal(await verifyMessage('move e2e4', sig, publicKeysOf(pair)), true);
  assert.equal(await verifyMessage('move e2e5', sig, publicKeysOf(pair)), false);

  const [, classic, quantum] = sig.split('.').length === 3 ? ['', ...sig.slice(4).split('.')] : [];
  // The ECDSA half alone is not a valid plain signature.
  assert.equal(await verifyMessage('move e2e4', classic, pair.pub), false);
  // A plain signature is refused once the signer's qpub is known.
  const plain = await signMessage('move e2e4', pair.priv);
  assert.equal(await verifyMessage('move e2e4', plain, pair.pub), true);
  assert.equal(await verifyMessage('move e2e4', plain, publicKeysOf(pair)), false);
  // A hybrid signature is refused by a verifier that has only pub.
  assert.equal(await verifyMessage('move e2e4', sig, pair.pub), false);
  // Swapping in another key's ML-DSA half fails.
  const other = await generateRandomPair();
  const otherSig = await signMessage('move e2e4', other);
  const mixed = `pq1.${classic}.${otherSig.slice(4).split('.')[1]}`;
  assert.equal(await verifyMessage('move e2e4', mixed, publicKeysOf(pair)), false);
  assert.equal(await verifyMessage('move e2e4', mixed, { pub: pair.pub, qpub: other.qpub }), false);
  assert.ok(quantum.length > 4000);
});

test('upgradePair keeps the P-256 identity and adds post-quantum keys', async () => {
  const old = await generateRandomPair({ postQuantum: false });
  const upgraded = upgradePair(old);
  assert.equal(upgraded.pub, old.pub);
  assert.equal(upgraded.priv, old.priv);
  assert.equal(hasPostQuantumKeys(upgraded), true);
  assert.deepEqual(upgradePair(upgraded), upgraded, 'upgrading again changes nothing');
  assert.equal(await verifyMessage('x', await signMessage('x', upgraded), publicKeysOf(upgraded)), true);
});

test('messages to a recipient with a kpub are hybrid encrypted', async () => {
  const bob = await generateRandomPair();
  const payload = await encryptMessageWithMeta('hello bob', publicKeysOf(bob));
  assert.equal(payload.v, 3);
  assert.equal(await decryptMessageWithMeta(payload, bob), 'hello bob');
  await assert.rejects(decryptMessageWithMeta(payload, bob.epriv), /kpriv/);
  const eve = await generateRandomPair();
  await assert.rejects(decryptMessageWithMeta(payload, { ...eve, epriv: bob.epriv }));
  await assert.rejects(decryptMessageWithMeta({ ...payload, timestamp: payload.timestamp + 1 }, bob));
  // Without a kpub it is the 2.0 format, which the epriv string still opens.
  const classic = await encryptMessageWithMeta('hi', { epub: bob.epub });
  assert.equal(classic.v, 2);
  assert.equal(await decryptMessageWithMeta(classic, bob.epriv), 'hi');
  assert.equal(await decryptMessageWithMeta(classic, bob), 'hi');
});

test('sender-to-receiver messages are hybrid when the receiver has a kpub', async () => {
  const alice = await generateRandomPair();
  const bob = await generateRandomPair();
  const payload = await encryptBySenderForReceiver('secret', alice.epriv, publicKeysOf(bob));
  assert.equal(payload.v, 3);
  assert.equal(await decryptBySenderForReceiver(payload, alice.epub, bob), 'secret');
  await assert.rejects(decryptBySenderForReceiver(payload, alice.epub, bob.epriv));
  const classic = await encryptBySenderForReceiver('secret', alice.epriv, bob.epub);
  assert.equal(await decryptBySenderForReceiver(classic, alice.epub, bob.epriv), 'secret');
});

test('password encryption uses Argon2id and refuses weak parameters', async () => {
  const sealed = await encryptWithPassword({ a: 1 }, 'Correct-Horse-9');
  assert.equal(sealed.kdf, 'argon2id');
  assert.ok(sealed.m >= 19456);
  assert.deepEqual(await decryptWithPassword(sealed, 'Correct-Horse-9'), { a: 1 });
  await assert.rejects(decryptWithPassword(sealed, 'wrong'));
  await assert.rejects(decryptWithPassword({ ...sealed, m: 8 }, 'Correct-Horse-9'), /out of range/);
});

test('derivePair gives the same post-quantum keys for the same password and salt', async () => {
  const a = await derivePair('a long enough passphrase', 'dan');
  const b = await derivePair('a long enough passphrase', 'dan');
  const c = await derivePair('a long enough passphrase', 'eve');
  assert.equal(a.qpub, b.qpub);
  assert.equal(a.kpub, b.kpub);
  assert.notEqual(a.qpub, c.qpub);
  assert.equal(hasPostQuantumKeys(await derivePair('a long enough passphrase', { legacyUnsalted: true })), false);
});
