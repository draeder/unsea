// Pages with no crypto.subtle (plain http): unsea runs on noble alone (src/subtle.js), and what it makes
// opens with WebCrypto, and the other way round.
import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { nobleSubtle } from '../src/subtle.js';

const native = webcrypto.subtle;
const enc = new TextEncoder();
const bytes = (n, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed * 7) % 256);
const hex = (b) => Buffer.from(new Uint8Array(b)).toString('hex');

test('SHA-256 matches WebCrypto', async () => {
  for (const data of [new Uint8Array(0), enc.encode('abc'), bytes(100_000)]) {
    assert.equal(hex(await nobleSubtle.digest('SHA-256', data)), hex(await native.digest('SHA-256', data)));
  }
  assert.equal(hex(await nobleSubtle.digest({ name: 'sha-256' }, enc.encode('x'))), hex(await native.digest('SHA-256', enc.encode('x'))));
  await assert.rejects(nobleSubtle.digest('SHA-1', enc.encode('x')), { name: 'NotSupportedError' });
});

test('HKDF and PBKDF2 bits match WebCrypto', async () => {
  const ikm = bytes(32), salt = enc.encode('salt'), info = enc.encode('info');
  const hkdf = { name: 'HKDF', hash: 'SHA-256', salt, info };
  const [n, w] = await Promise.all([
    nobleSubtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']).then((k) => nobleSubtle.deriveBits(hkdf, k, 256)),
    native.importKey('raw', ikm, 'HKDF', false, ['deriveBits']).then((k) => native.deriveBits(hkdf, k, 256)),
  ]);
  assert.equal(hex(n), hex(w));
  const pbkdf2 = { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 1000 };
  const [p, q] = await Promise.all([
    nobleSubtle.importKey('raw', enc.encode('password'), { name: 'PBKDF2' }, false, ['deriveBits']).then((k) => nobleSubtle.deriveBits(pbkdf2, k, 256)),
    native.importKey('raw', enc.encode('password'), { name: 'PBKDF2' }, false, ['deriveBits']).then((k) => native.deriveBits(pbkdf2, k, 256)),
  ]);
  assert.equal(hex(p), hex(q));
});

test('AES-GCM: the same ciphertext as WebCrypto, and each opens the other', async () => {
  for (const length of [128, 256]) {
    const raw = bytes(length / 8, length);
    const nk = await nobleSubtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const wk = await native.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    for (const [iv, additionalData] of [[bytes(12, 2), undefined], [bytes(12, 3), enc.encode('context')], [bytes(16, 4), enc.encode('a')]]) {
      const alg = { name: 'AES-GCM', iv, ...(additionalData ? { additionalData } : {}) };
      const data = bytes(1000, 5);
      const a = await nobleSubtle.encrypt(alg, nk, data);
      const b = await native.encrypt(alg, wk, data);
      assert.equal(hex(a), hex(b));
      assert.equal(hex(await nobleSubtle.decrypt(alg, nk, b)), hex(data));
      assert.equal(hex(await native.decrypt(alg, wk, a)), hex(data));
      const bad = new Uint8Array(a); bad[3] ^= 1;
      await assert.rejects(nobleSubtle.decrypt(alg, nk, bad), { name: 'OperationError' });
    }
  }
});

test('derived AES keys match WebCrypto', async () => {
  const ikm = bytes(32, 9);
  const hkdf = { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('s'), info: enc.encode('i') };
  const alg = { name: 'AES-GCM', iv: bytes(12, 6), additionalData: enc.encode('ad') };
  const nk = await nobleSubtle.deriveKey(hkdf, await nobleSubtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']), { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const wk = await native.deriveKey(hkdf, await native.importKey('raw', ikm, 'HKDF', false, ['deriveKey']), { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  assert.equal(hex(await nobleSubtle.exportKey('raw', nk)), hex(await native.exportKey('raw', wk)));
  assert.equal(hex(await nobleSubtle.encrypt(alg, nk, enc.encode('hi'))), hex(await native.encrypt(alg, wk, enc.encode('hi'))));
});

test('keys are kept to what they were made for', async () => {
  const k = await nobleSubtle.importKey('raw', bytes(32), { name: 'AES-GCM' }, false, ['encrypt']);
  await assert.rejects(nobleSubtle.decrypt({ name: 'AES-GCM', iv: bytes(12) }, k, bytes(32)), { name: 'InvalidAccessError' });
  await assert.rejects(nobleSubtle.exportKey('raw', k), { name: 'InvalidAccessError' });
  await assert.rejects(nobleSubtle.encrypt({ name: 'AES-GCM', iv: bytes(12) }, { type: 'secret' }, bytes(1)), { name: 'InvalidAccessError' });
  await assert.rejects(nobleSubtle.importKey('raw', bytes(20), { name: 'AES-GCM' }, false, ['encrypt']), { name: 'OperationError' });
  await assert.rejects(nobleSubtle.importKey('jwk', {}, { name: 'AES-GCM' }, false, ['encrypt']), { name: 'NotSupportedError' });
  const g = await nobleSubtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const alg = { name: 'AES-GCM', iv: bytes(12) };
  assert.equal(hex(await nobleSubtle.decrypt(alg, g, await nobleSubtle.encrypt(alg, g, enc.encode('x')))), hex(enc.encode('x')));
});

test('unsea itself: what one side makes, the other opens, with and without WebCrypto', { timeout: 120_000 }, async () => {
  // The library as built, twice: once while WebCrypto is here, once after it is taken away (a plain-http page).
  const withWc = await import('../dist/unsea.mjs?webcrypto');
  const alice = await withWc.generateRandomPair();
  const bob = await withWc.generateRandomPair();
  const fromNative = {
    meta: await withWc.encryptMessageWithMeta('to bob, pq', withWc.publicKeysOf(bob)),
    metaClassic: await withWc.encryptMessageWithMeta('to bob, classic', { epub: bob.epub }),
    pair: await withWc.encryptBySenderForReceiver('pair message', alice.epriv, withWc.publicKeysOf(bob)),
    sealed: await withWc.encryptWithPassword({ secret: 1 }, 'correct horse battery staple'),
    derived: await withWc.derivePair('a long enough password here', 'alias@example'),
    pow: await withWc.generateWork('data'),
  };

  const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { getRandomValues: (a) => webcrypto.getRandomValues(a) } });
  try {
    assert.equal(globalThis.crypto.subtle, undefined);
    const noWc = await import('../dist/unsea.mjs?no-webcrypto');
    assert.equal(noWc.hasNativeSubtle(), false);
    assert.equal(noWc.getSubtle(), noWc.nobleSubtle);

    assert.equal(await noWc.decryptMessageWithMeta(fromNative.meta, bob), 'to bob, pq');
    assert.equal(await noWc.decryptMessageWithMeta(fromNative.metaClassic, bob.epriv), 'to bob, classic');
    assert.equal(await noWc.decryptBySenderForReceiver(fromNative.pair, alice.epub, bob), 'pair message');
    assert.deepEqual(await noWc.decryptWithPassword(fromNative.sealed, 'correct horse battery staple'), { secret: 1 });
    const again = await noWc.derivePair('a long enough password here', 'alias@example');
    assert.equal(again.pub, fromNative.derived.pub, 'the same pair from the same password');
    assert.equal(again.epub, fromNative.derived.epub);
    assert.equal((await noWc.verifyWork(fromNative.pow)).valid, true);

    const sig = await noWc.signMessage('hello', alice);
    assert.equal(await withWc.verifyMessage('hello', sig, withWc.publicKeysOf(alice)), true);
    const back = {
      meta: await noWc.encryptMessageWithMeta('to alice', noWc.publicKeysOf(alice)),
      pair: await noWc.encryptBySenderForReceiver('back', bob.epriv, noWc.publicKeysOf(alice)),
      sealed: await noWc.encryptWithPassword('sealed here', 'another password, long'),
      pow: await noWc.generateWork('data'),
    };
    // And WebCrypto opens what was made without it.
    assert.equal(await withWc.decryptMessageWithMeta(back.meta, alice), 'to alice');
    assert.equal(await withWc.decryptBySenderForReceiver(back.pair, bob.epub, alice), 'back');
    assert.equal(await withWc.decryptWithPassword(back.sealed, 'another password, long'), 'sealed here');
    assert.equal((await withWc.verifyWork(back.pow)).valid, true);
    await assert.rejects(noWc.decryptWithPassword(fromNative.sealed, 'wrong password'));
  } finally {
    Object.defineProperty(globalThis, 'crypto', saved);
  }
});
