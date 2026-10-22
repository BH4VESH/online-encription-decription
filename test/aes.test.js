const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { encryptData, decryptData, parseKey, parseIv } = require('../src/services/aes');

test('PHP-compatible AES-256-CBC encrypt/decrypt round trip', () => {
  const key = crypto.randomBytes(32);
  const plaintext = JSON.stringify({ login: 100017, offset: 0, total: 100 });
  const encrypted = encryptData(plaintext, key, { mode: 'cbc', outputFormat: 'base64' });
  assert.equal(decryptData(encrypted, key, { mode: 'cbc', inputFormat: 'php' }), plaintext);
});

test('PHP-compatible envelope stores ciphertext and 16-byte IV in Base64', () => {
  const key = Buffer.from('MvhejNuJ+1awS2xZIeDoL6eEfn/ibS3HC7JhrP0Dpus=', 'base64');
  const encrypted = encryptData('hello', key, { mode: 'cbc' });
  const envelope = Buffer.from(encrypted, 'base64').toString('utf8');
  const [ciphertext, iv] = envelope.split('::');
  assert.equal(Buffer.from(iv, 'base64').length, 16);
  assert.equal(Buffer.from(ciphertext, 'base64').length % 16, 0);
  assert.equal(decryptData(encrypted, key), 'hello');
});

test('rejects invalid key size and IV size', () => {
  assert.throws(() => parseKey('short', 'plain', 256), /exactly 32 bytes/);
  assert.throws(() => parseIv('c2hvcnQ=', 'base64', 'cbc'), /exactly 16 bytes/);
});

test('AES-GCM round trip authenticates payload', () => {
  const key = crypto.randomBytes(32);
  const encrypted = encryptData('authenticated message', key, { mode: 'gcm' });
  assert.equal(decryptData(encrypted, key, { mode: 'gcm' }), 'authenticated message');
});

test('AES-GCM rejects altered ciphertext', () => {
  const key = crypto.randomBytes(32);
  const encrypted = encryptData('secret message', key, { mode: 'gcm' });
  const payload = JSON.parse(Buffer.from(encrypted, 'base64').toString('utf8'));
  payload.ciphertext = Buffer.from(payload.ciphertext, 'base64').map((byte, index) => index === 0 ? byte ^ 1 : byte).toString('base64');
  const altered = Buffer.from(JSON.stringify(payload)).toString('base64');
  assert.throws(() => decryptData(altered, key, { mode: 'gcm' }));
});

test('fixed-IV Node middleware raw Base64 format round trip (UTF-8 key and IV)', () => {
  const key = Buffer.from('PYMVYkekrwxgiFEicaeGxNoPZqaqkZfa', 'utf8');
  const iv = Buffer.from('ptvhpzxmHSwOznRM', 'utf8');
  assert.equal(key.length, 32);
  assert.equal(iv.length, 16);
  const plaintext = JSON.stringify({ login: 100017, from: 1792502352, to: 1792502860, offset: 0, total: 100 });
  const encrypted = encryptData(plaintext, key, { mode: 'cbc', iv, payloadFormat: 'raw-base64' });
  assert.equal(decryptData(encrypted, key, { mode: 'cbc', externalIv: iv, inputFormat: 'raw-base64' }), plaintext);
});

test('PHP-compatible Base64 key envelope round trip', () => {
  const key = Buffer.from('MvhejNuJ+1awS2xZIeDoL6eEfn/ibS3HC7JhrP0Dpus=', 'base64');
  assert.equal(key.length, 32);
  const plaintext = JSON.stringify({ login: 100017, offset: 0 });
  const encrypted = encryptData(plaintext, key, { mode: 'cbc', payloadFormat: 'php' });
  assert.equal(decryptData(encrypted, key, { mode: 'cbc', inputFormat: 'php' }), plaintext);
});
