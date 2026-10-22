const crypto = require('node:crypto');

function decodeByFormat(value, format, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be text.`);
  if (format === 'plain') return Buffer.from(value, 'utf8');
  if (format === 'hex') {
    if (!value || value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) throw new Error(`${label} must be valid even-length hexadecimal.`);
    return Buffer.from(value, 'hex');
  }
  if (format === 'base64') {
    if (!value || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`${label} must be valid Base64.`);
    return Buffer.from(value, 'base64');
  }
  throw new Error(`Unsupported ${label.toLowerCase()} format.`);
}

function parseKey(value, format = 'plain', keySize = 256) {
  const key = decodeByFormat(value, format, 'Secret key');
  if (key.length * 8 !== Number(keySize)) throw new Error(`Secret key must decode to exactly ${Number(keySize) / 8} bytes (${keySize} bits).`);
  return key;
}

function parseIv(value, format = 'plain', mode = 'cbc') {
  const iv = Buffer.isBuffer(value) ? value : decodeByFormat(value, format, 'IV');
  const expectedLength = mode === 'gcm' ? 12 : 16;
  if (iv.length !== expectedLength) throw new Error(`IV must be exactly ${expectedLength} bytes for AES-${mode.toUpperCase()}.`);
  return iv;
}

function algorithmFor(key, mode) {
  if (!['cbc', 'gcm'].includes(mode)) throw new Error('Unsupported cipher mode.');
  return `aes-${key.length * 8}-${mode}`;
}

function encryptData(plaintext, key, options = {}) {
  const mode = options.mode || 'cbc';
  const format = options.payloadFormat || 'php';
  const algorithm = algorithmFor(key, mode);
  if (mode === 'gcm') {
    const iv = options.iv || crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(algorithm, key, parseIv(iv, 'plain', 'gcm'));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return Buffer.from(JSON.stringify({v:1, mode:'gcm', iv:iv.toString('base64'), tag:cipher.getAuthTag().toString('base64'), ciphertext:ciphertext.toString('base64')}), 'utf8').toString('base64');
  }

  // PHP-compatible envelope: Base64(Base64(ciphertext)::Base64(IV)); random IV by default.
  // Fixed-IV Node middleware: output only Base64(ciphertext), using the supplied IV.
  const rawFormat = format === 'raw-base64' || format === 'raw-hex';
  if (rawFormat && !options.iv) throw new Error('A fixed IV is required for raw ciphertext output.');
  const iv = options.iv ? parseIv(options.iv, 'plain', 'cbc') : crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  if (format === 'raw-base64') return ciphertext.toString('base64');
  if (format === 'raw-hex') return ciphertext.toString('hex');
  if (format !== 'php' && format !== 'php-hex') throw new Error('Unsupported encryption output format.');
  const envelope = Buffer.from(`${ciphertext.toString('base64')}::${iv.toString('base64')}`, 'utf8');
  return format === 'php-hex' ? envelope.toString('hex') : envelope.toString('base64');
}

function decryptData(encryptedText, key, options = {}) {
  const mode = options.mode || 'cbc';
  const algorithm = algorithmFor(key, mode);
  if (mode === 'gcm') {
    let json;
    try { json = JSON.parse(decodeByFormat(encryptedText, 'base64', 'Encrypted payload').toString('utf8')); }
    catch { throw new Error('Invalid AES-GCM payload format.'); }
    if (json.mode !== 'gcm' || json.v !== 1) throw new Error('Unsupported AES-GCM payload version.');
    const iv = parseIv(json.iv, 'base64', 'gcm');
    const tag = decodeByFormat(json.tag, 'base64', 'Authentication tag');
    const ciphertext = decodeByFormat(json.ciphertext, 'base64', 'Ciphertext');
    if (tag.length !== 16) throw new Error('AES-GCM authentication tag must be 16 bytes.');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  }

  const inputFormat = options.inputFormat || 'php';
  let ciphertext;
  let iv;
  if (inputFormat === 'raw-base64' || inputFormat === 'raw-hex') {
    if (!options.externalIv) throw new Error('An external IV is required for raw ciphertext.');
    ciphertext = decodeByFormat(encryptedText, inputFormat === 'raw-base64' ? 'base64' : 'hex', 'Ciphertext');
    iv = parseIv(options.externalIv, 'plain', 'cbc');
  } else {
    let decoded;
    if (inputFormat === 'php-hex') decoded = decodeByFormat(encryptedText, 'hex', 'Encrypted payload').toString('utf8');
    else if (inputFormat === 'php-plain') decoded = encryptedText;
    else if (inputFormat === 'php') decoded = decodeByFormat(encryptedText, 'base64', 'Encrypted payload').toString('utf8');
    else throw new Error('Unsupported encrypted input format.');
    const separatorIndex = decoded.indexOf('::');
    if (separatorIndex < 0) throw new Error('Invalid PHP-compatible payload: expected ciphertext::IV.');
    const cipherTextBase64 = decoded.slice(0, separatorIndex);
    const ivBase64 = decoded.slice(separatorIndex + 2);
    ciphertext = decodeByFormat(cipherTextBase64, 'base64', 'Ciphertext');
    iv = parseIv(ivBase64, 'base64', 'IV');
  }
  if (!ciphertext.length || ciphertext.length % 16 !== 0) throw new Error('Ciphertext length must be a non-zero multiple of 16 bytes for AES-CBC.');
  try {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Decryption failed. Check that the key, IV, and input format exactly match the encryption settings.');
  }
}

module.exports = { encryptData, decryptData, parseKey, parseIv, decodeByFormat };
