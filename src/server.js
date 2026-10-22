require('dotenv').config();

const express = require('express');
const path = require('node:path');
const helmet = require('helmet');
const compression = require('compression');
const { rateLimit } = require('express-rate-limit');
const { encryptData, decryptData, parseKey, parseIv, decodeByFormat } = require('./services/aes');

const app = express();
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '127.0.0.1';
const maxRequestBytes = process.env.MAX_REQUEST_BYTES || '64kb';

app.disable('x-powered-by');
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));
app.use(compression());
app.use(express.urlencoded({ extended: false, limit: maxRequestBytes }));
app.use(express.json({ limit: maxRequestBytes }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', etag: true }));

const toolLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 60000),
  limit: Number(process.env.RATE_LIMIT_MAX || 60),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { code: 429, status: false, message: 'Too many requests. Please try again shortly.', data: null }
});

app.get('/', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.render('index', {
    title: 'AES Encryption & Decryption',
    csrfPlaceholder: ''
  });
});

function readText(value, fieldName, required = true) {
  if (value === undefined || value === null || value === '') {
    if (required) throw new Error(`${fieldName} is required.`);
    return '';
  }
  if (typeof value !== 'string') throw new Error(`${fieldName} must be text.`);
  return value;
}

function handleCrypto(mode) {
  return (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const body = req.body || {};
      const keyText = readText(body.key, 'Secret key');
      const keyFormat = body.keyFormat || 'base64';
      const keySize = Number(body.keySize || 256);
      const algorithmMode = body.mode || 'cbc';
      const format = body.payloadFormat || 'php';

      if (!['plain', 'base64', 'hex'].includes(keyFormat)) throw new Error('Invalid secret key format.');
      if (![128, 192, 256].includes(keySize)) throw new Error('Key size must be 128, 192, or 256 bits.');
      if (!['cbc', 'gcm'].includes(algorithmMode)) throw new Error('Unsupported cipher mode.');
      if (!['php', 'php-hex', 'raw-base64', 'raw-hex'].includes(format) && mode === 'encrypt') throw new Error('Invalid encryption output format.');

      const key = parseKey(keyText, keyFormat, keySize);
      const ivText = readText(body.iv, 'IV', false);
      const ivFormat = body.ivFormat || 'base64';
      const iv = ivText ? parseIv(ivText, ivFormat, algorithmMode) : null;

      if (mode === 'encrypt') {
        const plaintext = readText(body.plaintext, 'Plain text');
        const result = encryptData(plaintext, key, {
          keySize, mode: algorithmMode, iv, payloadFormat: format
        });
        return res.json({ code: 200, status: true, message: 'Encryption successful.', data: result });
      }

      const encryptedText = readText(body.ciphertext, 'Encrypted text');
      const result = decryptData(encryptedText, key, {
        keySize, mode: algorithmMode, externalIv: iv, inputFormat: body.inputFormat || 'php'
      });
      return res.json({ code: 200, status: true, message: 'Decryption successful.', data: result });
    } catch (error) {
      // Do not log keys, IVs, plaintext, or ciphertext.
      return res.status(400).json({
        code: 400,
        status: false,
        message: error.message || 'Unable to process cryptographic input.',
        data: null
      });
    }
  };
}

app.post('/api/encrypt', toolLimiter, handleCrypto('encrypt'));
app.post('/api/decrypt', toolLimiter, handleCrypto('decrypt'));

app.post('/api/base64', toolLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const text = readText(req.body?.text, 'Text');
    const action = req.body?.action;
    if (action === 'encode') return res.json({ code: 200, status: true, message: 'Base64 encoding successful.', data: Buffer.from(text, 'utf8').toString('base64') });
    if (action === 'decode') {
      const bytes = decodeByFormat(text, 'base64', 'Base64 input');
      return res.json({ code: 200, status: true, message: 'Base64 decoding successful.', data: bytes.toString('utf8') });
    }
    throw new Error('Choose Encode to Base64 or Decode from Base64.');
  } catch (error) {
    return res.status(400).json({ code: 400, status: false, message: error.message, data: null });
  }
});

app.use((err, _req, res, _next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ code: 413, status: false, message: 'Request body is too large.', data: null });
  }
  return res.status(400).json({ code: 400, status: false, message: 'Invalid request body.', data: null });
});

if (require.main === module) {
  app.listen(port, host, () => {
    console.log(`AES tool listening on http://${host}:${port} (${process.env.NODE_ENV || 'development'})`);
  });
}

module.exports = app;
