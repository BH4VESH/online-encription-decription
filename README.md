# AES Encryption, Decryption & Base64 Tool (Node.js + Pug)

Browser-based developer utility using Express, Pug and Node's native `crypto`. It supports both supplied AES-256-CBC backend formats, AES-GCM for Node-only experiments, and a Base64 text converter.

## Requirements and run

- Node.js 20+
- npm

```bash
cp .env.example .env
npm install
npm run dev
```

Open `http://127.0.0.1:3000`. Run tests with `npm test`.

## Match the fixed-IV Node middleware

Your first backend uses a UTF-8 key and a UTF-8 fixed IV, and sends only the Base64 ciphertext:

```js
const key = Buffer.from(process.env.SECRET_KEY, 'utf8'); // exactly 32 bytes
const iv = Buffer.from(process.env.REQ_AES_IV, 'utf8'); // exactly 16 bytes
```

In the UI, choose:

- Cipher Mode: `CBC`
- Key Size: `256 bits`
- Secret Key Format: `Plain Text`
- Secret Key: the exact `SECRET_KEY` value
- IV: the exact `REQ_AES_IV` value
- IV Format: `Plain Text (UTF-8)`
- Encryption output: `Fixed-IV Node middleware (Raw Base64 ciphertext)`
- Decryption input: `Fixed-IV Node middleware (Raw Base64)`

Use the same key and IV in both forms. The raw format does not contain the IV, so you must provide it when decrypting. Raw Hex formats are also available.

## Match the PHP-compatible envelope backend

The second backend Base64-decodes `ENCRYPTION_KEY` into 32 bytes and uses a random 16-byte IV for each encryption. Its format is:

```text
Base64( Base64(ciphertext) + "::" + Base64(IV) )
```

In the UI, choose:

- Cipher Mode: `CBC`
- Key Size: `256 bits`
- Secret Key Format: `Base64`
- Secret Key: the exact Base64 `ENCRYPTION_KEY`
- Encryption output: `PHP-compatible envelope (Base64)`
- Decryption input: `PHP-compatible envelope (Base64)`
- Leave IV blank for a fresh random IV on encryption and for decryption (the envelope carries its IV).

Do not use `SECRET_KEY` from the first backend as the Base64 key for the second backend unless the actual key bytes are intentionally the same. These are separate key conventions and wire formats.

## Base64 converter

The Base64 Converter section encodes UTF-8 text to Base64 or decodes Base64 to UTF-8 text. It is useful for inspecting envelope components and other text values; it does not encrypt data.

## API

### `POST /api/encrypt`

Fields: `plaintext`, `key`, `keyFormat` (`plain`, `base64`, `hex`), `keySize` (`128`, `192`, `256`), `mode` (`cbc`, `gcm`), optional `iv`, `ivFormat` (`plain`, `base64`, `hex`), and `payloadFormat` (`php`, `php-hex`, `raw-base64`, `raw-hex`).

### `POST /api/decrypt`

Fields: `ciphertext`, `key`, `keyFormat`, `keySize`, `mode`, optional `iv`, `ivFormat`, and `inputFormat` (`php`, `php-hex`, `php-plain`, `raw-base64`, `raw-hex`).

### `POST /api/base64`

```json
{ "text": "Hello world", "action": "encode" }
```

Use `action: "decode"` to decode Base64.

Successful API responses use `{ "code": 200, "status": true, "message": "...", "data": "..." }`. Errors return a 4xx response and do not log submitted secrets or payloads.

## Security notes

- Never log keys, IVs, plaintext, or ciphertext.
- Do not expose this utility publicly without authentication/access controls and HTTPS.
- AES-CBC does not authenticate ciphertext; use AES-GCM for new protocols when all clients support it.
- Fixed IVs are only for compatibility with your existing middleware. For new CBC messages, use a random IV per message.
- The interface does not save inputs in local storage, but do not treat a browser session as a secret vault.

## Matching the two existing Node.js backends

### Backend A: fixed UTF-8 key and IV

Your middleware calls `Buffer.from(SECRET_KEY, 'utf8')` and `Buffer.from(REQ_AES_IV, 'utf8')`, then encrypts/decrypts raw Base64 ciphertext. In the UI choose:

- Cipher mode: CBC
- Secret key format: Plain Text
- Key size: 256 bits (the UTF-8 key must be exactly 32 bytes)
- IV format: Plain Text (UTF-8)
- Encryption output: Fixed-IV Node middleware (Raw Base64 ciphertext)
- Decryption input: Fixed-IV Node middleware (Raw Base64)

Use the exact same key and IV values as the API server. Do not select Base64 key format for this backend unless the API itself decodes the key from Base64.

Postman request body:

```json
{
  "data": "PASTE_RAW_BASE64_CIPHERTEXT_HERE"
}
```

The API response will be encrypted too if `encryptResponse` is active. Copy its `data` value into the Decryption form, with the same plain-text key, fixed IV, and raw Base64 input format.

### Backend B: PHP-compatible envelope

Choose Secret key format Base64, AES-256-CBC, and PHP-compatible envelope for encryption. Leave the external IV blank so the tool generates a random IV and embeds it in the envelope. For decryption, select PHP-compatible envelope (Base64) and leave external IV blank. The decoded key must be exactly 32 bytes.

### Why a request may return HTTP 400

A key-format mismatch changes the actual key bytes even if the key text looks similar. Backend A expects the literal UTF-8 bytes of `SECRET_KEY`; Backend B expects `ENCRYPTION_KEY` decoded from Base64. Also make sure the API request contains the encrypted string in the JSON `data` field and that it is not URL-encoded or altered by line wrapping.
