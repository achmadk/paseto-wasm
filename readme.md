<div align="center">

  <h1>PASETO Rust WASM (<code>paseto-wasm</code>)</h1>
  
  <strong>Enable PASETO in JavaScript browsers using <a href="https://webassembly.org/">WebAssembly (WASM)</a></strong>

  <!-- <p>
    <a href="https://travis-ci.org/rustwasm/wasm-pack-template"><img src="https://img.shields.io/travisci/rustwasm/wasm-pack-template.svg?style=flat-square" alt="Build Status" /></a>
  </p>
  -->
  <sub>Built with 🦀🕸 by <a href="https://achmadk.com">Achmad Kurnianto</a></sub>
</div>

## 🌄 Background

PASETO (Platform-Agnostic Security Tokens) offers the benefits of JOSE standards (JWT, JWE, JWS) without their numerous design flaws.

This project began in 2022 when no PASETO libraries supported JavaScript browsers. The existing JavaScript/TypeScript implementations were:

1. **`paseto` by Filip Skokan** - Node.js only
2. **`paseto.js` by Samuel Judson** - Uses deprecated PASETO v1 and v2 implementations

Today, you can use the `paseto-ts` library for browser-based PASETO implementation. For better performance, consider `paseto-wasm`, which leverages WebAssembly.

Initially, I planned to use the [`pasetors`](https://github.com/brycx/pasetors) crate by [Johannes](https://github.com/brycx), which includes WASM support [but lacks comprehensive testing](https://github.com/brycx/pasetors/issues/75#issuecomment-1281376534). After evaluating options, I chose the [`rusty-paseto`](https://github.com/rrrodzilla/rusty_paseto) crate for its reliable WASM support.

## 🚀 Usage

### Installation

This crate produces the `paseto-wasm` library, compatible with both JavaScript browsers and Node.js.

```sh
npm install paseto-wasm      # npm
yarn add paseto-wasm         # yarn
pnpm add paseto-wasm         # pnpm
bun add paseto-wasm          # bun
```

### Quick Start

```javascript
// PASETO v4
import initV4, * as v4 from 'paseto-wasm'; // OR
import initV4, * as v4 from 'paseto-wasm/v4';

// PASETO v3
import initV3, * as v3 from 'paseto-wasm/v3';

// init WASM first before using other methods
await initV4(); // OR
await initV3();

// Generate a local encryption key (32 bytes)
const localKey = v4.generate_v4_local_key();

// Encrypt a message (local key - symmetric encryption)
const token = v4.encrypt_v4_local(localKey, { data: 'Hello PASETO!' });
const decrypted = v4.decrypt_v4_local(localKey, token);

// Or use asymmetric keys for signing
const keyPair = v4.generate_v4_public_key_pair();
const signedToken = v4.sign_v4_public(keyPair.secret, { user: 'alice' });
const verified = v4.verify_v4_public(keyPair.public, signedToken);
```

---

## API Documentation

### PASETO Versions

| Version | Algorithm (Local) | Algorithm (Public) | Use Case |
|---------|-----------------|-------------------|----------|
| v4 | XChaCha20-Poly1305 | Ed25519 | Modern applications (default) |
| v3 | AES-256-CTR + HMAC-SHA384 | P-384 + ECDSA | FIPS-compliant environments |

**Recommendation**: Use v4 for new applications. Use v3 only when required for FIPS compliance.

---

### PASETO v4 API (Default)

#### Key Generation

##### `generate_v4_local_key()`

Generates a cryptographically secure random key for local encryption.

**Returns**: `string` - A 64-character hex string (32 bytes)

```javascript
const key = v4.generate_v4_local_key();
// key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
```

##### `generate_v4_public_key_pair()`

Generates a new Ed25519 key pair for public signing/verification.

**Returns**: `KeyPair` object with:
- `secret`: 128-character hex string (64 bytes) - Keep secret!
- `public`: 64-character hex string (32 bytes)

```javascript
const keyPair = v4.generate_v4_public_key_pair();
console.log(keyPair.secret); // "a1b2...c3d4" (128 hex)
console.log(keyPair.public);  // "e5f6...g7h8" (64 hex)
```

---

#### Local Encryption (Symmetric)

##### `encrypt_v4_local(key_hex, message, footer?, implicit_assertion?)`

Encrypts a message using XChaCha20-Poly1305.

**Parameters**:
- `key_hex` (string, required): 64-character hex string (32 bytes)
- `message` (string \| object, required): Message to encrypt
- `footer` (string, optional): Additional footer data
- `implicit_assertion` (string, optional): Additional implicit assertion

**Returns**: `string` - PASETO token in format `v4.local.{payload}`

```javascript
// With string message
const token1 = v4.encrypt_v4_local(key, "Hello World");

// With object message (serialized as JSON)
const token2 = v4.encrypt_v4_local(key, { user: 'alice', role: 'admin' });

// With footer
const token3 = v4.encrypt_v4_local(key, "secret", "footer-data");
```

##### `decrypt_v4_local(key_hex, token, footer?, implicit_assertion?)`

Decrypts a PASETO v4 local token.

**Parameters**:
- `key_hex` (string, required): 64-character hex string (32 bytes)
- `token` (string, required): The PASETO token to decrypt
- `footer` (string, optional): Must match what was used during encryption
- `implicit_assertion` (string, optional): Must match what was used

**Returns**: `string` - The decrypted message as a JSON string

```javascript
const decrypted = v4.decrypt_v4_local(key, token);
// decrypted: '{"user":"alice","role":"admin"}'
```

**Errors**: Throws if key is invalid, token tampered, or wrong key used.

---

#### Public Signing (Asymmetric)

##### `sign_v4_public(secret_key_hex, message, footer?, implicit_assertion?)`

Signs a message using Ed25519. The message is visible in the token - this provides authentication/integrity, NOT secrecy.

**Parameters**:
- `secret_key_hex` (string, required): 128-character hex string (64 bytes)
- `message` (string \| object, required): Message to sign
- `footer` (string, optional): Additional footer data
- `implicit_assertion` (string, optional): Additional implicit assertion

**Returns**: `string` - PASETO token in format `v4.public.{signature}`

```javascript
const keyPair = v4.generate_v4_public_key_pair();
const token = v4.sign_v4_public(keyPair.secret, { user: 'alice' });
// token: "v4.public.eyJ1c2VyIjoiYWxpY2UifQ..."
```

##### `verify_v4_public(public_key_hex, token, footer?, implicit_assertion?)`

Verifies a PASETO v4 public token.

**Parameters**:
- `public_key_hex` (string, required): 64-character hex string (32 bytes)
- `token` (string, required): The PASETO token to verify
- `footer` (string, optional): Must match what was used during signing
- `implicit_assertion` (string, optional): Must match what was used

**Returns**: `string` - The original message

```javascript
const keyPair = v4.generate_v4_public_key_pair();
const token = v4.sign_v4_public(keyPair.secret, { user: 'alice' });
const verified = v4.verify_v4_public(keyPair.public, token);
// verified: '{"user":"alice"}'

// Verification fails with wrong key or tampered token
const wrongPair = v4.generate_v4_public_key_pair();
v4.verify_v4_public(wrongPair.public, token); // throws error
```

**Errors**: Throws if signature invalid or key doesn't match.

---

#### PASERK (Key Serialization)

PASERK provides a standardized format for encoding cryptographic keys.

##### Local Keys

```javascript
// Convert to PASERK format
const paserk = v4.key_to_paserk_local(key_hex);
// "k4.local.eyJhIjowfQ..."

// Convert back from PASERK
const restored = v4.paserk_local_to_key(paserk);
// "a1b2c3d4..."
```

##### Secret Keys

```javascript
const paserkSecret = v4.key_to_paserk_secret(secret_key_hex);
// "k4.secret.eyJhIjowfQ..."

const restoredSecret = v4.paserk_secret_to_key(paserkSecret);
```

##### Public Keys

```javascript
const paserkPublic = v4.key_to_paserk_public(public_key_hex);
// "k4.public.eyJhIjowfQ..."

const restoredPublic = v4.paserk_public_to_key(paserkPublic);
```

---

#### Key IDs

Key IDs allow key identification without exposing the key material.

##### `get_local_key_id(key_hex)`

**Returns**: Key ID in format `k4.lid.{hash}`

```javascript
const lid = v4.get_local_key_id(key);
// "k4.lid.xxxx..."
```

##### `get_public_key_id(public_key_hex)`

**Returns**: Key ID in format `k4.pid.{hash}`

##### `get_secret_key_id(secret_key_hex)`

**Returns**: Key ID in format `k4.sid.{hash}`

---

### PASETO v3 API

Access via `import * as v3 from 'paseto-wasm/v3'`

The v3 API is identical to v4 but uses different key sizes:

| Key Type | v4 Size | v3 Size |
|---------|---------|---------|
| Local Key | 32 bytes (64 hex) | 32 bytes (64 hex) |
| Secret Key | 64 bytes (128 hex) | 48 bytes (96 hex) |
| Public Key | 32 bytes (64 hex) | 49 bytes (98 hex) |

#### v3 Key Generation

```javascript
import * as v3 from 'paseto-wasm/v3';

const localKey = v3.generate_v3_local_key();
const keyPair = v3.generate_v3_public_key_pair();
```

#### v3 PASERK Functions

- `key_to_paserk_v3_local`, `paserk_v3_local_to_key`
- `key_to_paserk_v3_secret`, `paserk_v3_secret_to_key`
- `key_to_paserk_v3_public`, `paserk_v3_public_to_key`
- `get_v3_local_key_id`, `get_v3_public_key_id`, `get_v3_secret_key_id`

---

## Error Handling

All functions throw JavaScript errors with descriptive messages:

```javascript
try {
  const decrypted = v4.decrypt_v4_local(key, token);
} catch (error) {
  if (error.message.includes('Key must be')) {
    console.error('Invalid key length');
  } else if (error.message.includes('Decryption failed')) {
    console.error('Wrong key or tampered token');
  } else {
    console.error('Unknown error:', error);
  }
}
```

---

## Security Considerations

1. **Key Storage**: Store keys securely. Never expose secret keys in code or logs.
2. **Key Rotation**: Implement key rotation for long-lived applications.
3. **Algorithm Choice**: Use v4 for new applications. Use v3 only for FIPS compliance.
4. **Token Expiry**: Include expiration claims in your tokens:

```javascript
const claims = {
  sub: 'user123',
  exp: Math.floor(Date.now() / 1000) + 3600  // expires in 1 hour
};
const token = v4.sign_v4_public(secretKey, claims);
```

---

## 📝 Contributing

### Building

```sh
pnpm run build:wasm
```

### Testing

```sh
# Node.js environment
pnpm run test:wasm:node

# Browser environment
pnpm run test:wasm:web
pnpm run test:wasm:web:v3
```

For detailed contribution guidelines, please see [CONTRIBUTING.md](contributing.md).

## 🛠️ Built With

- [wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) - Facilitates communication between WebAssembly and JavaScript
- [rusty-paseto](https://github.com/rrrodzilla/rusty_paseto) - PASETO implementation in Rust

## 📋 Roadmap

- [x] Complete documentation
- [ ] Support PASERK in sign/verify operations
- [ ] Implement custom allocator (e.g., lol_alloc or talc) for improved performance and reduced file size