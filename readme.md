<div align="center">

  <h1>PASETO Rust WASM (<code>paseto-wasm</code>)</h1>
  
  <strong>Enable PASETO in JavaScript browsers using <a href="https://webassembly.org/">WebAssembly (WASM)</a></strong>

  <!-- <p>
    <a href="https://travis-ci.org/rustwasm/wasm-pack-template"><img src="https://img.shields.io/travis/rustwasm/wasm-pack-template.svg?style=flat-square" alt="Build Status" /></a>
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

## API Methods
### PASETO v4 (Default)
The following methods are available by default:

- `encrypt_v4_local`, `decrypt_v4_local`
- `sign_v4_public`, `verify_v4_public`
- `generate_v4_local_key`, `generate_v4_public_key_pair`
- `key_to_paserk_local`, `paserk_local_to_key`
- `key_to_paserk_secret`, `paserk_secret_to_key`
- `key_to_paserk_public`, `paserk_public_to_key`
- `get_local_key_id`, `get_public_key_id`, `get_secret_key_id`

### PASETO v3
Access v3 implementations via `paseto-wasm/v3`:
- `encrypt_v3_local`, `decrypt_v3_local`
- `sign_v3_public`, `verify_v3_public`
- `generate_v3_local_key`, `generate_v3_public_key_pair`
- `key_to_paserk_v3_local`, `paserk_v3_local_to_key`
- `key_to_paserk_v3_secret`, `paserk_v3_secret_to_key`
- `key_to_paserk_v3_public`, `paserk_v3_public_to_key`
- `get_v3_local_key_id`, `get_v3_public_key_id`, `get_v3_secret_key_id`

## Documentation
[Example usage is available in the test file](tests/node_test.cjs). Comprehensive documentation is currently a work in progress.

## 📝 Contributing
### 🛠️ Building
```sh
pnpm run build:wasm
```

### 🧪 Testing
```sh
# Node.js environment
pnpm run test:wasm:node

# Browser environment
pnpm run test:wasm:web
pnpm run test:wasm:web:v3
```

<!-- ### 📦 Publishing to NPM ``` wasm-pack publish ``` -->
For detailed contribution guidelines, please see [CONTRIBUTING.md](contributing.md).

## 🛠️ Built With
- [wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) - Facilitates communication between WebAssembly and JavaScript

- [rusty-paseto](https://github.com/rrrodzilla/rusty_paseto) - PASETO implementation in Rust

## 📋 Roadmap
- [ ] Complete documentation
- [ ] Support PASERK in sign/verify operations
- [ ] Implement custom allocator (e.g., lol_alloc or talc) for improved performance and reduced file size
