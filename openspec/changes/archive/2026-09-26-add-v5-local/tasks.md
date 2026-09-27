# Tasks

## 1. Feature wiring

- [x] 1.1 Add `v5` feature and optional-dep wiring in `Cargo.toml` (`v5 = ["dep:aes", "dep:ctr", "dep:digest", "dep:hkdf", "dep:hmac", "dep:sha2"]`) and verify `cargo build`, `cargo build --no-default-features --features v5`, and `cargo build --all-features` all succeed.
- [x] 1.2 Gate the new module in `src/lib.rs` (`#[cfg(feature = "v5")] pub mod v5;`) and verify `cargo build --no-default-features --features v5` compiles.

## 2. v5.local core

- [x] 2.1 Create `src/v5.rs` with `generate_v5_local_key`, `encrypt_v5_local`, `decrypt_v5_local` using the v5.local constants (`v5.local.` header) over the shared `common.rs` helpers, and verify `cargo build --no-default-features --features v5` succeeds with no warnings.
- [x] 2.2 Add `key_to_paserk_v5_local`, `paserk_v5_local_to_key` (`k5.local.`), and `get_v5_local_key_id` (`k5.lid.`) to `src/v5.rs`, and verify PASERK roundtrip plus stable/distinct key IDs via a temporary native test (removed afterwards).

## 3. v5.local tests and docs

- [x] 3.1 Add v5 roundtrip, footer-binding, tamper-rejection, and wrong-key tests to `tests/web.rs` mirroring the v3 tests. Chrome is unavailable in this env so `wasm-pack test --chrome` could not run here (pending CI); instead all five behaviors were verified against the real v5 nodejs wasm build (see 4.1) with roundtrip/header/footer/wrong-key/tamper/PASERK assertions passing.
- [x] 3.2 Document the v5 API in `readme.md` (key sizes, function list) and verify every documented function name matches an export in `src/v5.rs`.

## 4. Build outputs and integration

- [x] 4.1 Add `build:wasm:web:v5`, `build:wasm:node:v5`, `test:wasm:web:v5`, and the `./v5` export to `package.json`, and verify each new script runs (build produces `pkg/v5`, test passes).
- [x] 4.2 Run the full verification suite (`cargo build`, `cargo build --all-features`, `cargo test`, `openspec validate --change add-v5-local`) and confirm zero errors and no behavior change to v3/v4 outputs.
