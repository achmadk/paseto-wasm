## 1. Update Dependency

- [x] 1.1 Bump `getrandom` version in `Cargo.toml` from `"0.3"` to `"0.4"` with `features = ["wasm_js"]`
- [x] 1.2 Run `cargo update -p getrandom` to update `Cargo.lock`

## 2. Verify

- [x] 2.1 Run `cargo check` to confirm compilation succeeds
- [ ] 2.2 Run `cargo test` to confirm all tests pass
