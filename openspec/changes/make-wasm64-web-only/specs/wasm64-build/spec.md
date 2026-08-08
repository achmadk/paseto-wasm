## ADDED Requirements

### Requirement: wasm64 builds genuinely target memory64

The `build:wasm64:web` build SHALL compile for the `wasm64-unknown-unknown` target using nightly Rust with `-Z build-std=std,panic_abort`, producing a module whose linear memory uses 64-bit addressing. No `build:*:wasm64:*` script SHALL silently produce a `wasm32-unknown-unknown` module under the wasm64 name.

#### Scenario: Web wasm64 build uses real target flags

- **WHEN** the `build:wasm64:web` script runs
- **THEN** it passes `--target wasm64-unknown-unknown -Z build-std=std,panic_abort` to cargo and the resulting artifact is a memory64 module

#### Scenario: No silent wasm32 fallback

- **WHEN** any script or command is named to imply a wasm64 build
- **THEN** it MUST NOT invoke wasm-pack/cargo without the wasm64 target flags as that would emit a wasm32 module

### Requirement: Guard against incompatible builds

The wasm64 build pipeline SHALL detect when the active feature set would pull `ring` (or any C/assembly dependency) or enable the `threads`/`v3` features, and fail with a clear, actionable error instead of producing a module or a partially-reduced graph.

#### Scenario: v3 feature blocks wasm64

- **WHEN** a build for wasm64 requests the `v3` feature
- **THEN** the build aborts with an error explaining wasm64 cannot build C/assembly crypto (`ring`) and that a pure-Rust backend is required

#### Scenario: threads feature blocks wasm64

- **WHEN** a build for wasm64 requests the `threads` feature
- **THEN** the build aborts, since wasm64 does not support `panic=unwind`

#### Scenario: ring is present in the graph

- **WHEN** the resolved dependency graph for a wasm64 build contains `ring`
- **THEN** the build aborts with a message directing the user to the ring-removal change (pure-Rust backend)

### Requirement: wasm64 is web-only

The project SHALL document and enforce that memory64/wasm64 output is supported for web targets only. Node.js is explicitly NOT a supported runtime target for wasm64 within this project while Node's runtime lacks shipped memory64 support (V8 ≥13.3 grammar; upstream Node 24 bump unresolved).

#### Scenario: Node runtime target is documented as unsupported

- **WHEN** a user attempts to build or run a wasm64 artifact under Node.js
- **THEN** documentation explains it is not supported by the Node runtime and points to the upstream V8/Node work as blocking

### Requirement: Failing builds produce actionable messages

Any guard that aborts a wasm64 build SHALL print the specific feature/dependency that caused the failure and the referenced mitigation (e.g. "remove v3" / "use ring-free backend" / "run with a memory64-capable browser").

## REMOVED Requirements

### Requirement: Node/non-web wasm64 build scripts

**Reason**: These scripts have no valid target: Node.js runtime lacks memory64 support, and the `ring`/C dependency graph cannot compile for wasm64. Keeping them produces misleading wasm32 output labeled as wasm64.
**Migration**: Use `build:wasm64:web` for web output, or the standard `build` / `build:wasm:*` for wasm32.
