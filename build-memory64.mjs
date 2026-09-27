import { execSync } from 'node:child_process';
import { existsSync, readFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
const getArg = (name, fallback) => {
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
};

const OUT_DIR = getArg('--out-dir', 'pkg/memory64');
const JS_TARGET = getArg('--js-target', 'web');
const FEATURES = getArg('--features', null);
const NO_DEFAULT_FEATURES = args.includes('--no-default-features');
const SKIP_BINDGEN = args.includes('--no-bindgen');
const TRIPLE = 'wasm64-unknown-unknown';

const run = (cmd, opts = {}) => {
  console.log(`$ ${cmd}`);
  execSync(cmd, { stdio: 'inherit', ...opts });
};

function wasmBindgenVersion() {
  const lock = readFileSync('Cargo.lock', 'utf8');
  const m = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/);
  if (!m) throw new Error('wasm-bindgen version not found in Cargo.lock');
  return m[1];
}

function ensurePrereqs() {
  try {
    run('cargo +nightly --version');
  } catch {
    throw new Error('Nightly Rust toolchain required: rustup toolchain install nightly');
  }
  try {
    const list = execSync('rustup component list --toolchain nightly', { encoding: 'utf8' });
    if (!list.split('\n').some((l) => l.startsWith('rust-src') && l.includes('installed'))) {
      throw new Error('missing rust-src');
    }
  } catch (e) {
    if (e.message === 'missing rust-src') {
      console.log('Installing rust-src component...');
      run('rustup component add rust-src --toolchain nightly');
    } else {
      throw e;
    }
  }
  const want = wasmBindgenVersion();
  let have = null;
  try {
    have = execSync('wasm-bindgen --version', { encoding: 'utf8' }).trim().split(' ')[1];
  } catch {
    have = null;
  }
  if (have !== want) {
    console.log(`Installing wasm-bindgen-cli ${want} (found: ${have ?? 'none'})...`);
    run(`cargo install wasm-bindgen-cli --version ${want}`);
  }
}

function main() {
  ensurePrereqs();

  let build = 'cargo +nightly build --release --target ' + TRIPLE + ' -Z build-std=std,panic_abort';
  if (NO_DEFAULT_FEATURES) build += ' --no-default-features';
  if (FEATURES) build += ` --features ${FEATURES}`;
  run(build);

  if (SKIP_BINDGEN) return;

  const wasm = join('target', TRIPLE, 'release', 'paseto_wasm.wasm');
  if (!existsSync(wasm)) throw new Error(`Expected artifact missing: ${wasm}`);
  run(`wasm-bindgen ${wasm} --out-dir ${OUT_DIR} --target ${JS_TARGET}`);

  if (JS_TARGET === 'nodejs') {
    const js = join(OUT_DIR, 'paseto_wasm.js');
    const cjs = join(OUT_DIR, 'paseto_wasm.cjs');
    if (existsSync(js)) renameSync(js, cjs);
  }

  console.log(`\nMemory64 build complete: ${OUT_DIR}`);
  console.log('Run it with a memory64-enabled runtime, e.g. node --experimental-wasm-memory64');
}

main();
