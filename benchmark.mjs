import { bench, group, run } from 'mitata';

// Import panva/paseto (v4 composition API)
import { PublicProtocol } from 'paseto';
import {
  GenerateKeyPairFactory as V4GenerateKeyPairFactory,
  SignFactory as V4SignFactory,
  VerifyFactory as V4VerifyFactory,
} from 'paseto/v4/public';
import {
  GenerateKeyPairFactory as V3GenerateKeyPairFactory,
  SignFactory as V3SignFactory,
  VerifyFactory as V3VerifyFactory,
} from 'paseto/v3/public';

const V4 = new PublicProtocol(V4GenerateKeyPairFactory, V4SignFactory, V4VerifyFactory);
const V3 = new PublicProtocol(V3GenerateKeyPairFactory, V3SignFactory, V3VerifyFactory);

const footerBytes = new TextEncoder().encode('test');
const signOpts = { footer: footerBytes };
const verifyOpts = { footer: footerBytes };

// Import paseto-wasm (Node.js CJS builds)
import pasetoWasmV4 from './pkg/cjs/paseto_wasm.cjs';
import pasetoWasmV3 from './pkg/v3/cjs/paseto_wasm.cjs'; // default: generic Montgomery backend (see .cargo/config.toml)
import pasetoWasmV3Fiat from './pkg/v3-fiat/cjs/paseto_wasm.cjs'; // opt-in: p384_backend = "fiat" -- benchmarked SLOWER on wasm32, kept only for re-testing (e.g. on wasm64/Memory64, where limb width differs)
const { V3Signer, V3Verifier } = pasetoWasmV3;
const { V3Signer: V3SignerFiat, V3Verifier: V3VerifierFiat } = pasetoWasmV3Fiat;

const payload = { action: 'ping', timestamp: Date.now(), data: { id: 123 } };

// Generate keys for each library
// panva/paseto keys
const panvaV4Keys = await V4.GenerateKeyPair();
const panvaV3Keys = await V3.GenerateKeyPair();

// paseto-wasm keys (synchronous)
const wasmV4Keys = pasetoWasmV4.generate_v4_public_key_pair();
const wasmV3Keys = pasetoWasmV3.generate_v3_public_key_pair();
const wasmV3KeysFiat = pasetoWasmV3Fiat.generate_v3_public_key_pair();

// Pre-generate tokens for verify benchmarks (use same implementation's keys)
const panvaV4Token = await V4.Sign(panvaV4Keys.secretKey, payload, signOpts);
const panvaV3Token = await V3.Sign(panvaV3Keys.secretKey, payload, signOpts);
const wasmV4Token = pasetoWasmV4.sign_v4_public(wasmV4Keys.secret, payload, 'test');
const wasmV3Token = pasetoWasmV3.sign_v3_public(wasmV3Keys.secret, payload, 'test');

// Persistent V3 signer/verifier: key parsing + public-key derivation/
// decompression happen ONCE here, not on every bench iteration. This isolates
// how much of the V3 gap is "redoing EC point ops every call" versus
// irreducible P-384 field-arithmetic cost.
const wasmV3Signer = new V3Signer(wasmV3Keys.secret);
const wasmV3Verifier = new V3Verifier(wasmV3Keys.public);
const wasmV3TokenPersistent = wasmV3Signer.sign(payload, 'test', null);

// Same, but built with the fiat-crypto backend explicitly ON, so the fiat
// vs. generic-Montgomery comparison happens in the same process/run as
// everything else above — no cross-run clock-speed confound.
const wasmV3SignerFiat = new V3SignerFiat(wasmV3KeysFiat.secret);
const wasmV3VerifierFiat = new V3VerifierFiat(wasmV3KeysFiat.public);
const wasmV3TokenPersistentFiat = wasmV3SignerFiat.sign(payload, 'test', null);

group('V4 Public Sign (Ed25519)', () => {
  bench('panva/paseto', async () => {
    await V4.Sign(panvaV4Keys.secretKey, payload, signOpts);
  });

  bench('paseto-wasm', () => {
    pasetoWasmV4.sign_v4_public(wasmV4Keys.secret, payload, 'test');
  });
});

group('V4 Public Verify (Ed25519)', () => {
  bench('panva/paseto', async () => {
    await V4.Verify(panvaV4Keys.publicKey, panvaV4Token, verifyOpts);
  });

  bench('paseto-wasm', () => {
    pasetoWasmV4.verify_v4_public(wasmV4Keys.public, wasmV4Token, 'test');
  });
});

group('V3 Public Sign (P-384 ECDSA)', () => {
  bench('panva/paseto', async () => {
    await V3.Sign(panvaV3Keys.secretKey, payload, signOpts);
  });

  bench('paseto-wasm (stateless: re-parses key + re-derives pubkey every call)', () => {
    pasetoWasmV3.sign_v3_public(wasmV3Keys.secret, payload, 'test');
  });

  bench('paseto-wasm (V3Signer: key + pubkey cached once)', () => {
    wasmV3Signer.sign(payload, 'test', null);
  });

  bench('paseto-wasm (V3Signer, fiat-backend build, for comparison — currently slower, see .cargo/config.toml)', () => {
    wasmV3SignerFiat.sign(payload, 'test', null);
  });
});

group('V3 Public Verify (P-384 ECDSA)', () => {
  bench('panva/paseto', async () => {
    await V3.Verify(panvaV3Keys.publicKey, panvaV3Token, verifyOpts);
  });

  bench('paseto-wasm (stateless: re-decompresses pubkey every call)', () => {
    pasetoWasmV3.verify_v3_public(wasmV3Keys.public, wasmV3Token, 'test');
  });

  bench('paseto-wasm (V3Verifier: pubkey decompressed once)', () => {
    wasmV3Verifier.verify(wasmV3TokenPersistent, 'test', null);
  });

  bench('paseto-wasm (V3Verifier, fiat-backend build, for comparison — statistically tied)', () => {
    wasmV3VerifierFiat.verify(wasmV3TokenPersistentFiat, 'test', null);
  });
});

group('Key Generation', () => {
  bench('panva/paseto V4', async () => {
    await V4.GenerateKeyPair();
  });

  bench('paseto-wasm V4', () => {
    pasetoWasmV4.generate_v4_public_key_pair();
  });

  bench('panva/paseto V3', async () => {
    await V3.GenerateKeyPair();
  });

  bench('paseto-wasm V3', () => {
    pasetoWasmV3.generate_v3_public_key_pair();
  });
});

await run();
