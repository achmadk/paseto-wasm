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
import pasetoWasmV3 from './pkg/v3/cjs/paseto_wasm.cjs';

const payload = { action: 'ping', timestamp: Date.now(), data: { id: 123 } };

// Generate keys for each library
// panva/paseto keys
const panvaV4Keys = await V4.GenerateKeyPair();
const panvaV3Keys = await V3.GenerateKeyPair();

// paseto-wasm keys (synchronous)
const wasmV4Keys = pasetoWasmV4.generate_v4_public_key_pair();
const wasmV3Keys = pasetoWasmV3.generate_v3_public_key_pair();

// Pre-generate tokens for verify benchmarks (use same implementation's keys)
const panvaV4Token = await V4.Sign(panvaV4Keys.secretKey, payload, signOpts);
const panvaV3Token = await V3.Sign(panvaV3Keys.secretKey, payload, signOpts);
const wasmV4Token = pasetoWasmV4.sign_v4_public(wasmV4Keys.secret, payload, 'test');
const wasmV3Token = pasetoWasmV3.sign_v3_public(wasmV3Keys.secret, payload, 'test');

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

  bench('paseto-wasm', () => {
    pasetoWasmV3.sign_v3_public(wasmV3Keys.secret, payload, 'test');
  });
});

group('V3 Public Verify (P-384 ECDSA)', () => {
  bench('panva/paseto', async () => {
    await V3.Verify(panvaV3Keys.publicKey, panvaV3Token, verifyOpts);
  });

  bench('paseto-wasm', () => {
    pasetoWasmV3.verify_v3_public(wasmV3Keys.public, wasmV3Token, 'test');
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
