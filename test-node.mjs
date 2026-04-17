import * as paseto from './pkg/cjs/paseto_wasm.cjs';
import * as pasetoV3 from './pkg/v3/cjs/paseto_wasm.cjs';

const tests = {
  passed: 0,
  failed: 0,
};

async function testV4Local() {
  console.log('\n=== Testing V4 Local (Encryption) ===');
  
  const key = paseto.generate_v4_local_key();
  console.log('Generated key:', key.substring(0, 32) + '...');
  
  const message = '{"data":"test","exp":"2025-01-01T00:00:00+00:00"}';
  
  const token = paseto.encrypt_v4_local(key, message, null, null);
  console.log('Token:', token.substring(0, 50) + '...');
  
  const decrypted = paseto.decrypt_v4_local(key, token, null, null);
  console.log('Decrypted:', decrypted);
  
  if (decrypted === message) {
    console.log('✅ V4 Local test passed');
    tests.passed++;
  } else {
    console.log('❌ V4 Local test failed');
    tests.failed++;
  }
}

async function testV4Public() {
  console.log('\n=== Testing V4 Public (Signing) ===');
  
  const keyPair = paseto.generate_v4_public_key_pair();
  console.log('Public key:', keyPair.public.substring(0, 32) + '...');
  
  const message = '{"data":"signed message","exp":"2025-01-01T00:00:00+00:00"}';
  
  const token = paseto.sign_v4_public(keyPair.secret, message, null, null);
  console.log('Token:', token.substring(0, 50) + '...');
  
  const verified = paseto.verify_v4_public(keyPair.public, token, null, null);
  console.log('Verified:', verified);
  
  if (verified === message) {
    console.log('✅ V4 Public test passed');
    tests.passed++;
  } else {
    console.log('❌ V4 Public test failed');
    tests.failed++;
  }
}

async function testV3Local() {
  console.log('\n=== Testing V3 Local (Encryption) ===');
  
  const key = pasetoV3.generate_v3_local_key();
  console.log('Generated key:', key.substring(0, 32) + '...');
  
  const message = '{"data":"v3 secret","exp":"2025-01-01T00:00:00+00:00"}';
  
  const token = pasetoV3.encrypt_v3_local(key, message, null, null);
  console.log('Token:', token.substring(0, 50) + '...');
  
  const decrypted = pasetoV3.decrypt_v3_local(key, token, null, null);
  console.log('Decrypted:', decrypted);
  
  if (decrypted === message) {
    console.log('✅ V3 Local test passed');
    tests.passed++;
  } else {
    console.log('❌ V3 Local test failed');
    tests.failed++;
  }
}

async function testV3Public() {
  console.log('\n=== Testing V3 Public (Signing) ===');
  
  const keyPair = pasetoV3.generate_v3_public_key_pair();
  console.log('Public key:', keyPair.public.substring(0, 32) + '...');
  
  const message = '{"data":"v3 signed message","exp":"2025-01-01T00:00:00+00:00"}';
  
  const token = pasetoV3.sign_v3_public(keyPair.secret, message, null, null);
  console.log('Token:', token.substring(0, 50) + '...');
  
  const verified = pasetoV3.verify_v3_public(keyPair.public, token, null, null);
  console.log('Verified:', verified);
  
  if (verified === message) {
    console.log('✅ V3 Public test passed');
    tests.passed++;
  } else {
    console.log('❌ V3 Public test failed');
    tests.failed++;
  }
}

async function testV3PublicWithFooter() {
  console.log('\n=== Testing V3 Public with Footer ===');
  
  const keyPair = pasetoV3.generate_v3_public_key_pair();
  const footer = '{"kid":"test-key-id"}';
  const message = '{"data":"with footer"}';
  
  const token = pasetoV3.sign_v3_public(keyPair.secret, message, footer, null);
  
  const verified = pasetoV3.verify_v3_public(keyPair.public, token, footer, null);
  
  if (verified === message) {
    console.log('✅ V3 Public with footer test passed');
    tests.passed++;
  } else {
    console.log('❌ V3 Public with footer test failed');
    tests.failed++;
  }
}

async function testWrongKeyFails() {
  console.log('\n=== Testing Wrong Key Rejection ===');
  
  const keyPair1 = pasetoV3.generate_v3_public_key_pair();
  const keyPair2 = pasetoV3.generate_v3_public_key_pair();
  
  const message = '{"data":"test"}';
  const token = pasetoV3.sign_v3_public(keyPair1.secret, message, null, null);
  
  try {
    paseto.verify_v3_public(keyPair2.public, token, null, null);
    console.log('❌ Wrong key should have failed verification');
    tests.failed++;
  } catch (e) {
    console.log('✅ Wrong key correctly rejected');
    tests.passed++;
  }
}

async function main() {
  console.log('=== PASETO WASM Self-Tests ===');
  console.log('Initializing WASM...');
  
  console.log('WASM initialized!\n');
  
  await testV4Local();
  await testV4Public();
  await testV3Local();
  await testV3Public();
  await testV3PublicWithFooter();
  await testWrongKeyFails();
  
  console.log('\n=== Summary ===');
  console.log(`Passed: ${tests.passed}`);
  console.log(`Failed: ${tests.failed}`);
  console.log(`Total: ${tests.passed + tests.failed}`);
  
  if (tests.failed > 0) {
    process.exit(1);
  }
}

main().catch(console.error);
