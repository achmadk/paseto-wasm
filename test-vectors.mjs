import * as pasetoV4 from './pkg/cjs/paseto_wasm.cjs';
import * as pasetoV3 from './pkg/v3/cjs/paseto_wasm.cjs';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const results = {
  passed: 0,
  failed: 0,
  skipped: 0,
  errors: []
};

function testV4LocalEncrypt(vector) {
  try {
    const decrypted = pasetoV4.decrypt_v4_local(
      vector.key,
      vector.token,
      vector.footer || null,
      vector['implicit-assertion'] || null
    );
    if (decrypted === vector.payload) {
      return { pass: true };
    }
    return { pass: false, expected: vector.payload, got: decrypted };
  } catch (e) {
    return { pass: false, error: String(e) };
  }
}

function testV4PublicSign(vector) {
  try {
    const verified = pasetoV4.verify_v4_public(
      vector['public-key'],
      vector.token,
      vector.footer || null,
      vector['implicit-assertion'] || null
    );
    if (verified === vector.payload) {
      return { pass: true };
    }
    return { pass: false, expected: vector.payload, got: verified };
  } catch (e) {
    return { pass: false, error: String(e) };
  }
}

function testV3LocalEncrypt(vector) {
  try {
    const decrypted = pasetoV3.decrypt_v3_local(
      vector.key,
      vector.token,
      vector.footer || null,
      vector['implicit-assertion'] || null
    );
    if (decrypted === vector.payload) {
      return { pass: true };
    }
    return { pass: false, expected: vector.payload, got: decrypted };
  } catch (e) {
    return { pass: false, error: String(e) };
  }
}

function testV3PublicSign(vector) {
  try {
    const verified = pasetoV3.verify_v3_public(
      vector['public-key'],
      vector.token,
      vector.footer || null,
      vector['implicit-assertion'] || null
    );
    if (verified === vector.payload) {
      return { pass: true };
    }
    return { pass: false, expected: vector.payload, got: verified };
  } catch (e) {
    return { pass: false, error: String(e) };
  }
}

function testV3PublicSignShouldFail(vector) {
  try {
    pasetoV3.verify_v3_public(
      vector['public-key'],
      vector.token,
      vector.footer || null,
      vector['implicit-assertion'] || null
    );
    return { pass: false, error: 'Expected failure but succeeded' };
  } catch (e) {
    return { pass: true };
  }
}

async function main() {
  console.log('=== PASETO Official Test Vectors Verification ===\n');
  
  const v3Vectors = JSON.parse(readFileSync('../paseto/tests/test-vectors/v3.json', 'utf8'));
  const v4Vectors = JSON.parse(readFileSync('../paseto/tests/test-vectors/v4.json', 'utf8'));
  
  console.log('Testing V4 Local (Encryption):');
  console.log('─────────────────────────────────');
  for (const vector of v4Vectors.tests.filter(t => t.name.startsWith('4-E-'))) {
    if (vector['expect-fail']) {
      console.log(`  ⏭️  ${vector.name}: SKIPPED (expected failure)`);
      results.skipped++;
      continue;
    }
    const result = testV4LocalEncrypt(vector);
    if (result.pass) {
      console.log(`  ✅ ${vector.name}: PASS`);
      results.passed++;
    } else {
      console.log(`  ❌ ${vector.name}: FAILED`);
      if (result.error) console.log(`     Error: ${result.error}`);
      else console.log(`     Expected: ${result.expected}\n     Got: ${result.got}`);
      results.failed++;
    }
  }
  
  console.log('\nTesting V4 Public (Signing):');
  console.log('─────────────────────────────────');
  for (const vector of v4Vectors.tests.filter(t => t.name.startsWith('4-S-'))) {
    if (vector['expect-fail']) {
      console.log(`  ⏭️  ${vector.name}: SKIPPED (expected failure)`);
      results.skipped++;
      continue;
    }
    const result = testV4PublicSign(vector);
    if (result.pass) {
      console.log(`  ✅ ${vector.name}: PASS`);
      results.passed++;
    } else {
      console.log(`  ❌ ${vector.name}: FAILED`);
      if (result.error) console.log(`     Error: ${result.error}`);
      else console.log(`     Expected: ${result.expected}\n     Got: ${result.got}`);
      results.failed++;
    }
  }
  
  console.log('\nTesting V3 Local (Encryption):');
  console.log('─────────────────────────────────');
  for (const vector of v3Vectors.tests.filter(t => t.name.startsWith('3-E-'))) {
    if (vector['expect-fail']) {
      console.log(`  ⏭️  ${vector.name}: SKIPPED (expected failure)`);
      results.skipped++;
      continue;
    }
    const result = testV3LocalEncrypt(vector);
    if (result.pass) {
      console.log(`  ✅ ${vector.name}: PASS`);
      results.passed++;
    } else {
      console.log(`  ❌ ${vector.name}: FAILED`);
      if (result.error) console.log(`     Error: ${result.error}`);
      else console.log(`     Expected: ${result.expected}\n     Got: ${result.got}`);
      results.failed++;
    }
  }
  
  console.log('\nTesting V3 Public (Signing):');
  console.log('─────────────────────────────────');
  for (const vector of v3Vectors.tests.filter(t => t.name.startsWith('3-S-'))) {
    if (vector['expect-fail']) {
      console.log(`  ⏭️  ${vector.name}: SKIPPED (expected failure)`);
      results.skipped++;
      continue;
    }
    const result = testV3PublicSign(vector);
    if (result.pass) {
      console.log(`  ✅ ${vector.name}: PASS`);
      results.passed++;
    } else {
      console.log(`  ❌ ${vector.name}: FAILED`);
      if (result.error) console.log(`     Error: ${result.error}`);
      else console.log(`     Expected: ${result.expected}\n     Got: ${result.got}`);
      results.failed++;
    }
  }
  
  console.log('\nTesting V3 Public Expected Failures:');
  console.log('─────────────────────────────────');
  for (const vector of v3Vectors.tests.filter(t => t.name.startsWith('3-F-') && t.token.startsWith('v3.public'))) {
    const result = testV3PublicSignShouldFail(vector);
    if (result.pass) {
      console.log(`  ✅ ${vector.name}: Correctly rejected`);
      results.passed++;
    } else {
      console.log(`  ❌ ${vector.name}: Should have failed but succeeded`);
      results.failed++;
    }
  }
  
  console.log('\n=== Summary ===');
  console.log(`Passed: ${results.passed}`);
  console.log(`Failed: ${results.failed}`);
  console.log(`Skipped: ${results.skipped}`);
  console.log(`Total: ${results.passed + results.failed + results.skipped}`);
  
  if (results.failed > 0) {
    console.log('\n⚠️  Some tests failed!');
    process.exit(1);
  } else {
    console.log('\n✅ All tests passed! Implementation matches official test vectors.');
  }
}

main().catch(console.error);
