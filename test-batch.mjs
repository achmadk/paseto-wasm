import assert from "assert";
import * as paseto from "./pkg/v3/cjs/paseto_wasm.cjs";
import { PasetoWorker } from "./src/js/paseto.worker.js";
import crypto from "crypto";

// Polyfill Web Worker for Node.js if needed or use Node's Worker thread
// For simplicity we test batch in the current context first.
async function testBatch() {
  console.log("Testing Batch API...");

  // Generate key pair
  const kp = paseto.generate_v3_public_key_pair();

  const messages = [{ msg: "Hello 1" }, { msg: "Hello 2" }, { msg: "Hello 3" }];

  // Batch sign
  const batchTokens = paseto.sign_v3_public_batch(kp.secret, messages, null, null);
  console.log(batchTokens);
  assert.strictEqual(batchTokens.length, 3, "Should return 3 tokens");

  // Compare against single calls
  for (let i = 0; i < messages.length; i++) {
    const singleToken = paseto.sign_v3_public(kp.secret, messages[i], null, null);
    // ECDSA signatures are non-deterministic, so we can't do direct string comparison,
    // but we can verify the batch tokens using verify_v3_public!
    const batchVerified = paseto.verify_v3_public(kp.public, batchTokens[i], null, null);
    const parsedBatch = JSON.parse(batchVerified);
    assert.deepStrictEqual(parsedBatch, messages[i], `Batch verification failed for token ${i}`);

    const singleVerified = paseto.verify_v3_public(kp.public, singleToken, null, null);
    const parsedSingle = JSON.parse(singleVerified);
    assert.deepStrictEqual(parsedSingle, messages[i], `Single verification failed for token ${i}`);
  }

  // Batch verify
  const batchVerifiedOut = paseto.verify_v3_public_batch(kp.public, batchTokens, null, null);
  console.log(batchVerifiedOut);
  assert.strictEqual(batchVerifiedOut.length, 3, "Should return 3 verified messages");
  for (let i = 0; i < batchVerifiedOut.length; i++) {
    assert.deepStrictEqual(
      JSON.parse(batchVerifiedOut[i]),
      messages[i],
      `Batch output mismatch at ${i}`,
    );
  }

  console.log("Batch API tests passed!");
}

async function run() {
  try {
    await testBatch();
    console.log("All threaded optimization tests passed!");
  } catch (e) {
    console.error("Test failed:", e);
    process.exit(1);
  }
}

run();
