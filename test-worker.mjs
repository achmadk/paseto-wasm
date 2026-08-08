import assert from "assert";
import { Worker } from "worker_threads";
import * as paseto from "./pkg/v3/cjs/paseto_wasm.cjs";

// For Node.js we have to implement a slight wrapper or use the exact API since `PasetoWorker` uses web APIs.
// This is a minimal Node.js equivalent for the test:

class NodePasetoWorker {
  constructor() {
    this.worker = new Worker("./src/js/worker-node.mjs");
    this.resolvers = new Map();
    this.msgId = 0;

    this.worker.on("message", (data) => {
      const { id, result, error } = data;
      const resolver = this.resolvers.get(id);
      if (resolver) {
        if (error) {
          resolver.reject(new Error(error));
        } else {
          resolver.resolve(result);
        }
        this.resolvers.delete(id);
      }
    });
  }

  _postMessage(method, args) {
    return new Promise((resolve, reject) => {
      const id = this.msgId++;
      this.resolvers.set(id, { resolve, reject });
      this.worker.postMessage({ id, method, args });
    });
  }

  async signV3Public(secretKey, payload, footer, implicitAssertion) {
    return this._postMessage("sign_v3_public", [secretKey, payload, footer, implicitAssertion]);
  }

  async verifyV3Public(publicKey, token, implicitAssertion) {
    return this._postMessage("verify_v3_public", [publicKey, token, implicitAssertion]);
  }

  terminate() {
    this.worker.terminate();
  }
}

async function testWorker() {
  console.log("Testing PasetoWorker in Node...");

  const kp = paseto.generate_v3_public_key_pair();
  const worker = new NodePasetoWorker();

  try {
    const payload = { test: "worker offload" };

    // Sign asynchronously
    console.log("Waiting for worker to sign...");
    const token = await worker.signV3Public(kp.secret, payload, null, null);
    assert(token.startsWith("v3.public."), "Token should start with v3.public.");

    // Verify asynchronously
    console.log("Waiting for worker to verify...");
    const verified = await worker.verifyV3Public(kp.public, token, null, null);
    const parsed = JSON.parse(verified);
    assert.deepStrictEqual(parsed, payload, "Worker verification mismatch");

    console.log("PasetoWorker tests passed!");
  } finally {
    worker.terminate();
  }
}

testWorker().catch((e) => {
  console.error(e);
  process.exit(1);
});
