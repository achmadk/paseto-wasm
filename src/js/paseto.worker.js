// Web Worker wrapper for paseto-wasm
// This file can be imported and used to offload paseto operations.

class PasetoWorker {
  constructor(wasmModulePath) {
    // In a real application, you'd instantiate a Web Worker here.
    // For this abstraction, we just expose the promise-based API.
    this.worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
    this.resolvers = new Map();
    this.msgId = 0;

    this.worker.onmessage = (e) => {
      const { id, result, error } = e.data;
      const resolver = this.resolvers.get(id);
      if (resolver) {
        if (error) {
          resolver.reject(new Error(error));
        } else {
          resolver.resolve(result);
        }
        this.resolvers.delete(id);
      }
    };
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
}

export { PasetoWorker };
