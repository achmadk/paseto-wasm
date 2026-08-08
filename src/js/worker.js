import * as paseto from "../pkg/paseto_wasm.js"; // Adjust based on build output

// Initialize WASM
let initPromise = paseto.default();

self.onmessage = async (e) => {
  const { id, method, args } = e.data;
  try {
    await initPromise;
    let result;
    switch (method) {
      case "sign_v3_public":
        result = paseto.sign_v3_public(...args);
        break;
      case "verify_v3_public":
        result = paseto.verify_v3_public(...args);
        break;
      default:
        throw new Error(`Unknown method: ${method}`);
    }
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: error.message || error.toString() });
  }
};
