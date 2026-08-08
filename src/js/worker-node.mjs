import { parentPort } from "worker_threads";
import * as paseto from "../../pkg/v3/cjs/paseto_wasm.cjs";

// Initialize WASM not needed for CJS node build directly, it is sync loaded.
// If it was async we would await it.

parentPort.on("message", async (data) => {
  const { id, method, args } = data;
  try {
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
    parentPort.postMessage({ id, result });
  } catch (error) {
    parentPort.postMessage({ id, error: error.message || error.toString() });
  }
});
