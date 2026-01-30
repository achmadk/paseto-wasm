import './style.css'

import { Bench } from 'tinybench'
import init, { generate_v4_public_key_pair, key_to_paserk_public, key_to_paserk_secret, paserk_public_to_key, paserk_secret_to_key, sign_v4_public } from 'paseto-wasm'
import { sign, generateKeys } from "paseto-ts/v4"

// import typescriptLogo from './typescript.svg'
// import viteLogo from '/vite.svg'

// import { setupCounter } from './counter.ts'

const keys = generateKeys("public", { format: "paserk" })
console.log(keys);

await init();
console.log("PASETO wasm library initialized");
const pasetoWasmv4PublicKeyPair = generate_v4_public_key_pair();
const pasetoWasmv4PublicKeys = {
  public: paserk_public_to_key(keys.publicKey),
  secret: paserk_secret_to_key(keys.secretKey),
};
console.log(pasetoWasmv4PublicKeys);

const bench = new Bench({
  name: 'PASETO library benchmark',
  time: 1000,
})

const signPayload = { hello: "test" };

bench
  .add("paseto-ts sign", () => {
    sign(keys.secretKey, signPayload, { footer: "test" })
  })
  .add("paseto-wasm sign", () => {
    sign_v4_public(pasetoWasmv4PublicKeyPair.secret, signPayload, "test")
  })


await bench.run()

console.log(bench.name)
console.table(bench.table())

// document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
//   <div>
//     <a href="https://vite.dev" target="_blank">
//       <img src="${viteLogo}" class="logo" alt="Vite logo" />
//     </a>
//     <a href="https://www.typescriptlang.org/" target="_blank">
//       <img src="${typescriptLogo}" class="logo vanilla" alt="TypeScript logo" />
//     </a>
//     <h1>Vite + TypeScript</h1>
//     <div class="card">
//       <button id="counter" type="button"></button>
//     </div>
//     <p class="read-the-docs">
//       Click on the Vite and TypeScript logos to learn more
//     </p>
//   </div>
// `

// setupCounter(document.querySelector<HTMLButtonElement>('#counter')!)
