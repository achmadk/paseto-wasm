import { Bench } from 'tinybench'
import initV4, {
  generate_v4_public_key_pair,
  sign_v4_public,
  verify_v4_public,
} from 'paseto-wasm'
import { sign, generateKeys, verify } from 'paseto-ts/v4'

const WARMUP_ITERATIONS = 100
const BENCHMARK_ITERATIONS = 100
const TIME_MS = 5000

self.onmessage = async () => {
  await initV4()

  const pasetoTsKeys = generateKeys('public', { format: 'paserk' })
  const pasetoWasmV4Keys = generate_v4_public_key_pair()
  const payload = { action: 'ping', timestamp: Date.now(), data: { id: 123 } }

  const results = []

  self.postMessage({ type: 'status', message: 'V4 Public Sign...' })

  const v4SignBench = new Bench({
    warmup: true,
    warmupIterations: WARMUP_ITERATIONS,
    iterations: BENCHMARK_ITERATIONS,
    time: TIME_MS,
  })

  v4SignBench.add('paseto-ts V4 Sign', () => {
    sign(pasetoTsKeys.secretKey, payload, { footer: 'test' })
  })

  v4SignBench.add('paseto-wasm V4 Sign', () => {
    sign_v4_public(pasetoWasmV4Keys.secret, payload, 'test')
  })

  await v4SignBench.run()

  const v4SignTasks = v4SignBench.results
  results.push({
    name: 'paseto-ts V4 Sign',
    tag: 'ts',
    // @ts-expect-error
    opsPerSec: v4SignTasks[0].throughput.mean,
    // @ts-expect-error
    mean: v4SignTasks[0].latency.mean,
    // @ts-expect-error
    margin: v4SignTasks[0].latency.rme,
  })
  results.push({
    name: 'paseto-wasm V4 Sign',
    tag: 'wasm',
    // @ts-expect-error
    opsPerSec: v4SignTasks[1].throughput.mean,
    // @ts-expect-error
    mean: v4SignTasks[1].latency.mean,
    // @ts-expect-error
    margin: v4SignTasks[1].latency.rme,
  })

  self.postMessage({ type: 'done_partial', results })
  self.postMessage({ type: 'status', message: 'V4 Public Verify...' })

  const v4VerifyBench = new Bench({
    warmup: true,
    warmupIterations: WARMUP_ITERATIONS,
    iterations: BENCHMARK_ITERATIONS,
    time: TIME_MS,
  })

  const pasetoTsToken = sign(pasetoTsKeys.secretKey, payload, { footer: 'test' })
  const pasetoWasmToken = sign_v4_public(pasetoWasmV4Keys.secret, payload, 'test')

  v4VerifyBench.add('paseto-ts V4 Verify', () => {
    verify(pasetoTsKeys.publicKey, pasetoTsToken)
  })

  v4VerifyBench.add('paseto-wasm V4 Verify', () => {
    verify_v4_public(pasetoWasmV4Keys.public, pasetoWasmToken, 'test')
  })

  await v4VerifyBench.run()

  const v4VerifyTasks = v4VerifyBench.results
  results.push({
    name: 'paseto-ts V4 Verify',
    tag: 'ts',
    // @ts-expect-error
    opsPerSec: v4VerifyTasks[0].throughput.mean,
    // @ts-expect-error
    mean: v4VerifyTasks[0].latency.mean,
    // @ts-expect-error
    margin: v4VerifyTasks[0].latency.rme,
  })
  results.push({
    name: 'paseto-wasm V4 Verify',
    tag: 'wasm',
    // @ts-expect-error
    opsPerSec: v4VerifyTasks[1].throughput.mean,
    // @ts-expect-error
    mean: v4VerifyTasks[1].latency.mean,
    // @ts-expect-error
    margin: v4VerifyTasks[1].latency.rme,
  })

  self.postMessage({ type: 'done_all', results })
}
