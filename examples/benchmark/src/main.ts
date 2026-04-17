import './style.css'

const runBtn = document.getElementById('runBenchmark') as HTMLButtonElement
const statusEl = document.getElementById('status') as HTMLParagraphElement
const resultsEl = document.getElementById('results') as HTMLDivElement

interface BenchmarkResult {
  name: string
  tag: 'wasm' | 'ts'
  opsPerSec: number
  mean: number
  margin: number
}

runBtn.disabled = false
runBtn.textContent = 'Run Benchmark'

function formatOpsPerSec(ops: number): string {
  if (ops < 100) return ops.toFixed(2)
  if (ops < 1000) return ops.toFixed(1)
  return Math.round(ops).toLocaleString()
}

function formatMean(ms: number): string {
  if (ms < 1) return (ms * 1000).toFixed(2) + 'µs'
  if (ms < 1000) return ms.toFixed(2) + 'ms'
  return (ms / 1000).toFixed(2) + 's'
}

function renderResults(results: BenchmarkResult[]): void {
  const groups = [
    { title: 'V4 Public Sign (Ed25519)', items: results.filter((r) => r.name.includes('V4 Sign')) },
    { title: 'V4 Public Verify (Ed25519)', items: results.filter((r) => r.name.includes('V4 Verify')) },
  ]

  let html = '<div class="results-container">'

  for (const group of groups) {
    const wasmItem = group.items.find((i) => i.tag === 'wasm')
    const tsItem = group.items.find((i) => i.tag === 'ts')
    const wasmWinner = wasmItem && tsItem ? wasmItem.opsPerSec > tsItem.opsPerSec : false
    const tsWinner = wasmItem && tsItem ? tsItem.opsPerSec > wasmItem.opsPerSec : false
    const speedup = wasmItem && tsItem ? wasmItem.opsPerSec / tsItem.opsPerSec : null
    
    if (group.items.length > 0) {
      html += `<div class="test-group"><h2>${group.title}</h2>`

      for (const item of group.items) {
        const isWinner = (item.tag === 'wasm' && wasmWinner) || (item.tag === 'ts' && tsWinner)
        html +=
          '<div class="test-card ' + (isWinner ? 'winner' : '') + '">' +
          '<div class="test-name">' + item.name + ' <span class="tag ' + item.tag + '">' + item.tag.toUpperCase() + '</span></div>' +
          '<div class="metrics">' +
          '<div class="metric"><div class="metric-value">' + formatOpsPerSec(item.opsPerSec) + '</div><div class="metric-label">ops/sec</div></div>' +
          '<div class="metric"><div class="metric-value">' + formatMean(item.mean) + '</div><div class="metric-label">mean</div></div>' +
          '<div class="metric"><div class="metric-value">±' + item.margin.toFixed(1) + '%</div><div class="metric-label">margin</div></div>' +
          '</div></div>'
      }
    }

    html += '<div class="comparison">'
    if (speedup) {
      html += speedup > 1
        ? '<span class="winner-badge">WASM ' + speedup.toFixed(1) + 'x faster</span>'
        : '<span class="winner-badge">TypeScript ' + (1 / speedup).toFixed(1) + 'x faster</span>'
    }
    html += '</div></div>'
  }

  html += '</div>'
  resultsEl.innerHTML = html
}

const worker = new Worker(new URL('./workers/benchmark.worker.ts', import.meta.url), { type: 'module' })

worker.onmessage = (e) => {
  if (e.data.type === 'status') {
    statusEl.textContent = e.data.message
  } if (e.data.type === 'done_partial') {
    renderResults(e.data.results)
  } else if (e.data.type === 'done_all') {
    statusEl.textContent = 'Done!'
    runBtn.disabled = false
    runBtn.textContent = 'Run Again'
    runBtn.classList.remove('running')
    renderResults(e.data.results)
  }
}

runBtn.addEventListener('click', () => {
  runBtn.disabled = true
  runBtn.textContent = 'Running...'
  runBtn.classList.add('running')
  resultsEl.innerHTML = ''
  statusEl.textContent = 'Starting benchmark...'
  worker.postMessage({ type: 'start' })
})
