const WORDS = [
  "v4.local",
  "v4.public",
  "v3.local",
  "v3.public",
  "encrypt",
  "decrypt",
  "sign",
  "verify",
  "XChaCha20",
  "Poly1305",
  "Ed25519",
  "AES-256-CTR",
  "HMAC-SHA384",
  "P-384",
  "ECDSA",
  "key_to_paserk",
  "paserk_to_key",
  "k4.local",
  "k4.public",
  "k4.secret",
  "k4.lid",
  "k4.pid",
  "k4.sid",
  "token",
  "payload",
  "footer",
  "nonce",
  "generate_v4",
  "sign_v4",
  "verify_v4",
  "WASM",
  "RUST",
  "PASETO",
  "JOSE",
  "0x",
  "hex",
  "base64url",
  "kid",
  "sub",
  "exp",
  "iat",
];

const FONT_SIZE = 13;
const COLUMN_COUNT = 36;
const DROP_SPEED_MIN = 0.2;
const DROP_SPEED_MAX = 0.4;
const MIDDLE_SPEED = (DROP_SPEED_MIN + DROP_SPEED_MAX) / 2;
const WORD_CHANGE_RATE = 0.008;

let offscreen, ctx;
let w = 0,
  h = 0,
  dpr = 1;
let columns = [];
let animId = null;

function initColumns() {
  columns = [];
  const colWidth = w / COLUMN_COUNT;
  for (let i = 0; i < COLUMN_COUNT; i++) {
    const x = i * colWidth + colWidth / 2;
    columns.push({
      x,
      word: WORDS[Math.floor(Math.random() * WORDS.length)],
      speed: MIDDLE_SPEED,
      headY: -Math.random() * h * 1.5 - FONT_SIZE * 4,
      trailLength: 4 + Math.floor(Math.random() * 8),
      charSpacing: FONT_SIZE * 1.4,
    });
  }
}

function draw() {
  ctx.clearRect(0, 0, w, h);

  for (let c = 0; c < columns.length; c++) {
    const col = columns[c];
    col.headY += col.speed * (FONT_SIZE * 1.4);

    if (Math.random() < WORD_CHANGE_RATE) {
      col.word = WORDS[Math.floor(Math.random() * WORDS.length)];
    }

    const tailY = col.headY - col.trailLength * col.charSpacing;
    if (tailY > h + FONT_SIZE * 10) {
      col.headY = -Math.random() * 80 - FONT_SIZE * 4;
      col.trailLength = 4 + Math.floor(Math.random() * 8);
      col.word = WORDS[Math.floor(Math.random() * WORDS.length)];
    }

    for (let i = 0; i < col.trailLength; i++) {
      const y = col.headY - i * col.charSpacing;
      if (y < -FONT_SIZE || y > h + FONT_SIZE) continue;

      const fade = 1 - i / col.trailLength;
      const alpha = fade * 0.18;

      if (i === 0) {
        ctx.fillStyle = "rgba(45, 212, 168, 0.55)";
        ctx.shadowColor = "rgba(45, 212, 168, 0.3)";
        ctx.shadowBlur = 6;
      } else {
        ctx.fillStyle = `rgba(45, 212, 168, ${alpha})`;
        ctx.shadowBlur = 0;
      }

      ctx.font = `${i === 0 ? "600" : "400"} ${FONT_SIZE}px 'JetBrains Mono', monospace`;
      ctx.fillText(col.word, col.x, y);
    }
    ctx.shadowBlur = 0;
  }

  animId = requestAnimationFrame(draw);
}

function handleResize(width, height) {
  w = width;
  h = height;
  offscreen.width = w * dpr;
  offscreen.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  initColumns();
}

self.onmessage = function (e) {
  if (e.data.canvas) {
    offscreen = e.data.canvas;
    dpr = e.data.dpr || 1;
    ctx = offscreen.getContext("2d");
  }

  if (e.data.resize && e.data.width && e.data.height) {
    handleResize(e.data.width, e.data.height);
    if (!animId) {
      requestAnimationFrame(draw);
    }
  }
};
