const MASK64 = (1n << 64n) - 1n;
const POW10_WINDOW_CACHE = new Map();
const PARTIAL_WINDOW_CACHE = new Map();

const MAGIC_V1 = [0x5a, 0x53, 0x54, 0x31]; // ZST1
const MAGIC_V2 = [0x5a, 0x53, 0x54, 0x32]; // ZST2
const MAGIC = MAGIC_V2;
const CARRIER_MAGIC = [0x5a, 0x53, 0x57, 0x31]; // ZSW1
const APP_VERSION = '0.2.2';
const CARRIER_VERSION_V1 = 1; // v0.1 ZETA STAGE carrier
const CARRIER_VERSION_V2 = 2; // v0.2 hardened stage carrier
const DEFAULT_ITERATIONS = 450000;
const TAG_BYTES_V1 = 16;
const TAG_BYTES_V2 = 32;
const TAG_BYTES = TAG_BYTES_V2;
const DECODER_DISTANCE_LIMIT = 130;

// v0.2 expands the sampled calculation field. The final keystream is still deterministic,
// but the password route now selects deeper decimal positions and more intermediate stages.
const V2_STAGE_MIN = 16;
const V2_STAGE_MAX = 512;
const V2_STAGE_SPAN = V2_STAGE_MAX - V2_STAGE_MIN + 1;
const V2_DECIMAL_MAX = 1048573;
const V2_STAGE_SAMPLES_PER_BLOCK = 12;

const CELL_SIZE = 28;
const ROW_GAP = 4;
const MARGIN = 28;
const LINE_RADIUS = 1;
const MAX_COLS = 160;
const TEMPLATE_POINT_COUNT = CELL_SIZE * CELL_SIZE;

let generatedPngName = '';
let loadedPngImageData = null;
let templateTable = null;
let templateMaps = null;

const $ = (id) => document.getElementById(id);
const refs = {
  messageInput: $('messageInput'),
  encodePassword: $('encodePassword'),
  decodePassword: $('decodePassword'),
  plainOutput: $('plainOutput'),
  statusText: $('statusText'),
  encodeCanvas: $('encodeCanvas'),
  decodeCanvas: $('decodeCanvas'),
  encodeInfo: $('encodeInfo'),
  decodeInfo: $('decodeInfo'),
  loadPngFile: $('loadPngFile'),
  savePngBtn: $('savePngBtn'),
};

function setStatus(message, type = '') {
  refs.statusText.textContent = message;
  refs.statusText.className = type ? `status ${type}` : 'status';
}

function utf8Bytes(text) {
  return new TextEncoder().encode(text);
}

function rotl(x, k) {
  return ((x << BigInt(k)) | (x >> BigInt(64 - k))) & MASK64;
}

function read64(bytes, offset) {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(bytes[offset + i] || 0) << BigInt(i * 8);
  return v & MASK64;
}

class Xoshiro256StarStar {
  constructor(seedBytes) {
    this.s = [read64(seedBytes, 0), read64(seedBytes, 8), read64(seedBytes, 16), read64(seedBytes, 24)];
    if (this.s.every(v => v === 0n)) this.s[0] = 0x9e3779b97f4a7c15n;
  }
  next() {
    const result = (rotl((this.s[1] * 5n) & MASK64, 7) * 9n) & MASK64;
    const t = (this.s[1] << 17n) & MASK64;
    this.s[2] ^= this.s[0];
    this.s[3] ^= this.s[1];
    this.s[1] ^= this.s[2];
    this.s[0] ^= this.s[3];
    this.s[2] ^= t;
    this.s[3] = rotl(this.s[3], 45);
    return result;
  }
}

function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const a of arrays) { out.set(a, p); p += a.length; }
  return out;
}

function uint32Bytes(n) {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

function readUint32(bytes, pos) {
  return ((bytes[pos] << 24) | (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3]) >>> 0;
}

function constantTimeEqual(a, b) {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) diff |= (a[i] || 0) ^ (b[i] || 0);
  return diff === 0;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function deriveSeed(password, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', utf8Bytes(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, 256);
  return new Uint8Array(bits);
}

async function deriveKeys(password, salt, iterations = DEFAULT_ITERATIONS) {
  const material = await crypto.subtle.importKey('raw', utf8Bytes(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, 512);
  const keymat = new Uint8Array(bits);
  return {
    routeKey: keymat.slice(0, 32),
    authKey: keymat.slice(32, 64),
  };
}

async function importHmacKey(keyBytes) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function hmacSha256(key, bytes) {
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}

function pow10Mod(exp, mod) {
  if (mod <= 1n) return 0n;
  let result = 1n;
  let base = 10n % mod;
  let e = BigInt(exp);
  while (e > 0n) {
    if (e & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    e >>= 1n;
  }
  return result;
}

function floorPow10DivMod(exp, divisor, modulo) {
  const d = BigInt(divisor);
  const dm = d * modulo;
  const a = pow10Mod(exp, dm);
  const r = a % d;
  return ((a - r) / d) % modulo;
}

function zetaPartialWindow(stage, decimalPos, width = 2, guard = 5, maxStage = 128, maxDecimalPos = 131071) {
  // Decimal window from an intermediate partial sum of ζ(2):
  // S_stage = 1/1² + 1/2² + ... + 1/stage².
  // This computes only the requested local decimal window. No fixed ζ digit table is read.
  const safeStage = Math.max(2, Math.min(maxStage, stage | 0));
  const safePos = Math.max(1, Math.min(maxDecimalPos, decimalPos | 0));
  const key = `${safeStage}|${safePos}|${width}|${guard}`;
  const cached = PARTIAL_WINDOW_CACHE.get(key);
  if (cached !== undefined) return cached;

  const digits = width + guard;
  const modulo = 10n ** BigInt(digits);
  const exp = safePos + width + guard - 1;
  let sum = 0n;
  for (let n = 1; n <= safeStage; n++) {
    sum = (sum + floorPow10DivMod(exp, n * n, modulo)) % modulo;
  }
  const value = Number((sum / (10n ** BigInt(guard))) % (10n ** BigInt(width)));
  if (PARTIAL_WINDOW_CACHE.size > 16384) PARTIAL_WINDOW_CACHE.clear();
  PARTIAL_WINDOW_CACHE.set(key, value);
  return value;
}

function zetaStageByteV1(stage, decimalPos, mix) {
  // v0.1 compatibility: a byte made from several calculation-stage decimal windows.
  let acc = Number((mix ^ BigInt(stage) ^ (BigInt(decimalPos) << 11n)) & 255n);
  for (let k = 0; k < 2; k++) {
    const s = 6 + ((stage + k * 29 + Number((mix >> BigInt(k * 9)) & 31n)) % 73);
    const p = 1 + ((decimalPos + k * 9973 + Number((mix >> BigInt(17 + k * 7)) & 0xffffn)) % 131071);
    const w = zetaPartialWindow(s, p, 2, 5, 96, 131071);
    acc = ((acc * 131) ^ w ^ ((s * 17) & 255) ^ (p & 255) ^ ((p >> 8) & 255)) & 255;
  }
  return acc;
}

function templateStageShift(byte, stage) {
  const term = 2 + ((byte * 13 + stage * 17) % 89);
  const pos = 1 + ((byte * 257 + stage * 4099 + 17) % 4096);
  return zetaPartialWindow(term, pos, 1, 4, 128, 131071) & 3;
}

// v0.1 stream kept only for decoding old PNGs.
async function makeKeystreamV1(length, routeKeyBytes) {
  const key = await importHmacKey(routeKeyBytes);
  const stream = new Uint8Array(length);
  const domain = utf8Bytes('ZETASTAGETRACECYPHER:ROUTE:V1');
  let previous = new Uint8Array(32);
  let counter = 0;
  let p = 0;

  while (p < length) {
    const block = await hmacSha256(key, concatBytes(domain, uint32Bytes(counter), uint32Bytes(length), previous));
    for (let j = 0; j < block.length && p < length; j++) {
      const a = read64(block, (j * 3) % 24);
      const c = read64(block, (j * 7) % 24);
      const stage = 6 + Number((a ^ BigInt(counter) ^ BigInt(p)) % 73n);
      const decimalPos = 1 + Number((c ^ (a >> 13n) ^ (BigInt(p) << 9n)) % 131071n);
      const zbyte = zetaStageByteV1(stage, decimalPos, a ^ c ^ BigInt(p));
      const folded = Number((a >> BigInt((j % 8) * 8)) & 255n);
      stream[p++] = (zbyte ^ block[j] ^ block[(j + 11) & 31] ^ folded) & 255;
    }
    previous = block;
    counter++;
  }
  return stream;
}

function zetaStageMaterialV2(seedBlock, previous, counter, length) {
  // v0.2: the password route selects multiple calculation stages and arbitrary decimal windows.
  // The sampled values are folded into an HMAC block before becoming keystream bytes.
  const parts = [];
  for (let i = 0; i < V2_STAGE_SAMPLES_PER_BLOCK; i++) {
    const a = read64(seedBlock, (i * 5) % 24) ^ read64(previous, (i * 7) % 24);
    const b = read64(seedBlock, (i * 11) % 24) ^ (a >> 17n) ^ BigInt(counter) ^ BigInt(length);
    const stage = V2_STAGE_MIN + Number((a ^ (BigInt(i) << 29n) ^ BigInt(counter)) % BigInt(V2_STAGE_SPAN));
    const decimalPos = 1 + Number((b ^ (BigInt(i) << 41n)) % BigInt(V2_DECIMAL_MAX));
    const width = 3 + Number((a >> 61n) & 1n);
    const guard = 8;
    const windowValue = zetaPartialWindow(stage, decimalPos, width, guard, V2_STAGE_MAX, V2_DECIMAL_MAX);
    parts.push(
      uint32Bytes(stage),
      uint32Bytes(decimalPos),
      uint32Bytes(windowValue >>> 0),
      new Uint8Array([width, guard, i, Number((a ^ b) & 255n)])
    );
  }
  return concatBytes(...parts);
}

// v0.2 hardened stream: HMAC chooses the route, ζ(2) partial-sum windows individualize it,
// then another HMAC folds those calculated windows back into the final stream.
async function makeKeystreamV2(length, routeKeyBytes) {
  const key = await importHmacKey(routeKeyBytes);
  const stream = new Uint8Array(length);
  const domainSeed = utf8Bytes('ZETASTAGETRACECYPHER:ROUTE:V2:SEED');
  const domainZeta = utf8Bytes('ZETASTAGETRACECYPHER:ROUTE:V2:ZETA');
  const domainOut = utf8Bytes('ZETASTAGETRACECYPHER:ROUTE:V2:OUT');
  const domainFeedback = utf8Bytes('ZETASTAGETRACECYPHER:ROUTE:V2:FEEDBACK');
  let previous = new Uint8Array(32);
  let counter = 0;
  let p = 0;

  while (p < length) {
    const seedBlock = await hmacSha256(key, concatBytes(domainSeed, uint32Bytes(counter), uint32Bytes(length), previous));
    const stageMaterial = zetaStageMaterialV2(seedBlock, previous, counter, length);
    const zetaBlock = await hmacSha256(key, concatBytes(domainZeta, seedBlock, stageMaterial));
    const outBlock = await hmacSha256(key, concatBytes(domainOut, zetaBlock, previous, uint32Bytes(counter)));
    for (let j = 0; j < outBlock.length && p < length; j++) {
      stream[p++] = (outBlock[j] ^ zetaBlock[(j + 5) & 31] ^ seedBlock[(j + 17) & 31]) & 255;
    }
    previous = await hmacSha256(key, concatBytes(domainFeedback, previous, outBlock, zetaBlock));
    counter++;
  }
  return stream;
}

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildCarrierBytes({ salt, iterations, data, carrierVersion = CARRIER_VERSION_V2 }) {
  const header = concatBytes(
    new Uint8Array(CARRIER_MAGIC),
    new Uint8Array([carrierVersion, 0]),
    uint32Bytes(iterations >>> 0),
    salt,
    uint32Bytes(data.length >>> 0),
    data
  );
  return concatBytes(header, uint32Bytes(crc32(header)));
}

function parseCarrierBytes(bytes) {
  if (bytes.length < 34) throw new Error('PNGデータが短すぎます。');
  for (let i = 0; i < 4; i++) if (bytes[i] !== CARRIER_MAGIC[i]) throw new Error('ZETA STAGE TRACE PNGではありません。');
  const version = bytes[4];
  if (version !== CARRIER_VERSION_V1 && version !== CARRIER_VERSION_V2) throw new Error('未対応のPNGバージョンです。');
  const iterations = readUint32(bytes, 6);
  const salt = bytes.slice(10, 26);
  const dataLength = readUint32(bytes, 26);
  const end = 30 + dataLength;
  const crcPos = end;
  if (bytes.length < crcPos + 4) throw new Error('PNG内のデータが途中で切れています。');
  const body = bytes.slice(0, crcPos);
  const expected = readUint32(bytes, crcPos);
  const actual = crc32(body);
  if (expected !== actual) throw new Error('PNGからデータを正しく復元できません。');
  return { version, iterations, salt, data: bytes.slice(30, end), carrierLength: crcPos + 4 };
}

function setBitmapPixel(bitmap, x, y) {
  if (x < 0 || y < 0 || x >= CELL_SIZE || y >= CELL_SIZE) return;
  bitmap[y * CELL_SIZE + x] = 1;
}

function setThickPixel(bitmap, x, y) {
  for (let dy = -LINE_RADIUS; dy <= LINE_RADIUS; dy++) {
    for (let dx = -LINE_RADIUS; dx <= LINE_RADIUS; dx++) {
      setBitmapPixel(bitmap, x + dx, y + dy);
    }
  }
}

function drawLineToBitmap(bitmap, x0, y0, x1, y1) {
  x0 = Math.round(x0); y0 = Math.round(y0); x1 = Math.round(x1); y1 = Math.round(y1);
  let dx = Math.abs(x1 - x0);
  let sx = x0 < x1 ? 1 : -1;
  let dy = -Math.abs(y1 - y0);
  let sy = y0 < y1 ? 1 : -1;
  let err = dx + dy;
  while (true) {
    setThickPixel(bitmap, x0, y0);
    if (x0 === x1 && y0 === y1) break;
    const e2 = 2 * err;
    if (e2 >= dy) { err += dy; x0 += sx; }
    if (e2 <= dx) { err += dx; y0 += sy; }
  }
}

function makeTemplateBitmap(byte, mirrored = false) {
  // v0.2: each encrypted byte becomes a denser 8-step walk.
  // The high/low vertical bands keep decoding stable, while zeta jitter softens the repeated cell feel.
  const topBand = [6, 8, 5, 9, 7, 6, 8, 5];
  const bottomBand = [21, 18, 22, 19, 20, 22, 18, 21];
  const points = [[0, 14]];

  for (let stage = 0; stage < 8; stage++) {
    const bit = (byte >> (7 - stage)) & 1;
    const zd = templateStageShift(byte, stage);
    const jitter = (zd % 3) - 1;
    const x = 3 + stage * 3;
    const y = (bit ? bottomBand[stage] : topBand[stage]) + jitter;
    points.push([x, y]);
  }

  points.push([27, 14]);

  const bitmap = new Uint8Array(TEMPLATE_POINT_COUNT);
  for (let i = 0; i < points.length - 1; i++) {
    let [x0, y0] = points[i];
    let [x1, y1] = points[i + 1];
    if (mirrored) { x0 = CELL_SIZE - 1 - x0; x1 = CELL_SIZE - 1 - x1; }
    drawLineToBitmap(bitmap, x0, y0, x1, y1);
  }
  return bitmap;
}

function isComparableTemplatePixel(index) {
  const x = index % CELL_SIZE;
  // Row-wrap connectors touch the outer edge of a cell.
  // Keep those edge pixels visual-only so PNG reading remains stable.
  return x >= 2 && x < CELL_SIZE - 2;
}

function hashBitmap(bitmap) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < bitmap.length; i++) {
    if (!isComparableTemplatePixel(i)) continue;
    h ^= bitmap[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h.toString(16);
}

function hammingDistance(a, b) {
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    if (!isComparableTemplatePixel(i)) continue;
    if (a[i] !== b[i]) d++;
  }
  return d;
}

function buildTemplates() {
  const normal = [];
  const mirrored = [];
  const normalMap = new Map();
  const mirroredMap = new Map();
  for (let byte = 0; byte < 256; byte++) {
    const nb = makeTemplateBitmap(byte, false);
    const mb = makeTemplateBitmap(byte, true);
    normal.push(nb);
    mirrored.push(mb);
    normalMap.set(hashBitmap(nb), byte);
    mirroredMap.set(hashBitmap(mb), byte);
  }
  return { normal, mirrored, normalMap, mirroredMap };
}

function ensureTemplates() {
  if (!templateTable) {
    templateTable = buildTemplates();
    templateMaps = templateTable;
  }
  return templateTable;
}

function computeLayout(byteLength) {
  const cols = Math.min(MAX_COLS, Math.max(1, Math.ceil(Math.sqrt(byteLength * 1.35))));
  const rows = Math.ceil(byteLength / cols);
  const padded = rows * cols;
  const width = MARGIN * 2 + cols * CELL_SIZE;
  const height = MARGIN * 2 + rows * CELL_SIZE + Math.max(0, rows - 1) * ROW_GAP;
  return { cols, rows, padded, width, height };
}

function whiteImageData(width, height) {
  const imageData = new ImageData(width, height);
  const d = imageData.data;
  for (let i = 0; i < d.length; i += 4) {
    d[i] = 255; d[i + 1] = 255; d[i + 2] = 255; d[i + 3] = 255;
  }
  return imageData;
}

function drawBitmapAt(imageData, bitmap, ox, oy) {
  const data = imageData.data;
  const width = imageData.width;
  for (let y = 0; y < CELL_SIZE; y++) {
    for (let x = 0; x < CELL_SIZE; x++) {
      if (!bitmap[y * CELL_SIZE + x]) continue;
      const px = ox + x;
      const py = oy + y;
      const p = (py * width + px) * 4;
      data[p] = 0; data[p + 1] = 0; data[p + 2] = 0; data[p + 3] = 255;
    }
  }
}

function drawThickLineImageData(imageData, x0, y0, x1, y1) {
  const bitmap = new Uint8Array(imageData.width * imageData.height);
  const oldCell = CELL_SIZE;
  // Simple local Bresenham directly on the full image.
  x0 = Math.round(x0); y0 = Math.round(y0); x1 = Math.round(x1); y1 = Math.round(y1);
  let dx = Math.abs(x1 - x0);
  let sx = x0 < x1 ? 1 : -1;
  let dy = -Math.abs(y1 - y0);
  let sy = y0 < y1 ? 1 : -1;
  let err = dx + dy;
  const put = (x, y) => {
    const data = imageData.data;
    for (let yy = -LINE_RADIUS; yy <= LINE_RADIUS; yy++) {
      for (let xx = -LINE_RADIUS; xx <= LINE_RADIUS; xx++) {
        const px = x + xx;
        const py = y + yy;
        if (px < 0 || py < 0 || px >= imageData.width || py >= imageData.height) continue;
        const p = (py * imageData.width + px) * 4;
        data[p] = 0; data[p + 1] = 0; data[p + 2] = 0; data[p + 3] = 255;
      }
    }
  };
  while (true) {
    put(x0, y0);
    if (x0 === x1 && y0 === y1) break;
    const e2 = 2 * err;
    if (e2 >= dy) { err += dy; x0 += sx; }
    if (e2 <= dx) { err += dx; y0 += sy; }
  }
}

function renderWalkPngToCanvas(canvas, carrierBytes) {
  const templates = ensureTemplates();
  const layout = computeLayout(carrierBytes.length);
  const padded = new Uint8Array(layout.padded);
  padded.set(carrierBytes);

  canvas.width = layout.width;
  canvas.height = layout.height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const imageData = whiteImageData(layout.width, layout.height);

  let index = 0;
  for (let row = 0; row < layout.rows; row++) {
    const rtl = row % 2 === 1;
    for (let colInOrder = 0; colInOrder < layout.cols; colInOrder++) {
      const col = rtl ? layout.cols - 1 - colInOrder : colInOrder;
      const x = MARGIN + col * CELL_SIZE;
      const y = MARGIN + row * (CELL_SIZE + ROW_GAP);
      const byte = padded[index++];
      drawBitmapAt(imageData, rtl ? templates.mirrored[byte] : templates.normal[byte], x, y);
    }
    if (row < layout.rows - 1) {
      const edgeCol = rtl ? 0 : layout.cols - 1;
      const x = MARGIN + edgeCol * CELL_SIZE + (rtl ? 0 : CELL_SIZE - 1);
      const y0 = MARGIN + row * (CELL_SIZE + ROW_GAP) + Math.floor(CELL_SIZE / 2);
      const y1 = MARGIN + (row + 1) * (CELL_SIZE + ROW_GAP) + Math.floor(CELL_SIZE / 2);
      drawThickLineImageData(imageData, x, y0, x, y1);
    }
  }

  ctx.putImageData(imageData, 0, 0);
  return layout;
}

function luminanceAt(imageData, x, y) {
  x = Math.max(0, Math.min(imageData.width - 1, Math.floor(x)));
  y = Math.max(0, Math.min(imageData.height - 1, Math.floor(y)));
  const p = (y * imageData.width + x) * 4;
  const d = imageData.data;
  return (d[p] * 0.299 + d[p + 1] * 0.587 + d[p + 2] * 0.114);
}

function estimateThreshold(imageData) {
  const d = imageData.data;
  let min = 255;
  let max = 0;
  const step = Math.max(4, Math.floor(d.length / 16000 / 4) * 4);
  for (let p = 0; p < d.length; p += step * 4) {
    const lum = d[p] * 0.299 + d[p + 1] * 0.587 + d[p + 2] * 0.114;
    if (lum < min) min = lum;
    if (lum > max) max = lum;
  }
  // A high threshold keeps anti-aliased / recompressed dark strokes readable,
  // while still rejecting ordinary white background noise.
  return Math.max(110, Math.min(230, (min + max) / 2 + 24));
}

function extractCellBitmap(imageData, x0, y0, cellW = CELL_SIZE, cellH = CELL_SIZE, threshold = 128) {
  const bitmap = new Uint8Array(TEMPLATE_POINT_COUNT);
  for (let y = 0; y < CELL_SIZE; y++) {
    for (let x = 0; x < CELL_SIZE; x++) {
      const sx = x0 + (x + 0.5) * cellW / CELL_SIZE;
      const sy = y0 + (y + 0.5) * cellH / CELL_SIZE;
      const lum = luminanceAt(imageData, sx, sy);
      bitmap[y * CELL_SIZE + x] = lum < threshold ? 1 : 0;
    }
  }
  return bitmap;
}

function exactLayoutFromImage(width, height) {
  if (width <= MARGIN * 2 || height <= MARGIN * 2) throw new Error('PNGサイズが不正です。');
  const colsFloat = (width - MARGIN * 2) / CELL_SIZE;
  if (!Number.isInteger(colsFloat) || colsFloat < 1 || colsFloat > MAX_COLS) throw new Error('PNGレイアウトを認識できません。');
  const cols = colsFloat;
  const rowsFloat = (height - MARGIN * 2 + ROW_GAP) / (CELL_SIZE + ROW_GAP);
  if (!Number.isInteger(rowsFloat) || rowsFloat < 1) throw new Error('PNGレイアウトを認識できません。');
  const rows = rowsFloat;
  return { cols, rows, padded: cols * rows, width, height, scale: 1, scaled: false };
}

function inferLayoutsFromImage(width, height) {
  const candidates = [];
  try { candidates.push(exactLayoutFromImage(width, height)); } catch {}

  for (let cols = 1; cols <= MAX_COLS; cols++) {
    const baseWidth = MARGIN * 2 + cols * CELL_SIZE;
    const scale = width / baseWidth;
    if (!Number.isFinite(scale) || scale <= 0.15 || scale > 8) continue;
    const rowsFloat = (height / scale - (MARGIN * 2 - ROW_GAP)) / (CELL_SIZE + ROW_GAP);
    const rows = Math.round(rowsFloat);
    if (rows < 1) continue;
    const baseHeight = MARGIN * 2 + rows * CELL_SIZE + Math.max(0, rows - 1) * ROW_GAP;
    const expectedHeight = baseHeight * scale;
    const err = Math.abs(expectedHeight - height);
    const rel = err / Math.max(1, height);
    if (err <= 3 || rel <= 0.012) {
      const key = `${cols}x${rows}@${scale.toFixed(6)}`;
      if (!candidates.some(c => `${c.cols}x${c.rows}@${(c.scale || 1).toFixed(6)}` === key)) {
        candidates.push({ cols, rows, padded: cols * rows, width, height, scale, scaled: Math.abs(scale - 1) > 0.001, error: err });
      }
    }
  }

  candidates.sort((a, b) => {
    if (a.scaled !== b.scaled) return a.scaled ? 1 : -1;
    return (a.error || 0) - (b.error || 0);
  });
  if (!candidates.length) throw new Error('PNGレイアウトを認識できません。');
  return candidates;
}

function matchTemplate(bitmap, mirrored) {
  const templates = ensureTemplates();
  const h = hashBitmap(bitmap);
  const direct = mirrored ? templates.mirroredMap.get(h) : templates.normalMap.get(h);
  if (direct !== undefined) return direct;

  let bestByte = -1;
  let bestDistance = Infinity;
  const table = mirrored ? templates.mirrored : templates.normal;
  for (let byte = 0; byte < 256; byte++) {
    const d = hammingDistance(bitmap, table[byte]);
    if (d < bestDistance) { bestDistance = d; bestByte = byte; }
  }
  if (bestDistance <= DECODER_DISTANCE_LIMIT) return bestByte;
  throw new Error('PNGの線パターンを読み取れません。');
}

function carrierBytesFromLayout(imageData, layout, maxBytes = Infinity) {
  const bytes = [];
  const threshold = estimateThreshold(imageData);
  const s = layout.scale || 1;
  const cellW = CELL_SIZE * s;
  const cellH = CELL_SIZE * s;
  const gapH = ROW_GAP * s;
  const margin = MARGIN * s;
  const limit = Math.min(layout.padded, maxBytes);

  for (let row = 0; row < layout.rows; row++) {
    const rtl = row % 2 === 1;
    for (let colInOrder = 0; colInOrder < layout.cols; colInOrder++) {
      if (bytes.length >= limit) return new Uint8Array(bytes);
      const col = rtl ? layout.cols - 1 - colInOrder : colInOrder;
      const x = margin + col * cellW;
      const y = margin + row * (cellH + gapH);
      const bitmap = extractCellBitmap(imageData, x, y, cellW, cellH, threshold);
      bytes.push(matchTemplate(bitmap, rtl));
    }
  }
  return new Uint8Array(bytes);
}

function carrierBytesFromImageData(imageData) {
  const layouts = inferLayoutsFromImage(imageData.width, imageData.height);
  let lastError = null;

  for (const layout of layouts) {
    try {
      const head = carrierBytesFromLayout(imageData, layout, Math.min(34, layout.padded));
      if (head.length < 34) continue;
      for (let i = 0; i < 4; i++) if (head[i] !== CARRIER_MAGIC[i]) throw new Error('magic mismatch');
      const full = carrierBytesFromLayout(imageData, layout);
      // parseCarrierBytes verifies length and CRC. Return the full padded stream after validation.
      parseCarrierBytes(full);
      return full;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError && lastError.message && lastError.message !== 'magic mismatch'
    ? lastError
    : new Error('PNGからデータを正しく復元できません。');
}

function imageFileToImageData(file, canvas) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.imageSmoothingEnabled = false;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      resolve(ctx.getImageData(0, 0, canvas.width, canvas.height));
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('PNGを読み込めませんでした。'));
    };
    img.src = url;
  });
}

async function makeTag(authKeyBytes, salt, iterations, cipher, carrierVersion = CARRIER_VERSION_V2) {
  const key = await importHmacKey(authKeyBytes);
  const domain = carrierVersion === CARRIER_VERSION_V1
    ? utf8Bytes('ZETASTAGETRACECYPHER:AUTH:V1')
    : utf8Bytes('ZETASTAGETRACECYPHER:AUTH:V2:HARDENED');
  const full = await hmacSha256(key, concatBytes(domain, salt, uint32Bytes(iterations), uint32Bytes(cipher.length), cipher));
  return full.slice(0, carrierVersion === CARRIER_VERSION_V1 ? TAG_BYTES_V1 : TAG_BYTES_V2);
}

function verifyPlainPayload(plain, carrierVersion = CARRIER_VERSION_V2) {
  const magic = carrierVersion === CARRIER_VERSION_V1 ? MAGIC_V1 : MAGIC_V2;
  const digestBytes = carrierVersion === CARRIER_VERSION_V1 ? 8 : 16;
  const headerBytes = 8 + digestBytes;
  if (plain.length < headerBytes) throw new Error('復号できません。');
  for (let i = 0; i < magic.length; i++) {
    if (plain[i] !== magic[i]) throw new Error('復号できません。');
  }

  const len = readUint32(plain, 4);
  if (len > plain.length - headerBytes) throw new Error('復号できません。');
  return { digest: plain.slice(8, 8 + digestBytes), msgBytes: plain.slice(headerBytes, headerBytes + len), digestBytes };
}

async function decodePayloadToText(plain, carrierVersion = CARRIER_VERSION_V2) {
  const { digest, msgBytes, digestBytes } = verifyPlainPayload(plain, carrierVersion);
  const check = (await sha256(msgBytes)).slice(0, digestBytes);
  if (!constantTimeEqual(digest, check)) throw new Error('復号できません。');
  return new TextDecoder('utf-8', { fatal: true }).decode(msgBytes);
}

async function createCipherFromMessage(message, password) {
  const messageBytes = utf8Bytes(message);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = DEFAULT_ITERATIONS;
  const carrierVersion = CARRIER_VERSION_V2;
  const keys = await deriveKeys(password, salt, iterations);
  const digest = (await sha256(messageBytes)).slice(0, 16);
  const payload = concatBytes(new Uint8Array(MAGIC_V2), uint32Bytes(messageBytes.length), digest, messageBytes);
  const stream = await makeKeystreamV2(payload.length, keys.routeKey);
  const cipher = xorBytes(payload, stream);
  const tag = await makeTag(keys.authKey, salt, iterations, cipher, carrierVersion);
  return { salt, data: concatBytes(cipher, tag), messageBytes, iterations, carrierVersion };
}

async function decodeCipherToMessage(data, salt, iterations, password, carrierVersion = CARRIER_VERSION_V2) {
  if (carrierVersion !== CARRIER_VERSION_V1 && carrierVersion !== CARRIER_VERSION_V2) throw new Error('未対応のPNGバージョンです。');
  const tagBytes = carrierVersion === CARRIER_VERSION_V1 ? TAG_BYTES_V1 : TAG_BYTES_V2;
  if (data.length <= tagBytes) throw new Error('復号できません。');
  const cipher = data.slice(0, data.length - tagBytes);
  const tag = data.slice(data.length - tagBytes);
  const safeIterations = iterations || (carrierVersion === CARRIER_VERSION_V1 ? 320000 : DEFAULT_ITERATIONS);
  const keys = await deriveKeys(password, salt, safeIterations);
  const expected = await makeTag(keys.authKey, salt, safeIterations, cipher, carrierVersion);
  if (!constantTimeEqual(tag, expected)) throw new Error('復号できません。');
  const stream = carrierVersion === CARRIER_VERSION_V1
    ? await makeKeystreamV1(cipher.length, keys.routeKey)
    : await makeKeystreamV2(cipher.length, keys.routeKey);
  return decodePayloadToText(xorBytes(cipher, stream), carrierVersion);
}

async function encode() {
  try {
    const password = refs.encodePassword.value;
    const message = refs.messageInput.value;
    if (!message) throw new Error('文章を入力してください。');
    if (!password) throw new Error('パスワードを入力してください。');

    setStatus('PNG生成中…');
    refs.savePngBtn.disabled = true;
    ensureTemplates();

    const { salt, data, messageBytes, iterations, carrierVersion } = await createCipherFromMessage(message, password);
    const carrierBytes = buildCarrierBytes({ salt, iterations, data, carrierVersion });
    const layout = renderWalkPngToCanvas(refs.encodeCanvas, carrierBytes);
    generatedPngName = `zeta-stage-trace-v02-${new Date().toISOString().replace(/[:.]/g, '-')}.png`;
    refs.encodeInfo.textContent = `${carrierBytes.length} bytes / ${layout.cols}×${layout.rows} cells / ${refs.encodeCanvas.width}×${refs.encodeCanvas.height}px`;
    refs.savePngBtn.disabled = false;
    setStatus(`PNGを生成しました。本文 ${messageBytes.length} bytes。`, 'ok');
  } catch (err) {
    setStatus(err.message || String(err), 'error');
  }
}

function savePng() {
  if (refs.savePngBtn.disabled) return;
  refs.encodeCanvas.toBlob((blob) => {
    if (!blob) { setStatus('PNG保存に失敗しました。', 'error'); return; }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = generatedPngName || 'zeta-stage-trace.png';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
    setStatus('PNGを保存しました。', 'ok');
  }, 'image/png');
}

async function loadPngFile(event) {
  try {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    if (file.type && !file.type.startsWith('image/')) throw new Error('画像ファイルを選択してください。');
    setStatus('PNG読み込み中…');
    loadedPngImageData = await imageFileToImageData(file, refs.decodeCanvas);
    refs.plainOutput.value = '';
    refs.decodeInfo.textContent = `${file.name} / ${loadedPngImageData.width}×${loadedPngImageData.height}px`;
    setStatus('PNGを読み込みました。', 'ok');
  } catch (err) {
    loadedPngImageData = null;
    refs.decodeInfo.textContent = '読み込み失敗';
    setStatus(err.message || String(err), 'error');
  } finally {
    event.target.value = '';
  }
}

async function decode() {
  try {
    const password = refs.decodePassword.value;
    if (!loadedPngImageData) throw new Error('PNGを読み込んでください。');
    if (!password) throw new Error('パスワードを入力してください。');
    setStatus('復号中…');
    refs.plainOutput.value = '';
    ensureTemplates();

    const bytes = carrierBytesFromImageData(loadedPngImageData);
    const carrier = parseCarrierBytes(bytes);
    const message = await decodeCipherToMessage(carrier.data, carrier.salt, carrier.iterations, password, carrier.version);
    refs.plainOutput.value = message;
    refs.decodeInfo.textContent = `復元 ${carrier.carrierLength} bytes / data ${carrier.data.length} bytes / carrier v${carrier.version}`;
    setStatus('復号しました。', 'ok');
  } catch (err) {
    refs.plainOutput.value = '';
    setStatus(err.message || String(err), 'error');
  }
}

async function copyText(text, okMessage) {
  if (!text) { setStatus('コピーする内容がありません。', 'error'); return; }
  try {
    await navigator.clipboard.writeText(text);
    setStatus(okMessage, 'ok');
  } catch {
    setStatus('コピーできませんでした。', 'error');
  }
}

function clearEncode() {
  refs.messageInput.value = '';
  refs.encodeInfo.textContent = '未生成';
  refs.savePngBtn.disabled = true;
  refs.encodeCanvas.width = 1;
  refs.encodeCanvas.height = 1;
  setStatus('クリアしました。');
}

function clearDecode() {
  loadedPngImageData = null;
  refs.decodeInfo.textContent = '未読み込み';
  refs.decodeCanvas.width = 1;
  refs.decodeCanvas.height = 1;
  refs.plainOutput.value = '';
  setStatus('クリアしました。');
}

function togglePassword(input, button) {
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  button.textContent = showing ? '表示' : '隠す';
}

async function cleanupOldServiceWorkers() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const regs = await navigator.serviceWorker.getRegistrations();
    for (const reg of regs) await reg.unregister();
    if ('caches' in window) {
      const keys = await caches.keys();
      await Promise.all(keys.map(key => caches.delete(key)));
    }
  } catch {}
}

$('encodeBtn').addEventListener('click', encode);
$('decodeBtn').addEventListener('click', decode);
$('savePngBtn').addEventListener('click', savePng);
$('loadPngFile').addEventListener('change', loadPngFile);
$('copyPlainBtn').addEventListener('click', () => copyText(refs.plainOutput.value, 'コピーしました。'));
$('clearEncodeBtn').addEventListener('click', clearEncode);
$('clearDecodeBtn').addEventListener('click', clearDecode);
$('showEncodePassword').addEventListener('click', () => togglePassword(refs.encodePassword, $('showEncodePassword')));
$('showDecodePassword').addEventListener('click', () => togglePassword(refs.decodePassword, $('showDecodePassword')));

cleanupOldServiceWorkers();
