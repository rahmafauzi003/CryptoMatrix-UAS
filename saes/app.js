"use strict";

// ============================================================
// Konstanta S-AES
// ============================================================
const SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7];
const INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE];
const RCON1 = 0x80;
const RCON2 = 0x30;
const MIX_MATRIX = [[0x1, 0x4], [0x4, 0x1]];
const INV_MIX_MATRIX = [[0x9, 0x2], [0x2, 0x9]];

// Kasus pengujian siap pakai untuk fitur "Isi Data Contoh".
// Nilai ciphertext sudah diverifikasi menggunakan implementasi S-AES pada file ini.
const SAMPLE_CASES = [
  { id: "cryptomatrix", name: "RuangSandi Vector", plaintext: 0xCAFE, key: 0xBEEF, ciphertext: 0x2855 },
];

// State direpresentasikan sebagai array column-major:
// [n0, n1, n2, n3] <=> matriks [[n0, n2], [n1, n3]]

// ============================================================
// Utilitas representasi
// ============================================================
const hexNibble = (value) => (value & 0xF).toString(16).toUpperCase();
const hexByte = (value) => (value & 0xFF).toString(16).toUpperCase().padStart(2, "0");
const hexWord = (value) => (value & 0xFFFF).toString(16).toUpperCase().padStart(4, "0");
const binNibble = (value) => (value & 0xF).toString(2).padStart(4, "0");
const binByte = (value) => (value & 0xFF).toString(2).padStart(8, "0");
const binWord = (value) => (value & 0xFFFF).toString(2).padStart(16, "0");
const groupedBinary = (value, bits = 16) => (value >>> 0)
  .toString(2)
  .padStart(bits, "0")
  .match(/.{1,4}/g)
  .join(" ");

function normalizeBinary(text) {
  return String(text ?? "").replace(/\s+/g, "");
}

function wordToState(word) {
  return [
    (word >>> 12) & 0xF,
    (word >>> 8) & 0xF,
    (word >>> 4) & 0xF,
    word & 0xF,
  ];
}

function stateToWord(state) {
  return ((state[0] & 0xF) << 12)
    | ((state[1] & 0xF) << 8)
    | ((state[2] & 0xF) << 4)
    | (state[3] & 0xF);
}

function cloneState(state) {
  return state.slice();
}

function xorState(a, b) {
  return a.map((value, index) => value ^ b[index]);
}

function polynomialOfNibble(value) {
  const terms = [];
  if (value & 0x8) terms.push("x³");
  if (value & 0x4) terms.push("x²");
  if (value & 0x2) terms.push("x");
  if (value & 0x1) terms.push("1");
  return terms.length ? terms.join(" + ") : "0";
}

// ============================================================
// Operasi GF(2^4)
// Modulus: x^4 + x + 1 = 10011₂ = 0x13.
// Saat bit x^4 muncul setelah shift, XOR bagian bawah modulus (0011₂).
// ============================================================
function gfAdd(a, b) {
  return (a ^ b) & 0xF;
}

function gfMul(a, b) {
  let multiplicand = a & 0xF;
  let multiplier = b & 0xF;
  let product = 0;

  for (let i = 0; i < 4; i += 1) {
    if (multiplier & 1) product ^= multiplicand;

    const carry = multiplicand & 0x8;
    multiplicand = (multiplicand << 1) & 0xF;
    if (carry) multiplicand ^= 0x3; // reduksi oleh x^4 + x + 1

    multiplier >>>= 1;
  }

  return product & 0xF;
}

function gfMulDetailed(a, b) {
  let multiplicand = a & 0xF;
  let multiplier = b & 0xF;
  let product = 0;
  const lines = [
    `Hitung ${hexNibble(a)} ⊗ ${hexNibble(b)} di GF(2⁴)`,
    `${hexNibble(a)} = ${binNibble(a)}₂ = ${polynomialOfNibble(a)}`,
    `${hexNibble(b)} = ${binNibble(b)}₂ = ${polynomialOfNibble(b)}`,
    "Modulus m(x) = x⁴ + x + 1 (10011₂)",
  ];

  for (let i = 0; i < 4; i += 1) {
    const lsb = multiplier & 1;
    lines.push(`Iterasi ${i + 1}: a=${binNibble(multiplicand)}, b=${binNibble(multiplier)}, p=${binNibble(product)}`);

    if (lsb) {
      const before = product;
      product ^= multiplicand;
      lines.push(`  LSB b = 1 → p = ${binNibble(before)} ⊕ ${binNibble(multiplicand)} = ${binNibble(product)}`);
    } else {
      lines.push("  LSB b = 0 → p tidak berubah");
    }

    const carry = Boolean(multiplicand & 0x8);
    const shifted = (multiplicand << 1) & 0xF;
    multiplicand = shifted;

    if (carry) {
      const beforeReduction = multiplicand;
      multiplicand ^= 0x3;
      lines.push(`  Ada bit x⁴ → reduksi: ${binNibble(beforeReduction)} ⊕ 0011 = ${binNibble(multiplicand)}`);
    } else {
      lines.push(`  Tidak ada bit x⁴ → a setelah shift = ${binNibble(multiplicand)}`);
    }

    multiplier >>>= 1;
  }

  lines.push(`Hasil: ${binNibble(product)}₂ = ${hexNibble(product)}₁₆`);
  return { result: product & 0xF, lines };
}

// ============================================================
// Transformasi dasar
// ============================================================
function substituteState(state, box) {
  return state.map((nibble) => box[nibble]);
}

function shiftRows(state) {
  // Matriks [[s0,s2],[s1,s3]] → [[s0,s2],[s3,s1]]
  return [state[0], state[3], state[2], state[1]];
}

function mixColumnsDetailed(state, matrix) {
  const output = [0, 0, 0, 0];
  const calculations = [];

  for (let column = 0; column < 2; column += 1) {
    const topIndex = column * 2;
    const bottomIndex = topIndex + 1;
    const top = state[topIndex];
    const bottom = state[bottomIndex];

    const m00 = gfMulDetailed(matrix[0][0], top);
    const m01 = gfMulDetailed(matrix[0][1], bottom);
    const m10 = gfMulDetailed(matrix[1][0], top);
    const m11 = gfMulDetailed(matrix[1][1], bottom);

    output[topIndex] = gfAdd(m00.result, m01.result);
    output[bottomIndex] = gfAdd(m10.result, m11.result);

    calculations.push({
      column: column + 1,
      input: [top, bottom],
      top: {
        label: `s'${topIndex}`,
        expression: `(${hexNibble(matrix[0][0])}⊗${hexNibble(top)}) ⊕ (${hexNibble(matrix[0][1])}⊗${hexNibble(bottom)})`,
        left: m00,
        right: m01,
        result: output[topIndex],
      },
      bottom: {
        label: `s'${bottomIndex}`,
        expression: `(${hexNibble(matrix[1][0])}⊗${hexNibble(top)}) ⊕ (${hexNibble(matrix[1][1])}⊗${hexNibble(bottom)})`,
        left: m10,
        right: m11,
        result: output[bottomIndex],
      },
    });
  }

  return { output, calculations };
}

function mixColumns(state) {
  return mixColumnsDetailed(state, MIX_MATRIX).output;
}

function invMixColumns(state) {
  return mixColumnsDetailed(state, INV_MIX_MATRIX).output;
}

// ============================================================
// Key Expansion
// ============================================================
function rotNib(word) {
  return ((word & 0xF) << 4) | ((word >>> 4) & 0xF);
}

function subNibByte(word) {
  return (SBOX[(word >>> 4) & 0xF] << 4) | SBOX[word & 0xF];
}

function keyExpansion(key) {
  const w0 = (key >>> 8) & 0xFF;
  const w1 = key & 0xFF;

  const rot1 = rotNib(w1);
  const sub1 = subNibByte(rot1);
  const g1 = sub1 ^ RCON1;
  const w2 = w0 ^ g1;
  const w3 = w2 ^ w1;

  const rot2 = rotNib(w3);
  const sub2 = subNibByte(rot2);
  const g2 = sub2 ^ RCON2;
  const w4 = w2 ^ g2;
  const w5 = w4 ^ w3;

  const k0 = ((w0 << 8) | w1) & 0xFFFF;
  const k1 = ((w2 << 8) | w3) & 0xFFFF;
  const k2 = ((w4 << 8) | w5) & 0xFFFF;

  return {
    words: [w0, w1, w2, w3, w4, w5],
    roundKeys: [k0, k1, k2],
    details: {
      first: { input: w1, rot: rot1, sub: sub1, rcon: RCON1, g: g1, output: w2 },
      second: { input: w3, rot: rot2, sub: sub2, rcon: RCON2, g: g2, output: w4 },
    },
  };
}

// ============================================================
// Enkripsi dan dekripsi dengan snapshot setiap tahap
// ============================================================
function encryptSAES(plaintext, key) {
  const expansion = keyExpansion(key);
  const [k0, k1, k2] = expansion.roundKeys.map(wordToState);
  const steps = [];

  let state = wordToState(plaintext);

  const initialBefore = cloneState(state);
  state = xorState(state, k0);
  steps.push({
    type: "addRoundKey",
    title: "Initial AddRoundKey (K0)",
    description: "Plaintext di-XOR dengan round key awal K0 secara nibble/kolom.",
    before: initialBefore,
    key: k0,
    after: cloneState(state),
    keyName: "K0",
  });

  const sub1Before = cloneState(state);
  state = substituteState(state, SBOX);
  steps.push({
    type: "substitution",
    title: "Round 1 — SubNibbles",
    description: "Setiap nibble diganti menggunakan tabel S-Box S-AES.",
    before: sub1Before,
    after: cloneState(state),
    boxName: "S-Box",
  });

  const shift1Before = cloneState(state);
  state = shiftRows(state);
  steps.push({
    type: "shiftRows",
    title: "Round 1 — ShiftRows",
    description: "Baris kedua state digeser satu posisi ke kiri. Pada matriks 2×2, operasi ini menukar dua nibble pada baris kedua.",
    before: shift1Before,
    after: cloneState(state),
  });

  const mix1Before = cloneState(state);
  const mix1 = mixColumnsDetailed(state, MIX_MATRIX);
  state = mix1.output;
  steps.push({
    type: "mixColumns",
    title: "Round 1 — MixColumns",
    description: "Setiap kolom dikalikan matriks [[1,4],[4,1]] di GF(2⁴), dengan modulus x⁴+x+1.",
    before: mix1Before,
    after: cloneState(state),
    matrix: MIX_MATRIX,
    calculations: mix1.calculations,
  });

  const add1Before = cloneState(state);
  state = xorState(state, k1);
  steps.push({
    type: "addRoundKey",
    title: "Round 1 — AddRoundKey (K1)",
    description: "State hasil MixColumns di-XOR dengan K1.",
    before: add1Before,
    key: k1,
    after: cloneState(state),
    keyName: "K1",
  });

  const sub2Before = cloneState(state);
  state = substituteState(state, SBOX);
  steps.push({
    type: "substitution",
    title: "Round 2 — SubNibbles",
    description: "Setiap nibble kembali disubstitusi dengan S-Box.",
    before: sub2Before,
    after: cloneState(state),
    boxName: "S-Box",
  });

  const shift2Before = cloneState(state);
  state = shiftRows(state);
  steps.push({
    type: "shiftRows",
    title: "Round 2 — ShiftRows",
    description: "Baris kedua digeser satu posisi ke kiri.",
    before: shift2Before,
    after: cloneState(state),
  });

  const add2Before = cloneState(state);
  state = xorState(state, k2);
  steps.push({
    type: "addRoundKey",
    title: "Round 2 — AddRoundKey (K2)",
    description: "Final round tidak menggunakan MixColumns. State di-XOR dengan K2 untuk menghasilkan ciphertext.",
    before: add2Before,
    key: k2,
    after: cloneState(state),
    keyName: "K2",
  });

  return {
    mode: "encrypt",
    input: plaintext,
    key,
    output: stateToWord(state),
    expansion,
    steps,
  };
}

function decryptSAES(ciphertext, key) {
  const expansion = keyExpansion(key);
  const [k0, k1, k2] = expansion.roundKeys.map(wordToState);
  const steps = [];

  let state = wordToState(ciphertext);

  const initialBefore = cloneState(state);
  state = xorState(state, k2);
  steps.push({
    type: "addRoundKey",
    title: "Initial AddRoundKey (K2)",
    description: "Ciphertext di-XOR dengan round key terakhir K2.",
    before: initialBefore,
    key: k2,
    after: cloneState(state),
    keyName: "K2",
  });

  const invShift1Before = cloneState(state);
  state = shiftRows(state); // untuk 2 kolom, invers sama dengan operasi maju
  steps.push({
    type: "shiftRows",
    title: "Inverse Round 1 — InvShiftRows",
    description: "Baris kedua digeser satu posisi ke kanan. Karena hanya ada dua kolom, hasilnya sama dengan menukar kedua nibble pada baris kedua.",
    before: invShift1Before,
    after: cloneState(state),
  });

  const invSub1Before = cloneState(state);
  state = substituteState(state, INV_SBOX);
  steps.push({
    type: "substitution",
    title: "Inverse Round 1 — InvSubNibbles",
    description: "Setiap nibble diganti menggunakan Inverse S-Box.",
    before: invSub1Before,
    after: cloneState(state),
    boxName: "Inverse S-Box",
  });

  const add1Before = cloneState(state);
  state = xorState(state, k1);
  steps.push({
    type: "addRoundKey",
    title: "Inverse Round 1 — AddRoundKey (K1)",
    description: "State di-XOR dengan K1 sebelum InvMixColumns.",
    before: add1Before,
    key: k1,
    after: cloneState(state),
    keyName: "K1",
  });

  const invMixBefore = cloneState(state);
  const invMix = mixColumnsDetailed(state, INV_MIX_MATRIX);
  state = invMix.output;
  steps.push({
    type: "mixColumns",
    title: "Inverse Round 1 — InvMixColumns",
    description: "Setiap kolom dikalikan matriks invers [[9,2],[2,9]] di GF(2⁴).",
    before: invMixBefore,
    after: cloneState(state),
    matrix: INV_MIX_MATRIX,
    calculations: invMix.calculations,
  });

  const invShift2Before = cloneState(state);
  state = shiftRows(state);
  steps.push({
    type: "shiftRows",
    title: "Inverse Round 2 — InvShiftRows",
    description: "Baris kedua digeser satu posisi ke kanan.",
    before: invShift2Before,
    after: cloneState(state),
  });

  const invSub2Before = cloneState(state);
  state = substituteState(state, INV_SBOX);
  steps.push({
    type: "substitution",
    title: "Inverse Round 2 — InvSubNibbles",
    description: "Setiap nibble disubstitusi menggunakan Inverse S-Box.",
    before: invSub2Before,
    after: cloneState(state),
    boxName: "Inverse S-Box",
  });

  const add0Before = cloneState(state);
  state = xorState(state, k0);
  steps.push({
    type: "addRoundKey",
    title: "Inverse Round 2 — AddRoundKey (K0)",
    description: "State di-XOR dengan K0 untuk mendapatkan plaintext semula.",
    before: add0Before,
    key: k0,
    after: cloneState(state),
    keyName: "K0",
  });

  return {
    mode: "decrypt",
    input: ciphertext,
    key,
    output: stateToWord(state),
    expansion,
    steps,
  };
}

// ============================================================
// Rendering UI
// ============================================================
const elements = {
  form: document.getElementById("saesForm"),
  dataInput: document.getElementById("dataInput"),
  keyInput: document.getElementById("keyInput"),
  dataLabel: document.getElementById("dataLabel"),
  dataHelp: document.getElementById("dataHelp"),
  dataError: document.getElementById("dataError"),
  keyError: document.getElementById("keyError"),
  dataCount: document.getElementById("dataCount"),
  keyCount: document.getElementById("keyCount"),
  resultPanel: document.getElementById("resultPanel"),
  stepsPanel: document.getElementById("stepsPanel"),
  stepsContainer: document.getElementById("stepsContainer"),
  modeBadge: document.getElementById("modeBadge"),
  binaryResultLabel: document.getElementById("binaryResultLabel"),
  hexResultLabel: document.getElementById("hexResultLabel"),
  binaryResult: document.getElementById("binaryResult"),
  hexResult: document.getElementById("hexResult"),
  resultSummary: document.getElementById("resultSummary"),
  resetButton: document.getElementById("resetButton"),
  expandAllButton: document.getElementById("expandAllButton"),
  collapseAllButton: document.getElementById("collapseAllButton"),
  examplePreview: document.getElementById("examplePreview"),
  fillExampleButton: document.getElementById("fillExampleButton"),
  runExampleButton: document.getElementById("runExampleButton"),
  copyBinaryButton: document.getElementById("copyBinaryButton"),
  copyHexButton: document.getElementById("copyHexButton"),
  themeButton: document.getElementById("themeButton"),
  toast: document.getElementById("toast"),
};

function stateMatrixHTML(state, label) {
  const positions = [0, 2, 1, 3]; // tampilan baris matriks dari state column-major
  return `
    <div class="matrix-panel">
      <span>${label}</span>
      <div class="state-matrix">
        ${positions.map((index) => `
          <div class="nibble-cell">
            ${hexNibble(state[index])}
            <small>${binNibble(state[index])}</small>
          </div>
        `).join("")}
      </div>
      <div class="code-line" style="margin-top:10px">Hex: ${hexWord(stateToWord(state))} • Biner: ${groupedBinary(stateToWord(state))}</div>
    </div>
  `;
}

function operationMatricesHTML(before, middle, after, middleLabel = "Kunci") {
  return `
    <div class="operation-grid">
      ${stateMatrixHTML(before, "State sebelum")}
      ${stateMatrixHTML(middle, middleLabel)}
      ${stateMatrixHTML(after, "State sesudah")}
    </div>
  `;
}

function beforeAfterHTML(before, after) {
  return `
    <div class="operation-grid two">
      ${stateMatrixHTML(before, "State sebelum")}
      ${stateMatrixHTML(after, "State sesudah")}
    </div>
  `;
}

function renderSubstitutionDetails(step) {
  return `
    ${beforeAfterHTML(step.before, step.after)}
    <div class="subsection">
      <h4>Substitusi setiap nibble</h4>
      <div class="nibble-transform-list">
        ${step.before.map((value, index) => `
          <div class="nibble-transform">
            <span>s${index}: ${hexNibble(value)} (${binNibble(value)})</span>
            <strong>→ ${hexNibble(step.after[index])} (${binNibble(step.after[index])})</strong>
          </div>
        `).join("")}
      </div>
      <div class="formula-box">${step.boxName}[input] digunakan untuk seluruh nibble.</div>
    </div>
  `;
}

function renderAddRoundKeyDetails(step) {
  const rows = step.before.map((value, index) => `
    <tr>
      <td>s${index}</td>
      <td class="mono">${binNibble(value)}</td>
      <td>⊕</td>
      <td class="mono">${binNibble(step.key[index])}</td>
      <td>=</td>
      <td class="mono"><strong>${binNibble(step.after[index])}</strong></td>
    </tr>
  `).join("");

  return `
    ${operationMatricesHTML(step.before, step.key, step.after, step.keyName)}
    <div class="subsection table-scroll">
      <h4>Detail XOR per nibble</h4>
      <table class="comparison-table">
        <thead><tr><th>Nibble</th><th>State</th><th></th><th>${step.keyName}</th><th></th><th>Hasil</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderShiftRowsDetails(step) {
  return `
    ${beforeAfterHTML(step.before, step.after)}
    <div class="formula-box">
      Baris atas tetap: [${hexNibble(step.before[0])}, ${hexNibble(step.before[2])}] → [${hexNibble(step.after[0])}, ${hexNibble(step.after[2])}]<br />
      Baris bawah bergeser: [${hexNibble(step.before[1])}, ${hexNibble(step.before[3])}] → [${hexNibble(step.after[1])}, ${hexNibble(step.after[3])}]
    </div>
  `;
}

function renderOneGFResult(item) {
  return `
    <article class="gf-detail">
      <strong>${item.label} = ${item.expression}</strong>
      <div class="formula-box">
        = ${hexNibble(item.left.result)} ⊕ ${hexNibble(item.right.result)}
        = ${binNibble(item.left.result)} ⊕ ${binNibble(item.right.result)}
        = <strong>${binNibble(item.result)} (${hexNibble(item.result)})</strong>
      </div>
      <details>
        <summary>Lihat detail perkalian pertama</summary>
        <pre>${item.left.lines.join("\n")}</pre>
      </details>
      <details>
        <summary>Lihat detail perkalian kedua</summary>
        <pre>${item.right.lines.join("\n")}</pre>
      </details>
    </article>
  `;
}

function renderMixColumnsDetails(step) {
  const matrixString = `[[${hexNibble(step.matrix[0][0])},${hexNibble(step.matrix[0][1])}],[${hexNibble(step.matrix[1][0])},${hexNibble(step.matrix[1][1])}]]`;
  return `
    ${beforeAfterHTML(step.before, step.after)}
    <div class="formula-box">Matriks yang digunakan: ${matrixString}; seluruh perkalian dilakukan modulo x⁴+x+1.</div>
    ${step.calculations.map((column) => `
      <div class="subsection">
        <h4>Kolom ${column.column}: [${hexNibble(column.input[0])}, ${hexNibble(column.input[1])}]ᵀ</h4>
        <div class="gf-grid">
          ${renderOneGFResult(column.top)}
          ${renderOneGFResult(column.bottom)}
        </div>
      </div>
    `).join("")}
  `;
}

function renderStepCard(step, index) {
  let body = "";
  if (step.type === "substitution") body = renderSubstitutionDetails(step);
  if (step.type === "addRoundKey") body = renderAddRoundKeyDetails(step);
  if (step.type === "shiftRows") body = renderShiftRowsDetails(step);
  if (step.type === "mixColumns") body = renderMixColumnsDetails(step);

  return `
    <details class="step-card" ${index < 2 ? "open" : ""}>
      <summary><span class="step-number">${index + 2}</span><span>${step.title}</span></summary>
      <div class="step-content">
        <p class="step-description">${step.description}</p>
        ${body}
      </div>
    </details>
  `;
}

function renderKeyExpansion(expansion, key) {
  const [w0, w1, w2, w3, w4, w5] = expansion.words;
  const [k0, k1, k2] = expansion.roundKeys;
  const first = expansion.details.first;
  const second = expansion.details.second;

  return `
    <details class="step-card" open>
      <summary><span class="step-number">1</span><span>Key Expansion — Pembangkitan K0, K1, K2</span></summary>
      <div class="step-content">
        <p class="step-description">Kunci 16-bit dibagi menjadi w0 dan w1, lalu dikembangkan menjadi enam word 8-bit.</p>

        <div class="formula-box">Kunci awal = ${groupedBinary(key)}₂ = ${hexWord(key)}₁₆</div>

        <div class="table-scroll">
          <table class="word-table">
            <thead><tr><th>Word</th><th>Biner 8-bit</th><th>Hex</th><th>Rumus</th></tr></thead>
            <tbody>
              <tr><td>w0</td><td class="mono">${binByte(w0)}</td><td class="mono">${hexByte(w0)}</td><td>8 bit kiri kunci</td></tr>
              <tr><td>w1</td><td class="mono">${binByte(w1)}</td><td class="mono">${hexByte(w1)}</td><td>8 bit kanan kunci</td></tr>
              <tr><td>w2</td><td class="mono">${binByte(w2)}</td><td class="mono">${hexByte(w2)}</td><td>w0 ⊕ SubNib(RotNib(w1)) ⊕ RCON1</td></tr>
              <tr><td>w3</td><td class="mono">${binByte(w3)}</td><td class="mono">${hexByte(w3)}</td><td>w2 ⊕ w1</td></tr>
              <tr><td>w4</td><td class="mono">${binByte(w4)}</td><td class="mono">${hexByte(w4)}</td><td>w2 ⊕ SubNib(RotNib(w3)) ⊕ RCON2</td></tr>
              <tr><td>w5</td><td class="mono">${binByte(w5)}</td><td class="mono">${hexByte(w5)}</td><td>w4 ⊕ w3</td></tr>
            </tbody>
          </table>
        </div>

        <div class="subsection">
          <h4>Perhitungan w2 dan w3</h4>
          <div class="formula-box">
            RotNib(w1): ${binByte(first.input)} → ${binByte(first.rot)} (${hexByte(first.input)} → ${hexByte(first.rot)})<br />
            SubNib: ${binByte(first.rot)} → ${binByte(first.sub)} (${hexByte(first.rot)} → ${hexByte(first.sub)})<br />
            g(w1) = ${binByte(first.sub)} ⊕ ${binByte(first.rcon)} = ${binByte(first.g)}<br />
            w2 = ${binByte(w0)} ⊕ ${binByte(first.g)} = <strong>${binByte(w2)} (${hexByte(w2)})</strong><br />
            w3 = ${binByte(w2)} ⊕ ${binByte(w1)} = <strong>${binByte(w3)} (${hexByte(w3)})</strong>
          </div>
        </div>

        <div class="subsection">
          <h4>Perhitungan w4 dan w5</h4>
          <div class="formula-box">
            RotNib(w3): ${binByte(second.input)} → ${binByte(second.rot)} (${hexByte(second.input)} → ${hexByte(second.rot)})<br />
            SubNib: ${binByte(second.rot)} → ${binByte(second.sub)} (${hexByte(second.rot)} → ${hexByte(second.sub)})<br />
            g(w3) = ${binByte(second.sub)} ⊕ ${binByte(second.rcon)} = ${binByte(second.g)}<br />
            w4 = ${binByte(w2)} ⊕ ${binByte(second.g)} = <strong>${binByte(w4)} (${hexByte(w4)})</strong><br />
            w5 = ${binByte(w4)} ⊕ ${binByte(w3)} = <strong>${binByte(w5)} (${hexByte(w5)})</strong>
          </div>
        </div>

        <div class="subsection">
          <h4>Round key yang dihasilkan</h4>
          <div class="operation-grid">
            ${stateMatrixHTML(wordToState(k0), `K0 = w0 || w1 (${hexWord(k0)})`)}
            ${stateMatrixHTML(wordToState(k1), `K1 = w2 || w3 (${hexWord(k1)})`)}
            ${stateMatrixHTML(wordToState(k2), `K2 = w4 || w5 (${hexWord(k2)})`)}
          </div>
        </div>
      </div>
    </details>
  `;
}

function renderReferenceTable(box, idLabel) {
  const inputs = Array.from({ length: 16 }, (_, i) => hexNibble(i));
  return `
    <table class="reference-table" aria-label="${idLabel}">
      <thead><tr><th>Input</th>${inputs.map((v) => `<th>${v}</th>`).join("")}</tr></thead>
      <tbody><tr><th>Output</th>${box.map((v) => `<td>${hexNibble(v)}</td>`).join("")}</tr></tbody>
    </table>
  `;
}

function renderResult(result) {
  const isEncrypt = result.mode === "encrypt";
  const outputName = isEncrypt ? "Ciphertext" : "Plaintext";

  elements.modeBadge.textContent = isEncrypt ? "Enkripsi" : "Dekripsi";
  elements.binaryResultLabel.textContent = `${outputName} biner`;
  elements.hexResultLabel.textContent = `${outputName} heksadesimal`;
  elements.binaryResult.textContent = groupedBinary(result.output);
  elements.hexResult.textContent = hexWord(result.output);
  elements.resultSummary.innerHTML = `
    <strong>${isEncrypt ? "Enkripsi selesai." : "Dekripsi selesai."}</strong>
    Input <span class="mono">${hexWord(result.input)}</span> dengan kunci
    <span class="mono">${hexWord(result.key)}</span> menghasilkan
    <span class="mono">${hexWord(result.output)}</span>.
  `;

  elements.stepsContainer.innerHTML = renderKeyExpansion(result.expansion, result.key)
    + result.steps.map(renderStepCard).join("");

  elements.resultPanel.classList.remove("hidden");
  elements.stepsPanel.classList.remove("hidden");
  elements.resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function validateBinaryField(inputElement, errorElement, label) {
  const normalized = normalizeBinary(inputElement.value);
  let message = "";

  if (!normalized) {
    message = `${label} wajib diisi.`;
  } else if (!/^[01]+$/.test(normalized)) {
    message = `${label} hanya boleh berisi angka 0 dan 1.`;
  } else if (normalized.length !== 16) {
    message = `${label} harus tepat 16-bit; saat ini ${normalized.length} bit.`;
  }

  errorElement.textContent = message;
  inputElement.classList.toggle("invalid", Boolean(message));
  inputElement.setAttribute("aria-invalid", String(Boolean(message)));
  return { valid: !message, normalized };
}

function selectedMode() {
  return document.querySelector('input[name="mode"]:checked').value;
}

function updateModeUI() {
  const decrypt = selectedMode() === "decrypt";
  elements.dataLabel.textContent = decrypt ? "Ciphertext 16-bit" : "Plaintext 16-bit";
  elements.dataHelp.textContent = decrypt
    ? "Masukkan ciphertext 16-bit yang akan dikembalikan menjadi plaintext."
    : "Masukkan plaintext tepat 16-bit. Spasi antarnibble diperbolehkan.";
  updateExamplePreview();
}

function updateCounts() {
  const dataLength = normalizeBinary(elements.dataInput.value).length;
  const keyLength = normalizeBinary(elements.keyInput.value).length;
  elements.dataCount.textContent = `${dataLength}/16 bit`;
  elements.keyCount.textContent = `${keyLength}/16 bit`;
}

function getSelectedSample() {
  return SAMPLE_CASES[0];
}

function updateExamplePreview() {
  const sample = getSelectedSample();
  const decrypt = selectedMode() === "decrypt";
  const activeInputLabel = decrypt ? "Ciphertext yang akan diisikan" : "Plaintext yang akan diisikan";
  const activeInputValue = decrypt ? sample.ciphertext : sample.plaintext;

  elements.examplePreview.innerHTML = `
    <div class="example-preview__item example-preview__active">
      <span>${activeInputLabel}</span>
      <strong class="mono">${groupedBinary(activeInputValue)}</strong>
      <small>0x${hexWord(activeInputValue)}</small>
    </div>
    <div class="example-preview__item">
      <span>Kunci</span>
      <strong class="mono">${groupedBinary(sample.key)}</strong>
      <small>0x${hexWord(sample.key)}</small>
    </div>
    <div class="example-preview__item">
      <span>${decrypt ? "Plaintext yang diharapkan" : "Ciphertext yang diharapkan"}</span>
      <strong class="mono">${groupedBinary(decrypt ? sample.plaintext : sample.ciphertext)}</strong>
      <small>0x${hexWord(decrypt ? sample.plaintext : sample.ciphertext)}</small>
    </div>
  `;
}

function clearInputErrors() {
  elements.dataError.textContent = "";
  elements.keyError.textContent = "";
  elements.dataInput.classList.remove("invalid");
  elements.keyInput.classList.remove("invalid");
  elements.dataInput.setAttribute("aria-invalid", "false");
  elements.keyInput.setAttribute("aria-invalid", "false");
}

function fillSelectedExample(runImmediately = false) {
  const sample = getSelectedSample();
  const decrypt = selectedMode() === "decrypt";
  const inputValue = decrypt ? sample.ciphertext : sample.plaintext;

  elements.dataInput.value = groupedBinary(inputValue);
  elements.keyInput.value = groupedBinary(sample.key);
  updateCounts();
  clearInputErrors();

  showToast(`${sample.name} berhasil diisikan untuk mode ${decrypt ? "dekripsi" : "enkripsi"}.`);

  if (runImmediately) {
    requestAnimationFrame(() => elements.form.requestSubmit());
  } else {
    elements.dataInput.focus();
  }
}

let toastTimer;
function showToast(message) {
  clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.add("show");
  toastTimer = setTimeout(() => elements.toast.classList.remove("show"), 1700);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast("Hasil berhasil disalin.");
  } catch {
    showToast("Tidak dapat menyalin otomatis.");
  }
}

function resetOutput() {
  elements.resultPanel.classList.add("hidden");
  elements.stepsPanel.classList.add("hidden");
  elements.stepsContainer.innerHTML = "";
  elements.dataError.textContent = "";
  elements.keyError.textContent = "";
  elements.dataInput.classList.remove("invalid");
  elements.keyInput.classList.remove("invalid");
  setTimeout(() => {
    updateModeUI();
    updateCounts();
  }, 0);
}

// ============================================================
// Event handlers
// ============================================================
elements.form.addEventListener("submit", (event) => {
  event.preventDefault();

  const mode = selectedMode();
  const dataValidation = validateBinaryField(
    elements.dataInput,
    elements.dataError,
    mode === "encrypt" ? "Plaintext" : "Ciphertext",
  );
  const keyValidation = validateBinaryField(elements.keyInput, elements.keyError, "Kunci");

  if (!dataValidation.valid || !keyValidation.valid) {
    const firstInvalid = !dataValidation.valid ? elements.dataInput : elements.keyInput;
    firstInvalid.focus();
    return;
  }

  const data = parseInt(dataValidation.normalized, 2);
  const key = parseInt(keyValidation.normalized, 2);
  const result = mode === "encrypt" ? encryptSAES(data, key) : decryptSAES(data, key);
  renderResult(result);
});

elements.form.addEventListener("reset", resetOutput);

elements.dataInput.addEventListener("input", updateCounts);
elements.keyInput.addEventListener("input", updateCounts);

document.querySelectorAll('input[name="mode"]').forEach((radio) => {
  radio.addEventListener("change", updateModeUI);
});

elements.fillExampleButton.addEventListener("click", () => fillSelectedExample(false));
elements.runExampleButton.addEventListener("click", () => fillSelectedExample(true));

elements.expandAllButton.addEventListener("click", () => {
  document.querySelectorAll("#stepsContainer details.step-card").forEach((item) => { item.open = true; });
});

elements.collapseAllButton.addEventListener("click", () => {
  document.querySelectorAll("#stepsContainer details.step-card").forEach((item) => { item.open = false; });
});

elements.copyBinaryButton.addEventListener("click", () => copyText(elements.binaryResult.textContent.replace(/\s/g, "")));
elements.copyHexButton.addEventListener("click", () => copyText(elements.hexResult.textContent));

function readSavedTheme() {
  try {
    return localStorage.getItem("ruangsandi-theme");
  } catch {
    return null;
  }
}

function saveTheme(theme) {
  try {
    localStorage.setItem("ruangsandi-theme", theme);
  } catch {
    // Aplikasi tetap berfungsi ketika penyimpanan browser dibatasi.
  }
}

elements.themeButton.addEventListener("click", () => {
  const current = document.documentElement.dataset.theme;
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  saveTheme(next);
});

// ============================================================
// Inisialisasi dan self-test
// ============================================================
function initialize() {
  const savedTheme = readSavedTheme();
  if (savedTheme) document.documentElement.dataset.theme = savedTheme;

  document.getElementById("sboxTable").innerHTML = renderReferenceTable(SBOX, "Tabel S-Box S-AES");
  document.getElementById("inverseSboxTable").innerHTML = renderReferenceTable(INV_SBOX, "Tabel Inverse S-Box S-AES");
  updateModeUI();
  updateCounts();

  // Test vector tunggal RuangSandi: P=CAFE, K=BEEF → C=2855.
  const encrypted = encryptSAES(0xCAFE, 0xBEEF).output;
  const decrypted = decryptSAES(0x2855, 0xBEEF).output;
  console.assert(encrypted === 0x2855, `Self-test enkripsi gagal: ${hexWord(encrypted)}`);
  console.assert(decrypted === 0xCAFE, `Self-test dekripsi gagal: ${hexWord(decrypted)}`);

  SAMPLE_CASES.forEach((sample) => {
    const sampleCiphertext = encryptSAES(sample.plaintext, sample.key).output;
    const samplePlaintext = decryptSAES(sample.ciphertext, sample.key).output;
    console.assert(sampleCiphertext === sample.ciphertext, `Ciphertext ${sample.name} tidak sesuai.`);
    console.assert(samplePlaintext === sample.plaintext, `Dekripsi ${sample.name} tidak sesuai.`);
  });

  // Memastikan matriks invers benar pada seluruh nibble pasangan satu kolom.
  for (let a = 0; a < 16; a += 1) {
    for (let b = 0; b < 16; b += 1) {
      const mixed = mixColumns([a, b, 0, 0]);
      const restored = invMixColumns(mixed);
      console.assert(restored[0] === a && restored[1] === b, "Self-test matriks invers gagal");
    }
  }
}

initialize();

// Diekspor ke window agar mudah diuji melalui DevTools bila diperlukan.
window.SAES = {
  encryptSAES,
  decryptSAES,
  keyExpansion,
  gfAdd,
  gfMul,
  wordToState,
  stateToWord,
};
