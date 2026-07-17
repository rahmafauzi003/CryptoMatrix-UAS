'use strict';

/**
 * DES Visual Lab
 * Implementasi Data Encryption Standard (DES) 64-bit tanpa library kriptografi pihak ketiga.
 * Fitur utama: input hex/biner, enkripsi/dekripsi, key schedule 16 subkunci,
 * 16 round Feistel lengkap, visualisasi 8 S-Box, output hex+biner, reset, dan round-trip test.
 */

const DES_TABLES = {
  IP: [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
  ],
  IP_INV: [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
  ],
  PC1: [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
  ],
  PC2: [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
  ],
  E: [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
  ],
  P: [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
  ],
  SHIFTS: [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1],
  SBOXES: [
    [
      [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
      [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
      [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
      [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
      [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
      [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
      [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
      [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
  ]
};

const SAMPLE = {
  plaintextHex: '6A0F3C9D12B7E845',
  keyHex: '4D7A1C8E9B2036F5',
  ciphertextHex: '8271C1AAE8819F0B',
  plaintextBin: '0110101000001111001111001001110100010010101101111110100001000101',
  keyBin: '0100110101111010000111001000111010011011001000000011011011110101',
  ciphertextBin: '1000001001110001110000011010101011101000100000011001111100001011'
};

let lastRun = null;

function cleanInput(value) {
  return String(value || '')
    .replace(/^0x/i, '')
    .replace(/[\s_\-]/g, '')
    .toUpperCase();
}

function hexToBin(hex) {
  const cleaned = cleanInput(hex);
  return cleaned
    .split('')
    .map((char) => parseInt(char, 16).toString(2).padStart(4, '0'))
    .join('');
}

function binToHex(bin) {
  return (bin.match(/.{1,4}/g) || [])
    .map((chunk) => parseInt(chunk, 2).toString(16).toUpperCase())
    .join('');
}

function groupBits(bin, size = 4) {
  return (bin.match(new RegExp(`.{1,${size}}`, 'g')) || []).join(' ');
}

function normalizeBlock(value, selectedFormat, fieldName) {
  const cleaned = cleanInput(value);
  if (!cleaned) throw new Error(`${fieldName} belum diisi.`);

  const isBin64 = /^[01]{64}$/.test(cleaned);
  const isHex16 = /^[0-9A-F]{16}$/.test(cleaned);

  if (selectedFormat === 'bin') {
    if (!/^[01]+$/.test(cleaned)) throw new Error(`${fieldName} mode biner hanya boleh berisi 0 dan 1.`);
    if (cleaned.length !== 64) throw new Error(`${fieldName} biner harus tepat 64-bit.`);
    return { bits: cleaned, format: 'Biner 64-bit', raw: cleaned, hex: binToHex(cleaned) };
  }

  if (selectedFormat === 'hex') {
    if (!/^[0-9A-F]+$/.test(cleaned)) throw new Error(`${fieldName} mode heksadesimal hanya boleh berisi 0-9 atau A-F.`);
    if (cleaned.length !== 16) throw new Error(`${fieldName} heksadesimal harus tepat 16 digit atau 64-bit.`);
    return { bits: hexToBin(cleaned), format: 'Heksadesimal 16 digit', raw: cleaned, hex: cleaned };
  }

  if (isBin64) return { bits: cleaned, format: 'Biner 64-bit', raw: cleaned, hex: binToHex(cleaned) };
  if (isHex16) return { bits: hexToBin(cleaned), format: 'Heksadesimal 16 digit', raw: cleaned, hex: cleaned };

  throw new Error(`${fieldName} tidak valid. Gunakan 16 digit heksadesimal atau 64 digit biner.`);
}

function permute(bits, table) {
  return table.map((position) => bits[position - 1]).join('');
}

function leftShift(bits, count) {
  return bits.slice(count) + bits.slice(0, count);
}

function xorBits(a, b) {
  if (a.length !== b.length) throw new Error('Panjang bit untuk XOR tidak sama.');
  let result = '';
  for (let i = 0; i < a.length; i += 1) result += a[i] === b[i] ? '0' : '1';
  return result;
}

function splitEvery(bits, size) {
  return bits.match(new RegExp(`.{1,${size}}`, 'g')) || [];
}

function sBoxSubstitution(input48) {
  const chunks = splitEvery(input48, 6);
  let output = '';
  const lookups = chunks.map((chunk, index) => {
    const rowBits = chunk[0] + chunk[5];
    const colBits = chunk.slice(1, 5);
    const row = parseInt(rowBits, 2);
    const col = parseInt(colBits, 2);
    const value = DES_TABLES.SBOXES[index][row][col];
    const out = value.toString(2).padStart(4, '0');
    output += out;
    return {
      sbox: `S${index + 1}`,
      input: chunk,
      rowBits,
      row,
      colBits,
      col,
      value,
      output: out
    };
  });
  return { output, lookups };
}

function feistelFunction(right32, subkey48) {
  const expansion = permute(right32, DES_TABLES.E);
  const xor = xorBits(expansion, subkey48);
  const sbox = sBoxSubstitution(xor);
  const permutation = permute(sbox.output, DES_TABLES.P);
  return {
    expansion,
    xor,
    sboxOutput: sbox.output,
    sboxLookups: sbox.lookups,
    permutation,
    output: permutation
  };
}

function generateKeys(key64) {
  const pc1 = permute(key64, DES_TABLES.PC1);
  let c = pc1.slice(0, 28);
  let d = pc1.slice(28);
  const rounds = [];

  DES_TABLES.SHIFTS.forEach((shift, index) => {
    c = leftShift(c, shift);
    d = leftShift(d, shift);
    const combined = c + d;
    const subkey = permute(combined, DES_TABLES.PC2);
    rounds.push({
      round: index + 1,
      shift,
      c,
      d,
      combined,
      subkey,
      subkeyHex: binToHex(subkey)
    });
  });

  return {
    pc1,
    pc1Hex: binToHex(pc1),
    c0: pc1.slice(0, 28),
    d0: pc1.slice(28),
    rounds,
    subkeys: rounds.map((item) => item.subkey)
  };
}

function runDes(input64, key64, mode = 'encrypt') {
  const keySchedule = generateKeys(key64);
  const roundKeys = mode === 'decrypt'
    ? [...keySchedule.subkeys].reverse()
    : [...keySchedule.subkeys];

  const ip = permute(input64, DES_TABLES.IP);
  let left = ip.slice(0, 32);
  let right = ip.slice(32);
  const rounds = [];

  for (let i = 0; i < 16; i += 1) {
    const previousLeft = left;
    const previousRight = right;
    const keyIndex = mode === 'decrypt' ? 16 - i : i + 1;
    const subkey = roundKeys[i];
    const f = feistelFunction(previousRight, subkey);
    const nextLeft = previousRight; // swap: L_i mengambil R_(i-1)
    const nextRight = xorBits(previousLeft, f.output);

    rounds.push({
      round: i + 1,
      keyName: `K${keyIndex}`,
      subkey,
      subkeyHex: binToHex(subkey),
      previousLeft,
      previousRight,
      expansion: f.expansion,
      xorWithKey: f.xor,
      sboxOutput: f.sboxOutput,
      sboxLookups: f.sboxLookups,
      permutationP: f.permutation,
      fOutput: f.output,
      nextLeft,
      nextRight,
      swapDescription: `L${i + 1} = R${i}, R${i + 1} = L${i} XOR F(R${i}, ${mode === 'decrypt' ? `K${keyIndex}` : `K${keyIndex}`})`
    });

    left = nextLeft;
    right = nextRight;
  }

  const preoutput = right + left;
  const output = permute(preoutput, DES_TABLES.IP_INV);

  return {
    mode,
    input64,
    key64,
    keySchedule,
    ip,
    ipHex: binToHex(ip),
    l0: ip.slice(0, 32),
    r0: ip.slice(32),
    rounds,
    l16: left,
    r16: right,
    preoutput,
    preoutputHex: binToHex(preoutput),
    output,
    outputHex: binToHex(output)
  };
}

function $(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const element = $(id);
  if (element) element.textContent = value;
}

function renderBits(element, bits, groupEvery = 4) {
  if (!element) return;
  element.innerHTML = '';
  bits.split('').forEach((bit, index) => {
    const cell = document.createElement('span');
    cell.className = 'bit';
    if ((index + 1) % groupEvery === 0) cell.classList.add('group-end');
    cell.textContent = bit;
    cell.dataset.index = index + 1;
    element.appendChild(cell);
  });
}

function renderInlineBits(bits, groupEvery = 4) {
  return bits.split('').map((bit, index) => {
    const group = (index + 1) % groupEvery === 0 ? ' group-end' : '';
    return `<span class="mini-bit${group}" data-index="${index + 1}">${bit}</span>`;
  }).join('');
}

function showError(message) {
  const box = $('errorBox');
  box.textContent = message;
  box.hidden = false;
}

function clearError() {
  const box = $('errorBox');
  box.textContent = '';
  box.hidden = true;
}

function setStatus(message, type = 'neutral') {
  const status = $('statusLine');
  status.textContent = message;
  status.className = `status-line ${type}`;
}

function renderKeySchedule(schedule) {
  setText('pc1Hex', schedule.pc1Hex);
  renderBits($('pc1Bits'), schedule.pc1, 7);
  renderBits($('c0Bits'), schedule.c0, 7);
  renderBits($('d0Bits'), schedule.d0, 7);

  const tbody = document.querySelector('#subkeyTable tbody');
  tbody.innerHTML = '';
  schedule.rounds.forEach((item) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="pill">K${item.round}</span></td>
      <td>${item.shift}</td>
      <td><code>${groupBits(item.c, 7)}</code></td>
      <td><code>${groupBits(item.d, 7)}</code></td>
      <td><code>${groupBits(item.subkey, 6)}</code></td>
      <td><code>${item.subkeyHex}</code></td>
    `;
    tbody.appendChild(row);
  });
}

function kv(label, value) {
  return `<div class="kv"><span>${label}</span><code>${value}</code></div>`;
}

function renderSBoxCards(lookups) {
  return lookups.map((item) => `
    <div class="sbox-card">
      <div class="sbox-title">${item.sbox}</div>
      <div class="sbox-row"><span>Input 6-bit</span><code>${item.input}</code></div>
      <div class="sbox-row"><span>Baris</span><code>${item.rowBits}<sub>2</sub> = ${item.row}</code></div>
      <div class="sbox-row"><span>Kolom</span><code>${item.colBits}<sub>2</sub> = ${item.col}</code></div>
      <div class="sbox-row"><span>Nilai</span><code>${item.value}</code></div>
      <div class="sbox-row"><span>Output</span><code>${item.output}</code></div>
    </div>
  `).join('');
}

function renderRounds(rounds) {
  const container = $('roundsContainer');
  container.innerHTML = '';

  rounds.forEach((round, index) => {
    const card = document.createElement('article');
    card.className = `round-card ${index === 0 ? 'open' : ''}`;
    card.innerHTML = `
      <button type="button" class="round-header" aria-expanded="${index === 0}">
        <span class="round-no">Round ${round.round}</span>
        <strong>${round.keyName} <em>${round.subkeyHex}</em></strong>
        <span class="round-state">L${round.round}=${binToHex(round.nextLeft)} · R${round.round}=${binToHex(round.nextRight)}</span>
      </button>
      <div class="round-body">
        <div class="formula-box">
          <b>Swap Feistel:</b> ${round.swapDescription}<br>
          <span>Artinya L baru diambil dari R sebelumnya, sedangkan R baru diperoleh dari XOR L sebelumnya dengan output fungsi F.</span>
        </div>
        <div class="round-summary">
          ${kv(`L${round.round - 1}`, groupBits(round.previousLeft, 4))}
          ${kv(`R${round.round - 1}`, groupBits(round.previousRight, 4))}
          ${kv(`${round.keyName} hasil PC-2`, groupBits(round.subkey, 6))}
          ${kv('Ekspansi E(R)', groupBits(round.expansion, 6))}
          ${kv('XOR E(R) dengan subkunci', groupBits(round.xorWithKey, 6))}
          ${kv('Output 8 S-Box', groupBits(round.sboxOutput, 4))}
          ${kv('Permutasi P / F Output', groupBits(round.fOutput, 4))}
          ${kv(`Hasil Round ${round.round}`, `L${round.round}: ${groupBits(round.nextLeft, 4)} | R${round.round}: ${groupBits(round.nextRight, 4)}`)}
        </div>
        <h4>Visualisasi Lookup 8 S-Box</h4>
        <div class="sbox-grid">${renderSBoxCards(round.sboxLookups)}</div>
      </div>
    `;
    container.appendChild(card);
  });

  container.querySelectorAll('.round-header').forEach((button) => {
    button.addEventListener('click', () => {
      const card = button.closest('.round-card');
      card.classList.toggle('open');
      button.setAttribute('aria-expanded', card.classList.contains('open'));
    });
  });
}

function renderDesResult(result, inputMeta, keyMeta) {
  $('resultSection').hidden = false;
  $('keyScheduleSection').hidden = false;
  $('processSection').hidden = false;
  $('roundTripBtn').disabled = false;

  setText('detectedInfo', `${inputMeta.format} untuk pesan · ${keyMeta.format} untuk kunci`);
  setText('inputHexPreview', inputMeta.hex);
  setText('keyHexPreview', keyMeta.hex);
  setText('resultTitle', result.mode === 'encrypt' ? 'Ciphertext' : 'Plaintext');
  setText('hexOutput', result.outputHex);
  renderBits($('binaryOutput'), result.output, 4);

  renderKeySchedule(result.keySchedule);
  setText('ipHex', result.ipHex);
  renderBits($('ipBits'), result.ip, 4);
  renderBits($('l0Bits'), result.l0, 4);
  renderBits($('r0Bits'), result.r0, 4);
  renderRounds(result.rounds);
  setText('preoutputHex', result.preoutputHex);
  renderBits($('preoutputBits'), result.preoutput, 4);
  renderBits($('finalBits'), result.output, 4);

  const verify = $('roundTripResult');
  verify.className = 'verify-box';
  verify.innerHTML = 'Belum dijalankan.';
  setStatus('Perhitungan DES berhasil. Semua langkah sudah ditampilkan.', 'ok');
}

function getSelectedFormat() {
  return $('inputFormat').value;
}


function inferLimit(cleaned, selectedFormat) {
  if (selectedFormat === 'bin') return { max: 64, unit: 'bit biner' };
  if (selectedFormat === 'hex') return { max: 16, unit: 'digit hex' };
  if (/^[01]*$/.test(cleaned)) return { max: 64, unit: 'bit biner / auto' };
  return { max: 16, unit: 'digit hex / auto' };
}

function sanitizeLimitedValue(value, selectedFormat) {
  let cleaned = cleanInput(value);

  if (selectedFormat === 'bin') {
    return cleaned.replace(/[^01]/g, '').slice(0, 64);
  }

  if (selectedFormat === 'hex') {
    return cleaned.replace(/[^0-9A-F]/g, '').slice(0, 16);
  }

  cleaned = cleaned.replace(/[^0-9A-F]/g, '');
  if (/^[01]*$/.test(cleaned)) return cleaned.slice(0, 64);
  return cleaned.slice(0, 16);
}

function updateCounter(inputId, counterId) {
  const input = $(inputId);
  const counter = $(counterId);
  if (!input || !counter) return;

  const selectedFormat = getSelectedFormat();
  const limited = sanitizeLimitedValue(input.value, selectedFormat);
  if (input.value !== limited) input.value = limited;

  const cleaned = cleanInput(input.value);
  const limit = inferLimit(cleaned, selectedFormat);
  counter.textContent = `${cleaned.length}/${limit.max} ${limit.unit}`;
  counter.className = `input-counter ${cleaned.length === limit.max ? 'full' : ''}`;
}

function updateInputCounters() {
  updateCounter('messageInput', 'messageCounter');
  updateCounter('keyInput', 'keyCounter');
}

function clearRenderedResults() {
  setText('detectedInfo', '-');
  setText('inputHexPreview', '-');
  setText('keyHexPreview', '-');
  setText('resultTitle', 'Ciphertext');
  setText('hexOutput', '-');
  setText('pc1Hex', '-');
  setText('ipHex', '-');
  setText('preoutputHex', '-');

  [
    'binaryOutput', 'pc1Bits', 'c0Bits', 'd0Bits', 'ipBits',
    'l0Bits', 'r0Bits', 'preoutputBits', 'finalBits', 'roundsContainer'
  ].forEach((id) => {
    const element = $(id);
    if (element) element.innerHTML = '';
  });

  const tbody = document.querySelector('#subkeyTable tbody');
  if (tbody) tbody.innerHTML = '';

  const verify = $('roundTripResult');
  if (verify) {
    verify.className = 'verify-box';
    verify.innerHTML = 'Belum dijalankan.';
  }
}

function processInput() {
  clearError();
  updateInputCounters();
  try {
    const selectedFormat = getSelectedFormat();
    const mode = $('mode').value;
    const inputMeta = normalizeBlock($('messageInput').value, selectedFormat, 'Plaintext/ciphertext');
    const keyMeta = normalizeBlock($('keyInput').value, selectedFormat, 'Kunci DES');
    const result = runDes(inputMeta.bits, keyMeta.bits, mode);
    lastRun = { ...result, inputMeta, keyMeta };
    renderDesResult(result, inputMeta, keyMeta);
    $('resultSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    setStatus('Input belum valid. Periksa kembali panjang dan format data.', 'fail');
    showError(error.message);
  }
}

function runRoundTrip() {
  if (!lastRun) return;
  const reverseMode = lastRun.mode === 'encrypt' ? 'decrypt' : 'encrypt';
  const reversed = runDes(lastRun.output, lastRun.key64, reverseMode);
  const ok = reversed.output === lastRun.input64;
  const box = $('roundTripResult');
  box.className = `verify-box ${ok ? 'ok' : 'fail'}`;
  box.innerHTML = ok
    ? `Berhasil. Hasil ${reverseMode === 'decrypt' ? 'dekripsi' : 'enkripsi'} kembali ke input awal.<br><code>${binToHex(reversed.output)}</code><div class="inline-bits">${renderInlineBits(reversed.output, 4)}</div>`
    : `Gagal. Hasil tidak sama dengan input awal.<br><code>${binToHex(reversed.output)}</code>`;
}

function resetAll() {
  $('messageInput').value = '';
  $('keyInput').value = '';
  $('inputFormat').value = 'bin';
  $('mode').value = 'encrypt';
  $('inputLabel').textContent = 'Plaintext / Ciphertext 64-bit';
  $('resultSection').hidden = true;
  $('keyScheduleSection').hidden = true;
  $('processSection').hidden = true;
  $('roundTripBtn').disabled = true;
  clearRenderedResults();
  updateInputCounters();
  clearError();
  setStatus('Semua input dan hasil sudah dibersihkan.', 'neutral');
  lastRun = null;
}

function fillSampleHexEncrypt() {
  $('inputFormat').value = 'hex';
  $('mode').value = 'encrypt';
  $('messageInput').value = SAMPLE.plaintextHex;
  $('keyInput').value = SAMPLE.keyHex;
  $('inputLabel').textContent = 'Plaintext 64-bit';
  updateInputCounters();
  clearError();
  setStatus('Contoh enkripsi hex sudah diisi.', 'neutral');
}

function fillSampleBinEncrypt() {
  $('inputFormat').value = 'bin';
  $('mode').value = 'encrypt';
  $('messageInput').value = SAMPLE.plaintextBin;
  $('keyInput').value = SAMPLE.keyBin;
  $('inputLabel').textContent = 'Plaintext 64-bit';
  updateInputCounters();
  clearError();
  setStatus('Contoh enkripsi biner 64-bit sudah diisi.', 'neutral');
}

function fillSampleHexDecrypt() {
  $('inputFormat').value = 'hex';
  $('mode').value = 'decrypt';
  $('messageInput').value = SAMPLE.ciphertextHex;
  $('keyInput').value = SAMPLE.keyHex;
  $('inputLabel').textContent = 'Ciphertext 64-bit';
  updateInputCounters();
  clearError();
  setStatus('Contoh dekripsi hex sudah diisi.', 'neutral');
}

function fillSampleBinDecrypt() {
  $('inputFormat').value = 'bin';
  $('mode').value = 'decrypt';
  $('messageInput').value = SAMPLE.ciphertextBin;
  $('keyInput').value = SAMPLE.keyBin;
  $('inputLabel').textContent = 'Ciphertext 64-bit';
  updateInputCounters();
  clearError();
  setStatus('Contoh dekripsi biner 64-bit sudah diisi.', 'neutral');
}

async function copyOutput() {
  if (!lastRun) return;
  const text = `Hex: ${lastRun.outputHex}\nBiner: ${lastRun.output}`;
  try {
    await navigator.clipboard.writeText(text);
    setStatus('Output berhasil disalin.', 'ok');
  } catch (_) {
    setStatus('Browser tidak mengizinkan salin otomatis. Salin output secara manual.', 'fail');
  }
}

function runSelfTest() {
  const encrypted = runDes(hexToBin(SAMPLE.plaintextHex), hexToBin(SAMPLE.keyHex), 'encrypt');
  const decrypted = runDes(hexToBin(SAMPLE.ciphertextHex), hexToBin(SAMPLE.keyHex), 'decrypt');
  const ok = encrypted.outputHex === SAMPLE.ciphertextHex && decrypted.outputHex === SAMPLE.plaintextHex;
  setStatus(ok
    ? `Self-test valid: ${SAMPLE.plaintextHex} → ${SAMPLE.ciphertextHex} → ${SAMPLE.plaintextHex}`
    : 'Self-test gagal. Periksa implementasi DES.', ok ? 'ok' : 'fail');
}

function bindUi() {
  $('processBtn').addEventListener('click', processInput);
  $('roundTripBtn').addEventListener('click', runRoundTrip);
  $('resetBtn').addEventListener('click', resetAll);
  $('copyOutputBtn').addEventListener('click', copyOutput);
  $('selfTestBtn').addEventListener('click', runSelfTest);
  $('fillSampleHexBtn').addEventListener('click', fillSampleHexEncrypt);
  $('fillSampleBinBtn').addEventListener('click', fillSampleBinEncrypt);
  $('fillDecryptHexBtn').addEventListener('click', fillSampleHexDecrypt);
  $('fillDecryptBinBtn').addEventListener('click', fillSampleBinDecrypt);

  $('mode').addEventListener('change', (event) => {
    $('inputLabel').textContent = event.target.value === 'encrypt'
      ? 'Plaintext 64-bit'
      : 'Ciphertext 64-bit';
  });

  $('inputFormat').addEventListener('change', updateInputCounters);
  $('messageInput').addEventListener('input', updateInputCounters);
  $('keyInput').addEventListener('input', updateInputCounters);
  $('messageInput').addEventListener('paste', () => setTimeout(updateInputCounters, 0));
  $('keyInput').addEventListener('paste', () => setTimeout(updateInputCounters, 0));

  document.querySelectorAll('.toggle-btn').forEach((button) => {
    button.addEventListener('click', () => {
      const target = $(button.dataset.target);
      const isHidden = !target.hidden;
      target.hidden = isHidden;
      button.textContent = isHidden ? 'Tampilkan' : 'Sembunyikan';
    });
  });

  updateInputCounters();
  setStatus('Quantum Trace siap menjalankan simulasi DES 64-bit.', 'neutral');
}

if (typeof window !== 'undefined') {
  window.DESCore = { runDes, generateKeys, hexToBin, binToHex, SAMPLE };
  document.addEventListener('DOMContentLoaded', bindUi);
}

if (typeof module !== 'undefined') {
  module.exports = { runDes, generateKeys, hexToBin, binToHex, SAMPLE, normalizeBlock };
}
