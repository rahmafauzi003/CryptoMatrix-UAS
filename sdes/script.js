const TABLES = {
  P10: [3, 5, 2, 7, 4, 10, 1, 9, 8, 6],
  P8: [6, 3, 7, 4, 8, 5, 10, 9],
  IP: [2, 6, 3, 1, 4, 8, 5, 7],
  IP_INV: [4, 1, 3, 5, 7, 2, 8, 6],
  EP: [4, 1, 2, 3, 2, 3, 4, 1],
  P4: [2, 4, 3, 1]
};

const S0 = [
  [1, 0, 3, 2],
  [3, 2, 1, 0],
  [0, 2, 1, 3],
  [3, 1, 3, 2]
];

const S1 = [
  [0, 1, 2, 3],
  [2, 0, 1, 3],
  [3, 0, 1, 0],
  [2, 1, 0, 3]
];

const form = document.getElementById("sdesForm");
const inputBitsEl = document.getElementById("inputBits");
const keyBitsEl = document.getElementById("keyBits");
const errorBox = document.getElementById("errorBox");
const resultSection = document.getElementById("resultSection");
const resultBitsEl = document.getElementById("resultBits");
const resultLabel = document.getElementById("resultLabel");
const resultDescription = document.getElementById("resultDescription");
const solutionSection = document.getElementById("solutionSection");
const solutionBox = document.getElementById("solutionBox");
const solutionContent = document.getElementById("solutionContent");
const toggleSolution = document.getElementById("toggleSolution");
const resetBtn = document.getElementById("resetBtn");
const exampleBtn = document.getElementById("exampleBtn");

let latestResult = "";

function onlyBinary(value) {
  return /^[01]+$/.test(value);
}

function getMode() {
  return document.querySelector('input[name="mode"]:checked').value;
}

function setMode(mode) {
  const selected = document.querySelector(`input[name="mode"][value="${mode}"]`);
  if (selected) selected.checked = true;
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function hideError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

function validateInput(inputBits, keyBits) {
  if (inputBits.length !== 8 || !onlyBinary(inputBits)) {
    showError("Input plaintext/ciphertext harus berupa bilangan biner 8-bit. Contoh: 00101000");
    return false;
  }

  if (keyBits.length !== 10 || !onlyBinary(keyBits)) {
    showError("Kunci harus berupa bilangan biner 10-bit. Contoh: 1100011110");
    return false;
  }

  hideError();
  return true;
}

function permute(bits, table) {
  return table.map((position) => bits[position - 1]).join("");
}

function leftShift(bits, amount) {
  return bits.slice(amount) + bits.slice(0, amount);
}

function xor(bitsA, bitsB) {
  let result = "";
  for (let i = 0; i < bitsA.length; i++) {
    result += bitsA[i] === bitsB[i] ? "0" : "1";
  }
  return result;
}

function splitBits(bits, size) {
  return [bits.slice(0, size), bits.slice(size)];
}

function sBoxLookup(bits4, sBox) {
  const rowBinary = bits4[0] + bits4[3];
  const colBinary = bits4[1] + bits4[2];
  const row = parseInt(rowBinary, 2);
  const col = parseInt(colBinary, 2);
  const decimalValue = sBox[row][col];
  const binaryValue = decimalValue.toString(2).padStart(2, "0");

  return { rowBinary, colBinary, row, col, decimalValue, binaryValue };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function bitsWithSpace(bits, group = 4) {
  return bits.match(new RegExp(`.{1,${group}}`, "g")).join(" ");
}

function outputCells(bits) {
  return bits
    .split("")
    .map((bit, index) => `
      <span class="output-cell">
        <span class="idx">${index + 1}</span>
        <span class="bit">${bit}</span>
      </span>
    `)
    .join("");
}

function smallBitCells(bits) {
  return bits
    .split("")
    .map((bit, index) => `
      <span class="bit-cell">
        <span class="idx">${index + 1}</span>
        <span class="bit">${bit}</span>
      </span>
    `)
    .join("");
}

function bitChar(bit) {
  if (bit === undefined || bit === null || bit === "") return "";
  return `<span class="bit-char">${escapeHtml(bit)}</span>`;
}

function calculationTable(rows, bitCount = null) {
  const maxLen = bitCount || Math.max(...rows.map((row) => String(row.bits || "").length));
  const headerCells = Array.from({ length: maxLen }, (_, index) => `<th>${index + 1}</th>`).join("");

  const bodyRows = rows.map((row) => {
    const bits = String(row.bits || "");
    const cells = Array.from({ length: maxLen }, (_, index) => `<td>${bitChar(bits[index])}</td>`).join("");
    return `<tr><td>${row.label}</td>${cells}</tr>`;
  }).join("");

  return `
    <div class="table-wrap">
      <table class="calc-table">
        <thead>
          <tr><th>Bit #</th>${headerCells}</tr>
        </thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>
  `;
}

function miniBits(title, bits) {
  return `
    <div class="mini-card">
      <h4>${title}</h4>
      <div class="bit-row">${smallBitCells(bits)}</div>
      <p><strong>${bits}</strong></p>
    </div>
  `;
}

function stepBlock(title, subtitle, content) {
  const subtitleHtml = subtitle ? `<p>${subtitle}</p>` : "";
  return `
    <article class="step-block">
      <div class="step-header">
        <h3>${title}</h3>
        ${subtitleHtml}
      </div>
      <div class="step-content">${content}</div>
    </article>
  `;
}

function generateKeys(keyBits) {
  const p10 = permute(keyBits, TABLES.P10);
  const [p10Left, p10Right] = splitBits(p10, 5);
  const ls1Left = leftShift(p10Left, 1);
  const ls1Right = leftShift(p10Right, 1);
  const ls1Combined = ls1Left + ls1Right;
  const k1 = permute(ls1Combined, TABLES.P8);

  const ls2Left = leftShift(ls1Left, 2);
  const ls2Right = leftShift(ls1Right, 2);
  const ls2Combined = ls2Left + ls2Right;
  const k2 = permute(ls2Combined, TABLES.P8);

  const html = stepBlock(
    "2.1 Key Generation",
    "K1 dan K2 dibentuk menggunakan P10, left shift, dan P8.",
    `
      <div class="formula-box">
        P10 = ${TABLES.P10.join(" ")}<br>
        P8 = ${TABLES.P8.join(" ")}<br>
        Key awal = <strong>${bitsWithSpace(keyBits, 5)}</strong>
      </div>

      ${calculationTable([
      { label: "K", bits: keyBits },
      { label: "P10(K)", bits: p10 },
      { label: "LS-1(P10(K))", bits: ls1Combined },
      { label: "P8(LS-1) = K1", bits: k1 },
      { label: "LS-2(hasil LS-1)", bits: ls2Combined },
      { label: "P8(LS-2) = K2", bits: k2 }
    ], 10)}

      <div class="split-grid">
        ${miniBits("Hasil P10 bagian kiri", p10Left)}
        ${miniBits("Hasil P10 bagian kanan", p10Right)}
        ${miniBits("LS-1 bagian kiri", ls1Left)}
        ${miniBits("LS-1 bagian kanan", ls1Right)}
        ${miniBits("LS-2 bagian kiri", ls2Left)}
        ${miniBits("LS-2 bagian kanan", ls2Right)}
      </div>

      <p><strong>Kesimpulan key generation:</strong> K1 = ${bitsWithSpace(k1)} dan K2 = ${bitsWithSpace(k2)}.</p>
    `
  );

  return {
    k1,
    k2,
    p10,
    p10Left,
    p10Right,
    ls1Left,
    ls1Right,
    ls1Combined,
    ls2Left,
    ls2Right,
    ls2Combined,
    html
  };
}

function roundFunction(input8, subKey, subKeyName, roundNumber) {
  const [left, right] = splitBits(input8, 4);
  const ep = permute(right, TABLES.EP);
  const xorKey = xor(ep, subKey);
  const [xorLeft, xorRight] = splitBits(xorKey, 4);
  const s0 = sBoxLookup(xorLeft, S0);
  const s1 = sBoxLookup(xorRight, S1);
  const sboxCombined = s0.binaryValue + s1.binaryValue;
  const p4 = permute(sboxCombined, TABLES.P4);
  const leftXorP4 = xor(left, p4);
  const output = leftXorP4 + right;

  const html = stepBlock(
    `Round Function ${roundNumber}`,
    `Round ini menggunakan ${subKeyName} = ${bitsWithSpace(subKey)}.`,
    `
      <div class="formula-box">
        Input round = <strong>${bitsWithSpace(input8)}</strong><br>
        L = <strong>${left}</strong>, R = <strong>${right}</strong><br>
        fK(L, R) = (L ⊕ F(R, SK), R)
      </div>

      ${calculationTable([
      { label: "R", bits: right },
      { label: "E/P(R)", bits: ep },
      { label: subKeyName, bits: subKey },
      { label: "E/P(R) ⊕ " + subKeyName, bits: xorKey },
      { label: "S-Box", bits: sboxCombined },
      { label: "P4(S-Box)", bits: p4 }
    ], 8)}

      <div class="sbox-detail">
        <div class="mini-card">
          <h4>Substitusi S0</h4>
          <p>Input S0 = <strong>${xorLeft}</strong></p>
          <p>Baris = bit ke-1 dan ke-4 = ${s0.rowBinary}<sub>2</sub> = ${s0.row}</p>
          <p>Kolom = bit ke-2 dan ke-3 = ${s0.colBinary}<sub>2</sub> = ${s0.col}</p>
          <p>S0[${s0.row}][${s0.col}] = ${s0.decimalValue} = <strong>${s0.binaryValue}</strong></p>
        </div>
        <div class="mini-card">
          <h4>Substitusi S1</h4>
          <p>Input S1 = <strong>${xorRight}</strong></p>
          <p>Baris = bit ke-1 dan ke-4 = ${s1.rowBinary}<sub>2</sub> = ${s1.row}</p>
          <p>Kolom = bit ke-2 dan ke-3 = ${s1.colBinary}<sub>2</sub> = ${s1.col}</p>
          <p>S1[${s1.row}][${s1.col}] = ${s1.decimalValue} = <strong>${s1.binaryValue}</strong></p>
        </div>
      </div>

      <div class="formula-box">
        Hasil S-Box = ${s0.binaryValue} + ${s1.binaryValue} = <strong>${sboxCombined}</strong><br>
        P4 = ${TABLES.P4.join(" ")} sehingga P4(S-Box) = <strong>${p4}</strong><br>
        L ⊕ P4 = ${left} ⊕ ${p4} = <strong>${leftXorP4}</strong><br>
        Hasil round = ${leftXorP4} + ${right} = <strong>${bitsWithSpace(output)}</strong>
      </div>
    `
  );

  return {
    input8,
    subKey,
    subKeyName,
    roundNumber,
    left,
    right,
    ep,
    xorKey,
    xorLeft,
    xorRight,
    s0,
    s1,
    sboxCombined,
    p4,
    leftXorP4,
    output,
    html
  };
}

function processSDES(inputBits, keyBits, mode) {
  const keyData = generateKeys(keyBits);
  const firstKey = mode === "encrypt" ? keyData.k1 : keyData.k2;
  const secondKey = mode === "encrypt" ? keyData.k2 : keyData.k1;
  const firstKeyName = mode === "encrypt" ? "K1" : "K2";
  const secondKeyName = mode === "encrypt" ? "K2" : "K1";
  const modeLabel = mode === "encrypt" ? "Enkripsi" : "Dekripsi";

  const ip = permute(inputBits, TABLES.IP);
  const [ipLeft, ipRight] = splitBits(ip, 4);
  const round1 = roundFunction(ip, firstKey, firstKeyName, 1);
  const swapped = round1.output.slice(4) + round1.output.slice(0, 4);
  const [swLeft, swRight] = splitBits(swapped, 4);
  const round2 = roundFunction(swapped, secondKey, secondKeyName, 2);
  const finalResult = permute(round2.output, TABLES.IP_INV);

  const introHtml = `
    <div class="solution-intro">
      <strong>Diketahui:</strong><br>
      Mode = ${modeLabel}<br>
      Input 8-bit = <strong>${bitsWithSpace(inputBits)}</strong><br>
      Key 10-bit = <strong>${bitsWithSpace(keyBits, 5)}</strong><br>
      Urutan subkey = <strong>${firstKeyName}</strong> untuk Round 1 dan <strong>${secondKeyName}</strong> untuk Round 2.
    </div>
  `;

  const inputHtml = stepBlock(
    "2.2 Initial Permutation dan Pembagian L/R",
    "Input 8-bit dipermutasi menggunakan IP, kemudian dibagi menjadi bagian kiri dan kanan.",
    `
      <div class="formula-box">
        IP = ${TABLES.IP.join(" ")}<br>
        IP<sup>-1</sup> = ${TABLES.IP_INV.join(" ")}
      </div>
      ${calculationTable([
      { label: mode === "encrypt" ? "Plaintext" : "Ciphertext", bits: inputBits },
      { label: "IP(Input)", bits: ip }
    ], 8)}
      <div class="split-grid">
        ${miniBits("Bagian kiri hasil IP", ipLeft)}
        ${miniBits("Bagian kanan hasil IP", ipRight)}
      </div>
    `
  );

  const swapHtml = stepBlock(
    "Swap (SW)",
    "Setelah Round Function 1, bagian kiri dan kanan ditukar sebelum masuk ke Round Function 2.",
    `
      <div class="formula-box">
        Sebelum SW = <strong>${bitsWithSpace(round1.output)}</strong><br>
        SW(L, R) → (R, L)<br>
        Setelah SW = <strong>${bitsWithSpace(swapped)}</strong>
      </div>
      <div class="split-grid">
        ${miniBits("Bagian kiri setelah SW", swLeft)}
        ${miniBits("Bagian kanan setelah SW", swRight)}
      </div>
      ${calculationTable([
      { label: "Sebelum SW", bits: round1.output },
      { label: "Setelah SW", bits: swapped }
    ], 8)}
    `
  );

  const finalHtml = stepBlock(
    "Output Akhir: Inverse Initial Permutation",
    "Tidak ada swap setelah Round Function 2. Hasil round kedua langsung dipermutasi dengan IP inverse.",
    `
      ${calculationTable([
      { label: "Hasil Round 2", bits: round2.output },
      { label: "IP^-1(Hasil Round 2)", bits: finalResult }
    ], 8)}
      <div class="final-note">
        Hasil akhir ${modeLabel.toLowerCase()} adalah ${bitsWithSpace(finalResult)}.
      </div>
    `
  );

  const solutionHtml = [
    introHtml,
    keyData.html,
    inputHtml,
    round1.html,
    swapHtml,
    round2.html,
    finalHtml
  ].join("");

  return {
    result: finalResult,
    keyData,
    ip,
    round1,
    swapped,
    round2,
    solutionHtml
  };
}

function runCalculation() {
  const inputBits = inputBitsEl.value.trim();
  const keyBits = keyBitsEl.value.trim();
  const mode = getMode();

  if (!validateInput(inputBits, keyBits)) return;

  const data = processSDES(inputBits, keyBits, mode);
  latestResult = data.result;

  resultLabel.textContent = mode === "encrypt" ? "Ciphertext" : "Plaintext";
  resultDescription.textContent = mode === "encrypt"
    ? "Output akhir enkripsi setelah IP inverse."
    : "Output akhir dekripsi setelah IP inverse.";

  resultBitsEl.innerHTML = outputCells(data.result);
  solutionContent.innerHTML = data.solutionHtml;
  resultSection.classList.remove("hidden");
  solutionSection.classList.remove("hidden");
}

form.addEventListener("submit", function (event) {
  event.preventDefault();
  runCalculation();
});

resetBtn.addEventListener("click", function () {
  inputBitsEl.value = "";
  keyBitsEl.value = "";
  setMode("encrypt");
  hideError();
  latestResult = "";
  resultBitsEl.innerHTML = "";
  solutionContent.innerHTML = "";
  resultSection.classList.add("hidden");
  solutionSection.classList.add("hidden");
  solutionBox.classList.add("hidden");
  toggleSolution.textContent = "Tampilkan Solusi Penyelesaian";
});

exampleBtn.addEventListener("click", function () {
  const mode = getMode();


  keyBitsEl.value = "1001010100";

  if (mode === "decrypt") {
    inputBitsEl.value = "01100101";
  } else {
    inputBitsEl.value = "10010101";
  }

  hideError();
});

toggleSolution.addEventListener("click", function () {
  solutionBox.classList.toggle("hidden");
  toggleSolution.textContent = solutionBox.classList.contains("hidden")
    ? "Tampilkan Solusi Penyelesaian"
    : "Sembunyikan Solusi Penyelesaian";
});

[inputBitsEl, keyBitsEl].forEach((element) => {
  element.addEventListener("input", function () {
    element.value = element.value.replace(/[^01]/g, "");
  });
});

