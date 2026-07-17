# CryptoMatrix-UAS
CryptoMatrix UAS adalah aplikasi web simulasi algoritma kriptografi simetris yang menyatukan DES, S-DES, AES-128, dan S-AES dalam satu landing page. Aplikasi menampilkan proses enkripsi dan dekripsi secara bertahap untuk mendukung pembelajaran, validasi program, dan perbandingan dengan perhitungan manual.

## Struktur proyek

```text
CryptoMatrix UAS/
├── index.html
├── 404.html
├── assets/
│   ├── landing.css
│   ├── unified.css
│   └── theme.js
├── des/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── sdes/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── aes/
│   ├── index.html
│   ├── style.css
│   ├── aes.js
│   ├── app.js
│   └── test.js
└── saes/
    ├── index.html
    ├── style.css
    ├── app.js
    └── test.js
```

## Algoritma

### DES

Input 64-bit dan kunci 64-bit. Tampilan proses meliputi PC-1, pembagian C dan D, pergeseran kiri, PC-2, 16 subkunci, initial permutation, 16 ronde Feistel, ekspansi E, XOR, delapan S-Box, permutasi P, dan inverse initial permutation.

### S-DES

Input 8-bit dan kunci 10-bit. Tampilan proses meliputi P10, LS-1, LS-2, P8, pembentukan K1 dan K2, initial permutation, dua fungsi ronde, S0, S1, P4, swap, dan inverse initial permutation.

### AES-128

Input satu blok 128-bit dan kunci 128-bit. Tampilan proses meliputi key expansion W[0] sampai W[43], RK0 sampai RK10, initial AddRoundKey, SubBytes, ShiftRows, MixColumns, AddRoundKey, serta seluruh transformasi invers untuk dekripsi.

### S-AES

Input 16-bit dan kunci 16-bit. Tampilan proses meliputi pembentukan w0 sampai w5, K0 sampai K2, SubNibbles, ShiftRows, MixColumns pada GF(2⁴), AddRoundKey, dan seluruh operasi invers untuk dekripsi.

## Data contoh bawaan

| Algoritma | Plaintext | Kunci | Ciphertext |
|---|---|---|---|
| DES | `6A0F3C9D12B7E845` | `4D7A1C8E9B2036F5` | `8271C1AAE8819F0B` |
| S-DES | `10010101` | `1001010100` | `01100101` |
| AES-128 | `00112233445566778899AABBCCDDEEFF` | `000102030405060708090A0B0C0D0E0F` | `69C4E0D86A7B0430D8CDB78070B4C55A` |
| S-AES | `CAFE` | `BEEF` | `2855` |

## Menjalankan secara lokal

Aplikasi dapat dibuka langsung melalui `index.html`. Untuk menghindari pembatasan browser pada file lokal, jalankan server statis:

```bash
python -m http.server 8000
```

Kemudian buka `http://localhost:8000`.
