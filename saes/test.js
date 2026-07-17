// Pengujian mandiri algoritma inti untuk Node.js.
// Jalankan: node test.js

const SBOX = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7];
const INV_SBOX = [0xA,0x5,0x9,0xB,0x1,0x7,0x8,0xF,0x6,0x0,0x2,0x3,0xC,0x4,0xD,0xE];
const RCON1=0x80, RCON2=0x30;
const wordToState=w=>[(w>>>12)&15,(w>>>8)&15,(w>>>4)&15,w&15];
const stateToWord=s=>(s[0]<<12)|(s[1]<<8)|(s[2]<<4)|s[3];
const xorState=(a,b)=>a.map((v,i)=>v^b[i]);
const shiftRows=s=>[s[0],s[3],s[2],s[1]];
const sub=(s,box)=>s.map(v=>box[v]);
function mul(a,b){let p=0;for(let i=0;i<4;i++){if(b&1)p^=a;const c=a&8;a=(a<<1)&15;if(c)a^=3;b>>>=1;}return p&15;}
function mix(s,m){const o=[];for(let c=0;c<2;c++){const i=c*2;o[i]=mul(m[0][0],s[i])^mul(m[0][1],s[i+1]);o[i+1]=mul(m[1][0],s[i])^mul(m[1][1],s[i+1]);}return o;}
const rot=w=>((w&15)<<4)|(w>>>4);
const subByte=w=>(SBOX[w>>>4]<<4)|SBOX[w&15];
function keys(k){const w0=k>>>8,w1=k&255,w2=w0^subByte(rot(w1))^RCON1,w3=w2^w1,w4=w2^subByte(rot(w3))^RCON2,w5=w4^w3;return [(w0<<8)|w1,(w2<<8)|w3,(w4<<8)|w5];}
function enc(p,k){const [k0,k1,k2]=keys(k).map(wordToState);let s=xorState(wordToState(p),k0);s=sub(s,SBOX);s=shiftRows(s);s=mix(s,[[1,4],[4,1]]);s=xorState(s,k1);s=sub(s,SBOX);s=shiftRows(s);s=xorState(s,k2);return stateToWord(s);}
function dec(c,k){const [k0,k1,k2]=keys(k).map(wordToState);let s=xorState(wordToState(c),k2);s=shiftRows(s);s=sub(s,INV_SBOX);s=xorState(s,k1);s=mix(s,[[9,2],[2,9]]);s=shiftRows(s);s=sub(s,INV_SBOX);s=xorState(s,k0);return stateToWord(s);}
function assertEqual(actual,expected,label){if(actual!==expected)throw new Error(`${label}: expected ${expected.toString(16)}, got ${actual.toString(16)}`);console.log(`✓ ${label}`);}
const sampleCases = [
  [0xCAFE, 0xBEEF, 0x2855, "CryptoMatrix Vector"],
];
for (const [plaintext, key, ciphertext, name] of sampleCases) {
  assertEqual(enc(plaintext, key), ciphertext, `${name} — enkripsi`);
  assertEqual(dec(ciphertext, key), plaintext, `${name} — dekripsi`);
}
for(let p=0;p<0x10000;p+=257){for(let k=0;k<0x10000;k+=4099){assertEqual(dec(enc(p,k),k),p,`Round-trip P=${p.toString(16).padStart(4,"0")} K=${k.toString(16).padStart(4,"0")}`)}}
console.log("Semua pengujian berhasil.");
