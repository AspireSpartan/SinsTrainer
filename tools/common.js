// Shared helpers for the analysis scripts.
//   SINS_EXE     path to "Sins of a Solar Empire Rebellion.exe" (needed by pe/xref/vt/owner/pattern)
//   SINS_DECOMP  folder with the decompiled functions (needed by q/at); default: ./sins_decomp
const fs = require('fs');
const path = require('path');

function exePath() {
  const p = process.env.SINS_EXE;
  if (!p) { console.error('Set SINS_EXE to the path of "Sins of a Solar Empire Rebellion.exe".'); process.exit(1); }
  return p;
}

// Loads a PE32 file and returns helpers to convert between file offsets and virtual addresses.
function loadPe(file) {
  const b = fs.readFileSync(file || exePath());
  const pe = b.readUInt32LE(0x3c), nsec = b.readUInt16LE(pe + 6), optSz = b.readUInt16LE(pe + 20), opt = pe + 24;
  const base = b.readUInt32LE(opt + 28);
  const secs = [];
  for (let i = 0; i < nsec; i++) {
    const s = opt + optSz + i * 40;
    secs.push({ name: b.toString('latin1', s, s + 8).replace(/\0.*/, ''), vsize: b.readUInt32LE(s + 8), va: b.readUInt32LE(s + 12), rsize: b.readUInt32LE(s + 16), raw: b.readUInt32LE(s + 20) });
  }
  const o2va = o => { for (const s of secs) if (o >= s.raw && o < s.raw + s.rsize) return base + s.va + o - s.raw; return null; };
  const va2o = v => { const r = v - base; for (const s of secs) if (r >= s.va && r < s.va + s.rsize) return r - s.va + s.raw; return -1; };
  const text = secs.find(s => s.name === '.text');
  return { b, base, secs, o2va, va2o, text };
}

// All matches of an IDA-style pattern ("8B 0D ?? ?? ...") in .text, as virtual addresses.
function findPattern(pe, pattern) {
  const t = pattern.trim().split(/\s+/).map(x => (x === '??' ? -1 : parseInt(x, 16)));
  const { b, text } = pe, res = [];
  for (let i = text.raw; i <= text.raw + text.rsize - t.length; i++) {
    let j = 0;
    while (j < t.length && (t[j] < 0 || b[i + j] === t[j])) j++;
    if (j === t.length) res.push(pe.o2va(i));
  }
  return res;
}

function decompDir() { return process.env.SINS_DECOMP || path.join(process.cwd(), 'sins_decomp'); }

module.exports = { loadPe, findPattern, decompDir, exePath };
