// Which class's vtable contains a function, and at which slot? (MSVC RTTI)
// usage: node owner.js <funcaddr> [<funcaddr>...]
const { loadPe } = require('./common');
const { b, o2va, va2o } = loadPe();
const u32 = o => b.readUInt32LE(o);
function colName(colVa) {
  const c = va2o(colVa); if (c < 0 || u32(c) !== 0) return null;
  const td = va2o(u32(c + 12)); if (td < 0) return null;
  const n = b.toString('latin1', td + 8, b.indexOf(0, td + 8));
  return n.startsWith('.?A') ? n : null;
}
for (const a of process.argv.slice(2)) {
  const k = Buffer.alloc(4); k.writeUInt32LE(parseInt(a, 16));
  let i = b.indexOf(k); const out = [];
  while (i >= 0) {
    for (let back = 0; back < 0x800; back += 4) {   // walk back to the slot preceded by a COL pointer
      const name = colName(u32(i - back - 4));
      if (name) { out.push(`${name} slot+0x${back.toString(16)} vtable=0x${o2va(i - back).toString(16)}`); break; }
    }
    i = b.indexOf(k, i + 1);
  }
  console.log(a, '->', out.length ? '\n  ' + out.join('\n  ') : 'not in any vtable');
}
