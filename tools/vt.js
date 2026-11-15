// Find the vtables of a C++ class from its MSVC RTTI name and print selected slots.
// usage: node vt.js "<RTTI name>" [slotOffsetHex...]
//   e.g. node vt.js ".?AVPlayer@Iron@@" 20c      (use the row with thisOff=0x0 for the main vtable)
const { loadPe } = require('./common');
const pe = loadPe();
const { b, o2va, va2o } = pe;
const [name, ...slots] = process.argv.slice(2);
if (!name) { console.log('usage: node vt.js "<RTTI name>" [slotOffsetHex...]'); process.exit(1); }
const le = v => { const k = Buffer.alloc(4); k.writeUInt32LE(v >>> 0); return k; };
const findAll = k => { const r = []; let i = b.indexOf(k); while (i >= 0) { r.push(i); i = b.indexOf(k, i + 1); } return r; };
let p = b.indexOf(Buffer.from(name, 'latin1'));
while (p >= 0) {
  let s = p; while (b[s - 1] !== 0) s--;
  const tdName = b.toString('latin1', s, b.indexOf(0, s));
  const td = o2va(s - 8);                         // TypeDescriptor = { vfptr, spare, name }
  for (const r of findAll(le(td))) {
    const col = r - 12;                           // CompleteObjectLocator = { sig, offset, cdOffset, pTypeDescriptor }
    if (b.readUInt32LE(col) !== 0) continue;
    const off = b.readUInt32LE(col + 4);
    for (const vr of findAll(le(o2va(col)))) {
      const vt = o2va(vr) + 4;
      const out = slots.map(h => { const sl = parseInt(h, 16); return `+0x${sl.toString(16)}=0x${b.readUInt32LE(va2o(vt + sl)).toString(16)}`; });
      console.log(`${tdName} thisOff=0x${off.toString(16)} vtable=0x${vt.toString(16)} ${out.join(' ')}`);
    }
  }
  p = b.indexOf(Buffer.from(name, 'latin1'), p + 1);
}
