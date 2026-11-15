// Which decompiled function contains an address? (reads the "// range:" header of each function in all.c)
// usage: node at.js <hexaddr> [<hexaddr>...]
const fs = require('fs');
const path = require('path');
const { decompDir } = require('./common');
const all = fs.readFileSync(path.join(decompDir(), 'all.c'), 'utf8');
const re = /\/\/\/\/FILE (0x[0-9a-f]+)\.c\n[\s\S]*?\/\/ range: ([^\n]+)/g;
const fns = [];
let m;
while ((m = re.exec(all))) {
  const ranges = m[2].replace(' inclusive', '').split(/,\s*/).map(r => r.split('-').map(x => parseInt(x, 16)));
  fns.push({ a: m[1], ranges });
}
for (const a of process.argv.slice(2)) {
  const v = parseInt(a, 16);
  const f = fns.find(x => x.ranges.some(([s, e]) => v >= s && v <= e));
  console.log(a, '->', f ? f.a : 'none');
}
