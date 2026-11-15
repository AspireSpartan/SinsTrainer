// Check the trainer's byte patterns against a game exe and print the addresses they resolve to.
// usage: node pattern.js                       (checks all patterns used by SinsTrainer.cs)
//        node pattern.js "8B 0D ?? ?? ?? ??"   (any pattern: prints every match)
const { loadPe, findPattern } = require('./common');
const pe = loadPe();
const hex = v => '0x' + v.toString(16);
const rd = va => pe.b.readUInt32LE(pe.va2o(va));
const custom = process.argv[2];
if (custom) {
  const hits = findPattern(pe, custom);
  console.log(hits.length + ' match(es): ' + hits.map(hex).join(' '));
  process.exit(0);
}
const checks = [
  { name: 'PAT_GAME (Game global @+2)', pat: '8B 0D ?? ?? ?? ?? 8B 81 0C 57 00 00 8B 80 68 26 00 00', at: [2] },
  { name: 'PAT_GAME_ALT (Game global @+2, all must agree)', pat: '8B 0D ?? ?? ?? ?? 8B 89 0C 57 00 00', at: [2] },
  { name: 'PAT_SEL (selection @+1, hover @+22 = selection+8)', pat: 'A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 00 A1 ?? ?? ?? ?? 89 40 04 C7 05 ?? ?? ?? ?? 00 00 00 00', at: [1, 22] },
  { name: 'PAT_SEL_ALT (selection @+1)', pat: 'A1 ?? ?? ?? ?? 53 56 57 8B 30 8B F9 3B F0 74 1E', at: [1] },
];
for (const c of checks) {
  const hits = findPattern(pe, c.pat);
  const vals = hits.map(h => c.at.map(o => hex(rd(h + o))).join('/'));
  console.log(`${c.name}: ${hits.length} match(es)` + (hits.length ? '  -> ' + [...new Set(vals)].join(', ') : ''));
}
console.log('image base ' + hex(pe.base) + ' (addresses above are at this base)');
