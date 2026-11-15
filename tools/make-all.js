// Joins every decompiled function file (<SINS_DECOMP>/functions/*.c, as written by REA decompile_all)
// into <SINS_DECOMP>/all.c, separated by "////FILE <name>" lines. q.js and at.js read all.c.
// usage: node make-all.js
const fs = require('fs');
const path = require('path');
const { decompDir } = require('./common');
const dir = decompDir();
const files = fs.readdirSync(path.join(dir, 'functions')).filter(f => f.endsWith('.c')).sort();
const out = fs.openSync(path.join(dir, 'all.c'), 'w');
for (const f of files) fs.writeSync(out, '\n////FILE ' + f + '\n' + fs.readFileSync(path.join(dir, 'functions', f), 'utf8'));
fs.closeSync(out);
console.log('wrote all.c with ' + files.length + ' functions');
