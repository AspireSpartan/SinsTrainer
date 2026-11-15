// Query the decompiled game (all.c, see make-all.js).
// usage: node q.js find <regex> [<regex>...]   functions whose pseudocode matches ALL regexes
//        node q.js show <addr>                  print one function, e.g. node q.js show 58b860
//        node q.js calls <FUN_name>             functions that call FUN_name
const fs = require('fs');
const path = require('path');
const { decompDir } = require('./common');
const all = fs.readFileSync(path.join(decompDir(), 'all.c'), 'utf8').split('\n////FILE ');
const funcs = all.slice(1).map(s => { const i = s.indexOf('\n'); return { f: s.slice(0, i), b: s.slice(i + 1) }; });
const [cmd, ...args] = process.argv.slice(2);
if (cmd === 'find') {
  const res = args.map(a => new RegExp(a));
  const hits = funcs.filter(x => res.every(r => r.test(x.b)));
  console.log(hits.length + ' hits');
  for (const h of hits.slice(0, 60)) console.log(h.f, h.b.length);
} else if (cmd === 'show') {
  const a = args[0].toLowerCase().replace(/^0x/, '');
  const h = funcs.find(x => x.f === '0x' + a + '.c');
  console.log(h ? h.b : 'not found');
} else if (cmd === 'calls') {
  const re = new RegExp('\\b' + args[0] + '\\(');
  const hits = funcs.filter(x => re.test(x.b) && !x.f.includes(args[0].replace(/^FUN_0*/, '').toLowerCase()));
  console.log(hits.length + ' callers');
  for (const h of hits.slice(0, 60)) console.log(h.f, h.b.length);
} else {
  console.log('usage: node q.js find <regex>... | show <addr> | calls <FUN_name>');
}
