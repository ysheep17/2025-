// node convert_constants_node.js constants.json constants.circom
const fs = require('fs');

if (process.argv.length < 4) {
  console.error('Usage: node convert_constants_node.js constants.json constants.circom');
  process.exit(1);
}

const inFile = process.argv[2];
const outFile = process.argv[3];

const raw = JSON.parse(fs.readFileSync(inFile, 'utf8'));
const t = raw.t;
const mds = raw.mds;
const rc = raw.roundConstants;

function arrToC(a) {
  return '[' + a.map(x => JSON.stringify(x)).join(', ') + ']';
}

let out = '';
out += 'pragma circom 2.0.0;\n\n';
out += '// Auto-generated constants.circom\n\n';
out += 'const MDS_CONST = [\n';
for (let i = 0; i < mds.length; i++) {
  out += '  ' + arrToC(mds[i]) + (i+1 < mds.length ? ',\n' : '\n');
}
out += '];\n\n';
out += 'const RC_CONST = [\n';
for (let i = 0; i < rc.length; i++) {
  out += '  ' + arrToC(rc[i]) + (i+1 < rc.length ? ',\n' : '\n');
}
out += '];\n';
fs.writeFileSync(outFile, out, 'utf8');
console.log('Wrote', outFile);
