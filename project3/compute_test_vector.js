// node compute_test_vector.js
// usage: node compute_test_vector.js pre1 pre2
const { poseidon2 } = require('@zkpassport/poseidon2');
const bigInt = require('big-integer');

async function run() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error('Usage: node compute_test_vector.js pre1 pre2');
    process.exit(1);
  }
  const pre = args.map(x => BigInt(x));
  // poseidon2 API may accept array of BigInt; check package docs
  const digest = poseidon2(pre);
  console.log('digest:', digest.toString());
}
run();
