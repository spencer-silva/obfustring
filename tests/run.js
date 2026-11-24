// Usage: node tests/run.js <file> [file...]  — prints findings, IOCs and decoded strings.
const { analyze } = require('../analyzer.js');
const fs = require('fs');
for (const f of process.argv.slice(2)) {
  const r = analyze(new Uint8Array(fs.readFileSync(f)));
  console.log(`\n== ${f}  ${r.size} bytes  ${r.elapsedMs}ms  score ${r.score}  ${r.verdict}`);
  for (const x of r.findings) console.log(`  [${x.severity} +${x.points}] ${x.title}`);
  console.log('  IOCs:'); for (const i of r.iocs) console.log(`    ${i.source.padEnd(8)}${i.type.padEnd(10)}${i.defanged}${i.benign ? ' (benign)' : ''}${i.method ? '  via ' + i.method : ''}`);
  console.log('  Decoded:'); for (const d of r.decoded.slice(0, 20)) console.log(`    ${String(d.score).padStart(4)}  ${d.method.padEnd(18)}${d.value.slice(0, 90)}`);
}
