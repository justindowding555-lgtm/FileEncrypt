import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

// Measure the actual catalog functions without opening a webview or reading
// private files. Optional --baseline <git-ref> compares the same input/workload.
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== "--baseline")) {
  throw new Error("Usage: node scripts/benchmark-sandbox.mjs [--baseline <git-ref>]");
}
const root = fileURLToPath(new URL("../", import.meta.url));
const files = Array.from({ length: 10_000 }, (_, index) => ({
  id: index, name: `file${(index * 7919) % 10_000}.txt`, kind: "text",
}));
const expected = files.map((item) => item.name).sort(new Intl.Collator(undefined, {
  numeric: true, sensitivity: "base",
}).compare);

function measure(label, source) {
  const context = vm.createContext({
    document: { readyState: "loading", addEventListener() {} },
    window: {}, files,
  });
  vm.runInContext(source, context);
  vm.runInContext("sandbox.items=files; indexSandboxFiles()", context);
  const actual = Array.from(vm.runInContext("sandboxVisibleEntries().map(item=>item.label)", context));
  assert.equal(actual.length, expected.length);
  assert.ok(actual.every((name, index) => name === expected[index]), "Numeric filename order changed");
  const workloads = [
    ["Fresh name sort", "sandbox.query=''; sandbox.category=''; sandbox.visibleEntries=null; sandbox.sortedEntries=null; sandboxVisibleEntries()"],
    ["Repeat same view", "sandboxVisibleEntries()"],
    ["Search filter (cached sort)", "sandbox.query='file'; sandbox.category='text'; sandbox.visibleEntries=null; sandboxVisibleEntries()"],
  ];
  const results = [];
  for (const [workload, code] of workloads) {
    vm.runInContext(code, context); // Warm up each workload before sampling.
    const times = [];
    for (let sample = 0; sample < 7; sample++) {
      const start = performance.now();
      const entries = vm.runInContext(code, context);
      times.push(performance.now() - start);
      assert.equal(entries.length, files.length);
    }
    times.sort((a, b) => a - b);
    results.push({ version: label, workload, medianMs: Number(times[3].toFixed(3)) });
  }
  return results;
}

const results = [];
if (args.length) {
  const baseline = execFileSync("git", ["show", `${args[1]}:src/main.js`], {
    cwd: root, encoding: "utf8", maxBuffer: 2 * 1024 * 1024,
  });
  results.push(...measure(args[1], baseline));
}
results.push(...measure("Working tree", fs.readFileSync(new URL("../src/main.js", import.meta.url), "utf8")));
console.log(JSON.stringify({ files: files.length, samples: 7, runtime: process.version, results }, null, 2));
