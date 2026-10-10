import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import vm from "node:vm";
import { buildSandboxCsp, buildSha256, watchSandboxCsp } from "../scripts/build-csp.mjs";

function fixture(t) {
  const directory = fs.mkdtempSync(join(tmpdir(), "fileencrypt-csp-"));
  const root = pathToFileURL(directory + "/");
  for (const name of ["src", "src-tauri"]) fs.mkdirSync(new URL(name, root));
  const write = (name, value) => fs.writeFileSync(new URL(name, root), value);
  const read = (name) => fs.readFileSync(new URL(name, root), "utf8");
  write("src/sandbox-content.js", 'const SANDBOX_STYLE = "body{color:red}" + `\r\n/* café */\r\n`;');
  write("src/sandbox-viewer.js", 'const SANDBOX_VIEWER_SCRIPT = String.raw`(() => {\r\n  const pattern = /\\d/;\r\n})();`;');
  write("src-tauri/tauri.conf.json", JSON.stringify({
    app: { security: { csp: "default-src 'self'; style-src 'self' 'sha256-unrelated'; script-src 'self'; object-src 'none'" } },
  }));
  t.after(() => {
    for (const name of ["src", "src-tauri"]) {
      const path = new URL(name + "/", root);
      for (const file of fs.readdirSync(path)) fs.unlinkSync(new URL(file, path));
      fs.rmdirSync(path);
    }
    fs.rmdirSync(directory);
  });
  return { root, write, read };
}

test("generated CSP matches browser template strings without changing tracked inputs", (t) => {
  const { root, read } = fixture(t);
  const inputs = ["src/sandbox-content.js", "src/sandbox-viewer.js", "src-tauri/tauri.conf.json"];
  const original = inputs.map(read);
  const result = buildSandboxCsp(root);
  assert.equal(result.styleHash, buildSha256("body{color:red}\n/* café */\n"));
  assert.equal(result.scriptHash, buildSha256("(() => {\n  const pattern = /\\d/;\n})();"));
  assert.deepEqual(inputs.map(read), original);
  const context = vm.createContext({});
  vm.runInContext(read("src/sandbox-hashes.generated.js"), context);
  assert.equal(vm.runInContext("SANDBOX_STYLE_HASH", context), result.styleHash);
  assert.equal(vm.runInContext("SANDBOX_VIEWER_SCRIPT_HASH", context), result.scriptHash);
  for (const platform of ["windows", "linux", "macos"]) {
    const config = JSON.parse(read(`src-tauri/tauri.${platform}.conf.json`));
    assert.equal(config.app.security.csp, result.csp);
  }
  assert.ok(result.csp.includes("'sha256-unrelated'"));
  assert.ok(result.csp.includes("object-src 'none'"));
  assert.ok(!result.csp.includes("unsafe-inline"));
  assert.ok(!result.csp.includes("unsafe-eval"));
  const output = new URL("src-tauri/tauri.windows.conf.json", root);
  const modified = fs.statSync(output).mtimeMs;
  buildSandboxCsp(root);
  assert.equal(fs.statSync(output).mtimeMs, modified);
});

test("dev watcher refreshes hashes after CSS and script edits", async (t) => {
  const { root, write, read } = fixture(t);
  buildSandboxCsp(root);
  const errors = [];
  const close = watchSandboxCsp(root, (error) => errors.push(error));
  t.after(close);
  const originalConfig = read("src-tauri/tauri.conf.json");
  write("src/sandbox-content.js", 'const SANDBOX_STYLE = "body{color:blue}";');
  write("src/sandbox-viewer.js", 'const SANDBOX_VIEWER_SCRIPT = "(() => {})();";');
  const expectedStyle = buildSha256("body{color:blue}");
  const expectedScript = buildSha256("(() => {})();");
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const generated = read("src/sandbox-hashes.generated.js");
    if (generated.includes(expectedStyle) && generated.includes(expectedScript)) break;
    await delay(20);
  }
  close();
  assert.deepEqual(errors, []);
  const generatedConfig = read("src-tauri/tauri.windows.conf.json");
  assert.ok(generatedConfig.includes(expectedStyle));
  assert.ok(generatedConfig.includes(expectedScript));
  assert.equal(read("src-tauri/tauri.conf.json"), originalConfig);
});

test("invalid sandbox source fails generation before replacing outputs", (t) => {
  const { root, write, read } = fixture(t);
  buildSandboxCsp(root);
  const previous = read("src-tauri/tauri.windows.conf.json");
  write("src/sandbox-viewer.js", "const SANDBOX_VIEWER_SCRIPT = ;");
  assert.throws(() => buildSandboxCsp(root), /Unexpected token/);
  assert.equal(read("src-tauri/tauri.windows.conf.json"), previous);
});
