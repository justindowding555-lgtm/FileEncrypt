import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

function fixture(invoke) {
  let created = 0;
  const refs = new Map();
  function element(fragment = false) {
    return { fragment, children: [], handlers: new Map(), value: "", checked: false,
      classList: { toggle() {} },
      append(...items) { for (const item of items) this.children.push(...(item.fragment ? item.children : [item])); },
      replaceChildren(...items) { this.children = []; this.append(...items); },
      setAttribute() {}, removeAttribute() {}, addEventListener(name, callback) { this.handlers.set(name, callback); },
    };
  }
  const document = { readyState: "loading", addEventListener() {},
    getElementById(id) { if (!refs.has(id)) refs.set(id, element()); return refs.get(id); },
    createElement() { created++; return element(); }, createDocumentFragment() { return element(true); },
  };
  const context = vm.createContext({ document, window: { __TAURI__: { core: { invoke } } } });
  vm.runInContext(fs.readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), context);
  return { context, refs, count: () => created, evaluate: (code) => vm.runInContext(code, context) };
}

test("large selections stay paged and unrelated actions do not recreate rows", async () => {
  const ui = fixture();
  ui.evaluate('addSelectedFiles(Array.from({length:10000},(_,i)=>`C:/folder/${i}.txt`))');
  assert.equal(ui.refs.get("file-list").children.length, 100);
  const before = ui.count();
  await ui.evaluate("run(async()=>null,false)");
  assert.equal(ui.count(), before);
  ui.evaluate('addSelectedFiles(Array.from({length:10000},(_,i)=>`C:/folder/${i}.txt`))');
  assert.equal(ui.evaluate("state.files.length"), 10000);
  assert.equal(ui.evaluate("state.fileSet.size"), 10000);
});

test("removing a file on a later page updates the correct selection", () => {
  const ui = fixture();
  ui.evaluate('addSelectedFiles(Array.from({length:250},(_,i)=>`C:/folder/${i}.txt`))');
  ui.refs.get("file-pages").children[2].handlers.get("click")();
  const remove = ui.refs.get("file-list").children[0].children[1];
  remove.handlers.get("click")();
  assert.equal(ui.evaluate('state.fileSet.has("C:/folder/100.txt")'), false);
  assert.equal(ui.evaluate('state.fileSet.has("C:/folder/0.txt")'), true);
  assert.equal(ui.evaluate("state.files.length"), 249);
});

test("results and previews render a bounded number of rows", () => {
  const ui = fixture();
  ui.evaluate('renderResults(Array.from({length:10000},(_,i)=>({input:`${i}.fenc`,ok:true,message:"Verified"})))');
  assert.equal(ui.refs.get("results").children.length, 100);
  ui.evaluate('renderPaged("preview-list","preview-pages",Array.from({length:10000},(_,i)=>i),()=>document.createElement("li"))');
  assert.equal(ui.refs.get("preview-list").children.length, 100);
});


test("deletion retry updates the original status without repeating the successful copy", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    return { state: "removed", source: "C:/source.txt", reason: null, retryId: null };
  });
  ui.evaluate('renderResults([{input:"C:/source.txt",output:"C:/saved.fenc",ok:true,message:"Encrypted",deletion:{state:"retained",source:"C:/source.txt",reason:"File is open",retryId:"receipt"}}])');
  assert.match(ui.refs.get("result-summary").textContent, /1 succeeded, 0 failed.*1 originals retained/);
  const button = ui.refs.get("results").children[0].children[0].children[3];
  assert.equal(button.textContent, "Retry deletion");
  await button.handlers.get("click")();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "retry_deletion");
  assert.equal(calls[0].args.retryId, "receipt");
  assert.equal(ui.evaluate("state.results[0].ok"), true);
  assert.equal(ui.evaluate("state.results[0].deletion.state"), "removed");
  assert.equal(ui.refs.get("result-summary").textContent, "1 succeeded, 0 failed");
  assert.equal(ui.refs.get("results").children[0].children[0].children.length, 3);
  assert.equal(ui.refs.get("progress-panel").hidden, true);
});

test("pending deletion checks are serialized and can be cancelled", async () => {
  let finish;
  let calls = 0;
  const ui = fixture(() => { calls++; return new Promise((resolve) => { finish = resolve; }); });
  ui.evaluate('renderResults([{input:"bundle.zip",ok:true,message:"Decrypted",deletion:{state:"pending",source:"bundle.zip",retryId:"receipt"}}])');
  const before = ui.count();
  const button = ui.refs.get("results").children[0].children[0].children[3];
  assert.equal(button.textContent, "Check deletion");
  const running = button.handlers.get("click")();
  assert.equal(button.disabled, true);
  assert.equal(ui.refs.get("cancel-job").disabled, false);
  assert.equal(ui.count(), before);
  await button.handlers.get("click")();
  assert.equal(calls, 1);
  finish({ state: "pending", source: "bundle.zip", retryId: "next", reason: "Waiting for open readers" });
  await running;
  assert.equal(ui.evaluate("state.results[0].deletion.retryId"), "next");
  assert.equal(ui.refs.get("cancel-job").disabled, true);
  assert.equal(ui.refs.get("results").children[0].children[0].children[3].disabled, false);
});
