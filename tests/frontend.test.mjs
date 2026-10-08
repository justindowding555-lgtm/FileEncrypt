import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

function fixture(invoke) {
  let created = 0;
  let nextTimer = 0;
  const timers = new Map();
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
  const context = vm.createContext({ document, window: { __TAURI__: { core: { invoke } } },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(fs.readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), context);
  return { context, refs, timers, count: () => created, evaluate: (code) => vm.runInContext(code, context),
    fireTimer() {
      const [id, timer] = timers.entries().next().value;
      timers.delete(id);
      return timer.callback();
    },
  };
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

test("pending deletions update automatically without blocking controls or requiring a button", async () => {
  let finish;
  const calls = [];
  const ui = fixture((command, args) => {
    calls.push({ command, args });
    return new Promise((resolve) => { finish = resolve; });
  });
  ui.evaluate('renderResults([{input:"bundle.zip",ok:true,message:"Decrypted",deletion:{state:"pending",source:"bundle.zip",retryId:"receipt"}}]); renderControls()');
  const text = ui.refs.get("results").children[0].children[0];
  assert.equal(text.children.length, 3);
  assert.match(text.children[2].textContent, /Checking automatically/);
  assert.equal(ui.timers.size, 1);
  const running = ui.fireTimer();
  assert.equal(calls[0].command, "check_pending_deletions");
  assert.equal(JSON.stringify(calls[0].args.retryIds), '["receipt"]');
  assert.equal(ui.evaluate("state.busy"), false);
  assert.equal(ui.evaluate("state.jobRunning"), false);
  assert.equal(ui.refs.get("add-files").disabled, false);
  assert.equal(ui.refs.get("cancel-job").disabled, true);
  await ui.evaluate("checkPendingDeletions()");
  assert.equal(calls.length, 1);
  finish([{ retryId: "receipt", deletion: { state: "removed", source: "bundle.zip", retryId: null, reason: null } }]);
  await running;
  assert.equal(ui.evaluate("state.results[0].deletion.state"), "removed");
  assert.equal(ui.refs.get("result-summary").textContent, "1 succeeded, 0 failed");
  assert.equal(ui.timers.size, 0);
});

test("automatic checks pause during jobs and do not redraw unchanged pending rows", async () => {
  let calls = 0;
  const ui = fixture(async () => {
    calls++;
    return [{ retryId: "receipt", deletion: { state: "pending", source: "bundle.zip", retryId: "receipt", reason: "Waiting" } }];
  });
  ui.evaluate('renderResults([{input:"bundle.zip",ok:true,message:"Decrypted",deletion:{state:"pending",source:"bundle.zip",retryId:"receipt",reason:"Waiting"}}]); state.busy=true');
  await ui.fireTimer();
  assert.equal(calls, 0);
  assert.equal(ui.timers.size, 1);
  ui.evaluate("state.busy=false");
  const before = ui.count();
  await ui.fireTimer();
  assert.equal(calls, 1);
  assert.equal(ui.count(), before);
  assert.equal(ui.timers.size, 1);
});

test("an in-flight automatic check cannot overwrite a newer report", async () => {
  let finish;
  const ui = fixture(() => new Promise((resolve) => { finish = resolve; }));
  ui.evaluate('renderResults([{input:"old.zip",ok:true,message:"Decrypted",deletion:{state:"pending",source:"old.zip",retryId:"old"}}])');
  const running = ui.fireTimer();
  ui.evaluate('renderResults([{input:"new.fenc",ok:true,message:"Verified"}])');
  finish([{ retryId: "old", deletion: { state: "removed", source: "old.zip", retryId: null } }]);
  await running;
  assert.equal(ui.evaluate("state.results[0].input"), "new.fenc");
  assert.equal(ui.evaluate("state.results[0].deletion"), undefined);
  assert.equal(ui.timers.size, 0);
});

test("a check finishing during another job still records the confirmed deletion", async () => {
  let finish;
  const ui = fixture(() => new Promise((resolve) => { finish = resolve; }));
  ui.evaluate('renderResults([{input:"bundle.zip",ok:true,message:"Decrypted",deletion:{state:"pending",source:"bundle.zip",retryId:"receipt"}}])');
  const running = ui.fireTimer();
  ui.evaluate("state.busy=true; state.jobRunning=true");
  finish([{ retryId: "receipt", deletion: { state: "removed", source: "bundle.zip", retryId: null } }]);
  await running;
  assert.equal(ui.evaluate("state.results[0].deletion.state"), "removed");
  assert.equal(ui.evaluate("state.busy"), true);
  assert.equal(ui.evaluate("state.jobRunning"), true);
  assert.equal(ui.timers.size, 0);
});

test("automatic checks cover pending rows across pages in bounded batches and leave retained files alone", async () => {
  const checked = new Set();
  const sizes = [];
  const ui = fixture(async (command, { retryIds }) => {
    assert.equal(command, "check_pending_deletions");
    sizes.push(retryIds.length);
    return retryIds.map((retryId) => {
      checked.add(retryId);
      return { retryId, deletion: { state: "pending", source: `${retryId}.zip`, retryId, reason: "Waiting" } };
    });
  });
  ui.evaluate('renderResults([...Array.from({length:250},(_,i)=>({input:`${i}.zip`,ok:true,message:"Decrypted",deletion:{state:"pending",source:`${i}.zip`,retryId:String(i),reason:"Waiting"}})), {input:"retained.txt",ok:true,deletion:{state:"retained",source:"retained.txt",retryId:"retained"}}, {input:"expired.zip",ok:true,deletion:{state:"pending",source:"expired.zip",retryId:null}}])');
  for (let i = 0; i < 3; i++) await ui.fireTimer();
  assert.equal(checked.size, 250);
  assert.equal(checked.has("retained"), false);
  assert.ok(sizes.every((size) => size <= 100));
  assert.equal(ui.evaluate("state.results[250].deletion.retryId"), "retained");
  assert.equal(ui.refs.get("results").children.length, 100);
  assert.equal(ui.timers.size, 1);
  ui.evaluate("renderResults([])");
  assert.equal(ui.timers.size, 0);
});

test("automatic checks back off after errors and stop on an expired receipt without claiming retention", async () => {
  let calls = 0;
  const ui = fixture(async () => {
    if (++calls <= 4) throw new Error("IPC unavailable");
    return [{ retryId: "receipt", deletion: null }];
  });
  ui.evaluate('renderResults([{input:"bundle.zip",ok:true,message:"Decrypted",deletion:{state:"pending",source:"bundle.zip",retryId:"receipt"}}])');
  for (const expectedDelay of [2000, 4000, 8000, 10000]) {
    await ui.fireTimer();
    assert.equal(ui.timers.values().next().value.delay, expectedDelay);
    assert.equal(ui.evaluate("state.results[0].deletion.state"), "pending");
  }
  await ui.fireTimer();
  assert.equal(ui.evaluate("state.results[0].deletion.state"), "pending");
  assert.equal(ui.evaluate("state.results[0].deletion.retryId"), null);
  assert.match(ui.evaluate("state.results[0].deletion.reason"), /no longer available/);
  assert.equal(ui.timers.size, 0);
});
