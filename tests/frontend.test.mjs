import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { createHash } from "node:crypto";

function fixture(invoke) {
  let created = 0;
  let nextTimer = 0;
  const timers = new Map();
  const refs = new Map();
  const events = new Map();
  function element(fragment = false) {
    return { fragment, children: [], handlers: new Map(), attributes: new Map(), value: "", checked: false,
      classList: { toggle() {} },
      append(...items) { for (const item of items) this.children.push(...(item.fragment ? item.children : [item])); },
      replaceChildren(...items) { this.children = []; this.append(...items); },
      setAttribute(name, value) { this.attributes.set(name, value); }, removeAttribute(name) { this.attributes.delete(name); },
      addEventListener(name, callback) { this.handlers.set(name, callback); }, focus() {},
      showModal() { this.open = true; }, close() { this.open = false; this.handlers.get("close")?.(); },
    };
  }
  const document = { readyState: "loading", addEventListener() {},
    getElementById(id) { if (!refs.has(id)) refs.set(id, element()); return refs.get(id); },
    createElement() { created++; return element(); }, createDocumentFragment() { return element(true); },
  };
  const context = vm.createContext({ document, atob, TextDecoder, Error, window: { addEventListener() {}, __TAURI__: {
    core: { invoke }, event: { async listen(name, callback) { events.set(name, callback); } },
  } },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(fs.readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), context);
  return { context, refs, timers, events, count: () => created, evaluate: (code) => vm.runInContext(code, context),
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

test("Verify shows original names and counts files inside ZIPs without implying saved outputs", async () => {
  const results = [
    { input: "C:/opaque.fenc", originalName: "private notes.txt", output: null, ok: true, message: "Verified" },
    { input: "C:/bundle.zip / a.fenc", originalName: "first/report.txt", output: null, ok: true, message: "Verified" },
    { input: "C:/bundle.zip / b.fenc", originalName: "second/report.txt", output: null, ok: true, message: "Verified" },
    { input: "C:/bundle.zip / damaged.fenc", originalName: "unverified.txt", output: null, ok: false, message: "Authentication failed" },
  ];
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "run_job") return results;
    return { keyLoaded: true, keyPath: "C:/vault.key", fingerprint: "1234" };
  });
  ui.evaluate('state.keyLoaded=true; state.pendingJob={request:{operation:"verify",paths:["C:/opaque.fenc","C:/bundle.zip"]},preview:{canRun:true},revision:state.planRevision}');
  await ui.evaluate("startJob()");
  assert.equal(ui.refs.get("result-summary").textContent, "4 files | 3 verified, 1 failed");
  const rows = ui.refs.get("results").children.map((item) => item.children[0]);
  assert.equal(rows[0].children[0].textContent, "private notes.txt");
  assert.equal(rows[0].children[1].textContent, "Verified · C:/opaque.fenc");
  assert.equal(rows[1].children[0].textContent, "first/report.txt");
  assert.equal(rows[2].children[0].textContent, "second/report.txt");
  assert.match(rows[3].children[0].textContent, /damaged\.fenc$/);
  assert.doesNotMatch(rows[3].children[0].textContent, /unverified/);
  assert.deepEqual(calls.map(({ command }) => command), ["run_job", "get_status"]);
  assert.equal(calls[0].args.request.operation, "verify");
  ui.context.singleResult = [results[0]];
  ui.evaluate('renderResults(singleResult, "verify")');
  assert.equal(ui.refs.get("result-summary").textContent, "1 file | 1 verified, 0 failed");
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

const savedKeyStatus = { keyLoaded: true, keyPath: "C:/vault.key", fingerprint: "1234", sandboxAvailable: true };
const textPreview = (text = "private contents") => ({ kind: "text", mime: "text/plain", data: Buffer.from(text).toString("base64") });

test("encrypted selections warn until a key is loaded", () => {
  const ui = fixture();
  ui.evaluate('addSelectedFiles(["C:/notes.txt"])');
  assert.equal(ui.refs.get("missing-key-warning").hidden, true);
  ui.evaluate('addSelectedFiles(["C:/private.FENC", "C:/bundle.zip"])');
  assert.equal(ui.refs.get("missing-key-warning").hidden, false);
  assert.match(ui.refs.get("missing-key-title").textContent, /No encryption key loaded/);
  ui.context.status = savedKeyStatus;
  ui.evaluate("applyStatus(status, false)");
  assert.equal(ui.refs.get("missing-key-warning").hidden, true);
});

const disconnectedKeyStatus = {
  keyLoaded: false, keyPath: "C:/vault.key", fingerprint: null,
  sandboxAvailable: false, startupKeyUnavailable: true,
};

const settle = () => new Promise(setImmediate);

test("key reconnection keeps file selection and options without restarting work or restoring a cleared list", async () => {
  const calls = [];
  const ui = fixture(async (command) => {
    calls.push(command);
    return { ...savedKeyStatus, keyRevision: 1 };
  });
  await ui.evaluate("init()");
  ui.evaluate('addSelectedFiles({paths:["F:/encrypted/one.fenc","F:/encrypted/two.fenc"],roots:{"F:/encrypted/one.fenc":"F:/encrypted","F:/encrypted/two.fenc":"F:/encrypted"}}); $("overwrite").checked=true; $("remove-original").checked=true; $("output-dir").value="C:/restored"');
  const files = ui.evaluate("JSON.stringify(state.files)");
  const roots = ui.evaluate("JSON.stringify([...state.folderRoots])");
  const changed = ui.events.get("key-status-changed");
  changed({ payload: { ...disconnectedKeyStatus, keyRevision: 2 } });
  assert.match(ui.refs.get("key-recovery-files").textContent, /2 selected files are kept/);
  assert.equal(ui.refs.get("file-list").children.length, 2);
  changed({ payload: { ...savedKeyStatus, keyRevision: 3 } });
  await settle();
  assert.equal(ui.evaluate("JSON.stringify(state.files)"), files);
  assert.equal(ui.evaluate("JSON.stringify([...state.folderRoots])"), roots);
  assert.equal(ui.evaluate("state.fileSet.size"), 2);
  assert.equal(ui.refs.get("file-count").textContent, "(2)");
  assert.equal(ui.refs.get("decrypt").disabled, false);
  assert.equal(ui.refs.get("overwrite").checked, true);
  assert.equal(ui.refs.get("remove-original").checked, true);
  assert.equal(ui.refs.get("output-dir").value, "C:/restored");
  assert.deepEqual(calls, ["get_status"]);
  changed({ payload: { ...disconnectedKeyStatus, keyRevision: 4 } });
  ui.refs.get("startup-key-dialog").close();
  ui.refs.get("clear-files").handlers.get("click")();
  changed({ payload: { ...savedKeyStatus, keyRevision: 5 } });
  assert.equal(ui.evaluate("state.files.length"), 0);
  assert.equal(ui.refs.get("decrypt").disabled, true);
  assert.equal(ui.refs.get("key-recovery-files").hidden, true);
  assert.deepEqual(calls, ["get_status"]);
});

test("a preview finishing after disconnect and reconnect cannot reveal stale names or start a job", async () => {
  for (const operation of ["encrypt", "decrypt", "verify"]) {
    for (const reviewFirst of [false, true]) {
      let finish;
      const calls = [];
      const ui = fixture((command) => {
        calls.push(command);
        return new Promise((resolve) => { finish = resolve; });
      });
      ui.context.loaded = { ...savedKeyStatus, keyRevision: 1 };
      ui.evaluate('applyStatus(loaded,false); addSelectedFiles(["C:/private.fenc"])');
      ui.refs.get("review-first").checked = reviewFirst;
      const preparing = ui.evaluate(`prepareJob("${operation}")`);
      ui.context.disconnected = { ...disconnectedKeyStatus, keyRevision: 2 };
      ui.context.reconnected = { ...savedKeyStatus, keyRevision: 3 };
      ui.evaluate("applyStatus(disconnected,false); applyStatus(reconnected,false)");
      finish({ canRun: true, items: [{ input: "C:/private.fenc", output: "private name.txt", bytes: 1 }], warnings: [], totalBytes: 1 });
      await preparing;
      assert.deepEqual(calls, ["preview_job"]);
      assert.equal(ui.evaluate("state.pendingJob"), null);
      assert.equal(ui.refs.get("preview-panel").hidden, true);
      assert.equal(ui.refs.get("start-job").disabled, true);
      assert.equal(ui.refs.get("file-list").children.length, 1);
    }
  }
});

test("reloading the same key discards reviewed work and requires a fresh plan before starting", async () => {
  const calls = [];
  const ui = fixture(async (command) => {
    calls.push(command);
    if (command === "preview_job") return { canRun: true, items: [{ input: "C:/private.fenc", output: "Verify only", bytes: 1 }], warnings: [], totalBytes: 1 };
    if (command === "run_job") return [{ input: "C:/private.fenc", ok: true, message: "Verified" }];
    return { ...savedKeyStatus, keyRevision: 2 };
  });
  ui.context.loaded = { ...savedKeyStatus, keyRevision: 1 };
  ui.evaluate('applyStatus(loaded,false); addSelectedFiles(["C:/private.fenc"]); $("review-first").checked=true');
  await ui.evaluate('prepareJob("verify")');
  assert.equal(ui.refs.get("start-job").disabled, false);
  ui.context.oldPlan = ui.evaluate("state.pendingJob");
  ui.context.reloaded = { ...savedKeyStatus, keyRevision: 2 };
  ui.evaluate("applyStatus(reloaded,false)");
  assert.equal(ui.evaluate("state.pendingJob"), null);
  assert.equal(ui.refs.get("preview-panel").hidden, true);
  ui.evaluate("state.pendingJob=oldPlan");
  await ui.evaluate("startJob()");
  assert.deepEqual(calls, ["preview_job"]);
  await ui.evaluate('prepareJob("verify")');
  await ui.evaluate("startJob()");
  assert.deepEqual(calls, ["preview_job", "preview_job", "run_job", "get_status"]);
});

async function recoveryFixture() {
  const calls = [];
  let keyStatus = { ...savedKeyStatus, keyRevision: 1 };
  let available = true;
  let opened = 0;
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "get_status" || command === "recheck_key_file") return keyStatus;
    if (command === "check_sandbox" && !available) throw new Error("Sandbox locked. Key file unavailable.");
    if (command === "open_sandbox") {
      if (!available) throw new Error("Sandbox locked. Key file unavailable.");
      return { sessionId: String(++opened), items: [{ id: 0, name: "first.txt" }, { id: 1, name: "second.txt" }], warnings: [] };
    }
    if (command === "read_sandbox_file") return textPreview(`preview ${opened}/${args.itemId}`);
  });
  await ui.evaluate('init()');
  ui.evaluate('addSelectedFiles(["C:/private.fenc", "C:/bundle.zip"])');
  await ui.evaluate('openSandbox()');
  await ui.evaluate('viewSandboxFile(sandbox.items[1])');
  return {
    ui, calls, setAvailable(value) { available = value; },
    change(status, emit = true) {
      keyStatus = status;
      if (emit) ui.events.get("key-status-changed")({ payload: status });
    },
  };
}

test("reconnecting the same key opens a fresh sandbox and restores the previous preview", async () => {
  const { ui, calls, change } = await recoveryFixture();
  ui.evaluate('showAlert("An unrelated file error")');
  const changed = ui.events.get("key-status-changed");
  change({ ...disconnectedKeyStatus, keyRevision: 2 });
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  assert.equal(ui.refs.get("startup-key-path").textContent, "C:/vault.key");
  assert.equal(ui.refs.get("fingerprint").textContent, "Key disconnected");
  assert.equal(ui.refs.get("missing-key-title").textContent, "Key disconnected.");
  assert.equal(ui.refs.get("missing-key-warning").hidden, false);
  assert.equal(ui.refs.get("decrypt").disabled, true);
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
  assert.equal(ui.refs.get("sandbox-preview").children.length, 0);
  assert.equal(ui.refs.get("sandbox-list").children.length, 0);
  assert.equal(ui.refs.get("key-recovery-sandbox").hidden, false);
  assert.equal(ui.evaluate("sandbox.recovery.itemId"), 1);
  assert.doesNotMatch(ui.evaluate("JSON.stringify(sandbox.recovery)"), /second\.txt|preview 1/);

  changed({ payload: { ...savedKeyStatus, keyRevision: 3, message: "Key reconnected and loaded." } });
  await settle();
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(ui.refs.get("missing-key-warning").hidden, true);
  assert.equal(ui.refs.get("decrypt").disabled, false);
  assert.equal(ui.refs.get("view-sandbox").disabled, false);
  assert.equal(ui.refs.get("key-message").textContent, "Key reconnected and loaded.");
  assert.equal(ui.refs.get("alert").textContent, "An unrelated file error");
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  assert.equal(ui.refs.get("sandbox-preview").children.length, 1);
  assert.match(ui.refs.get("sandbox-preview").children[0].srcdoc, /preview 2\/1/);
  assert.equal(ui.refs.get("sandbox-file-name").textContent, "second.txt");
  assert.equal(ui.evaluate("sandbox.recovery"), null);
  const openings = calls.filter(({ command }) => command === "open_sandbox");
  assert.equal(openings.length, 2);
  assert.equal(JSON.stringify(openings[1].args.paths), '["C:/private.fenc","C:/bundle.zip"]');
  ui.evaluate("resetSandbox()");
});

test("a quick key reconnect recovers even before the global key monitor reports removal", async () => {
  const { ui, setAvailable } = await recoveryFixture();
  setAvailable(false);
  await ui.fireTimer();
  assert.equal(ui.evaluate("state.keyLoaded"), true);
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
  assert.equal(ui.timers.values().next().value.delay, 1000);
  setAvailable(true);
  await ui.fireTimer();
  await settle();
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  assert.equal(ui.refs.get("sandbox-file-name").textContent, "second.txt");
  ui.evaluate("resetSandbox()");
});

test("sandbox recovery waits for a protected key to be unlocked in Key options", async () => {
  const { ui, calls, change } = await recoveryFixture();
  change({ ...disconnectedKeyStatus, keyRevision: 2 });
  change({ ...disconnectedKeyStatus, keyRevision: 3, startupKeyUnavailable: false, message: "Key file needs its passphrase." });
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
  assert.equal(ui.evaluate("sandbox.recovery.waitingForUnlock"), true);
  assert.equal(ui.timers.size, 0);
  ui.refs.get("sandbox-key-options").handlers.get("click")();
  assert.equal(ui.refs.get("key-dialog").open, true);
  change({ ...savedKeyStatus, keyRevision: 4 });
  assert.equal(calls.filter(({ command }) => command === "open_sandbox").length, 1);
  ui.refs.get("key-dialog").close();
  await settle();
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  assert.equal(ui.refs.get("sandbox-file-name").textContent, "second.txt");
  ui.evaluate("resetSandbox()");
});

test("closing, unloading, or switching keys cancels automatic sandbox recovery", async () => {
  for (const action of ["close", "unload", "switch"]) {
    const { ui, calls, change, setAvailable } = await recoveryFixture();
    if (action === "unload") {
      setAvailable(false);
      await ui.fireTimer();
      change({ ...disconnectedKeyStatus, keyRevision: 2, startupKeyUnavailable: false });
    } else {
      change({ ...disconnectedKeyStatus, keyRevision: 2 });
      if (action === "close") ui.refs.get("sandbox-dialog").close();
      else change({ ...savedKeyStatus, keyRevision: 3, fingerprint: "different-key" });
    }
    assert.equal(ui.evaluate("sandbox.recovery"), null);
    setAvailable(true);
    change({ ...savedKeyStatus, keyRevision: 4 });
    await settle();
    assert.equal(calls.filter(({ command }) => command === "open_sandbox").length, 1);
    assert.equal(ui.evaluate("sandbox.sessionId"), null);
    assert.equal(ui.timers.size, 0);
  }
});

test("reconnected sandbox waits for an in-flight action to finish", async () => {
  const { ui, calls, change } = await recoveryFixture();
  let finish;
  ui.context.work = new Promise((resolve) => { finish = resolve; });
  const working = ui.evaluate("run(() => work, false)");
  change({ ...disconnectedKeyStatus, keyRevision: 2 });
  change({ ...savedKeyStatus, keyRevision: 3 });
  assert.equal(calls.filter(({ command }) => command === "open_sandbox").length, 1);
  finish(null);
  await working;
  await settle();
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  ui.evaluate("resetSandbox()");
});

test("popup checks the saved path and offers a direct picker with inline errors", async () => {
  const calls = [];
  let selected = false;
  const ui = fixture(async (command) => {
    calls.push(command);
    if (command === "browse_key") {
      if (!selected) throw new Error("This key needs its passphrase. Open Key options to unlock it.");
      return { ...savedKeyStatus, keyRevision: 2 };
    }
    return { ...disconnectedKeyStatus, keyRevision: 1 };
  });
  await ui.evaluate("init()");
  await ui.refs.get("check-key-again").handlers.get("click")();
  assert.ok(calls.includes("recheck_key_file"));
  assert.equal(ui.refs.get("key-recovery-status").textContent, "Still waiting for your key");
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  await settle();
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  assert.equal(ui.refs.get("key-recovery-alert").hidden, false);
  assert.match(ui.refs.get("key-recovery-alert").textContent, /passphrase/);
  selected = true;
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  await settle();
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(ui.evaluate("state.keyLoaded"), true);
  assert.equal(calls.filter((command) => command === "browse_key").length, 2);
});

test("a protected key returning clears the disconnect popup but still requires unlocking", async () => {
  const ui = fixture(async () => ({ ...disconnectedKeyStatus, keyRevision: 1 }));
  await ui.evaluate("init()");
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  ui.refs.get("startup-key-dialog").close();
  ui.events.get("key-status-changed")({ payload: { ...disconnectedKeyStatus, keyRevision: 1 } });
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  // Reopen the existing warning to check that recovery closes it itself.
  ui.refs.get("startup-key-dialog").showModal();
  ui.events.get("key-status-changed")({ payload: {
    ...disconnectedKeyStatus, keyRevision: 2, startupKeyUnavailable: false,
    message: "Key file reconnected. This key file needs its passphrase.",
  } });
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(ui.refs.get("fingerprint").textContent, "No key loaded");
  assert.match(ui.refs.get("key-message").textContent, /needs its passphrase/);
  assert.equal(ui.refs.get("decrypt").disabled, true);
});

test("repeated recovery checks share one read while a key drive is stalled", async () => {
  let finish;
  let calls = 0;
  const ui = fixture(() => {
    calls++;
    return new Promise((resolve) => { finish = resolve; });
  });
  const first = ui.evaluate("recheckKeyFileStatus()");
  const expired = assert.rejects(first, /taking too long/);
  ui.fireTimer();
  await expired;
  const second = ui.evaluate("recheckKeyFileStatus()");
  assert.equal(calls, 1);
  finish(savedKeyStatus);
  assert.equal(await second, savedKeyStatus);
  assert.equal(ui.timers.size, 0);
});

test("an invalid encrypted source does not start automatic key recovery", async () => {
  const ui = fixture(async () => { throw new Error("This file is not a FileEncrypt file."); });
  readySandbox(ui);
  await ui.evaluate("openSandbox()");
  assert.equal(ui.evaluate("sandbox.recovery"), null);
  assert.equal(ui.timers.size, 0);
  assert.match(ui.refs.get("sandbox-status").textContent, /not a FileEncrypt file/);
});

test("late status responses cannot undo key removal or reconnection", async () => {
  const ui = fixture(async () => ({ ...savedKeyStatus, keyRevision: 1 }));
  await ui.evaluate("init()");
  const changed = ui.events.get("key-status-changed");
  changed({ payload: { ...disconnectedKeyStatus, keyRevision: 2 } });
  ui.context.oldStatus = { ...savedKeyStatus, keyRevision: 1 };
  ui.evaluate("applyStatus(oldStatus, true)");
  assert.equal(ui.evaluate("state.keyLoaded"), false);
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  changed({ payload: { ...savedKeyStatus, keyRevision: 3 } });
  changed({ payload: { ...disconnectedKeyStatus, keyRevision: 2 } });
  assert.equal(ui.evaluate("state.keyLoaded"), true);
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
});

function readySandbox(ui) {
  ui.context.savedKeyStatus = savedKeyStatus;
  ui.evaluate('applyStatus(savedKeyStatus, false); addSelectedFiles(["C:/private.fenc"])');
}

test("sandbox control requires a saved key even when a session key is loaded", () => {
  const ui = fixture();
  readySandbox(ui);
  assert.equal(ui.refs.get("view-sandbox").disabled, false);
  ui.evaluate('applyStatus({keyLoaded:true,keyPath:null,fingerprint:"1234",sandboxAvailable:true},false)');
  assert.equal(ui.refs.get("view-sandbox").disabled, true);
  assert.equal(ui.refs.get("decrypt").disabled, false);
});

test("sandbox uses an isolated inert preview and never invokes disk decryption", async () => {
  const calls = [];
  const content = textPreview('<script>parent.stolen=true</script><img src="https://example.com/leak">');
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "open_sandbox") return { sessionId: "1", items: [{ id: 0, name: "private.html", kind: "text" }], warnings: [] };
    if (command === "read_sandbox_file") return content;
  });
  readySandbox(ui);
  await ui.evaluate("openSandbox()");
  const frame = ui.refs.get("sandbox-preview").children[0];
  assert.equal(frame.attributes.get("sandbox"), "");
  assert.equal(frame.attributes.get("referrerpolicy"), "no-referrer");
  assert.match(frame.srcdoc, /&lt;script&gt;/);
  assert.doesNotMatch(frame.srcdoc, /<script>|<img src="https:/);
  assert.match(frame.srcdoc, /default-src 'none'/);
  assert.match(frame.srcdoc, /img-src data:; media-src data:/);
  assert.equal(content.data, "");
  assert.ok(calls.every(({ command }) => ["open_sandbox", "read_sandbox_file", "check_sandbox"].includes(command)));
  ui.evaluate("resetSandbox()");
  assert.equal(ui.refs.get("sandbox-preview").children.length, 0);
  assert.equal(ui.refs.get("sandbox-list").children.length, 0);
  assert.equal(ui.evaluate("sandbox.items.length"), 0);
  assert.equal(ui.refs.get("sandbox-file-name").textContent, "");
  assert.equal(ui.timers.size, 0);
});

test("sandbox preview style is allowed by the exact CSP hash without allowing inline scripts", () => {
  const ui = fixture();
  const hash = "sha256-" + createHash("sha256").update(ui.evaluate("SANDBOX_STYLE")).digest("base64");
  assert.equal(ui.evaluate("SANDBOX_STYLE_HASH"), hash);
  const config = JSON.parse(fs.readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.ok(config.app.security.csp.includes(`'${hash}'`));
  assert.ok(!config.app.security.csp.includes("unsafe-inline"));
  assert.ok(!config.app.security.csp.includes("unsafe-eval"));
});

test("media stays inside the isolated document and active image formats are refused", () => {
  const ui = fixture();
  ui.context.content = { kind: "image", mime: "image/png", data: "cHJpdmF0ZQ==" };
  const html = ui.evaluate("sandboxDocument(content)");
  assert.match(html, /<img src="data:image\/png;base64,cHJpdmF0ZQ=="/);
  assert.equal(ui.context.content.data, "");
  ui.context.content = { kind: "image", mime: "image/svg+xml", data: "cHJpdmF0ZQ==" };
  assert.throws(() => ui.evaluate("sandboxDocument(content)"), /Unsupported preview format/);
});

test("loss of key-file access clears already displayed plaintext despite a cached key", async () => {
  let available = true;
  const ui = fixture(async (command) => {
    if (command === "open_sandbox") return { sessionId: "1", items: [{ id: 0, name: "private.txt" }], warnings: [] };
    if (command === "read_sandbox_file") return textPreview();
    if (command === "check_sandbox" && !available) throw new Error("Key file unavailable");
  });
  readySandbox(ui);
  await ui.evaluate("openSandbox()");
  assert.equal(ui.refs.get("sandbox-preview").children.length, 1);
  available = false;
  await ui.fireTimer();
  assert.equal(ui.evaluate("state.keyLoaded"), true);
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
  assert.equal(ui.refs.get("sandbox-preview").children.length, 0);
  assert.equal(ui.refs.get("sandbox-list").children.length, 0);
  assert.match(ui.refs.get("sandbox-status").textContent, /Key file unavailable/);
  assert.equal(ui.timers.size, 1);
  ui.evaluate("resetSandbox()");
  assert.equal(ui.timers.size, 0);
});

test("a stalled key check locks after its deadline and cannot revive the preview", async () => {
  let finish;
  const ui = fixture((command) => command === "check_sandbox" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve());
  ui.evaluate('sandbox.sessionId="1"; $("sandbox-preview").append(document.createElement("iframe")); scheduleSandboxCheck()');
  const check = ui.fireTimer();
  assert.equal(ui.timers.values().next().value.delay, 1500);
  ui.fireTimer();
  await check;
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
  assert.equal(ui.refs.get("sandbox-preview").children.length, 0);
  finish();
  await Promise.resolve();
  assert.equal(ui.timers.size, 0);
});

test("a delayed plaintext response cannot repopulate a closed or locked sandbox", async () => {
  let finish;
  const content = textPreview();
  const ui = fixture((command) => command === "read_sandbox_file" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve());
  ui.evaluate('sandbox.sessionId="1"');
  const viewing = ui.evaluate('viewSandboxFile({id:0,name:"private.txt"})');
  ui.evaluate("lockSandbox()");
  finish(content);
  await viewing;
  assert.equal(ui.refs.get("sandbox-preview").children.length, 0);
  assert.equal(content.data, "");
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
});

test("a catalogue that arrives after closing is revoked without revealing file names", async () => {
  let finish;
  const closed = [];
  const ui = fixture((command, args) => {
    if (command === "open_sandbox") return new Promise((resolve) => { finish = resolve; });
    if (command === "close_sandbox") closed.push(args.sessionId);
    return Promise.resolve();
  });
  readySandbox(ui);
  const opening = ui.evaluate("openSandbox()");
  ui.evaluate("resetSandbox()");
  finish({ sessionId: "late", items: [{ id: 0, name: "private.txt" }], warnings: [] });
  await opening;
  assert.deepEqual(closed, ["late"]);
  assert.equal(ui.refs.get("sandbox-list").children.length, 0);
  assert.equal(ui.evaluate("state.busy"), false);
});
