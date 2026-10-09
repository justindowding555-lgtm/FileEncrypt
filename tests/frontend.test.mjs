import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { createHash } from "node:crypto";

function fixture(invoke, script = "main", automaticVerification = false, automaticDecode = true) {
  let created = 0;
  let nextTimer = 0;
  const timers = new Map();
  const refs = new Map();
  const events = new Map();
  function element(fragment = false) {
    return { fragment, children: [], handlers: new Map(), attributes: new Map(), value: "", checked: false, style: {}, offsetWidth: 220, offsetHeight: 120,
      classList: { toggle() {}, add() {}, remove() {} },
      append(...items) { for (const item of items) {
        this.children.push(...(item.fragment ? item.children : [item]));
        if (automaticDecode && item.contentWindow && script === "sandbox-preview") queueMicrotask(() => {
          context.testFrame = item;
          vm.runInContext('handlePrivatePreviewMessage({source:testFrame.contentWindow,origin:"null",data:{channel:"fileencrypt-preview",type:"ready",kind:previewWindow.kind}})', context);
        });
      } },
      replaceChildren(...items) { this.children = []; this.append(...items); },
      setAttribute(name, value) { this.attributes.set(name, value); }, removeAttribute(name) { this.attributes.delete(name); },
      addEventListener(name, callback) { this.handlers.set(name, callback); }, focus() { document.activeElement = this; },
      getBoundingClientRect() { return { left: 0, top: 0, right: 1100, bottom: 780 }; },
      contains(target) { return this === target || this.children.some((child) => child.contains?.(target)); },
      showModal() { this.open = true; }, close() { this.open = false; this.handlers.get("close")?.(); },
    };
  }
  const document = { readyState: "loading", addEventListener() {},
    getElementById(id) { if (!refs.has(id)) refs.set(id, element()); return refs.get(id); },
    createElement(tag) { created++; const item = element(); if (tag === "iframe") item.contentWindow = { messages: [], postMessage(data) { this.messages.push(data); } }; return item; }, createDocumentFragment() { return element(true); },
  };
  const context = vm.createContext({ document, atob, TextDecoder, Error, window: { addEventListener() {}, __TAURI__: {
    core: { invoke(command, args) {
      if (command === "verify_selected_files" && !automaticVerification) {
        return Promise.resolve(args.paths.map((input) => ({ input, state: "verified", complete: true, entryCount: 1 })));
      }
      return invoke?.(command, args);
    } }, event: { async listen(name, callback) { events.set(name, callback); } },
  } },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  for (const file of ["explorer-icons.js", "sandbox-viewer.js", "sandbox-content.js", `${script}.js`]) {
    vm.runInContext(fs.readFileSync(new URL(`../src/${file}`, import.meta.url), "utf8"), context);
  }
  return { context, refs, timers, events, count: () => created, evaluate: (code) => vm.runInContext(code, context),
    fireTimer() {
      const [id, timer] = timers.entries().next().value;
      timers.delete(id);
      return timer.callback();
    },
  };
}

test("added encrypted files and folder ZIPs verify with an icon before the filename", async () => {
  let finish;
  const calls = [];
  const ui = fixture((command, args) => {
    calls.push({ command, args });
    return new Promise((resolve) => { finish = resolve; });
  }, "main", true);
  ui.evaluate('state.keyLoaded=true; state.keyRevision=1; fileVerification.ready=true; renderResults([{input:"earlier.txt",ok:true,message:"Encrypted"}]); addSelectedFiles({paths:["C:/folder/one.fenc","C:/folder/bundle.zip","C:/folder/plain.txt"],roots:{"C:/folder/one.fenc":"C:/folder"}})');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "verify_selected_files");
  assert.equal(JSON.stringify(calls[0].args), '{"paths":["C:/folder/one.fenc","C:/folder/bundle.zip"],"keyRevision":1}');
  const rows = ui.refs.get("file-list").children;
  const heading = rows[0].children[0].children[0];
  assert.match(heading.children[0].className, /is-checking/);
  assert.equal(heading.children[1].textContent, "one.fenc");
  assert.equal(rows[0].children[0].children.length, 1);
  assert.equal(rows[2].children[0].children[0].children.length, 2);
  assert.match(rows[2].children[0].children[0].children[0].className, /is-unencrypted/);
  const before = ui.count();
  finish(calls[0].args.paths.map((input) => ({ input, state: "verified", complete: true })));
  await settle();
  assert.match(heading.children[0].className, /is-verified/);
  assert.match(heading.children[0].innerHTML, /<circle/);
  assert.equal(ui.count(), before);
  assert.equal(ui.refs.get("result-summary").textContent, "1 succeeded, 0 failed");
  assert.equal(ui.refs.has("verify"), false);
  assert.doesNotMatch(fs.readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), /Expected result/);
});

test("automatic verification handles large selections in bounded batches", async () => {
  const batches = [];
  const ui = fixture(async (command, args) => {
    assert.equal(command, "verify_selected_files");
    batches.push(args.paths.length);
    return args.paths.map((input) => ({ input, state: "verified", complete: true }));
  }, "main", true);
  ui.evaluate('state.keyLoaded=true; fileVerification.ready=true; addSelectedFiles(Array.from({length:70},(_,i)=>`C:/folder/${i}.fenc`))');
  await settle();
  assert.deepEqual(batches, [32, 32, 6]);
  assert.equal(ui.evaluate('[...fileVerification.entries.values()].every(result=>result.state==="verified")'), true);
  assert.equal(ui.evaluate("state.busy"), false);
});

test("key changes invalidate checkmarks and ignore verification from the previous key", async () => {
  const requests = [];
  const ui = fixture((command, args) => new Promise((resolve) => { requests.push({ args, resolve }); }), "main", true);
  ui.evaluate('fileVerification.ready=true; addSelectedFiles(["C:/private.fenc"])');
  assert.equal(requests.length, 0);
  ui.context.loaded = { ...savedKeyStatus, keyRevision: 1 };
  ui.evaluate('applyStatus(loaded,false)');
  assert.equal(requests.length, 1);
  ui.context.changed = { ...savedKeyStatus, fingerprint: "other", keyRevision: 2 };
  ui.evaluate('applyStatus(changed,false)');
  requests[0].resolve([{ input: "C:/private.fenc", state: "verified", complete: true }]);
  await settle();
  assert.equal(requests.length, 2);
  assert.equal(requests[1].args.keyRevision, 2);
  assert.equal(ui.evaluate('fileVerification.entries.get("C:/private.fenc").state'), "checking");
  requests[1].resolve([{ input: "C:/private.fenc", state: "failed", message: "Authentication failed" }]);
  await settle();
  assert.match(ui.refs.get("file-list").children[0].children[0].children[0].children[0].title, /Authentication failed/);
});

test("removing and adding the same file ignores the previous verification result", async () => {
  const requests = [];
  const ui = fixture((command, args) => new Promise((resolve) => { requests.push({ args, resolve }); }), "main", true);
  ui.evaluate('state.keyLoaded=true; fileVerification.ready=true; addSelectedFiles(["C:/private.fenc"])');
  ui.refs.get("file-list").children[0].children[1].handlers.get("click")();
  ui.evaluate('addSelectedFiles(["C:/private.fenc"])');
  requests[0].resolve([{ input: "C:/private.fenc", state: "verified", complete: true }]);
  await settle();
  assert.equal(requests.length, 2);
  assert.equal(ui.evaluate('fileVerification.entries.get("C:/private.fenc").state'), "checking");
  requests[1].resolve([{ input: "C:/private.fenc", state: "verified", complete: false, message: "Older ZIP completeness cannot be authenticated." }]);
  await settle();
  const badge = ui.refs.get("file-list").children[0].children[0].children[0].children[0];
  assert.match(badge.className, /is-partial/);
  assert.match(badge.title, /completeness/);
});

test("verification pauses for foreground work without repeatedly retrying a paused batch", async () => {
  let calls = 0;
  const ui = fixture(async (command, args) => {
    calls++;
    return args.paths.map((input) => ({ input, state: calls === 1 ? "pending" : "verified", complete: true }));
  }, "main", true);
  ui.evaluate('state.keyLoaded=true; state.busy=true; fileVerification.ready=true; addSelectedFiles(["C:/private.fenc"])');
  await settle();
  assert.equal(calls, 0);
  ui.evaluate('state.busy=false; startAutomaticVerification()');
  await settle();
  assert.equal(calls, 1);
  ui.evaluate('startAutomaticVerification()');
  await settle();
  assert.equal(calls, 2);
  assert.equal(ui.evaluate('fileVerification.entries.get("C:/private.fenc").state'), "verified");
});

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

test("selection additions enforce the total limit before changing files or roots", () => {
  const calls = [];
  const ui = fixture(async (command) => { calls.push(command); });
  ui.evaluate('savedSelection.ready=true; addSelectedFiles(Array.from({length:6000},(_,i)=>`C:/first/${i}.txt`))');
  const before = calls.length;
  assert.throws(() => ui.evaluate('addSelectedFiles({paths:["C:/first/0.txt",...Array.from({length:6000},(_,i)=>`C:/second/${i}.txt`)],roots:{"C:/first/0.txt":"C:/changed"}})'), /at most 10,000 files in total/);
  assert.equal(ui.evaluate("state.files.length"), 6000);
  assert.equal(ui.evaluate("state.fileSet.size"), 6000);
  assert.equal(ui.evaluate("state.folderRoots.size"), 0);
  assert.equal(calls.length, before);
  ui.evaluate('addSelectedFiles(Array.from({length:4000},(_,i)=>`C:/second/${i}.txt`)); addSelectedFiles(["C:/second/0.txt","C:/second/0.txt"])');
  assert.equal(ui.evaluate("state.files.length"), 10000);
  assert.throws(() => ui.evaluate('addSelectedFiles(["C:/extra.txt"])'), /at most 10,000/);
});

test("partial key rotation rechecks selected files even when the old key stays loaded", async () => {
  let rotated = false;
  let checks = 0;
  const status = { ...savedKeyStatus, keyRevision: 1 };
  const ui = fixture(async (command, args) => {
    if (command === "get_status") return status;
    if (command === "restore_selected_files") return { paths: [], roots: {} };
    if (command === "verify_selected_files") {
      checks++;
      return args.paths.map((input) => ({ input, state: rotated && input === "C:/first.fenc" ? "failed" : "verified", complete: true }));
    }
    if (command === "rotate_key") {
      rotated = true;
      return { results: [{ input: "C:/first.fenc", output: "C:/rotated.fenc", ok: true }, { input: "C:/second.fenc", ok: false }], status, newKeyPath: "C:/new.key", notice: "Rotation was incomplete. New key file: C:/new.key." };
    }
  }, "main", true);
  await ui.evaluate("init()");
  ui.evaluate('addSelectedFiles(["C:/first.fenc","C:/second.fenc"])');
  await settle();
  assert.equal(checks, 1);
  assert.equal(ui.evaluate('fileVerification.entries.get("C:/first.fenc").state'), "verified");
  await ui.refs.get("rotate-key").handlers.get("click")();
  await settle();
  assert.equal(checks, 2);
  assert.equal(ui.evaluate('fileVerification.entries.get("C:/first.fenc").state'), "failed");
  assert.equal(ui.evaluate('fileVerification.entries.get("C:/second.fenc").state'), "verified");
  assert.equal(ui.evaluate("state.results.length"), 2);
  assert.match(ui.refs.get("alert").textContent, /C:\/new\.key/);
});

test("rotation reports preserve recovery instructions during emergency lock", async () => {
  const ui = fixture(async (command) => {
    if (command === "get_status") return { ...savedKeyStatus, keyRevision: 1 };
    if (command === "restore_selected_files") return { paths: [], roots: {} };
    if (command === "rotate_key") return {
      results: [{ input: "C:/first.fenc", output: "C:/rotated.fenc", ok: true }],
      status: { ...savedKeyStatus, keyRevision: 2, keyLoaded: false, emergencyLocked: true, message: "Unable to read the saved key." },
      newKeyPath: "C:/new.key", notice: "Files were rotated, but the new key could not be activated. New key file: C:/new.key.",
    };
  });
  await ui.evaluate("init()");
  ui.evaluate('addSelectedFiles(["C:/first.fenc"])');
  await ui.refs.get("rotate-key").handlers.get("click")();
  assert.equal(ui.evaluate("state.results.length"), 1);
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  assert.match(ui.refs.get("key-recovery-alert").textContent, /New key file: C:\/new\.key/);
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

test("encrypted selections keep key-dependent actions disabled without a duplicate Files warning", () => {
  const ui = fixture();
  ui.evaluate('addSelectedFiles(["C:/notes.txt"])');
  ui.evaluate('addSelectedFiles(["C:/private.FENC", "C:/bundle.zip"])');
  assert.equal(ui.refs.has("missing-key-warning"), false);
  assert.equal(ui.refs.get("decrypt").disabled, true);
  assert.equal(ui.refs.get("view-sandbox").disabled, true);
  assert.doesNotMatch(fs.readFileSync(new URL("../src/index.html", import.meta.url), "utf8"), /id="missing-key-warning"/);
  ui.context.status = savedKeyStatus;
  ui.evaluate("applyStatus(status, false)");
  assert.equal(ui.refs.get("decrypt").disabled, false);
});

const disconnectedKeyStatus = {
  keyLoaded: false, keyPath: "C:/vault.key", fingerprint: null,
  sandboxAvailable: false, startupKeyUnavailable: true,
};

test("files and folders can be added without a key and show blue key badges until a key is loaded", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push(command);
    if (command === "get_status") return { keyLoaded: false, keyRevision: 0 };
    if (command === "pick_input_files") return ["C:/notes.txt", "C:/private.fenc"];
    if (command === "pick_input_folder") return { paths: ["C:/folder/bundle.zip"], roots: { "C:/folder/bundle.zip": "C:/folder" } };
    if (command === "verify_selected_files") return args.paths.map((input) => ({ input, state: "verified", complete: true }));
  }, "main", true);
  await ui.evaluate("init()");
  assert.equal(ui.refs.get("add-files").disabled, false);
  assert.equal(ui.refs.get("add-folder").disabled, false);
  await ui.refs.get("add-files").handlers.get("click")();
  await ui.refs.get("add-folder").handlers.get("click")();
  assert.equal(ui.evaluate("state.files.length"), 3);
  assert.equal(calls.includes("verify_selected_files"), false);
  for (const row of ui.refs.get("file-list").children) {
    const badge = row.children[0].children[0].children[0];
    assert.match(badge.className, /is-needsKey/);
    assert.equal(badge.innerHTML, ui.evaluate("EXPLORER_ICONS.needsKey"));
    assert.match(badge.title, /Load a key/);
    assert.equal(row.children[1].disabled, false);
  }
  ui.context.loaded = { ...savedKeyStatus, keyRevision: 1 };
  ui.evaluate("applyStatus(loaded,false)");
  await settle();
  assert.match(ui.refs.get("file-list").children[0].children[0].children[0].children[0].className, /is-unencrypted/);
  assert.match(ui.refs.get("file-list").children[1].children[0].children[0].children[0].className, /is-verified/);
});

test("disconnected selection remains editable while a cancelled operation is winding down", async () => {
  const ui = fixture(async (command) => {
    if (command === "get_status") return { ...savedKeyStatus, keyRevision: 1 };
    if (command === "pick_input_files") return ["C:/new.fenc"];
  });
  await ui.evaluate("init()");
  ui.evaluate('addSelectedFiles(["C:/old.fenc"]); state.busy=true; state.jobRunning=true');
  ui.events.get("key-status-changed")({ payload: { ...disconnectedKeyStatus, keyRevision: 2 } });
  const remove = ui.refs.get("file-list").children[0].children[1];
  assert.equal(remove.disabled, false);
  assert.equal(ui.refs.get("add-files").disabled, false);
  assert.equal(ui.refs.get("add-folder").disabled, false);
  assert.equal(ui.refs.get("choose-recovery-key").disabled, false);
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  remove.handlers.get("click")();
  assert.equal(ui.evaluate("state.files.length"), 0);
  await ui.refs.get("add-files").handlers.get("click")();
  assert.equal(ui.evaluate('state.fileSet.has("C:/new.fenc")'), true);
  assert.equal(ui.evaluate("state.busy"), true, "editing the selection must not unlock the pending operation");
  assert.match(ui.refs.get("file-list").children[0].children[0].children[0].children[0].className, /is-disconnected/);
});

const settle = () => new Promise(setImmediate);

test("startup restores remembered paths and folder roots when a saved key is loaded", async () => {
  const selection = { paths: ["E:/encrypted/notes.fenc", "E:/encrypted/photos.zip"], roots: { "E:/encrypted/notes.fenc": "E:/encrypted" } };
  const calls = [];
  const ui = fixture(async (command) => {
    calls.push(command);
    if (command === "get_status") return { ...savedKeyStatus, keyRevision: 1 };
    if (command === "restore_selected_files") return selection;
  });
  await ui.evaluate("init()");
  assert.equal(ui.evaluate("JSON.stringify(state.files)"), JSON.stringify(selection.paths));
  assert.equal(ui.evaluate("state.folderRoots.get('E:/encrypted/notes.fenc')"), "E:/encrypted");
  assert.equal(ui.evaluate("state.fileSet.size"), 2);
  assert.equal(ui.refs.get("file-list").children.length, 2);
  assert.equal(ui.refs.get("file-count").textContent, "(2)");
  assert.equal(ui.refs.get("view-sandbox").disabled, false);
  assert.equal(ui.evaluate("state.pendingJob"), null);
  assert.deepEqual(calls, ["get_status", "restore_selected_files"]);
  ui.events.get("key-status-changed")({ payload: { ...savedKeyStatus, keyRevision: 2 } });
  await settle();
  assert.deepEqual(calls, ["get_status", "restore_selected_files"], "later status changes do not reload the list");
});

test("a remembered list waits for an unavailable or protected file key and restores after it is loaded", async () => {
  for (const initial of [disconnectedKeyStatus, { ...disconnectedKeyStatus, startupKeyUnavailable: false }]) {
    const calls = [];
    const ui = fixture(async (command) => {
      calls.push(command);
      if (command === "get_status") return { ...initial, keyRevision: 1 };
      if (command === "restore_selected_files") return { paths: ["E:/private.fenc"], roots: {} };
    });
    await ui.evaluate("init()");
    assert.equal(ui.evaluate("state.files.length"), 0);
    assert.deepEqual(calls, ["get_status"]);
    ui.context.unlocked = { ...savedKeyStatus, keyRevision: 2 };
    await ui.evaluate("run(async()=>unlocked,true)");
    await settle();
    assert.equal(ui.evaluate("JSON.stringify(state.files)"), '["E:/private.fenc"]');
    assert.deepEqual(calls, ["get_status", "restore_selected_files"]);
  }
});

test("additions, removals, and clearing update the selection remembered for the next launch", async () => {
  let remembered = { paths: ["E:/private.fenc"], roots: { "E:/private.fenc": "E:/" } };
  const saves = [];
  const invoke = async (command, args) => {
    if (command === "get_status") return savedKeyStatus;
    if (command === "restore_selected_files") return remembered;
    if (command === "remember_selected_files") {
      const snapshot = JSON.parse(JSON.stringify(args));
      saves.push(snapshot);
      remembered = snapshot.selection;
    }
  };
  const ui = fixture(invoke);
  await ui.evaluate("init()");
  ui.evaluate('addSelectedFiles({paths:["E:/folder/new.zip"],roots:{"E:/folder/new.zip":"E:/folder"}})');
  assert.deepEqual(saves[0].selection, { paths: ["E:/private.fenc", "E:/folder/new.zip"], roots: { "E:/private.fenc": "E:/", "E:/folder/new.zip": "E:/folder" } });
  ui.evaluate('addSelectedFiles(["E:/folder/new.zip"])');
  assert.equal(saves.length, 1, "unchanged selections are not saved again");
  ui.refs.get("file-list").children[0].children[1].handlers.get("click")();
  assert.deepEqual(saves[1].selection, { paths: ["E:/folder/new.zip"], roots: { "E:/folder/new.zip": "E:/folder" } });
  ui.refs.get("clear-files").handlers.get("click")();
  assert.deepEqual(saves[2].selection, { paths: [], roots: {} });
  assert.deepEqual(saves.map(({ revision }) => revision), [1, 2, 3]);
  const reopened = fixture(invoke);
  await reopened.evaluate("init()");
  assert.equal(reopened.evaluate("state.files.length"), 0);
  assert.equal(reopened.refs.get("file-empty").hidden, false);
});

test("late startup restoration cannot resurrect cleared files or overwrite a new selection", async () => {
  for (const clear of [true, false]) {
    let finish;
    const saves = [];
    const ui = fixture(async (command, args) => {
      if (command === "get_status") return savedKeyStatus;
      if (command === "restore_selected_files") return new Promise((resolve) => { finish = resolve; });
      if (command === "remember_selected_files") saves.push(JSON.parse(JSON.stringify(args.selection)));
    });
    const initializing = ui.evaluate("init()");
    await settle();
    ui.evaluate('addSelectedFiles(["C:/new.fenc"])');
    if (clear) ui.refs.get("clear-files").handlers.get("click")();
    finish({ paths: ["E:/old.fenc"], roots: {} });
    await initializing;
    assert.equal(ui.evaluate("JSON.stringify(state.files)"), clear ? "[]" : '["C:/new.fenc"]');
    assert.deepEqual(saves.at(-1), { paths: clear ? [] : ["C:/new.fenc"], roots: {} });
  }
});

test("key loss during startup defers the list until a fresh restore after reconnection", async () => {
  let finish;
  let reads = 0;
  const selection = { paths: ["E:/private.fenc"], roots: {} };
  const ui = fixture(async (command) => {
    if (command === "get_status") return { ...savedKeyStatus, keyRevision: 1 };
    if (command === "restore_selected_files") {
      if (++reads === 1) return new Promise((resolve) => { finish = resolve; });
      return selection;
    }
  });
  const initializing = ui.evaluate("init()");
  await settle();
  ui.events.get("key-status-changed")({ payload: { ...disconnectedKeyStatus, keyRevision: 2 } });
  finish(selection);
  await initializing;
  assert.equal(ui.evaluate("state.files.length"), 0);
  ui.events.get("key-status-changed")({ payload: { ...savedKeyStatus, keyRevision: 3 } });
  await settle();
  assert.equal(reads, 2);
  assert.equal(ui.evaluate("JSON.stringify(state.files)"), JSON.stringify(selection.paths));
});

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
  assert.equal(ui.refs.has("key-recovery-files"), false);
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
  assert.deepEqual(calls, ["get_status", "restore_selected_files", "remember_selected_files"]);
  changed({ payload: { ...disconnectedKeyStatus, keyRevision: 4 } });
  ui.refs.get("startup-key-dialog").close();
  ui.refs.get("clear-files").handlers.get("click")();
  changed({ payload: { ...savedKeyStatus, keyRevision: 5 } });
  assert.equal(ui.evaluate("state.files.length"), 0);
  assert.equal(ui.refs.get("decrypt").disabled, true);
  assert.equal(ui.refs.has("key-recovery-files"), false);
  assert.deepEqual(calls, ["get_status", "restore_selected_files", "remember_selected_files", "remember_selected_files"]);
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

test("emergency locking closes the explorer, cancels recovery, and keeps selected paths", async () => {
  const { ui, change, calls } = await recoveryFixture();
  ui.evaluate('$("key-text").value="secret"; $("key-passphrase").value="secret"');
  const paths = ui.evaluate("JSON.stringify(state.files)");
  change({ ...savedKeyStatus, keyRevision: 2, keyLoaded: false, fingerprint: null,
    emergencyLocked: true, startupKeyUnavailable: true, sandboxAvailable: false });
  assert.equal(ui.refs.get("sandbox-dialog").open, false);
  assert.equal(ui.evaluate("sandbox.recovery"), null);
  assert.equal(ui.evaluate("JSON.stringify(state.files)"), paths);
  assert.equal(ui.refs.get("key-text").value, "");
  assert.equal(ui.refs.get("key-passphrase").value, "");
  assert.equal(ui.refs.get("startup-key-heading").textContent, "Key unavailable");
  assert.equal(ui.refs.get("startup-key-description").textContent, "The saved key file could not be opened.");
  assert.equal(ui.refs.get("startup-key-instructions").hidden, true);
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  for (let revision = 3; revision < 6; revision++) {
    change({ ...savedKeyStatus, keyRevision: revision, emergencyLocked: true });
    assert.equal(ui.evaluate("state.keyLoaded"), false);
    assert.equal(ui.refs.get("key-message").textContent, "Unable to read the saved key.");
  }
  change({ ...savedKeyStatus, keyRevision: 6, emergencyLocked: false });
  await settle();
  assert.equal(ui.refs.get("sandbox-dialog").open, false);
  assert.equal(calls.filter(({ command }) => command === "open_sandbox_preview").length, 1);
});

test("emergency shortcuts ignore repeat, extra modifiers, and native-handled keys", async () => {
  const calls = [];
  const ui = fixture(async (command) => {
    calls.push(command);
    return { ...savedKeyStatus, emergencyLocked: true, keyLoaded: false };
  });
  ui.evaluate('state.emergencyShortcutsNative=true; handleEmergencyShortcut({key:"F12",ctrlKey:true,shiftKey:true,preventDefault(){}})');
  ui.evaluate('state.emergencyShortcutsNative=false; handleEmergencyShortcut({key:"F12",ctrlKey:true,shiftKey:true,repeat:true,preventDefault(){}})');
  ui.evaluate('handleEmergencyShortcut({key:"F12",ctrlKey:true,shiftKey:true,altKey:true,preventDefault(){}})');
  ui.evaluate('handleEmergencyShortcut({key:"F10",ctrlKey:true,shiftKey:true,preventDefault(){}})');
  assert.deepEqual(calls, []);
  await ui.evaluate('handleEmergencyShortcut({key:"F12",ctrlKey:true,shiftKey:true,preventDefault(){}})');
  assert.deepEqual(calls, ["emergency_lock"]);
});

test("Browse and load remains usable during emergency lock and reports the fake read error", async () => {
  const calls = [];
  const locked = { ...savedKeyStatus, keyLoaded: false, emergencyLocked: true,
    emergencyShortcutsNative: true, startupKeyUnavailable: true, sandboxAvailable: false };
  const ui = fixture(async (command) => {
    calls.push(command);
    if (command === "get_status") return locked;
    if (command === "browse_key") throw "Unable to read the saved key.";
  });
  await ui.evaluate("init()");
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  const browse = ui.refs.get("browse-load");
  assert.equal(browse.disabled, false);
  browse.handlers.get("click")();
  await settle();
  assert.equal(calls.filter((command) => command === "browse_key").length, 1);
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  assert.equal(ui.refs.get("startup-key-description").textContent, "The saved key file could not be opened.");
  assert.equal(ui.refs.get("alert").hidden, true);
  assert.equal(ui.refs.get("key-recovery-alert").hidden, true);
  assert.equal(ui.evaluate("state.emergencyLocked"), true);
  assert.equal(ui.evaluate("state.keyLoaded"), false);
  assert.equal(browse.disabled, false);
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  browse.handlers.get("click")();
  await settle();
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  assert.equal(ui.refs.get("key-recovery-alert").hidden, true);
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  ui.evaluate('openKeyOptions(); showAlert("Unable to read  the saved key.")');
  assert.equal(ui.refs.get("key-dialog").open, false);
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  assert.equal(ui.refs.get("key-dialog-alert").hidden, true);
});

test("protected emergency unlock clears each submitted passphrase and stays locked after failure", async () => {
  const calls = [];
  const locked = { ...savedKeyStatus, keyRevision: 1, keyLoaded: false, emergencyLocked: true,
    emergencyShortcutsNative: true, startupKeyUnavailable: true, sandboxAvailable: false };
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "get_status") return locked;
    if (command === "emergency_unlock") {
      if (args.passphrase !== "correct") throw "This key file needs its passphrase.";
      return { ...savedKeyStatus, keyRevision: 2, emergencyLocked: false, emergencyShortcutsNative: true };
    }
  });
  await ui.evaluate("init()");
  await ui.events.get("emergency-unlock-requested")();
  assert.equal(ui.evaluate("state.emergencyLocked"), true);
  assert.equal(ui.refs.get("key-dialog").open, true);
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.match(ui.refs.get("key-dialog-alert").textContent, /passphrase/);
  ui.refs.get("key-passphrase").value = "correct";
  await ui.events.get("emergency-unlock-requested")();
  assert.equal(ui.refs.get("key-passphrase").value, "");
  assert.equal(ui.evaluate("state.emergencyLocked"), false);
  assert.equal(ui.evaluate("state.keyLoaded"), true);
  assert.equal(calls.filter(({ command }) => command === "emergency_unlock").length, 2);
});

test("key deletion cannot be armed until explicitly enabled and can be disarmed", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "get_status") return { ...savedKeyStatus, emergencyShortcutsNative: true };
    if (command === "arm_emergency_deletion") return { ...savedKeyStatus, emergencyShortcutsNative: true,
      emergencyDeletionArmed: args.enabled, emergencyDeletionPath: args.enabled ? "C:/saved.key" : null };
  });
  await ui.evaluate("init()");
  const arm = ui.refs.get("arm-emergency-deletion");
  assert.equal(arm.disabled, true);
  arm.handlers.get("click")();
  assert.equal(calls.some(({ command }) => command === "arm_emergency_deletion"), false);
  const enable = ui.refs.get("enable-emergency-deletion");
  enable.checked = true;
  enable.handlers.get("change")();
  assert.equal(arm.disabled, false);
  arm.handlers.get("click")();
  await settle();
  assert.equal(ui.evaluate("state.emergencyDeletionArmed"), true);
  assert.equal(enable.disabled, true);
  assert.equal(ui.refs.get("emergency-deletion-path").textContent, "C:/saved.key");
  ui.refs.get("disarm-emergency-deletion").handlers.get("click")();
  await settle();
  assert.equal(ui.evaluate("state.emergencyDeletionArmed"), false);
  assert.equal(ui.refs.get("disarm-emergency-deletion").hidden, true);
});

test("reconnecting the same key opens a fresh sandbox and restores the previous preview", async () => {
  const { ui, calls, change } = await recoveryFixture();
  ui.evaluate('showAlert("An unrelated file error")');
  const changed = ui.events.get("key-status-changed");
  change({ ...disconnectedKeyStatus, keyRevision: 2 });
  assert.equal(ui.refs.get("startup-key-dialog").open, true);
  assert.equal(ui.refs.get("sandbox-dialog").open, false);
  assert.equal(ui.refs.has("startup-key-options"), false);
  assert.equal(ui.refs.get("file-list").children.length, 2);
  assert.equal(ui.evaluate('JSON.stringify(state.files)'), '["C:/private.fenc","C:/bundle.zip"]');
  for (const row of ui.refs.get("file-list").children) {
    const badge = row.children[0].children[0].children[0];
    assert.match(badge.className, /is-disconnected/);
    assert.match(badge.title, /Key disconnected/);
    assert.equal(badge.innerHTML, ui.evaluate("EXPLORER_ICONS.disconnected"));
  }
  assert.equal(ui.refs.get("startup-key-path").textContent, "C:/vault.key");
  assert.equal(ui.refs.get("fingerprint").textContent, "Key disconnected");
  assert.equal(ui.refs.get("current-key-icon").innerHTML, ui.evaluate("EXPLORER_ICONS.unplug"));
  assert.match(ui.refs.get("current-key-icon").className, /is-disconnected/);
  assert.equal(ui.refs.get("key-message").textContent, "Reconnect your key drive to continue.");
  assert.equal(ui.refs.get("key-filename").textContent, "vault.key");
  assert.equal(ui.refs.get("key-filename").title, "C:/vault.key");
  assert.equal(ui.refs.get("key-filename").hidden, false);
  assert.equal(ui.refs.has("missing-key-warning"), false);
  assert.equal(ui.refs.get("decrypt").disabled, true);
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
  assert.equal(ui.refs.has("sandbox-preview"), false);
  assert.equal(ui.refs.get("sandbox-list").children.length, 0);
  assert.equal(ui.refs.get("key-recovery-sandbox").hidden, false);
  assert.equal(ui.evaluate("sandbox.recovery.itemId"), 1);
  assert.doesNotMatch(ui.evaluate("JSON.stringify(sandbox.recovery)"), /second\.txt|preview 1/);

  changed({ payload: { ...savedKeyStatus, keyRevision: 3, message: "Key reconnected and loaded." } });
  await settle();
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(ui.refs.get("sandbox-dialog").open, true);
  assert.equal(ui.refs.get("file-list").children.length, 2);
  for (const row of ui.refs.get("file-list").children) {
    assert.match(row.children[0].children[0].children[0].className, /is-verified/);
  }
  assert.equal(ui.refs.get("decrypt").disabled, false);
  assert.equal(ui.refs.get("view-sandbox").disabled, false);
  assert.equal(ui.refs.get("key-message").textContent, "");
  assert.equal(ui.refs.get("fingerprint").textContent, "Key loaded");
  assert.equal(ui.refs.get("fingerprint").title, "Fingerprint: 1234");
  assert.equal(ui.refs.get("alert").textContent, "An unrelated file error");
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  assert.equal(ui.evaluate("sandbox.openedItemId"), 1);
  const previewOpenings = calls.filter(({ command }) => command === "open_sandbox_preview");
  assert.equal(previewOpenings.length, 2);
  assert.equal(previewOpenings[1].args.sessionId, "2");
  assert.equal(ui.evaluate("sandbox.recovery"), null);
  const openings = calls.filter(({ command }) => command === "open_sandbox");
  assert.equal(openings.length, 2);
  assert.equal(JSON.stringify(openings[1].args.paths), '["C:/private.fenc","C:/bundle.zip"]');
  ui.evaluate("resetSandbox()");
});

test("removing or clearing disconnected files prevents recovery from reopening removed sources", async () => {
  for (const clear of [false, true]) {
    const { ui, calls, change } = await recoveryFixture();
    change({ ...disconnectedKeyStatus, keyRevision: 2 });
    ui.refs.get("choose-recovery-key").handlers.get("click")();
    if (clear) ui.refs.get("clear-files").handlers.get("click")();
    else ui.refs.get("file-list").children[1].children[1].handlers.get("click")();
    change({ ...savedKeyStatus, keyRevision: 3 });
    await settle();
    const openings = calls.filter(({ command }) => command === "open_sandbox");
    assert.equal(openings.length, clear ? 1 : 2);
    if (!clear) assert.equal(JSON.stringify(openings[1].args.paths), '["C:/private.fenc"]');
    assert.equal(calls.filter(({ command }) => command === "open_sandbox_preview").length, 1);
    ui.evaluate("resetSandbox()");
  }
});

test("a delayed close event from hiding the sandbox cannot clear a restored viewer", async () => {
  const { ui, change } = await recoveryFixture();
  const dialog = ui.refs.get("sandbox-dialog");
  const closed = dialog.handlers.get("close");
  dialog.close = function () { this.open = false; };
  change({ ...disconnectedKeyStatus, keyRevision: 2 });
  assert.equal(dialog.open, false);
  assert.equal(ui.evaluate("sandbox.hiddenClosures"), 1);
  change({ ...savedKeyStatus, keyRevision: 3 });
  await settle();
  assert.equal(dialog.open, true);
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  closed();
  assert.equal(ui.evaluate("sandbox.hiddenClosures"), 0);
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  assert.equal(ui.evaluate("sandbox.openedItemId"), 1);
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
  assert.equal(ui.evaluate("sandbox.openedItemId"), 1);
  ui.evaluate("resetSandbox()");
});

test("key-loss preview closures restore the sandbox and last opened file in every event order", async () => {
  for (const order of ["preview-first", "status-first", "sandbox-first"]) {
    const { ui, calls, change, setAvailable } = await recoveryFixture();
    // Selecting a different file must not replace the preview to recover.
    ui.evaluate("selectSandboxEntry(sandbox.entries[0])");
    setAvailable(false);
    const previewClosed = () => ui.events.get("sandbox-preview-closed")({ payload: { sessionId: "1", itemId: 1, locked: true } });
    const disconnected = () => change({ ...disconnectedKeyStatus, keyRevision: 2 });
    if (order === "preview-first") {
      previewClosed();
      disconnected();
    } else if (order === "status-first") {
      disconnected();
      previewClosed();
    } else {
      ui.events.get("sandbox-locked")({ payload: "1" });
      previewClosed();
      disconnected();
    }
    assert.equal(ui.refs.get("sandbox-dialog").open, false);
    assert.equal(ui.evaluate("sandbox.sessionId"), null);
    assert.equal(ui.evaluate("sandbox.recovery.itemId"), 1);
    assert.equal(ui.refs.get("sandbox-list").children.length, 0);
    setAvailable(true);
    change({ ...savedKeyStatus, keyRevision: 3 });
    await settle();
    assert.equal(ui.refs.get("sandbox-dialog").open, true);
    assert.equal(ui.evaluate("sandbox.sessionId"), "2");
    assert.equal(ui.evaluate("sandbox.openedItemId"), 1);
    const previews = calls.filter(({ command }) => command === "open_sandbox_preview");
    assert.equal(previews.length, 2);
    assert.equal(previews[1].args.itemId, 1);
    assert.equal(previews[1].args.sessionId, "2");
    previewClosed();
    assert.equal(ui.evaluate("sandbox.sessionId"), "2", "late closure from the old session cannot lock the restored sandbox");
    ui.evaluate("resetSandbox()");
  }
});

test("sandbox recovery waits for a protected key to be unlocked in Key options", async () => {
  const { ui, calls, change } = await recoveryFixture();
  change({ ...disconnectedKeyStatus, keyRevision: 2 });
  change({ ...disconnectedKeyStatus, keyRevision: 3, startupKeyUnavailable: false, message: "Key file needs its passphrase." });
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(ui.evaluate("sandbox.sessionId"), null);
  assert.equal(ui.evaluate("sandbox.recovery.waitingForUnlock"), true);
  assert.equal(ui.timers.size, 0);
  ui.refs.get("open-key-options").handlers.get("click")();
  assert.equal(ui.refs.get("key-dialog").open, true);
  change({ ...savedKeyStatus, keyRevision: 4 });
  assert.equal(calls.filter(({ command }) => command === "open_sandbox").length, 1);
  ui.refs.get("key-dialog").close();
  await settle();
  assert.equal(ui.evaluate("sandbox.sessionId"), "2");
  assert.equal(ui.evaluate("sandbox.openedItemId"), 1);
  ui.evaluate("resetSandbox()");
});

test("closing, unloading, or switching keys cancels automatic sandbox recovery", async () => {
  for (const action of ["close", "unload", "switch"]) {
    const { ui, calls, change, setAvailable } = await recoveryFixture();
    if (action === "unload") {
      setAvailable(false);
      await ui.fireTimer();
      change({ ...disconnectedKeyStatus, keyRevision: 2, startupKeyUnavailable: false });
    } else if (action === "close") {
      ui.refs.get("sandbox-dialog").close();
      change({ ...disconnectedKeyStatus, keyRevision: 2 });
    } else {
      change({ ...disconnectedKeyStatus, keyRevision: 2 });
      change({ ...savedKeyStatus, keyRevision: 3, fingerprint: "different-key" });
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

test("Back to files only dismisses the popup and key picking stays in the main window", async () => {
  const calls = [];
  let selected = false;
  const ui = fixture(async (command) => {
    calls.push(command);
    if (command === "browse_key") {
      assert.equal(ui.refs.get("startup-key-dialog").open, false);
      if (!selected) throw new Error("This key needs its passphrase. Open Key options to unlock it.");
      return { ...savedKeyStatus, keyRevision: 2 };
    }
    return { ...disconnectedKeyStatus, keyRevision: 1 };
  });
  await ui.evaluate("init()");
  assert.equal(ui.refs.has("check-key-again"), false);
  assert.equal(ui.refs.has("close-startup-key"), false);
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(calls.includes("browse_key"), false);
  ui.refs.get("browse-load").handlers.get("click")();
  await settle();
  assert.equal(ui.refs.get("startup-key-dialog").open, false);
  assert.equal(ui.refs.get("alert").hidden, false);
  assert.match(ui.refs.get("alert").textContent, /passphrase/);
  selected = true;
  ui.refs.get("browse-load").handlers.get("click")();
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
  assert.equal(ui.refs.get("key-filename").hidden, true);
  assert.equal(ui.refs.get("key-filename").textContent, "");
  assert.equal(ui.refs.get("key-filename").title, "");
  assert.equal(ui.refs.get("fingerprint").textContent, "Session key");
  ui.evaluate('applyStatus({keyLoaded:true,keyPath:null,fingerprint:"1234",message:"Key loaded for this session only. It will be cleared when you close the app."},false)');
  assert.match(ui.refs.get("key-message").textContent, /session only/);
  ui.evaluate('applyStatus({keyLoaded:true,keyPath:null,fingerprint:"1234",message:"Key loaded. Could not save preferences."},false)');
  assert.match(ui.refs.get("key-message").textContent, /Could not save preferences/);
});

test("native preview isolates file content and permits only the fixed viewer script", async () => {
  const calls = [];
  const content = textPreview('<script>parent.stolen=true</script><img src="https://example.com/leak">');
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "private.html", kind: "text" } };
    if (command === "read_sandbox_preview") return content;
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  const frame = ui.refs.get("preview-content").children[0];
  assert.equal(frame.attributes.get("sandbox"), "allow-scripts");
  assert.equal(frame.attributes.get("referrerpolicy"), "no-referrer");
  assert.match(frame.srcdoc, /&lt;script&gt;/);
  assert.doesNotMatch(frame.srcdoc, /<script>parent.stolen|<img src="https:/);
  assert.equal((frame.srcdoc.match(/<script>/g) || []).length, 1);
  assert.ok(frame.srcdoc.includes(ui.evaluate("SANDBOX_VIEWER_SCRIPT")));
  assert.match(frame.srcdoc, /default-src 'none'/);
  assert.match(frame.srcdoc, /img-src data:; media-src data:/);
  assert.equal(content.data, "");
  assert.ok(calls.every(({ command }) => ["sandbox_preview_info", "read_sandbox_preview", "check_sandbox", "cancel_sandbox_preview_read"].includes(command)));
  ui.evaluate("closePrivatePreview()");
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.equal(ui.evaluate("document.title"), "Private preview - FileEncrypt");
  assert.equal(ui.timers.size, 0);
});

test("sandbox preview allows only the exact style and trusted script hashes", () => {
  const ui = fixture();
  const hash = "sha256-" + createHash("sha256").update(ui.evaluate("SANDBOX_STYLE")).digest("base64");
  assert.equal(ui.evaluate("SANDBOX_STYLE_HASH"), hash);
  const config = JSON.parse(fs.readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.ok(config.app.security.csp.includes(`'${hash}'`));
  const scriptHash = "sha256-" + createHash("sha256").update(ui.evaluate("SANDBOX_VIEWER_SCRIPT")).digest("base64");
  assert.equal(ui.evaluate("SANDBOX_VIEWER_SCRIPT_HASH"), scriptHash);
  assert.ok(config.app.security.csp.includes(`script-src 'self' '${scriptHash}'`));
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

test("image viewer uses the trusted gesture script without same-origin or network access", () => {
  const ui = fixture();
  ui.context.content = { kind: "image", mime: "image/png", data: "cHJpdmF0ZQ==" };
  const frame = ui.evaluate('createSandboxFrame(content, "photo.png")');
  assert.equal(frame.attributes.get("sandbox"), "allow-scripts");
  assert.equal(frame.attributes.get("referrerpolicy"), "no-referrer");
  assert.match(frame.srcdoc, /<body data-kind="image">/);
  assert.match(frame.srcdoc, /tabindex="0" aria-label="Image preview\. Pinch to zoom; scroll to pan\."/);
  assert.equal((frame.srcdoc.match(/data:image\/png;base64,/g) || []).length, 1);
  assert.doesNotMatch(frame.srcdoc, /\son\w+=|allow-same-origin|unsafe-inline/);
  assert.equal(ui.context.content.data, "");
  ui.context.content = { kind: "video", mime: "video/mp4", data: "cHJpdmF0ZQ==" };
  assert.doesNotMatch(ui.evaluate("sandboxDocument(content)"), /<select|<main id="preview-stage"/);
});

test("key loss discards the entire image viewer including its zoom controls", async () => {
  let available = true;
  const content = { kind: "image", mime: "image/png", data: "cHJpdmF0ZQ==" };
  const ui = fixture(async (command) => {
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "photo.png" } };
    if (command === "read_sandbox_preview") return content;
    if (command === "check_sandbox" && !available) throw new Error("Key file unavailable");
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  assert.match(ui.refs.get("preview-content").children[0].srcdoc, /<main id="preview-stage"/);
  assert.equal(content.data, "");
  available = false;
  await ui.fireTimer();
  assert.equal(ui.evaluate("previewWindow.closed"), true);
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.equal(ui.refs.get("preview-content").hidden, true);
  assert.equal(ui.refs.get("preview-image-toolbar").hidden, true);
  assert.equal(ui.refs.get("preview-image-name").textContent, "");
  assert.equal(ui.evaluate("previewWindow.scale"), null);
  assert.equal(ui.timers.size, 0);
});

function viewerFixture(kind = "image") {
  const sent = [], handlers = new Map(), mediaHandlers = new Map(), stageHandlers = new Map();
  const parent = { postMessage(data) { sent.push(data); } };
  const stage = { clientWidth: 640, clientHeight: 480, scrollLeft: 0, scrollTop: 0,
    addEventListener(name, action, options) { stageHandlers.set(name, { action, options }); },
    getBoundingClientRect() { return { left: 0, top: 0 }; },
  };
  const media = { naturalWidth: 800, naturalHeight: 400, complete: true, readyState: 1, style: {},
    addEventListener(name, action) { mediaHandlers.set(name, action); },
    getBoundingClientRect() { return { left: 24 - stage.scrollLeft, top: 24 - stage.scrollTop }; },
  };
  const context = vm.createContext({ parent, window: { addEventListener(name, action) { handlers.set(name, action); } },
    document: { body: { dataset: { kind } }, getElementById(id) { return id === "preview-media" ? media : stage; },
      addEventListener(name, action) { handlers.set(name, action); } },
    ResizeObserver: class { observe() {} },
  });
  const source = fs.readFileSync(new URL("../src/sandbox-viewer.js", import.meta.url), "utf8");
  const script = vm.runInNewContext(source + "; SANDBOX_VIEWER_SCRIPT");
  vm.runInContext(script, context);
  return { sent, parent, handlers, media, mediaHandlers, stageHandlers };
}

test("pinch zoom changes image scale, clamps extreme gestures, and preserves normal scrolling", () => {
  const viewer = viewerFixture();
  const wheel = viewer.stageHandlers.get("wheel");
  assert.equal(wheel.options.passive, false);
  assert.equal(viewer.sent.at(-1).type, "ready");
  const before = Number.parseFloat(viewer.media.style.width);
  let prevented = 0;
  wheel.action({ ctrlKey: false, deltaY: -30, deltaMode: 0, preventDefault() { prevented++; } });
  assert.equal(Number.parseFloat(viewer.media.style.width), before);
  assert.equal(prevented, 0);
  wheel.action({ ctrlKey: true, deltaY: -30, deltaMode: 0, clientX: 200, clientY: 180, preventDefault() { prevented++; } });
  assert.ok(Number.parseFloat(viewer.media.style.width) > before);
  assert.equal(prevented, 1);
  assert.equal(viewer.sent.at(-1).fit, false);
  for (let i = 0; i < 20; i++) wheel.action({ ctrlKey: true, deltaY: -1000, deltaMode: 0, clientX: 200, clientY: 180, preventDefault() {} });
  assert.equal(viewer.sent.at(-1).scale, 4);
  assert.equal(viewerFixture("video").stageHandlers.has("wheel"), false);
  assert.equal(viewerFixture("audio").stageHandlers.has("gesturestart"), false);
});

test("viewer forwards Escape and media errors, and rejects zoom messages from other windows", () => {
  const viewer = viewerFixture();
  const message = { data: { channel: "fileencrypt-preview", type: "zoom", value: 2 } };
  const before = viewer.media.style.width;
  viewer.handlers.get("message")({ ...message, source: {} });
  assert.equal(viewer.media.style.width, before);
  viewer.handlers.get("message")({ ...message, source: viewer.parent });
  assert.equal(viewer.media.style.width, "1600px");
  viewer.handlers.get("keydown")({ key: "Escape", preventDefault() {} });
  assert.equal(viewer.sent.at(-1).type, "close");
  const video = viewerFixture("video");
  video.mediaHandlers.get("error")();
  assert.equal(video.sent.at(-1).type, "error");
  video.handlers.get("keydown")({ key: "Escape", preventDefault() {} });
  assert.equal(video.sent.at(-1).type, "close");
});

test("image navigation reuses the window and clears the previous image before loading the next", async () => {
  const calls = [];
  let current = 0;
  const info = () => ({ sessionId: "1", item: { id: current, name: `photo-${current}.png`, kind: "image" },
    navigation: { previous: current > 0, next: current < 1, index: current + 1, total: 2 } });
  const ui = fixture(async (command, args) => {
    calls.push(command);
    if (command === "sandbox_preview_info") return info();
    if (command === "navigate_sandbox_preview") { current += args.direction; return info(); }
    if (command === "read_sandbox_preview") return { kind: "image", mime: "image/png", data: "cHJpdmF0ZQ==" };
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  const first = ui.refs.get("preview-content").children[0];
  assert.equal(ui.refs.get("preview-previous-image").disabled, true);
  const moving = ui.evaluate("navigatePrivatePreview(1)");
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  await moving;
  assert.notEqual(ui.refs.get("preview-content").children[0], first);
  assert.equal(ui.refs.get("preview-image-position").textContent, "2 / 2");
  assert.equal(ui.refs.get("preview-next-image").disabled, true);
  assert.equal(ui.refs.get("preview-previous-image").disabled, false);
  assert.ok(calls.includes("cancel_sandbox_preview_read"));
  assert.ok(!calls.includes("open_sandbox_preview"));
});

test("only the active opaque frame can report decoder failures or request closing", async () => {
  const ui = fixture(async (command) => {
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "photo.png", kind: "image" } };
    if (command === "read_sandbox_preview") return { kind: "image", mime: "image/png", data: "cHJpdmF0ZQ==" };
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  const frame = ui.refs.get("preview-content").children[0];
  ui.context.activeFrame = frame;
  ui.evaluate('handlePrivatePreviewMessage({source:{},origin:"null",data:{channel:"fileencrypt-preview",type:"close"}})');
  ui.evaluate('handlePrivatePreviewMessage({source:activeFrame.contentWindow,origin:"https://example.com",data:{channel:"fileencrypt-preview",type:"close"}})');
  assert.equal(ui.evaluate("previewWindow.closed"), false);
  ui.evaluate('handlePrivatePreviewMessage({source:activeFrame.contentWindow,origin:"null",data:{channel:"fileencrypt-preview",type:"error",kind:"image"}})');
  await settle();
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.match(ui.refs.get("preview-message-detail").textContent, /damaged/);
  ui.evaluate('handlePrivatePreviewMessage({source:activeFrame.contentWindow,origin:"null",data:{channel:"fileencrypt-preview",type:"close"}})');
  assert.equal(ui.evaluate("previewWindow.closed"), false);
});

test("a missing decoder response times out without revealing the frame", async () => {
  const ui = fixture(async (command) => {
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "photo.png", kind: "image" } };
    if (command === "read_sandbox_preview") return { kind: "image", mime: "image/png", data: "cHJpdmF0ZQ==" };
  }, "sandbox-preview", false, false);
  const loading = ui.evaluate("loadPrivatePreview()");
  await settle();
  const timer = [...ui.timers.values()].find((timer) => timer.delay === 15000);
  assert.ok(timer);
  timer.callback();
  await loading;
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.match(ui.refs.get("preview-message-detail").textContent, /decoded in time/);
});

test("retrying a failed preview reloads its file instead of treating the click as navigation", async () => {
  let fail = true;
  const calls = [];
  const ui = fixture(async (command) => {
    calls.push(command);
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "photo.png", kind: "image" } };
    if (command === "read_sandbox_preview") {
      if (fail) throw new Error("Image unavailable");
      return { kind: "image", mime: "image/png", data: "cHJpdmF0ZQ==" };
    }
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  assert.equal(ui.refs.get("retry-private-preview").hidden, false);
  assert.equal(ui.refs.get("retry-private-preview").disabled, false);
  fail = false;
  await ui.refs.get("retry-private-preview").handlers.get("click")({ type: "click" });
  assert.equal(ui.refs.get("preview-content").children.length, 1);
  assert.equal(ui.refs.get("preview-message").hidden, true);
  assert.ok(!calls.includes("navigate_sandbox_preview"));
});

test("loss of key-file access clears already displayed plaintext despite a cached key", async () => {
  let available = true;
  const ui = fixture(async (command) => {
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "private.txt" } };
    if (command === "read_sandbox_preview") return textPreview();
    if (command === "check_sandbox" && !available) throw new Error("Key file unavailable");
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  assert.equal(ui.refs.get("preview-content").children.length, 1);
  available = false;
  await ui.fireTimer();
  assert.equal(ui.evaluate("previewWindow.closed"), true);
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.equal(ui.evaluate("document.title"), "Private preview - FileEncrypt");
  assert.equal(ui.timers.size, 0);
});

test("a stalled key check locks after its deadline and cannot revive the preview", async () => {
  let finish;
  const ui = fixture((command) => command === "check_sandbox" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve(), "sandbox-preview");
  ui.evaluate('previewWindow.sessionId="1"; previewElement("preview-content").append(document.createElement("iframe")); schedulePrivatePreviewCheck()');
  const check = ui.fireTimer();
  assert.equal(ui.timers.values().next().value.delay, 1500);
  ui.fireTimer();
  await check;
  assert.equal(ui.evaluate("previewWindow.closed"), true);
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  finish();
  await Promise.resolve();
  assert.equal(ui.timers.size, 0);
});

test("a delayed plaintext response cannot repopulate a closed or locked sandbox", async () => {
  let finish;
  const content = textPreview();
  const ui = fixture((command) => {
    if (command === "sandbox_preview_info") return Promise.resolve({ sessionId: "1", item: { id: 0, name: "private.txt" } });
    return command === "read_sandbox_preview" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve();
  }, "sandbox-preview");
  const viewing = ui.evaluate('loadPrivatePreview()');
  await settle();
  ui.evaluate("closePrivatePreview()");
  finish(content);
  await viewing;
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.equal(content.data, "");
  assert.equal(ui.evaluate("previewWindow.closed"), true);
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

function explorerFixture(items) {
  const ui = fixture(async () => {});
  ui.context.catalogItems = items;
  ui.evaluate('sandbox.items=catalogItems; sandbox.sessionId="explorer"; indexSandboxFiles(); renderSandboxExplorer()');
  return ui;
}

test("explorer groups paths into folders and opens the correct file when names repeat", () => {
  const ui = explorerFixture([
    { id: 0, name: "Projects/April/report.txt", kind: "text" },
    { id: 1, name: "Projects\\May\\report.txt", kind: "text" },
    { id: 2, name: "Photos/spring.jpg", kind: "image" },
    { id: 3, name: "readme.md", kind: "text" },
  ]);
  assert.equal(ui.refs.get("sandbox-list").children.length, 3);
  assert.equal(ui.evaluate('sandbox.folders.get("Projects").count'), 2);
  assert.equal(ui.refs.get("sandbox-total").textContent, "4");
  ui.evaluate('navigateSandbox("Projects/May")');
  const file = ui.refs.get("sandbox-list").children[0].children[0];
  assert.equal(file.sandboxItemId, 1);
  assert.equal(file.children[1].textContent, "report.txt");
  assert.equal(ui.refs.get("sandbox-location-name").textContent, "May");
  const crumbs = ui.refs.get("sandbox-breadcrumbs").children.filter((e) => e.handlers.has("click"));
  assert.deepEqual(crumbs.map((e) => e.textContent), ["Sandbox", "Projects", "May"]);
  crumbs[1].handlers.get("click")();
  assert.equal(ui.evaluate("sandbox.folder"), "Projects");
  assert.equal(ui.refs.get("sandbox-list").children.length, 2);
});

test("explorer history supports back, forward, and branching from an earlier folder", () => {
  const ui = explorerFixture([
    { id: 0, name: "A/file.txt", kind: "text" },
    { id: 1, name: "B/photo.png", kind: "image" },
  ]);
  ui.evaluate('navigateSandbox("A"); navigateSandbox("B"); stepSandboxHistory(-1)');
  assert.equal(ui.evaluate("sandbox.folder"), "A");
  assert.equal(ui.refs.get("sandbox-forward").disabled, false);
  ui.evaluate("stepSandboxHistory(1)");
  assert.equal(ui.evaluate("sandbox.folder"), "B");
  ui.evaluate('stepSandboxHistory(-1); navigateSandbox("", "image")');
  assert.equal(ui.refs.get("sandbox-forward").disabled, true);
  assert.equal(ui.evaluate("sandbox.category"), "image");
  ui.evaluate("stepSandboxHistory(-1)");
  assert.equal(ui.evaluate("sandbox.folder"), "A");
});

test("explorer search spans nested folders and respects the selected file type", () => {
  const ui = explorerFixture([
    { id: 0, name: "Photos/Holidays/sunset.png", kind: "image" },
    { id: 1, name: "Photos/Holidays/sunset-notes.md", kind: "text" },
    { id: 2, name: "Projects/report.txt", kind: "text" },
  ]);
  ui.evaluate('navigateSandbox("Projects"); sandbox.query="SUNSET"; renderSandboxExplorer()');
  assert.equal(ui.refs.get("sandbox-list").children.length, 2);
  assert.equal(ui.refs.get("sandbox-list").children[0].children[0].children[2].textContent, "Photos/Holidays");
  ui.evaluate('navigateSandbox("", "image"); sandbox.query="sunset"; renderSandboxExplorer()');
  assert.equal(ui.refs.get("sandbox-list").children.length, 1);
  assert.equal(ui.refs.get("sandbox-list").children[0].children[0].sandboxItemId, 0);
  ui.evaluate('sandbox.query="no match"; renderSandboxExplorer()');
  assert.equal(ui.refs.get("sandbox-list").children.length, 0);
  assert.equal(ui.refs.get("sandbox-browser-empty").hidden, false);
  assert.equal(ui.refs.get("sandbox-clear-search").hidden, false);
});

test("explorer sorts naturally with folders first and retains selection across views", () => {
  const ui = explorerFixture([
    { id: 0, name: "file10.txt", kind: "text" },
    { id: 1, name: "file2.txt", kind: "text" },
    { id: 2, name: "Folder/file.txt", kind: "text" },
    { id: 3, name: "photo.png", kind: "image" },
  ]);
  const labels = () => ui.refs.get("sandbox-list").children.map((row) => row.children[0].children[1].textContent);
  assert.deepEqual(labels(), ["Folder", "file2.txt", "file10.txt", "photo.png"]);
  ui.evaluate('sandbox.sort="name-desc"; renderSandboxExplorer()');
  assert.deepEqual(labels(), ["Folder", "photo.png", "file10.txt", "file2.txt"]);
  ui.evaluate('selectSandboxEntry(sandbox.entries[1]); sandbox.view="details"; sandbox.sort="type"; renderSandboxExplorer()');
  assert.equal(ui.refs.get("sandbox-list").className, "explorer-details");
  assert.equal(ui.refs.get("sandbox-list-heading").hidden, false);
  const selected = ui.refs.get("sandbox-list").children.map((row) => row.children[0]).find((b) => b.sandboxItemId === 1);
  assert.equal(selected.attributes.get("aria-pressed"), "true");
  assert.equal(ui.refs.get("sandbox-details").attributes.get("aria-pressed"), "true");
  assert.deepEqual(labels(), ["Folder", "photo.png", "file2.txt", "file10.txt"]);
});

test("explorer bounds large catalogues and resets pagination when changing folders", () => {
  const ui = explorerFixture(Array.from({ length: 10000 }, (_, id) => ({ id, name: `Folder/file${id}.txt`, kind: "text" })));
  assert.equal(ui.refs.get("sandbox-list").children.length, 1);
  ui.evaluate('navigateSandbox("Folder")');
  assert.equal(ui.refs.get("sandbox-list").children.length, 48);
  ui.refs.get("sandbox-pages").children[2].handlers.get("click")();
  assert.equal(ui.refs.get("sandbox-list").children[0].children[0].sandboxItemId, 48);
  ui.evaluate('navigateSandbox(); navigateSandbox("Folder")');
  assert.equal(ui.refs.get("sandbox-list").children[0].children[0].sandboxItemId, 0);
  assert.ok(ui.refs.get("sandbox-folders").children.length <= 9);
});

test("locking clears explorer names, paths, search, history, properties, and context menu", () => {
  const ui = explorerFixture([{ id: 0, name: "Private/Secret/report.txt", kind: "text" }]);
  ui.evaluate('sandbox.paths=["C:/encrypted.fenc"]; sandbox.fingerprint="1234"; navigateSandbox("Private/Secret"); sandbox.query="Secret"; selectSandboxEntry(sandbox.entries[0]); showSandboxProperties(sandbox.entries[0]); renderSandboxExplorer(); lockSandbox()');
  assert.equal(ui.evaluate("sandbox.folders.size"), 0);
  assert.equal(ui.evaluate("sandbox.entries.length"), 0);
  assert.equal(ui.evaluate("sandbox.query"), "");
  assert.equal(ui.evaluate("sandbox.history.length"), 1);
  assert.equal(ui.evaluate("sandbox.selectedKey"), null);
  assert.equal(ui.refs.get("sandbox-property-name").textContent, "");
  assert.equal(ui.refs.get("sandbox-property-location").textContent, "");
  assert.equal(ui.refs.get("sandbox-property-icon").children.length, 0);
  assert.equal(ui.refs.get("sandbox-properties").open, false);
  assert.equal(ui.refs.get("sandbox-context-menu").hidden, true);
  assert.equal(ui.refs.get("sandbox-folders").children.length, 0);
  assert.equal(ui.refs.get("sandbox-search").value, "");
  assert.equal(ui.refs.get("sandbox-key-state").textContent, "Viewer locked");
  assert.doesNotMatch(ui.evaluate("JSON.stringify(sandbox.recovery)"), /Private|Secret|report/);
  ui.evaluate("resetSandbox()");
});

test("closing the explorer cannot revive a late preview-window response", async () => {
  let finish;
  const ui = fixture((command) => command === "open_sandbox_preview" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve());
  ui.evaluate('sandbox.sessionId="explorer"; sandbox.items=[{id:0,name:"A/notes.txt",kind:"text"},{id:1,name:"B/notes.txt",kind:"text"}]; indexSandboxFiles(); navigateSandbox("A")');
  const viewing = ui.evaluate("viewSandboxFile(sandbox.entries[0])");
  ui.evaluate('resetSandbox()');
  assert.equal(ui.evaluate("sandbox.currentItemId"), null);
  finish();
  await viewing;
  assert.equal(ui.evaluate("sandbox.openedItemId"), null);
  assert.equal(ui.refs.has("sandbox-preview"), false);
  assert.equal(ui.evaluate("sandbox.loading"), false);
  ui.evaluate("resetSandbox()");
});

test("single click selects without reading plaintext and double click opens a native window", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => { calls.push({ command, args }); });
  ui.evaluate('sandbox.sessionId="explorer"; sandbox.items=[{id:7,name:"notes.txt",kind:"text"}]; indexSandboxFiles(); renderSandboxExplorer()');
  const file = ui.refs.get("sandbox-list").children[0].children[0];
  file.handlers.get("click")();
  assert.equal(file.attributes.get("aria-pressed"), "true");
  assert.equal(ui.evaluate("sandbox.selectedKey"), "file:7");
  assert.equal(calls.length, 0);
  await file.handlers.get("dblclick")();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "open_sandbox_preview");
  assert.equal(calls[0].args.itemId, 7);
  assert.equal(ui.refs.has("sandbox-preview"), false);
});

test("folder cards require double click while navigation shortcuts remain single click", () => {
  const ui = explorerFixture([{ id: 0, name: "Documents/notes.txt", kind: "text" }]);
  const folder = ui.refs.get("sandbox-list").children[0].children[0];
  folder.handlers.get("click")();
  assert.equal(ui.evaluate("sandbox.folder"), "");
  assert.equal(folder.attributes.get("aria-pressed"), "true");
  folder.handlers.get("dblclick")();
  assert.equal(ui.evaluate("sandbox.folder"), "Documents");
  ui.refs.get("sandbox-categories").children[0].handlers.get("click")();
  assert.equal(ui.evaluate("sandbox.category"), "text");
});

test("rebuilt file and navigation icons contain inline Lucide paths without external references", () => {
  const ui = explorerFixture([{ id: 0, name: "notes.txt", kind: "text" }]);
  for (let index = 0; index < 3; index++) {
    ui.evaluate('navigateSandbox("", "text"); renderSandboxExplorer()');
    const icon = ui.refs.get("sandbox-categories").children[0].children[0].innerHTML;
    assert.match(icon, /<svg[^>]*>[\s\S]*<path/);
    assert.doesNotMatch(icon, /<use|href=/);
    assert.equal(ui.refs.get("sandbox-list").children[0].children[0].children[0].innerHTML, icon);
  }
});

test("right click selects a file and offers working open, containing-folder, and properties options", () => {
  const ui = explorerFixture([{ id: 0, name: "Documents/notes.txt", kind: "text" }]);
  ui.evaluate('navigateSandbox("", "text")');
  const file = ui.refs.get("sandbox-list").children[0].children[0];
  let prevented = false;
  file.handlers.get("contextmenu")({ preventDefault() { prevented = true; }, clientX: 1090, clientY: 770 });
  assert.equal(prevented, true);
  assert.equal(file.attributes.get("aria-pressed"), "true");
  const menu = ui.refs.get("sandbox-context-menu");
  assert.equal(menu.hidden, false);
  assert.deepEqual(menu.children.map((b) => b.children[1].textContent), ["Open preview", "Show containing folder", "Properties"]);
  assert.equal(menu.style.left, "872px");
  assert.equal(menu.style.top, "652px");
  menu.children[2].handlers.get("click")();
  assert.equal(menu.hidden, true);
  assert.equal(ui.refs.get("sandbox-properties").open, true);
  assert.equal(ui.refs.get("sandbox-property-name").textContent, "notes.txt");
  ui.refs.get("sandbox-properties").close();
  file.handlers.get("contextmenu")({ preventDefault() {}, clientX: 50, clientY: 50 });
  menu.children[1].handlers.get("click")();
  assert.equal(ui.evaluate("sandbox.folder"), "Documents");
  assert.equal(ui.evaluate("sandbox.selectedKey"), "file:0");
});

test("closing a native preview prevents it from reopening during later key recovery", async () => {
  const { ui, change, calls } = await recoveryFixture();
  ui.events.get("sandbox-preview-closed")({ payload: { sessionId: "1", itemId: 1 } });
  assert.equal(ui.evaluate("sandbox.openedItemId"), null);
  change({ ...disconnectedKeyStatus, keyRevision: 2 });
  change({ ...savedKeyStatus, keyRevision: 3 });
  await settle();
  assert.equal(calls.filter(({ command }) => command === "open_sandbox_preview").length, 1);
  ui.evaluate("resetSandbox()");
});

test("key loss events clear a native preview immediately instead of waiting for polling", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "Secret/report.txt", kind: "text" } };
    if (command === "read_sandbox_preview") return textPreview();
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  assert.equal(ui.refs.get("preview-content").children.length, 1);
  ui.events.get("key-status-changed")({ payload: { sandboxAvailable: false } });
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.equal(ui.evaluate("document.title"), "Private preview - FileEncrypt");
  assert.equal(ui.evaluate("previewWindow.closed"), true);
  assert.equal(ui.timers.size, 0);
  const closed = calls.find(({ command }) => command === "close_sandbox_preview");
  assert.equal(closed.args.locked, true);
});

test("key protection clears entered secrets and waits for recovery-code acknowledgement before saving", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args: { ...args } });
    if (command === "get_status") return savedKeyStatus;
    if (command === "prepare_key_protection") return { token: "setup-1", recoveryCode: "FE-R1-example", keyPath: savedKeyStatus.keyPath };
    if (command === "commit_key_protection") return { ...savedKeyStatus, keyRevision: 1 };
  });
  await ui.evaluate("init()");
  ui.evaluate("openKeyOptions()");
  ui.evaluate('document.getElementById("key-passphrase").value="current reference"');
  ui.refs.get("new-key-passphrase").value = "a long new reference";
  ui.refs.get("confirm-key-passphrase").value = "a long new reference";
  await ui.evaluate("prepareKeyProtection()");
  const prepared = calls.find(({ command }) => command === "prepare_key_protection");
  assert.equal(prepared.args.passphrase, "current reference");
  assert.equal(prepared.args.newPassphrase, "a long new reference");
  assert.equal(prepared.args.recoveryCode, null);
  for (const id of ["key-passphrase", "new-key-passphrase", "confirm-key-passphrase"]) assert.equal(ui.refs.get(id).value, "");
  assert.equal(ui.refs.get("new-recovery-code").value, "FE-R1-example");
  assert.equal(ui.refs.get("commit-key-protection").disabled, true);
  await ui.evaluate("commitKeyProtection()");
  assert.equal(calls.some(({ command }) => command === "commit_key_protection"), false);
  ui.refs.get("recovery-code-saved").checked = true;
  ui.refs.get("recovery-code-saved").handlers.get("change")();
  assert.equal(ui.refs.get("commit-key-protection").disabled, false);
  await ui.evaluate("commitKeyProtection()");
  assert.equal(ui.refs.get("new-recovery-code").value, "");
  assert.equal(ui.refs.get("access-recovery-result").hidden, true);
  assert.equal(ui.evaluate("keyProtection.token"), null);
  assert.equal(calls.find(({ command }) => command === "commit_key_protection").args.recoverySaved, true);
});

test("closing Key options cancels a prepared setup and clears its recovery code", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "get_status") return savedKeyStatus;
    if (command === "prepare_key_protection") return { token: "cancel-me", recoveryCode: "FE-R1-example" };
  });
  await ui.evaluate("init()");
  ui.evaluate("openKeyOptions()");
  ui.refs.get("new-key-passphrase").value = "a long new reference";
  ui.refs.get("confirm-key-passphrase").value = "a long new reference";
  await ui.evaluate("prepareKeyProtection()");
  ui.refs.get("key-dialog").close();
  assert.equal(ui.refs.get("new-recovery-code").value, "");
  assert.equal(ui.evaluate("keyProtection.token"), null);
  assert.equal(calls.find(({ command }) => command === "cancel_key_protection").args.token, "cancel-me");
});

test("late protection setup cannot reveal a recovery code after closing its dialog", async () => {
  let finish;
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "get_status") return savedKeyStatus;
    if (command === "prepare_key_protection") return new Promise((resolve) => { finish = resolve; });
  });
  await ui.evaluate("init()");
  ui.evaluate("openKeyOptions()");
  ui.refs.get("new-key-passphrase").value = "a long new reference";
  ui.refs.get("confirm-key-passphrase").value = "a long new reference";
  const pending = ui.evaluate("prepareKeyProtection()");
  ui.refs.get("key-dialog").close();
  finish({ token: "late-setup", recoveryCode: "FE-R1-example" });
  await pending;
  assert.equal(ui.refs.get("new-recovery-code").value, "");
  assert.equal(ui.evaluate("keyProtection.token"), null);
  assert.equal(calls.find(({ command }) => command === "cancel_key_protection").args.token, "late-setup");
});

test("recovery submits the saved code and new reference while leaving emergency lock active", async () => {
  const calls = [];
  const locked = { ...savedKeyStatus, keyLoaded: false, emergencyLocked: true, keyRevision: 1 };
  const ui = fixture(async (command, args) => {
    calls.push({ command, args: { ...args } });
    if (command === "get_status") return locked;
    if (command === "prepare_key_protection") return { token: "recovery", recoveryCode: "FE-R1-replacement" };
    if (command === "commit_key_protection") return { ...locked, keyRevision: 2 };
  });
  await ui.evaluate("init()");
  ui.refs.get("choose-recovery-key").handlers.get("click")();
  ui.evaluate("openKeyOptions()");
  ui.refs.get("new-key-passphrase").value = "a long new reference";
  ui.refs.get("confirm-key-passphrase").value = "a long new reference";
  ui.refs.get("key-recovery-code").value = "FE-R1-saved";
  await ui.evaluate("prepareKeyProtection(true)");
  assert.equal(ui.refs.get("key-recovery-code").value, "");
  assert.equal(calls.find(({ command }) => command === "prepare_key_protection").args.recoveryCode, "FE-R1-saved");
  ui.refs.get("recovery-code-saved").checked = true;
  await ui.evaluate("commitKeyProtection()");
  assert.equal(ui.evaluate("state.emergencyLocked"), true);
  assert.equal(ui.evaluate("state.keyLoaded"), false);
  assert.match(ui.refs.get("key-protection-status").textContent, /unlock shortcut/);
});

test("routine status updates do not erase a reference being entered during emergency lock", async () => {
  const locked = { ...savedKeyStatus, keyLoaded: false, emergencyLocked: true, keyRevision: 1 };
  const ui = fixture(async (command) => command === "get_status" ? locked : undefined);
  await ui.evaluate("init()");
  ui.refs.get("key-passphrase").value = "typing my reference";
  ui.events.get("key-status-changed")({ payload: locked });
  assert.equal(ui.refs.get("key-passphrase").value, "typing my reference");
  ui.events.get("key-status-changed")({ payload: { ...locked, keyRevision: 2 } });
  assert.equal(ui.refs.get("key-passphrase").value, "");
});

test("failed protection publication preserves the displayed recovery code", async () => {
  const ui = fixture(async (command) => {
    if (command === "get_status") return savedKeyStatus;
    if (command === "prepare_key_protection") return { token: "uncertain", recoveryCode: "FE-R1-keep-this" };
    if (command === "commit_key_protection") throw "Key publication could not be verified. Keep the recovery code.";
  });
  await ui.evaluate("init()");
  ui.evaluate("openKeyOptions()");
  ui.refs.get("new-key-passphrase").value = "a long new reference";
  ui.refs.get("confirm-key-passphrase").value = "a long new reference";
  await ui.evaluate("prepareKeyProtection()");
  ui.refs.get("recovery-code-saved").checked = true;
  await ui.evaluate("commitKeyProtection()");
  assert.equal(ui.refs.get("new-recovery-code").value, "FE-R1-keep-this");
  assert.equal(ui.refs.get("access-recovery-result").hidden, false);
});

test("first launch requires a reference and saved recovery code before opening the workspace", async () => {
  const calls = [];
  const firstLaunch = { keyLoaded: false, keyPath: null, accessSetupRequired: true, accessSetupKeyPath: "C:/profile/workspace.key", keyRevision: 0 };
  const completed = { ...savedKeyStatus, keyPath: firstLaunch.accessSetupKeyPath, accessSetupRequired: false, keyRevision: 1 };
  const ui = fixture(async (command, args) => {
    calls.push({ command, args: { ...args } });
    if (command === "get_status") return firstLaunch;
    if (command === "prepare_first_run") return { token: "first-run", recoveryCode: "FE-R1-first", keyPath: firstLaunch.accessSetupKeyPath };
    if (command === "commit_key_protection") return completed;
  });
  await ui.evaluate("init()");
  assert.equal(ui.refs.get("key-dialog").open, true);
  assert.equal(ui.refs.get("key-dialog-heading").textContent, "Create your password");
  assert.equal(ui.refs.get("new-reference-label").textContent, "Password");
  assert.equal(ui.refs.get("confirm-reference-label").textContent, "Confirm password");
  assert.equal(ui.refs.get("current-reference-field").hidden, true);
  assert.equal(ui.refs.get("key-location-field").hidden, true);
  assert.equal(ui.refs.get("new-key-passphrase"), ui.evaluate("document.activeElement"));
  assert.equal(ui.refs.get("key-path").value, firstLaunch.accessSetupKeyPath);
  assert.equal(ui.refs.get("close-key-options").hidden, true);
  assert.equal(ui.refs.get("prepare-key-protection").disabled, false);
  assert.equal(ui.evaluate("selectionBlocked()"), true);
  let prevented = false;
  ui.refs.get("key-dialog").handlers.get("cancel")({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  ui.refs.get("key-dialog").close();
  assert.equal(ui.refs.get("key-dialog").open, true);
  ui.refs.get("new-key-passphrase").value = "first long reference";
  ui.refs.get("confirm-key-passphrase").value = "first long reference";
  await ui.evaluate("prepareKeyProtection()");
  assert.equal(ui.refs.get("key-dialog-heading").textContent, "Save your recovery code");
  assert.equal(ui.refs.get("access-fields").hidden, true);
  assert.equal(calls.find(({ command }) => command === "prepare_first_run").args.path, firstLaunch.accessSetupKeyPath);
  assert.equal(ui.refs.get("new-key-passphrase").value, "");
  await ui.evaluate("commitKeyProtection()");
  assert.equal(calls.some(({ command }) => command === "commit_key_protection"), false);
  ui.refs.get("recovery-code-saved").checked = true;
  await ui.evaluate("commitKeyProtection()");
  assert.equal(calls.find(({ command }) => command === "commit_key_protection").args.activationCode, "FE-R1-first");
  assert.equal(ui.evaluate("state.accessSetupRequired"), false);
  assert.equal(ui.evaluate("state.keyLoaded"), true);
  assert.equal(ui.refs.get("key-dialog").open, false);
  assert.equal(ui.refs.get("new-recovery-code").value, "");
});

test("slow password preparation shows activity and rejects duplicate submissions", async () => {
  let finish;
  let preparations = 0;
  const firstLaunch = { keyLoaded: false, accessSetupRequired: true, accessSetupKeyPath: "C:/profile/workspace.key", keyRevision: 0 };
  const ui = fixture(async (command) => {
    if (command === "get_status") return firstLaunch;
    if (command === "prepare_first_run") {
      preparations++;
      return new Promise((resolve) => { finish = resolve; });
    }
  });
  await ui.evaluate("init()");
  ui.refs.get("new-key-passphrase").value = "first long password";
  ui.refs.get("confirm-key-passphrase").value = "first long password";
  const pending = ui.evaluate("prepareKeyProtection()");
  assert.equal(ui.refs.get("key-protection-loading").hidden, false);
  assert.equal(ui.refs.get("key-protection-loading-title").textContent, "Preparing emergency access…");
  assert.equal(ui.refs.get("access-fields").hidden, true);
  assert.equal(ui.refs.get("prepare-key-protection").disabled, true);
  ui.events.get("key-status-changed")({ payload: firstLaunch });
  assert.equal(ui.refs.get("key-protection-loading").hidden, false);
  await ui.evaluate("prepareKeyProtection()");
  assert.equal(preparations, 1);
  finish({ token: "slow-setup", recoveryCode: "FE-R1-example" });
  await pending;
  assert.equal(ui.refs.get("key-protection-loading").hidden, true);
  assert.equal(ui.refs.get("access-recovery-result").hidden, false);
  assert.equal(ui.refs.get("new-recovery-code").value, "FE-R1-example");
});

test("password preparation failure removes activity and allows a retry", async () => {
  let fail;
  const firstLaunch = { keyLoaded: false, accessSetupRequired: true, accessSetupKeyPath: "C:/profile/workspace.key", keyRevision: 0 };
  const ui = fixture(async (command) => {
    if (command === "get_status") return firstLaunch;
    if (command === "prepare_first_run") return new Promise((resolve, reject) => { fail = reject; });
  });
  await ui.evaluate("init()");
  ui.refs.get("new-key-passphrase").value = "first long password";
  ui.refs.get("confirm-key-passphrase").value = "first long password";
  const pending = ui.evaluate("prepareKeyProtection()");
  fail("The selected key file is unavailable.");
  await pending;
  assert.equal(ui.refs.get("key-protection-loading").hidden, true);
  assert.equal(ui.refs.get("access-fields").hidden, false);
  assert.equal(ui.refs.get("prepare-key-protection").disabled, false);
  assert.equal(ui.refs.get("new-key-passphrase").disabled, false);
  assert.match(ui.refs.get("key-dialog-alert").textContent, /unavailable/);
  assert.equal(ui.evaluate("state.busy"), false);
});

test("slow or failed setup saving keeps the recovery code and prevents duplicate writes", async () => {
  let fail;
  let commits = 0;
  const ui = fixture(async (command) => {
    if (command === "get_status") return savedKeyStatus;
    if (command === "prepare_key_protection") return { token: "saving", recoveryCode: "FE-R1-keep-this" };
    if (command === "commit_key_protection") {
      commits++;
      return new Promise((resolve, reject) => { fail = reject; });
    }
  });
  await ui.evaluate("init()");
  ui.evaluate("openKeyOptions()");
  ui.refs.get("new-key-passphrase").value = "a long new reference";
  ui.refs.get("confirm-key-passphrase").value = "a long new reference";
  await ui.evaluate("prepareKeyProtection()");
  ui.refs.get("recovery-code-saved").checked = true;
  const pending = ui.evaluate("commitKeyProtection()");
  assert.equal(ui.refs.get("key-protection-loading").hidden, false);
  assert.equal(ui.refs.get("key-protection-loading-title").textContent, "Saving emergency access…");
  assert.equal(ui.refs.get("commit-key-protection").disabled, true);
  assert.equal(ui.refs.get("cancel-key-protection").disabled, true);
  assert.equal(ui.refs.get("recovery-code-saved").disabled, true);
  assert.equal(ui.refs.get("new-recovery-code").value, "FE-R1-keep-this");
  await ui.evaluate("commitKeyProtection()");
  assert.equal(commits, 1);
  fail("Key publication could not be verified. Keep the recovery code.");
  await pending;
  assert.equal(ui.refs.get("key-protection-loading").hidden, true);
  assert.equal(ui.refs.get("new-recovery-code").value, "FE-R1-keep-this");
  assert.equal(ui.refs.get("cancel-key-protection").disabled, false);
  assert.equal(ui.refs.get("recovery-code-saved").disabled, false);
});

test("existing dev users are prompted while completed profiles do not repeat first-launch setup", async () => {
  const existing = { ...savedKeyStatus, accessSetupRequired: true, accessSetupKeyPath: savedKeyStatus.keyPath };
  const ui = fixture(async (command) => command === "get_status" ? existing : undefined);
  await ui.evaluate("init()");
  assert.equal(ui.refs.get("key-dialog").open, true);
  assert.equal(ui.refs.get("key-path").readOnly, true);
  assert.equal(ui.refs.get("set-path").disabled, true);
  const completed = fixture(async (command) => command === "get_status" ? { ...savedKeyStatus, accessSetupRequired: false } : undefined);
  await completed.evaluate("init()");
  assert.notEqual(completed.refs.get("key-dialog").open, true);
  assert.equal(completed.evaluate("state.accessSetupRequired"), false);
});

test("routine first-launch status checks preserve the reference and chosen location", async () => {
  const firstLaunch = { keyLoaded: false, accessSetupRequired: true, accessSetupKeyPath: "C:/profile/workspace.key", keyRevision: 0 };
  const ui = fixture(async (command) => command === "get_status" ? firstLaunch : undefined);
  await ui.evaluate("init()");
  ui.refs.get("new-key-passphrase").value = "my first reference";
  ui.refs.get("first-run-key-path").value = "D:/my-key.key";
  ui.events.get("key-status-changed")({ payload: firstLaunch });
  assert.equal(ui.refs.get("new-key-passphrase").value, "my first reference");
  assert.equal(ui.refs.get("first-run-key-path").value, "D:/my-key.key");
});

test("legacy setup reuses one emergency password without a separate key-password field", async () => {
  const firstLaunch = { ...savedKeyStatus, accessSetupRequired: true, accessSetupRequiresCurrentReference: true };
  const ui = fixture(async (command) => command === "get_status" ? firstLaunch : undefined);
  await ui.evaluate("init()");
  assert.equal(ui.refs.get("current-reference-field").hidden, true);
  assert.match(ui.refs.get("new-reference-hint").textContent, /only have its recovery code/);
  assert.equal(ui.refs.get("new-reference-label").textContent, "Password");
  assert.equal(ui.refs.get("key-location-field").hidden, true);
  assert.equal(ui.refs.get("first-run-location").hidden, true);
  assert.equal(ui.refs.get("key-dialog-heading").textContent, "Update emergency access");
});

test("recovery-only legacy setup guides entry of a new password and the saved code", async () => {
  let prepared;
  const legacy = { ...savedKeyStatus, keyLoaded: false, accessSetupRequired: true, accessSetupRequiresCurrentReference: true };
  const ui = fixture(async (command, args) => {
    if (command === "get_status") return legacy;
    if (command === "prepare_first_run") { prepared = { ...args }; return { token: "recovered-migration", recoveryCode: "FE-R1-replacement", migrationBackupPath: "D:/original-key-backup.key" }; }
  });
  await ui.evaluate("init()");
  ui.refs.get("access-recovery").open = true;
  ui.refs.get("access-recovery").handlers.get("toggle")();
  assert.equal(ui.refs.get("new-reference-label").textContent, "New password");
  assert.equal(ui.refs.get("prepare-key-protection").hidden, true);
  assert.equal(ui.refs.get("recover-key-protection").textContent, "Set new emergency password");
  assert.equal(ui.refs.get("confirm-reference-label").textContent, "Confirm new password");
  ui.refs.get("new-key-passphrase").value = "a new emergency password";
  ui.refs.get("confirm-key-passphrase").value = "a new emergency password";
  ui.refs.get("key-recovery-code").value = "FE-R1-previous";
  await ui.evaluate("prepareKeyProtection(true)");
  assert.equal(prepared.passphrase, "");
  assert.equal(prepared.newPassphrase, "a new emergency password");
  assert.equal(prepared.recoveryCode, "FE-R1-previous");
  assert.match(ui.refs.get("key-protection-status").textContent, /exact backup at D:\/original-key-backup.key/);
  assert.equal(ui.refs.get("key-dialog-heading").textContent, "Save your recovery code");
});

test("recovery validation identifies missing new-password fields without losing the saved code", async () => {
  const calls = [];
  const legacy = { ...savedKeyStatus, keyLoaded: false, accessSetupRequired: true, accessSetupRequiresCurrentReference: true };
  const ui = fixture(async (command, args) => {
    if (command === "get_status") return legacy;
    if (command === "prepare_first_run") { calls.push({ ...args }); return { token: "recovered", recoveryCode: "FE-R1-replacement" }; }
  });
  await ui.evaluate("init()");
  ui.refs.get("access-recovery").open = true;
  ui.refs.get("access-recovery").handlers.get("toggle")();
  assert.equal(ui.refs.get("key-recovery-code"), ui.evaluate("document.activeElement"));
  assert.equal(ui.refs.get("key-dialog-alert").hidden, true);
  await ui.refs.get("recover-key-protection").handlers.get("click")();
  assert.equal(ui.refs.get("key-dialog-alert").textContent, "Enter your saved recovery code.");
  ui.refs.get("key-recovery-code").value = "FE-R1-saved";
  await ui.refs.get("recover-key-protection").handlers.get("click")();
  assert.match(ui.refs.get("key-dialog-alert").textContent, /Choose a new emergency password/);
  assert.equal(ui.refs.get("new-key-passphrase"), ui.evaluate("document.activeElement"));
  assert.equal(ui.refs.get("key-recovery-code").value, "FE-R1-saved");
  ui.refs.get("new-key-passphrase").value = "my new emergency password";
  await ui.refs.get("recover-key-protection").handlers.get("click")();
  assert.equal(ui.refs.get("key-dialog-alert").textContent, "Enter the same new password in Confirm new password.");
  assert.equal(ui.refs.get("confirm-key-passphrase"), ui.evaluate("document.activeElement"));
  assert.equal(ui.refs.get("new-key-passphrase").value, "my new emergency password");
  assert.equal(ui.refs.get("key-recovery-code").value, "FE-R1-saved");
  assert.equal(calls.length, 0);
  ui.refs.get("confirm-key-passphrase").value = "my new emergency password";
  await ui.refs.get("recover-key-protection").handlers.get("click")();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].passphrase, "");
  assert.equal(calls[0].recoveryCode, "FE-R1-saved");
  assert.equal(ui.refs.get("new-recovery-code").value, "FE-R1-replacement");
});

test("ordinary key actions never use the emergency reference to protect or load a file key", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "get_status" || ["generate_key", "load_key", "browse_key"].includes(command)) return savedKeyStatus;
  });
  await ui.evaluate("init()");
  for (const [button, command] of [["generate", "generate_key"], ["load", "load_key"], ["browse-load", "browse_key"]]) {
    ui.evaluate("openKeyOptions()");
    ui.refs.get("key-passphrase").value = "my emergency password";
    ui.refs.get(button).handlers.get("click")();
    await settle();
    assert.equal(calls.find((call) => call.command === command).args?.passphrase, undefined);
  }
});

test("legacy recovery while locked uses first setup without a second password", async () => {
  let prepared;
  const locked = { ...savedKeyStatus, keyLoaded: false, emergencyLocked: true, accessSetupRequired: true, accessSetupRequiresCurrentReference: true };
  const ui = fixture(async (command, args) => {
    if (command === "get_status") return locked;
    if (command === "prepare_first_run") { prepared = { ...args }; return { token: "migration", recoveryCode: "replacement" }; }
  });
  await ui.evaluate("init()");
  ui.evaluate("openKeyOptions()");
  ui.refs.get("new-key-passphrase").value = "a new emergency password";
  ui.refs.get("confirm-key-passphrase").value = "a new emergency password";
  ui.refs.get("key-recovery-code").value = "FE-R1-legacy-code";
  await ui.evaluate("prepareKeyProtection(true)");
  assert.equal(prepared.path, savedKeyStatus.keyPath);
  assert.equal(prepared.passphrase, "");
  assert.equal(prepared.recoveryCode, "FE-R1-legacy-code");
  assert.equal(ui.evaluate("state.emergencyLocked"), true);
});

test("a password mismatch keeps first-launch input available to correct without submitting", async () => {
  const calls = [];
  const firstLaunch = { keyLoaded: false, accessSetupRequired: true, accessSetupKeyPath: "C:/profile/workspace.key" };
  const ui = fixture(async (command) => { calls.push(command); if (command === "get_status") return firstLaunch; });
  await ui.evaluate("init()");
  ui.refs.get("new-key-passphrase").value = "first long password";
  ui.refs.get("confirm-key-passphrase").value = "different password";
  await ui.evaluate("prepareKeyProtection()");
  assert.equal(calls.includes("prepare_first_run"), false);
  assert.equal(ui.refs.get("new-key-passphrase").value, "first long password");
  assert.equal(ui.refs.get("confirm-key-passphrase").value, "different password");
  assert.match(ui.refs.get("key-dialog-alert").textContent, /matching passwords/);
  assert.equal(ui.refs.get("key-dialog").open, true);
});

test("manually closing a preview does not request key recovery", async () => {
  const calls = [];
  const ui = fixture(async (command, args) => {
    calls.push({ command, args });
    if (command === "sandbox_preview_info") return { sessionId: "1", item: { id: 0, name: "report.txt", kind: "text" } };
    if (command === "read_sandbox_preview") return textPreview();
  }, "sandbox-preview");
  await ui.evaluate("initPrivatePreview()");
  await ui.evaluate("closePrivatePreview()");
  const closed = calls.find(({ command }) => command === "close_sandbox_preview");
  assert.equal(closed.args.locked, false);
  assert.equal(ui.refs.get("preview-content").children.length, 0);
  assert.equal(ui.timers.size, 0);
});
