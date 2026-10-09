const state = {
  files: [],
  results: [],
  resultsOperation: "",
  fileSet: new Set(),
  folderRoots: new Map(),
  busy: false,
  keyLoaded: false,
  keyDisconnected: false,
  keyRevision: 0,
  keyHasFile: false,
  sandboxAvailable: false,
  keyFingerprint: null,
  keyPath: null,
  pendingJob: null,
  planRevision: 0,
  jobRunning: false,
  updatesConfigured: false,
  updateAvailable: false,
};

const $ = (id) => document.getElementById(id);
const KEY_DISCONNECTED_GUIDANCE = "Reconnect the drive containing your saved key. FileEncrypt checks for it automatically. If the file moved or the drive letter changed, use Browse and load.";

function invoke(command, args) {
  const call = window.__TAURI__?.core?.invoke;
  if (!call) {
    throw new Error("FileEncrypt commands are only available in the desktop window.");
  }
  return call(command, args);
}

async function invokeWithPassphrase(command, args = {}) {
  const field = $("key-passphrase");
  const passphrase = field.value;
  field.value = "";
  return invoke(command, { ...args, passphrase });
}

function normalizeError(error) {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}

function baseName(path) {
  const parts = String(path).split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function showAlert(message) {
  const alert = $("startup-key-dialog").open ? $("key-recovery-alert")
    : $("key-dialog").open ? $("key-dialog-alert") : $("alert");
  alert.hidden = false;
  alert.textContent = message;
}

function clearAlert() {
  for (const id of ["alert", "key-dialog-alert", "key-recovery-alert"]) {
    const alert = $(id);
    alert.hidden = true;
    alert.textContent = "";
  }
}

function showSpecificKeyView(show) {
  $("key-management-view").hidden = show;
  $("specific-key-view").hidden = !show;
  $("key-dialog-heading").textContent = show ? "Use a specific key" : "Key options";
  $("key-dialog-description").textContent = show
    ? "Use an existing key for this session or save it to a file."
    : "Manage the key file used for this workspace.";
  if (show) {
    $("key-text").focus();
  } else {
    $("key-text").value = "";
    $("open-specific-key").focus();
  }
}

function invalidatePreview() {
  state.planRevision++;
  state.pendingJob = null;
  $("preview-panel").hidden = true;
}

function addSelectedFiles(selected) {
  const paths = Array.isArray(selected) ? selected : selected.paths;
  const roots = Array.isArray(selected) ? {} : selected.roots;
  let changed = false;
  for (const path of paths) {
    if (roots[path] && state.folderRoots.get(path) !== roots[path]) {
      state.folderRoots.set(path, roots[path]);
      changed = true;
    }
    if (!state.fileSet.has(path)) {
      state.fileSet.add(path);
      state.files.push(path);
      changed = true;
    }
  }
  if (changed) invalidatePreview();
  renderFiles();
}

function applyStatus(status, updatePath) {
  const keyRevisionChanged = typeof status.keyRevision === "number" && status.keyRevision !== state.keyRevision;
  if (typeof status.keyRevision === "number") {
    if (status.keyRevision < state.keyRevision) return;
    state.keyRevision = status.keyRevision;
  }
  const wasDisconnected = state.keyDisconnected;
  if (keyRevisionChanged || (state.keyFingerprint !== null && state.keyFingerprint !== status.fingerprint)) {
    invalidatePreview();
  }
  state.keyFingerprint = status.fingerprint;
  state.keyPath = status.keyPath || null;
  state.keyLoaded = Boolean(status.keyLoaded);
  state.keyDisconnected = !state.keyLoaded && Boolean(status.startupKeyUnavailable);
  state.keyHasFile = state.keyLoaded && Boolean(status.keyPath);
  state.sandboxAvailable = state.keyHasFile && Boolean(status.sandboxAvailable);
  if (sandbox.paths.length && (!state.sandboxAvailable || state.keyFingerprint !== sandbox.fingerprint)) {
    lockSandbox(state.keyDisconnected
      ? "Sandbox locked because the key disconnected."
      : "Sandbox locked because the loaded key changed.", state.keyDisconnected);
  }
  if (sandbox.recovery) {
    if (state.keyLoaded && state.keyFingerprint !== sandbox.recovery.fingerprint) {
      cancelSandboxRecovery();
      $("sandbox-status").textContent = "Sandbox stays locked because a different key was loaded. Close this viewer to start a new sandbox.";
    } else if (!state.keyLoaded && !state.keyDisconnected) {
      if (wasDisconnected || sandbox.recovery.waitingForUnlock) {
        sandbox.recovery.waitingForUnlock = true;
        clearTimeout(sandbox.recoveryTimer);
        sandbox.recoveryTimer = null;
        $("sandbox-status").textContent = "Key file found. Open Key options to load it; the viewer will reload when the same key is unlocked.";
      } else {
        cancelSandboxRecovery();
      }
    } else if (state.sandboxAvailable) {
      sandbox.recovery.ready = true;
    }
  }
  state.updatesConfigured = Boolean(status.updatesConfigured);
  if (!state.updatesConfigured) $("update-status").textContent = "Signed updates are not configured in this build.";
  $("fingerprint").classList.toggle("is-loaded", state.keyLoaded);
  $("fingerprint").classList.toggle("is-disconnected", state.keyDisconnected);
  if (updatePath) {
    $("key-path").value = status.keyPath || "";
  }
  if (updatePath && typeof status.outputDir === "string") {
    $("output-dir").value = status.outputDir;
  }
  $("fingerprint").textContent = status.keyLoaded
    ? `${state.keyHasFile ? "Key loaded" : "Session key"} · ${status.fingerprint}`
    : state.keyDisconnected
      ? "Key disconnected"
      : "No key loaded";
  $("key-message").textContent = state.keyDisconnected
    ? KEY_DISCONNECTED_GUIDANCE
    : status.message || (state.keyLoaded
      ? "Ready to encrypt or decrypt your files."
      : "Choose a key to get started.");
  if (state.keyDisconnected && !wasDisconnected && !$("startup-key-dialog").open) {
    $("key-recovery-alert").hidden = true;
    $("key-recovery-status").textContent = "Watching for your key";
    $("startup-key-path").textContent = status.keyPath || "Unknown location";
    $("startup-key-dialog").showModal();
    $("check-key-again").focus();
  } else if (!state.keyDisconnected && $("startup-key-dialog").open) {
    $("startup-key-dialog").close();
  }
  renderControls();
  updateSandboxRecoveryUI();
  maybeResumeSandbox();
}

let fileRemoveButtons = [];
let deletionButtons = [];
let pendingDeletionTimer = null;
let pendingDeletionCheckRunning = false;
let pendingDeletionCursor = 0;
let pendingDeletionDelay = 1000;
const PENDING_DELETION_BATCH_SIZE = 100;
const pagedLists = new Map();
const PAGE_SIZE = 100;
function renderPaged(listId, pagerId, items, renderRow) {
  let view = pagedLists.get(listId);
  if (!view) {
    const previous = document.createElement("button");
    const next = document.createElement("button");
    const label = document.createElement("span");
    previous.type = next.type = "button";
    previous.textContent = "Previous";
    next.textContent = "Next";
    view = { page: 0, previous, next, label, items: [], renderRow: null };
    view.draw = () => {
      const count = Math.max(1, Math.ceil(view.items.length / PAGE_SIZE));
      view.page = Math.max(0, Math.min(view.page, count - 1));
      const start = view.page * PAGE_SIZE;
      if (listId === "file-list") fileRemoveButtons = [];
      if (listId === "results") deletionButtons = [];
      if (listId === "sandbox-list") sandbox.buttons = [];
      const fragment = document.createDocumentFragment();
      for (let index = start; index < Math.min(start + PAGE_SIZE, view.items.length); index++) {
        fragment.append(view.renderRow(view.items[index], index));
      }
      $(listId).replaceChildren(fragment);
      $(pagerId).hidden = count <= 1;
      previous.disabled = view.page === 0;
      next.disabled = view.page >= count - 1;
      label.textContent = `Page ${view.page + 1} of ${count} | ${view.items.length} items`;
    };
    previous.addEventListener("click", () => { view.page--; view.draw(); });
    next.addEventListener("click", () => { view.page++; view.draw(); });
    $(pagerId).append(previous, label, next);
    pagedLists.set(listId, view);
  }
  view.items = items;
  view.renderRow = renderRow;
  view.draw();
}

function renderControls() {
  for (const button of [...fileRemoveButtons, ...deletionButtons]) button.disabled = state.busy;
  const noFiles = state.files.length === 0;
  const blocked = state.busy || !state.keyLoaded || noFiles;
  $("key-recovery-files").hidden = noFiles;
  $("key-recovery-files").textContent = `${state.files.length} selected ${state.files.length === 1 ? "file is" : "files are"} kept for this app session. They will be ready when your key is loaded again.`;
  $("missing-key-warning").hidden = state.keyLoaded
    || !state.files.some((path) => /\.(fenc|zip)$/i.test(path));
  $("missing-key-title").textContent = state.keyDisconnected
    ? "Key disconnected."
    : "No encryption key loaded.";
  $("missing-key-guidance").textContent = state.keyDisconnected
    ? KEY_DISCONNECTED_GUIDANCE
    : "Use Browse and load to load the key used to encrypt these files before viewing, decrypting, or verifying them.";
  $("generate").classList.toggle("primary", !state.keyLoaded && !state.keyDisconnected);
  $("browse-load").classList.toggle("primary", state.keyDisconnected);
  $("encrypt").disabled = blocked;
  $("decrypt").disabled = blocked;
  $("view-sandbox").disabled = blocked || !state.sandboxAvailable;
  $("view-sandbox").title = state.sandboxAvailable
    ? "View without saving decrypted files; the key file must stay readable."
    : state.keyDisconnected
      ? "Reconnect your key drive; the sandbox is available once the key is loaded."
      : "Load a saved key file to use the sandbox. Session-only keys cannot keep it active.";
  $("verify").disabled = blocked;
  $("add-files").disabled = state.busy;
  $("add-folder").disabled = state.busy;
  $("clear-files").disabled = state.busy || noFiles;
  $("generate").disabled = state.busy;
  $("load").disabled = state.busy;
  $("unload").disabled = state.busy || !state.keyLoaded;
  $("check-key-again").disabled = state.busy;
  $("choose-recovery-key").disabled = state.busy;
  $("startup-key-options").disabled = state.busy;
  $("sandbox-key-options").disabled = state.busy;
  $("check-key-again").textContent = state.busy ? "Please wait…" : "Check again";
  $("set-path").disabled = state.busy;
  $("browse-load").disabled = state.busy;
  $("backup-key").disabled = state.busy || !state.keyHasFile;
  $("backup-key").title = state.keyLoaded && !state.keyHasFile
    ? "Session keys have no file to back up."
    : "";
  $("check-backup").disabled = state.busy || !state.keyLoaded;
  $("rotate-key").disabled = blocked;
  $("save-typed").disabled = state.busy;
  $("use-typed").disabled = state.busy;
  $("open-key-options").disabled = state.busy;
  $("open-specific-key").disabled = state.busy;
  $("choose-output").disabled = state.busy;
  $("clear-output").disabled = state.busy || $("output-dir").value.trim() === "";
  $("zip").disabled = state.busy;
  $("compress").disabled = state.busy || !$("zip").checked;
  $("review-first").disabled = state.busy;
  $("overwrite").disabled = state.busy;
  $("remove-original").disabled = state.busy;
  $("output-dir").disabled = state.busy;
  $("start-job").disabled = state.busy || !state.keyLoaded || !state.pendingJob?.preview?.canRun
    || state.pendingJob.revision !== state.planRevision;
  $("cancel-job").disabled = !state.jobRunning;
  $("check-update").disabled = state.busy || !state.updatesConfigured;
  $("install-update").disabled = state.busy || !state.updateAvailable;
  $("file-count").textContent = noFiles ? "" : `(${state.files.length})`;
  $("action-hint").textContent = state.busy
    ? "Working. Please wait…"
    : state.keyDisconnected
      ? "Reconnect your key drive; FileEncrypt will check for it automatically."
      : !state.keyLoaded && noFiles
        ? "Load a key and add files to get started."
        : !state.keyLoaded
          ? "Load a key to continue."
          : noFiles
            ? "Add files to continue."
            : `${state.files.length} ${state.files.length === 1 ? "file" : "files"} ready to encrypt, view, decrypt, or verify.`;
  renderOutputHint();
}

function plannedName(path) {
  const name = baseName(path);
  if (name.toLowerCase().endsWith(".zip")) return "files restored from inside the ZIP";
  if (name.length > 5 && name.toLowerCase().endsWith(".fenc")) {
    return "original name from inside the file";
  }
  if ($("zip").checked) return "an encrypted file inside the ZIP";
  return "a random .fenc name";
}

function renderOutputHint() {
  const dir = $("output-dir").value.trim();
  if ($("zip").checked) {
    const where = dir ? "to the chosen folder" : "beside the first selected file";
    $("output-hint").textContent = `One randomly named ZIP is saved ${where}. Add it later to decrypt its files.`;
  } else {
    const where = dir ? "to the chosen folder" : "beside each original";
    $("output-hint").textContent = `Saved ${where} with a random name. Decrypt restores the original name.`;
  }
}

function renderFiles() {
  const empty = $("file-empty");
  empty.hidden = state.files.length > 0;
  $("selection-area").classList.toggle("has-files", state.files.length > 0);
  renderPaged("file-list", "file-pages", state.files, (path) => {
    const item = document.createElement("li");
    item.className = "file-row";

    const text = document.createElement("div");
    text.className = "file-text";
    const name = document.createElement("div");
    name.className = "file-name";
    name.textContent = baseName(path);
    const full = document.createElement("div");
    full.className = "file-path";
    full.textContent = `Expected result: ${plannedName(path)}`;
    full.title = path;
    text.append(name, full);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "text-button";
    remove.textContent = "Remove";
    remove.disabled = state.busy;
    remove.setAttribute("aria-label", `Remove ${baseName(path)}`);
    fileRemoveButtons.push(remove);
    remove.addEventListener("click", () => {
      if (state.busy) return;
      const index = state.files.indexOf(path);
      if (index < 0) return;
      state.files.splice(index, 1);
      state.fileSet.delete(path);
      state.folderRoots.delete(path);
      invalidatePreview();
      renderFiles();
      renderControls();
    });

    item.append(text, remove);
    return item;
  });
  renderControls();
}

function renderResults(results, operation = state.resultsOperation) {
  if (state.results !== results) {
    pendingDeletionCursor = 0;
    pendingDeletionDelay = 1000;
    if (pendingDeletionTimer !== null) clearTimeout(pendingDeletionTimer);
    pendingDeletionTimer = null;
  }
  state.results = results;
  state.resultsOperation = operation;
  $("results-panel").hidden = results.length === 0;
  const succeeded = results.filter((result) => result.ok).length;
  const retained = results.filter((result) => result.deletion?.state === "retained").length;
  const pending = results.filter((result) => result.deletion?.state === "pending").length;
  $("result-summary").textContent = (operation === "verify"
    ? `${results.length} ${results.length === 1 ? "file" : "files"} | ${succeeded} verified, ${results.length - succeeded} failed`
    : `${succeeded} succeeded, ${results.length - succeeded} failed`)
    + (retained ? ` | ${retained} originals retained` : "")
    + (pending ? ` | ${pending} deletions pending` : "");
  renderPaged("results", "result-pages", results, (result) => {
    const item = document.createElement("li");
    item.className = result.ok ? "result ok" : "result fail";
    const text = document.createElement("div");
    text.className = "result-text";
    const title = document.createElement("div");
    title.className = "result-title";
    const originalName = result.ok ? result.originalName : null;
    title.textContent = originalName || (result.output
      ? `${baseName(result.input)} → ${baseName(result.output)}`
      : baseName(result.input));
    title.title = originalName
      ? `${result.input} → ${originalName}`
      : result.output ? `${result.input} → ${result.output}` : result.input;
    const message = document.createElement("div");
    message.className = "result-msg";
    message.textContent = originalName
      ? `${result.message} · ${result.input}`
      : result.output
      ? `${result.message} · ${result.output}`
      : result.message;
    text.append(title, message);
    const deletion = result.deletion;
    if (deletion && deletion.state !== "notRequested") {
      const status = document.createElement("div");
      status.className = "deletion-status";
      const label = { removed: "Original removed", pending: "Deletion pending", retained: "Original retained" }[deletion.state];
      status.textContent = `${label}: ${deletion.source}` + (deletion.reason ? ` | ${deletion.reason}` : "");
      if (deletion.state === "pending" && deletion.retryId) {
        status.textContent += " Checking automatically.";
      }
      text.append(status);
      if (deletion.retryId && deletion.state === "retained") {
        const retry = document.createElement("button");
        retry.type = "button";
        retry.className = "text-button deletion-retry";
        retry.textContent = "Retry deletion";
        retry.disabled = state.busy;
        retry.title = "The app verifies the original and saved copies, then retries deletion.";
        retry.addEventListener("click", () => retryOriginalDeletion(deletion.retryId));
        deletionButtons.push(retry);
        text.append(retry);
      }
    }
    item.append(text);
    return item;
  });
  schedulePendingDeletionCheck();
}

function schedulePendingDeletionCheck() {
  const pending = state.results.some((result) => result.deletion?.state === "pending" && result.deletion.retryId);
  if (!pending) {
    if (pendingDeletionTimer !== null) clearTimeout(pendingDeletionTimer);
    pendingDeletionTimer = null;
    pendingDeletionDelay = 1000;
    return;
  }
  if (pendingDeletionTimer !== null || pendingDeletionCheckRunning) return;
  pendingDeletionTimer = setTimeout(() => {
    pendingDeletionTimer = null;
    return checkPendingDeletions();
  }, pendingDeletionDelay);
}

async function checkPendingDeletions() {
  if (pendingDeletionCheckRunning) return;
  if (state.busy) {
    schedulePendingDeletionCheck();
    return;
  }
  const results = state.results;
  const pending = results.filter((result) => result.deletion?.state === "pending" && result.deletion.retryId);
  if (!pending.length) return;
  // Rotate through the whole report, including rows outside the current page.
  const start = pendingDeletionCursor % pending.length;
  const retryIds = Array.from({ length: Math.min(pending.length, PENDING_DELETION_BATCH_SIZE) },
    (_, index) => pending[(start + index) % pending.length].deletion.retryId);
  pendingDeletionCursor = (start + retryIds.length) % pending.length;
  pendingDeletionCheckRunning = true;
  try {
    const updates = await invoke("check_pending_deletions", { retryIds });
    pendingDeletionDelay = 1000;
    if (state.results !== results) return;
    const byId = new Map(updates.map((update) => [update.retryId, update.deletion]));
    let changed = false;
    for (const result of results) {
      const previous = result.deletion;
      if (previous?.state !== "pending" || !byId.has(previous.retryId)) continue;
      const deletion = byId.get(previous.retryId) || {
        ...previous, retryId: null,
        reason: "Deletion was accepted, but its automatic status receipt is no longer available.",
      };
      if (previous.state !== deletion.state || previous.source !== deletion.source
        || previous.reason !== deletion.reason || previous.retryId !== deletion.retryId) {
        result.deletion = deletion;
        changed = true;
      }
    }
    if (changed) renderResults(results);
  } catch {
    // Transient IPC failures should not interrupt a successful file job or
    // create an alert every second. Keep the honest pending status and retry.
    pendingDeletionDelay = Math.min(pendingDeletionDelay * 2, 10000);
  } finally {
    pendingDeletionCheckRunning = false;
    schedulePendingDeletionCheck();
  }
}

async function retryOriginalDeletion(retryId) {
  if (state.busy) return;
  state.jobRunning = true;
  $("progress-panel").hidden = false;
  $("job-progress").removeAttribute("value");
  $("progress-label").textContent = "Checking files before deleting the original...";
  try {
    await run(async () => {
      const deletion = await invoke("retry_deletion", { retryId });
      for (const result of state.results) {
        if (result.deletion?.retryId === retryId) result.deletion = deletion;
      }
      renderResults(state.results);
    }, false);
  } finally {
    state.jobRunning = false;
    $("progress-panel").hidden = true;
    renderControls();
  }
}

async function run(work, updatePathOnSuccess) {
  if (state.busy) return;
  state.busy = true;
  renderControls();
  clearAlert();
  try {
    const value = await work();
    if (value && typeof value === "object" && "keyLoaded" in value) {
      applyStatus(value, updatePathOnSuccess);
    }
    return value;
  } catch (error) {
    showAlert(normalizeError(error));
    try {
      applyStatus(await invoke("get_status"), false);
    } catch {
      renderControls();
    }
    return null;
  } finally {
    state.busy = false;
    renderControls();
    maybeResumeSandbox();
  }
}

async function runKeyOption(work, updatePathOnSuccess) {
  const result = await run(work, updatePathOnSuccess);
  if (result) $("key-dialog").close();
  return result;
}

function openKeyOptions() {
  clearAlert();
  $("key-management-view").hidden = false;
  $("specific-key-view").hidden = true;
  $("key-dialog-heading").textContent = "Key options";
  $("key-dialog-description").textContent = "Manage the key file used for this workspace.";
  if (!$("key-dialog").open) $("key-dialog").showModal();
  if (sandbox.recovery?.waitingForUnlock) $("key-passphrase").focus();
  else $("close-key-options").focus();
}

async function recheckKeyFile() {
  if (state.busy) return;
  $("key-recovery-status").textContent = "Checking the saved key…";
  const result = await run(recheckKeyFileStatus, false);
  if (result && state.keyDisconnected) $("key-recovery-status").textContent = "Still waiting for your key";
}

let keyFileCheck = null;
function recheckKeyFileStatus() {
  // A timeout must not spawn more blocked reads against the same slow drive.
  if (!keyFileCheck) {
    const pending = invoke("recheck_key_file");
    keyFileCheck = pending;
    const settled = () => { if (keyFileCheck === pending) keyFileCheck = null; };
    pending.then(settled, settled);
  }
  return withSandboxDeadline(keyFileCheck, "The key drive is taking too long to respond. FileEncrypt will keep watching for it.");
}

const sandbox = {
  generation: 0, sessionId: null, fingerprint: null,
  selection: 0, items: [], buttons: [], loading: false, timer: null,
  paths: [], currentItemId: null, recovery: null, recoveryTimer: null,
};
// Keep this exact stylesheet's SHA-256 in tauri.conf.json and the preview CSP.
const SANDBOX_STYLE = "html{color-scheme:light dark}body{margin:16px;font:14px system-ui,sans-serif}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px ui-monospace,monospace}img,video{display:block;max-width:100%;max-height:85vh;margin:auto}audio{width:100%}";
const SANDBOX_STYLE_HASH = "sha256-+d/I4iYM/9I6DotUkT3YfqOsiHrpFkzcIQG8DqehNDo=";

function clearSandboxPreview() {
  // Removing the frame stops playback and destroys the document containing text.
  $("sandbox-preview").replaceChildren();
  $("sandbox-file-name").textContent = "";
}

function resetSandbox() {
  const sessionId = sandbox.sessionId;
  sandbox.generation++;
  sandbox.selection++;
  sandbox.sessionId = null;
  sandbox.fingerprint = null;
  sandbox.items = [];
  sandbox.buttons = [];
  sandbox.loading = false;
  sandbox.paths = [];
  sandbox.currentItemId = null;
  cancelSandboxRecovery();
  clearTimeout(sandbox.timer);
  sandbox.timer = null;
  clearSandboxPreview();
  renderPaged("sandbox-list", "sandbox-pages", [], () => document.createElement("li"));
  $("sandbox-warnings").textContent = "";
  $("sandbox-status").textContent = "";
  if (sessionId) invoke("close_sandbox", { sessionId }).catch(() => {});
}

function lockSandbox(message = "Sandbox locked because key-file access was lost or changed.", canResume = true) {
  // Recovery keeps encrypted source paths, a fingerprint, and an item index.
  // Plaintext, decrypted names, and the revoked session are always discarded.
  const recovery = canResume ? sandbox.recovery || (sandbox.paths.length && sandbox.fingerprint ? {
    paths: [...sandbox.paths], fingerprint: sandbox.fingerprint,
    itemId: sandbox.currentItemId, ready: false, waitingForUnlock: false,
  } : null) : null;
  resetSandbox();
  sandbox.recovery = recovery;
  $("sandbox-status").textContent = message + (recovery ? " This viewer will reload when the same key is available." : "");
  updateSandboxRecoveryUI();
  scheduleSandboxRecoveryCheck();
}

function cancelSandboxRecovery() {
  clearTimeout(sandbox.recoveryTimer);
  sandbox.recoveryTimer = null;
  sandbox.recovery = null;
  updateSandboxRecoveryUI();
}

function updateSandboxRecoveryUI() {
  $("sandbox-recovery").hidden = !sandbox.recovery;
  $("key-recovery-sandbox").hidden = !sandbox.recovery;
}

function scheduleSandboxRecoveryCheck() {
  clearTimeout(sandbox.recoveryTimer);
  sandbox.recoveryTimer = null;
  if (!sandbox.recovery || sandbox.recovery.waitingForUnlock || !$("sandbox-dialog").open) return;
  sandbox.recoveryTimer = setTimeout(checkSandboxRecovery, 1000);
}

async function checkSandboxRecovery() {
  sandbox.recoveryTimer = null;
  const recovery = sandbox.recovery;
  if (!recovery || !$("sandbox-dialog").open) return;
  if (!state.busy) {
    try {
      const status = await recheckKeyFileStatus();
      if (sandbox.recovery === recovery) applyStatus(status, false);
    } catch {
      // Stay locked if the drive or IPC is slow; a later check can recover.
    }
  }
  if (sandbox.recovery === recovery) scheduleSandboxRecoveryCheck();
}

function maybeResumeSandbox() {
  const recovery = sandbox.recovery;
  if (!recovery?.ready || state.busy || !state.sandboxAvailable
      || !$("sandbox-dialog").open || $("key-dialog").open || $("startup-key-dialog").open) return;
  if (state.keyFingerprint !== recovery.fingerprint) {
    cancelSandboxRecovery();
    return;
  }
  cancelSandboxRecovery();
  return openSandbox(recovery);
}

function withSandboxDeadline(promise, message = "Sandbox locked because key-file access could not be confirmed.") {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), 1500);
    promise.then((value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); });
  });
}

function scheduleSandboxCheck() {
  clearTimeout(sandbox.timer);
  if (!sandbox.sessionId) return;
  sandbox.timer = setTimeout(checkSandboxKey, 500);
}

async function checkSandboxKey() {
  const sessionId = sandbox.sessionId;
  const generation = sandbox.generation;
  if (!sessionId) return;
  try {
    await withSandboxDeadline(invoke("check_sandbox", { sessionId }));
  } catch (error) {
    if (generation === sandbox.generation) lockSandbox(normalizeError(error));
    return;
  }
  if (generation === sandbox.generation) scheduleSandboxCheck();
}

async function openSandbox(options = {}) {
  const paths = options.paths || [...state.files];
  if (state.busy || !state.sandboxAvailable || !paths.length) return;
  resetSandbox();
  sandbox.paths = [...paths];
  sandbox.fingerprint = state.keyFingerprint;
  const generation = sandbox.generation;
  state.busy = true;
  renderControls();
  $("sandbox-status").textContent = "Reading encrypted file names…";
  if (!$("sandbox-dialog").open) $("sandbox-dialog").showModal();
  $("close-sandbox").focus();
  try {
    const catalog = await invoke("open_sandbox", { paths });
    if (generation !== sandbox.generation) {
      invoke("close_sandbox", { sessionId: catalog.sessionId }).catch(() => {});
      return;
    }
    sandbox.sessionId = catalog.sessionId;
    // A late catalogue response must not reveal names after a key disconnect.
    await withSandboxDeadline(invoke("check_sandbox", { sessionId: catalog.sessionId }));
    if (generation !== sandbox.generation) return;
    sandbox.items = catalog.items;
    $("sandbox-warnings").textContent = catalog.warnings.join("\n");
    renderPaged("sandbox-list", "sandbox-pages", sandbox.items, (item) => {
      const row = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "sandbox-file";
      button.textContent = item.name;
      button.disabled = sandbox.loading;
      sandbox.buttons.push(button);
      button.addEventListener("click", () => viewSandboxFile(item));
      row.append(button);
      return row;
    });
    $("sandbox-status").textContent = "Choose a file to preview. Keep the key file connected and readable.";
    scheduleSandboxCheck();
    const previous = sandbox.items.find((item) => item.id === options.itemId);
    if (previous || sandbox.items.length === 1) await viewSandboxFile(previous || sandbox.items[0]);
  } catch (error) {
    if (generation === sandbox.generation) {
      const message = normalizeError(error);
      lockSandbox(message, state.keyDisconnected || message.startsWith("Sandbox locked"));
    }
  } finally {
    state.busy = false;
    renderControls();
    maybeResumeSandbox();
  }
}

function escapeSandboxText(text) {
  return text.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function sandboxDocument(content) {
  const encoded = content.data;
  content.data = "";
  let body;
  if (content.kind === "text") {
    const bytes = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
    try {
      body = `<pre>${escapeSandboxText(new TextDecoder("utf-8", { fatal: true }).decode(bytes))}</pre>`;
    } finally {
      bytes.fill(0);
    }
  } else {
    const allowed = {
      image: ["image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/x-icon"],
      audio: ["audio/mpeg", "audio/wav", "audio/ogg", "audio/mp4", "audio/flac"],
      video: ["video/mp4", "video/webm", "video/ogg"],
    };
    if (!allowed[content.kind]?.includes(content.mime)) throw new Error("Unsupported preview format.");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new Error("Invalid preview data.");
    // Data URLs work in an opaque-origin frame without granting same-origin
    // access or exposing a reusable object URL outside that frame.
    const url = `data:${content.mime};base64,${encoded}`;
    body = content.kind === "image"
      ? `<img src="${url}" alt="File preview">`
      : `<${content.kind} src="${url}" controls controlslist="nodownload noremoteplayback" disablepictureinpicture disableremoteplayback></${content.kind}>`;
  }
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; media-src data:; style-src '${SANDBOX_STYLE_HASH}'; base-uri 'none'; form-action 'none'"><style>${SANDBOX_STYLE}</style></head><body>${body}</body></html>`;
}

async function viewSandboxFile(item) {
  const sessionId = sandbox.sessionId;
  if (!sessionId || sandbox.loading) return;
  const generation = sandbox.generation;
  const selection = ++sandbox.selection;
  sandbox.currentItemId = item.id;
  sandbox.loading = true;
  for (const button of sandbox.buttons) button.disabled = true;
  clearSandboxPreview();
  $("sandbox-status").textContent = "Authenticating file in memory…";
  let content;
  try {
    content = await invoke("read_sandbox_file", { sessionId, itemId: item.id });
    if (generation !== sandbox.generation || selection !== sandbox.selection) return;
    try {
      await withSandboxDeadline(invoke("check_sandbox", { sessionId }));
    } catch (error) {
      if (generation === sandbox.generation) lockSandbox(normalizeError(error));
      return;
    }
    if (generation !== sandbox.generation || selection !== sandbox.selection) return;
    const frame = document.createElement("iframe");
    // No scripts, same-origin access, downloads, popups, forms, or navigation.
    frame.setAttribute("sandbox", "");
    frame.setAttribute("referrerpolicy", "no-referrer");
    frame.setAttribute("allow", "camera 'none'; microphone 'none'; geolocation 'none'; clipboard-write 'none'");
    frame.title = `Read-only preview: ${item.name}`;
    frame.srcdoc = sandboxDocument(content);
    $("sandbox-preview").replaceChildren(frame);
    $("sandbox-file-name").textContent = item.name;
    $("sandbox-status").textContent = "Read-only preview • Key file access is checked continuously.";
  } catch (error) {
    if (generation === sandbox.generation && selection === sandbox.selection) {
      clearSandboxPreview();
      $("sandbox-status").textContent = normalizeError(error);
    }
  } finally {
    if (content) content.data = "";
    if (generation === sandbox.generation && selection === sandbox.selection) {
      sandbox.loading = false;
      for (const button of sandbox.buttons) button.disabled = false;
    }
  }
}

async function init() {
  try {
    await window.__TAURI__?.event?.listen("key-status-changed", ({ payload }) => {
      applyStatus(payload, false);
    });
    await window.__TAURI__?.event?.listen("sandbox-locked", ({ payload }) => {
      if (payload === sandbox.sessionId) lockSandbox();
    });
    await window.__TAURI__?.event?.listen("job-progress", ({ payload }) => {
      const { processedBytes, totalBytes, currentFile, fileIndex, fileCount, stage } = payload;
      const percentage = totalBytes ? Math.min(100, Math.round((processedBytes / totalBytes) * 100)) : 0;
      $("job-progress").value = percentage;
      $("progress-label").textContent = `${stage}: ${baseName(currentFile)} (${fileIndex}/${fileCount}) · ${percentage}%`;
    });
    await window.__TAURI__?.webview?.getCurrentWebview()?.onDragDropEvent((event) => {
      if (event.payload.type === "drop" && !state.busy) {
        run(async () => {
          addSelectedFiles(await invoke("expand_dropped_paths", { paths: event.payload.paths }));
          return null;
        }, false);
      }
      document.body.classList.toggle("drag-over", event.payload.type === "enter" || event.payload.type === "over");
    });
  } catch (error) {
    showAlert(normalizeError(error));
  }
  $("open-key-options").addEventListener("click", openKeyOptions);
  $("sandbox-key-options").addEventListener("click", openKeyOptions);
  $("close-key-options").addEventListener("click", () => $("key-dialog").close());
  for (const id of ["close-startup-key", "dismiss-startup-key"]) {
    $(id).addEventListener("click", () => $("startup-key-dialog").close());
  }
  $("startup-key-dialog").addEventListener("close", () => {
    if (!$("key-dialog").open) {
      if ($("sandbox-dialog").open) $("close-sandbox").focus();
      else $("open-key-options").focus();
    }
    maybeResumeSandbox();
  });
  $("startup-key-options").addEventListener("click", () => {
    $("startup-key-dialog").close();
    $("key-path").value = state.keyPath || $("key-path").value;
    openKeyOptions();
  });
  $("check-key-again").addEventListener("click", recheckKeyFile);
  $("choose-recovery-key").addEventListener("click", () => {
    run(() => invokeWithPassphrase("browse_key"), true);
  });
  $("key-dialog").addEventListener("close", () => {
    $("key-text").value = "";
    if ($("sandbox-dialog").open) $("close-sandbox").focus();
    else $("open-key-options").focus();
    maybeResumeSandbox();
  });
  $("open-specific-key").addEventListener("click", () => showSpecificKeyView(true));
  $("back-to-key-options").addEventListener("click", () => showSpecificKeyView(false));
  $("set-path").addEventListener("click", () => {
    run(async () => {
      const picked = await invoke("pick_save_path");
      if (picked) $("key-path").value = picked;
      return invoke("get_status");
    }, false);
  });

  $("browse-load").addEventListener("click", () => {
    run(() => invokeWithPassphrase("browse_key"), true);
  });

  $("generate").addEventListener("click", () => {
    run(
      () => invokeWithPassphrase("generate_key", { path: $("key-path").value }),
      true,
    );
  });

  $("load").addEventListener("click", () => {
    runKeyOption(() => invokeWithPassphrase("load_key", { path: $("key-path").value }), true);
  });

  $("unload").addEventListener("click", () => {
    runKeyOption(() => invoke("unload_key"), false);
  });

  $("save-typed").addEventListener("click", () => {
    runKeyOption(async () => {
      const keyText = $("key-text").value;
      $("key-text").value = "";
      const status = await invokeWithPassphrase("save_typed_key", {
        path: $("key-path").value,
        keyText,
      });
      return status;
    }, true);
  });

  $("use-typed").addEventListener("click", () => {
    runKeyOption(async () => {
      let keyText = $("key-text").value;
      $("key-text").value = "";
      $("key-passphrase").value = "";
      try {
        return await invoke("use_typed_key", { keyText });
      } finally {
        keyText = "";
      }
    }, true);
  });

  $("backup-key").addEventListener("click", () => runKeyOption(() => invokeWithPassphrase("backup_key"), false));
  $("check-backup").addEventListener("click", () =>
    runKeyOption(() => invokeWithPassphrase("check_key_backup"), false));

  $("rotate-key").addEventListener("click", async () => {
    if (state.busy || !state.keyLoaded || !state.files.length) return;
    $("key-dialog").close();
    state.jobRunning = true;
    $("progress-panel").hidden = false;
    $("job-progress").value = 0;
    $("progress-label").textContent = "Choose a new key-file path...";
    try {
      await run(async () => {
        const report = await invokeWithPassphrase("rotate_key", {
          paths: [...state.files],
          outputDir: $("output-dir").value,
          removeOriginal: $("remove-original").checked,
        });
        if (report) {
          renderResults(report.results, "rotate");
          applyStatus(report.status, true);
        }
        return null;
      }, false);
    } finally {
      state.jobRunning = false;
      $("progress-panel").hidden = true;
      renderControls();
    }
  });

  $("output-dir").addEventListener("input", () => {
    invalidatePreview();
    renderControls();
  });

  $("zip").addEventListener("change", () => {
    invalidatePreview();
    renderFiles();
  });

  $("compress").addEventListener("change", invalidatePreview);

  for (const id of ["overwrite", "remove-original"]) {
    $(id).addEventListener("change", invalidatePreview);
  }

  $("choose-output").addEventListener("click", () => {
    run(async () => {
      const picked = await invoke("pick_output_dir");
      if (picked) $("output-dir").value = picked;
      invalidatePreview();
      renderOutputHint();
      return null;
    }, false);
  });

  $("clear-output").addEventListener("click", () => {
    $("output-dir").value = "";
    invalidatePreview();
    run(() => invoke("set_output_dir", { path: "" }), true);
  });

  $("add-files").addEventListener("click", () => {
    run(async () => {
      const picked = await invoke("pick_input_files");
      addSelectedFiles(picked);
      return null;
    }, false);
  });

  $("file-empty").addEventListener("click", () => $("add-files").click());
  $("file-empty").addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      $("add-files").click();
    }
  });

  $("add-folder").addEventListener("click", () => {
    run(async () => {
      addSelectedFiles(await invoke("pick_input_folder"));
      return null;
    }, false);
  });

  $("clear-files").addEventListener("click", () => {
    state.files = [];
    state.fileSet.clear();
    state.folderRoots.clear();
    invalidatePreview();
    renderFiles();
  });

  $("encrypt").addEventListener("click", () => prepareJob("encrypt"));
  $("decrypt").addEventListener("click", () => prepareJob("decrypt"));
  $("view-sandbox").addEventListener("click", openSandbox);
  $("close-sandbox").addEventListener("click", () => $("sandbox-dialog").close());
  $("sandbox-dialog").addEventListener("close", () => {
    resetSandbox();
    $("view-sandbox").focus();
  });
  window.addEventListener("pagehide", () => resetSandbox());
  $("verify").addEventListener("click", () => prepareJob("verify"));
  $("start-job").addEventListener("click", startJob);
  $("dismiss-preview").addEventListener("click", invalidatePreview);
  $("cancel-job").addEventListener("click", async () => {
    if (await invoke("cancel_job")) $("progress-label").textContent = "Cancelling after the current chunk...";
  });

  $("check-update").addEventListener("click", async () => {
    const checked = await run(async () => ({ update: await invoke("check_for_updates") }), false);
    if (!checked) return;
    const { update } = checked;
    state.updateAvailable = Boolean(update);
    $("install-update").hidden = !update;
    $("update-status").textContent = update
      ? `Version ${update.version} is available.${update.notes ? ` ${update.notes}` : ""}`
      : "You are up to date.";
    renderControls();
  });

  $("install-update").addEventListener("click", async () => {
    const message = await run(() => invoke("install_update"), false);
    if (message) $("update-status").textContent = message;
  });

  try {
    const initialStatus = await invoke("get_status");
    applyStatus(initialStatus, true);
  } catch (error) {
    showAlert(normalizeError(error));
    renderControls();
  }
  renderFiles();
}

async function prepareJob(operation) {
  if (state.busy || !state.keyLoaded || !state.files.length) return;
  invalidatePreview();
  const revision = state.planRevision;
  const request = {
      paths: [...state.files],
      folderRoots: Object.fromEntries(state.folderRoots),
      outputDir: $("output-dir").value,
      overwrite: $("overwrite").checked,
      removeOriginal: $("remove-original").checked,
      zip: $("zip").checked,
      compress: $("zip").checked && $("compress").checked,
      operation,
  };
  const preview = await run(() => invoke("preview_job", { request }), false);
  if (!preview || revision !== state.planRevision || !state.keyLoaded) return;
  state.pendingJob = { request, preview, revision };
  if (preview.canRun && !$("review-first").checked) {
    await startJob();
    return;
  }
  renderPaged("preview-list", "preview-pages", preview.items, (item) => {
    const row = document.createElement("li");
    row.className = item.issue ? "preview-issue" : "";
    row.textContent = `${baseName(item.input)} → ${item.output}${item.issue ? ` · ${item.issue}` : ""}`;
    row.title = item.input;
    return row;
  });
  const warnings = $("preview-warnings");
  warnings.replaceChildren();
  for (const warning of preview.warnings) {
    const row = document.createElement("li");
    row.textContent = warning;
    warnings.append(row);
  }
  $("preview-heading").textContent = `Review ${operation}`;
  $("preview-summary").textContent = `${preview.items.length} ${preview.items.length === 1 ? "file" : "files"} · ${formatBytes(preview.totalBytes)}`;
  $("preview-panel").hidden = false;
  renderControls();
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let index = -1;
  do { value /= 1024; index++; } while (value >= 1024 && index < units.length - 1);
  return `${value.toFixed(1)} ${units[index]}`;
}

async function startJob() {
  const job = state.pendingJob;
  if (state.busy || !state.keyLoaded || !job?.preview?.canRun || job.revision !== state.planRevision) return;
  invalidatePreview();
  state.jobRunning = true;
  $("progress-panel").hidden = false;
  $("job-progress").value = 0;
  $("progress-label").textContent = "Preparing...";
  try {
    await run(async () => {
      const results = await invoke("run_job", { request: job.request });
      renderResults(results, job.request.operation);
      return invoke("get_status");
    }, false);
  } finally {
    state.jobRunning = false;
    $("progress-panel").hidden = true;
    renderControls();
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    init();
  });
} else {
  init();
}
