const state = {
  files: [],
  results: [],
  resultsOperation: "",
  fileSet: new Set(),
  folderRoots: new Map(),
  busy: false,
  selectionBusy: false,
  keyLoaded: false,
  keyDisconnected: false,
  emergencyLocked: false,
  emergencyDeletionArmed: false,
  emergencyDeletionPath: null,
  emergencyDeletionMessage: "",
  emergencyShortcutsNative: false,
  accessSetupRequired: false,
  accessSetupIsUpgrade: false,
  accessSetupKeyPath: null,
  accessSetupRequiresCurrentReference: false,
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
const keyProtection = { token: null, generation: 0, firstRun: false, firstRunVisible: false, operation: null };
const savedSelection = { revision: 0, ready: false, pending: true, restoring: false, timer: null, writing: false, dirty: false, inFlight: null };
const fileVerification = { ready: false, generation: 0, running: false, entries: new Map(), badges: new Map() };
const KEY_DISCONNECTED_GUIDANCE = "Reconnect your key drive to continue.";
const KEY_READ_ERROR = "Unable to read the saved key.";
const MAX_SELECTED_FILES = 10000;
const ROUTINE_KEY_MESSAGES = new Set([
  "Key loaded.",
  "Key loaded from the saved location.",
  "Key reconnected and loaded.",
  "Key reconnected and loaded from the saved location.",
  "New key generated and saved.",
  "Key written to the file.",
  "Ready to encrypt or decrypt your files.",
]);

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
  if (message.replace(/\s+/g, " ").trim() === KEY_READ_ERROR) {
    clearAlert();
    showKeyRecoveryDialog(true);
    return;
  }
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

function updateKeyRecoveryDialog(readError = state.emergencyLocked) {
  const dialog = $("startup-key-dialog");
  dialog.classList.toggle("is-read-error", readError);
  $("key-disconnected-icon").innerHTML = EXPLORER_ICONS[readError ? "disconnected" : "unplug"];
  $("startup-key-file-icon").innerHTML = EXPLORER_ICONS.needsKey;
  $("startup-key-heading").textContent = readError ? "Key unavailable" : "Key disconnected";
  $("startup-key-description").textContent = readError
    ? "The saved key file could not be opened." : KEY_DISCONNECTED_GUIDANCE;
  $("startup-key-path").textContent = state.keyPath || "Location unavailable";
  $("startup-key-path").title = state.keyPath || "";
  $("startup-key-instructions").hidden = readError;
}

function showKeyRecoveryDialog(readError = state.emergencyLocked) {
  $("key-recovery-alert").hidden = true;
  updateKeyRecoveryDialog(readError);
  if ($("key-dialog").open) $("key-dialog").close();
  if (!$("startup-key-dialog").open) $("startup-key-dialog").showModal();
  $("choose-recovery-key").focus();
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

function addSelectedFiles(selected, remember = true) {
  const paths = Array.isArray(selected) ? selected : selected.paths;
  const roots = Array.isArray(selected) ? {} : selected.roots;
  const additions = new Set(paths.filter((path) => !state.fileSet.has(path)));
  if (state.files.length + additions.size > MAX_SELECTED_FILES) {
    throw new Error("Select at most 10,000 files in total. Remove some selected files before adding this selection.");
  }
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
  if (changed) {
    invalidatePreview();
    if (remember) rememberSelectedFiles();
  }
  renderFiles();
  queueFileVerification(paths);
}

function updateFileVerification(path) {
  const badge = fileVerification.badges.get(path);
  if (!badge) return;
  const result = fileVerification.entries.get(path);
  const encrypted = /\.(fenc|zip)$/i.test(path);
  const status = state.keyDisconnected ? "disconnected" : !state.keyLoaded ? "needsKey"
    : encrypted ? result?.state || "pending" : "unencrypted";
  const label = status === "verified" ? "Verified" : status === "checking" ? "Verifying"
    : status === "failed" ? "Verification failed" : status === "disconnected" ? "Key disconnected"
      : status === "unencrypted" ? "Ready to encrypt" : status === "needsKey"
        ? encrypted ? "Load a key to verify" : "Load a key to encrypt" : "Waiting to verify";
  badge.className = `file-verification is-${status}${result?.complete === false && status === "verified" ? " is-partial" : ""}`;
  badge.innerHTML = EXPLORER_ICONS[status];
  badge.title = status === "disconnected" ? "Key disconnected. Reconnect the key to use this file."
    : status === "needsKey" || status === "unencrypted" ? label
    : result?.message ? `${label}: ${result.message}` : label;
  badge.setAttribute("aria-label", badge.title);
}

function queueFileVerification(paths) {
  for (const path of paths) {
    if (!state.fileSet.has(path) || !/\.(fenc|zip)$/i.test(path)) continue;
    fileVerification.entries.set(path, { state: "pending" });
    updateFileVerification(path);
  }
  startAutomaticVerification();
}

function resetFileVerification() {
  fileVerification.generation++;
  fileVerification.entries.clear();
  for (const path of state.files) {
    if (/\.(fenc|zip)$/i.test(path)) fileVerification.entries.set(path, { state: "pending" });
    updateFileVerification(path);
  }
}

async function startAutomaticVerification() {
  if (!fileVerification.ready || fileVerification.running || state.busy || state.selectionBusy || !state.keyLoaded) return;
  const batch = [...fileVerification.entries].filter(([path, result]) => state.fileSet.has(path) && result.state === "pending").slice(0, 32);
  if (!batch.length) return;
  const generation = fileVerification.generation;
  const keyRevision = state.keyRevision;
  fileVerification.running = true;
  for (const [path, result] of batch) {
    result.state = "checking";
    updateFileVerification(path);
  }
  let paused = false;
  try {
    const results = await invoke("verify_selected_files", { paths: batch.map(([path]) => path), keyRevision });
    if (generation !== fileVerification.generation || keyRevision !== state.keyRevision || !state.keyLoaded) return;
    for (const [path, token] of batch) {
      if (!state.fileSet.has(path) || fileVerification.entries.get(path) !== token) continue;
      const result = results.find((result) => result.input === path);
      Object.assign(token, result || { state: "failed", message: "No verification result was returned." });
      paused ||= token.state === "pending";
      updateFileVerification(path);
    }
  } catch (error) {
    if (generation !== fileVerification.generation) return;
    for (const [path, token] of batch) {
      if (!state.fileSet.has(path) || fileVerification.entries.get(path) !== token) continue;
      Object.assign(token, { state: "failed", message: normalizeError(error) });
      updateFileVerification(path);
    }
  } finally {
    fileVerification.running = false;
    if (generation !== fileVerification.generation || !paused) startAutomaticVerification();
  }
}

function rememberSelectedFiles() {
  savedSelection.revision++;
  savedSelection.pending = false;
  savedSelection.dirty = true;
  if (!savedSelection.ready) return;
  clearTimeout(savedSelection.timer);
  savedSelection.timer = setTimeout(flushSelectedFiles, 150);
}

function flushSelectedFiles() {
  clearTimeout(savedSelection.timer);
  savedSelection.timer = null;
  if (savedSelection.writing) return savedSelection.inFlight;
  // Closing may flush a user edit while the initial status call is pending.
  if (!savedSelection.dirty) return;
  savedSelection.writing = true;
  savedSelection.dirty = false;
  const revision = savedSelection.revision;
  const selection = { paths: [...state.files], roots: Object.fromEntries(state.folderRoots) };
  savedSelection.inFlight = Promise.resolve().then(() => invoke("remember_selected_files", {
      revision,
      selection,
    })).catch((error) => {
    if (revision === savedSelection.revision) showAlert(`Could not remember the file selection: ${normalizeError(error)}`);
  }).finally(() => {
    savedSelection.writing = false;
    savedSelection.inFlight = null;
    if (savedSelection.dirty) return flushSelectedFiles();
  });
  return savedSelection.inFlight;
}

async function maybeRestoreSelectedFiles() {
  if (!savedSelection.ready || !savedSelection.pending || savedSelection.restoring
      || state.busy || state.selectionBusy || !state.keyHasFile) return;
  savedSelection.restoring = true;
  const revision = savedSelection.revision;
  const keyRevision = state.keyRevision;
  try {
    const selection = await invoke("restore_selected_files");
    if (revision !== savedSelection.revision || keyRevision !== state.keyRevision || !state.keyHasFile) return;
    if (Array.isArray(selection?.paths)) {
      savedSelection.pending = false;
      addSelectedFiles(selection, false);
    }
  } catch (error) {
    if (revision === savedSelection.revision && keyRevision === state.keyRevision) {
      savedSelection.pending = false;
      showAlert(`Could not restore the file selection: ${normalizeError(error)}`);
    }
  } finally {
    savedSelection.restoring = false;
    if (savedSelection.pending && keyRevision !== state.keyRevision) maybeRestoreSelectedFiles();
  }
}

function applyStatus(status, updatePath) {
  const keyRevisionChanged = typeof status.keyRevision === "number" && status.keyRevision !== state.keyRevision;
  if (typeof status.keyRevision === "number") {
    if (status.keyRevision < state.keyRevision) return;
    state.keyRevision = status.keyRevision;
  }
  const wasDisconnected = state.keyDisconnected;
  const wasEmergencyLocked = state.emergencyLocked;
  const wasSetupRequired = state.accessSetupRequired;
  if (typeof status.accessSetupRequired === "boolean") state.accessSetupRequired = status.accessSetupRequired;
  state.accessSetupIsUpgrade = Boolean(status.accessSetupIsUpgrade);
  state.accessSetupKeyPath = status.accessSetupKeyPath || state.accessSetupKeyPath;
  state.accessSetupRequiresCurrentReference = Boolean(status.accessSetupRequiresCurrentReference);
  state.emergencyLocked = Boolean(status.emergencyLocked);
  state.emergencyDeletionArmed = Boolean(status.emergencyDeletionArmed);
  state.emergencyDeletionPath = status.emergencyDeletionPath || null;
  state.emergencyDeletionMessage = status.emergencyDeletionMessage || "";
  state.emergencyShortcutsNative = Boolean(status.emergencyShortcutsNative);
  if (keyRevisionChanged || (state.keyFingerprint !== null && state.keyFingerprint !== status.fingerprint)) {
    resetKeyProtection();
    invalidatePreview();
    resetFileVerification();
  }
  state.keyFingerprint = status.fingerprint;
  state.keyPath = status.keyPath || null;
  state.keyLoaded = !state.emergencyLocked && Boolean(status.keyLoaded);
  state.keyDisconnected = !state.keyLoaded && (state.emergencyLocked || Boolean(status.startupKeyUnavailable));
  state.keyHasFile = state.keyLoaded && Boolean(status.keyPath);
  state.sandboxAvailable = state.keyHasFile && Boolean(status.sandboxAvailable);
  for (const path of fileVerification.badges.keys()) updateFileVerification(path);
  if (sandbox.paths.length && (!state.sandboxAvailable || state.keyFingerprint !== sandbox.fingerprint)) {
    lockSandbox(state.keyDisconnected
      ? "Sandbox locked because the key disconnected."
      : "Sandbox locked because the loaded key changed.", state.keyDisconnected && !state.emergencyLocked);
  }
  if (state.emergencyLocked) {
    cancelSandboxRecovery();
    $("key-text").value = "";
    if (!wasEmergencyLocked || keyRevisionChanged) $("key-passphrase").value = "";
    if (!wasEmergencyLocked && $("key-dialog").open) $("key-dialog").close();
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
  const keyIcon = $("current-key-icon");
  keyIcon.className = `key-status-icon${state.keyDisconnected ? " is-disconnected" : state.keyLoaded ? " is-loaded" : ""}`;
  keyIcon.innerHTML = EXPLORER_ICONS[state.keyDisconnected ? "unplug" : state.keyLoaded ? "shield" : "needsKey"];
  const filename = $("key-filename");
  filename.hidden = !state.keyPath;
  filename.textContent = state.keyPath ? baseName(state.keyPath) : "";
  filename.title = state.keyPath || "";
  if (updatePath) {
    $("key-path").value = status.keyPath || "";
  }
  if (updatePath && typeof status.outputDir === "string") {
    $("output-dir").value = status.outputDir;
  }
  $("fingerprint").textContent = state.keyLoaded
    ? state.keyHasFile ? "Key loaded" : "Session key"
    : state.keyDisconnected
      ? state.emergencyLocked ? "Key unavailable" : "Key disconnected"
      : "No key loaded";
  const fingerprintDetails = state.keyLoaded && status.fingerprint ? `Fingerprint: ${status.fingerprint}` : "";
  $("fingerprint").title = fingerprintDetails;
  $("fingerprint").setAttribute("aria-label", fingerprintDetails
    ? `${$("fingerprint").textContent}. ${fingerprintDetails}` : $("fingerprint").textContent);
  const message = status.message || "";
  $("key-message").textContent = state.emergencyLocked
    ? KEY_READ_ERROR
    : state.keyDisconnected
      ? KEY_DISCONNECTED_GUIDANCE
      : state.keyLoaded
        ? ROUTINE_KEY_MESSAGES.has(message) ? "" : message
        : message || "Choose a key to get started.";
  updateKeyRecoveryDialog();
  if (state.keyDisconnected && (!state.accessSetupRequired || state.emergencyLocked) && (!wasDisconnected || state.emergencyLocked && !wasEmergencyLocked) && !$("startup-key-dialog").open) {
    showKeyRecoveryDialog();
  } else if (!state.keyDisconnected && $("startup-key-dialog").open) {
    $("startup-key-dialog").close();
  }
  renderControls();
  if (wasSetupRequired && !state.accessSetupRequired) {
    keyProtection.firstRunVisible = false;
    $("key-dialog").classList.toggle("is-first-run", false);
    if ($("key-dialog").open) $("key-dialog").close();
  }
  maybeShowFirstRun();
  updateSandboxRecoveryUI();
  maybeResumeSandbox();
  maybeRestoreSelectedFiles();
  startAutomaticVerification();
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
function renderPaged(listId, pagerId, items, renderRow, pageSize = PAGE_SIZE) {
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
      const count = Math.max(1, Math.ceil(view.items.length / view.pageSize));
      view.page = Math.max(0, Math.min(view.page, count - 1));
      const start = view.page * view.pageSize;
      if (listId === "file-list") {
        fileRemoveButtons = [];
        fileVerification.badges.clear();
      }
      if (listId === "results") deletionButtons = [];
      if (listId === "sandbox-list") sandbox.buttons = [];
      const fragment = document.createDocumentFragment();
      for (let index = start; index < Math.min(start + view.pageSize, view.items.length); index++) {
        fragment.append(view.renderRow(view.items[index], index));
      }
      $(listId).replaceChildren(fragment);
      if (listId === "sandbox-list") $("sandbox-file-scroll").scrollTop = 0;
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
  view.pageSize = pageSize;
  view.renderRow = renderRow;
  view.draw();
}

function selectionBlocked() {
  return emergencyUnlockPending || state.accessSetupRequired || state.selectionBusy || (state.busy && state.keyLoaded);
}

function renderControls() {
  const busy = state.busy || state.selectionBusy || emergencyUnlockPending;
  for (const button of fileRemoveButtons) button.disabled = selectionBlocked();
  for (const button of deletionButtons) button.disabled = busy;
  const noFiles = state.files.length === 0;
  const blocked = busy || state.accessSetupRequired || !state.keyLoaded || noFiles;
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
  $("add-files").disabled = selectionBlocked();
  $("add-folder").disabled = selectionBlocked();
  $("clear-files").disabled = selectionBlocked() || noFiles;
  $("generate").disabled = busy;
  $("load").disabled = busy;
  $("unload").disabled = busy || !state.keyLoaded;
  $("choose-recovery-key").disabled = false;
  $("sandbox-key-options").disabled = busy;
  $("set-path").disabled = busy;
  $("browse-load").disabled = busy;
  $("backup-key").disabled = busy || !state.keyHasFile;
  $("backup-key").title = state.keyLoaded && !state.keyHasFile
    ? "Session keys have no file to back up."
    : "";
  $("check-backup").disabled = busy || !state.keyLoaded;
  $("rotate-key").disabled = blocked;
  $("save-typed").disabled = busy;
  $("use-typed").disabled = busy;
  $("open-key-options").disabled = busy;
  renderEmergencyControls();
  renderKeyProtection();
  $("open-specific-key").disabled = busy;
  $("choose-output").disabled = busy;
  $("clear-output").disabled = busy || $("output-dir").value.trim() === "";
  $("zip").disabled = busy;
  $("compress").disabled = busy || !$("zip").checked;
  $("review-first").disabled = busy;
  $("overwrite").disabled = busy;
  $("remove-original").disabled = busy;
  $("output-dir").disabled = busy;
  $("start-job").disabled = busy || !state.keyLoaded || !state.pendingJob?.preview?.canRun
    || state.pendingJob.revision !== state.planRevision;
  $("cancel-job").disabled = !state.jobRunning;
  $("check-update").disabled = busy || !state.updatesConfigured;
  $("install-update").disabled = busy || !state.updateAvailable;
  $("file-count").textContent = noFiles ? "" : `(${state.files.length})`;
  $("action-hint").textContent = busy
    ? "Working. Please wait…"
    : state.keyDisconnected
      ? "Reconnect your key drive; FileEncrypt will check for it automatically."
      : !state.keyLoaded && noFiles
        ? "Load a key and add files to get started."
        : !state.keyLoaded
          ? "Load a key to continue."
          : noFiles
            ? "Add files to continue."
            : `${state.files.length} ${state.files.length === 1 ? "file" : "files"} ready to encrypt, view, or decrypt. Encrypted files are verified automatically.`;
  renderOutputHint();
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
    name.title = path;
    const heading = document.createElement("div");
    heading.className = "file-name-row";
    const badge = document.createElement("span");
    badge.setAttribute("role", "img");
    fileVerification.badges.set(path, badge);
    updateFileVerification(path);
    heading.append(badge);
    heading.append(name);
    text.append(heading);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "text-button";
    remove.textContent = "Remove";
    remove.disabled = selectionBlocked();
    remove.setAttribute("aria-label", `Remove ${baseName(path)}`);
    fileRemoveButtons.push(remove);
    remove.addEventListener("click", () => {
      if (selectionBlocked()) return;
      const index = state.files.indexOf(path);
      if (index < 0) return;
      state.files.splice(index, 1);
      state.fileSet.delete(path);
      state.folderRoots.delete(path);
      fileVerification.entries.delete(path);
      if (sandbox.recovery?.paths.includes(path)) {
        sandbox.recovery.paths = sandbox.recovery.paths.filter((source) => source !== path);
        sandbox.recovery.itemId = null;
        if (!sandbox.recovery.paths.length) cancelSandboxRecovery();
      }
      invalidatePreview();
      rememberSelectedFiles();
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

async function selectFiles(work) {
  if (selectionBlocked()) return;
  state.selectionBusy = true;
  renderControls();
  clearAlert();
  try {
    addSelectedFiles(await work());
  } catch (error) {
    showAlert(normalizeError(error));
  } finally {
    state.selectionBusy = false;
    renderControls();
    maybeResumeSandbox();
    maybeRestoreSelectedFiles();
    startAutomaticVerification();
  }
}

async function run(work, updatePathOnSuccess) {
  if (state.busy || state.selectionBusy || emergencyUnlockPending) return;
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
    maybeRestoreSelectedFiles();
    startAutomaticVerification();
  }
}

async function runKeyOption(work, updatePathOnSuccess) {
  const result = await run(work, updatePathOnSuccess);
  if (result) $("key-dialog").close();
  return result;
}

function openKeyOptions() {
  const firstRun = state.accessSetupRequired && !state.emergencyLocked;
  keyProtection.firstRunVisible = firstRun;
  clearAlert();
  $("key-management-view").hidden = false;
  $("specific-key-view").hidden = true;
  $("key-dialog").classList.toggle("is-first-run", firstRun);
  $("close-key-options").hidden = firstRun;
  $("key-path").readOnly = firstRun && Boolean(state.keyPath);
  $("key-dialog-heading").textContent = firstRun ? "Create your password" : "Key options";
  $("key-dialog-description").textContent = firstRun
    ? state.accessSetupRequiresCurrentReference ? "Enter your existing emergency password once to restore automatic key loading." : "You'll only use this password to leave emergency mode."
    : "Manage the key file used for this workspace.";
  if (firstRun) {
    $("emergency-options").open = true;
    $("access-settings").open = true;
    if (!state.keyPath && !$("key-path").value) $("key-path").value = state.accessSetupKeyPath || "";
    if (!$("first-run-key-path").value) $("first-run-key-path").value = state.accessSetupKeyPath || "";
  }
  renderKeyProtection();
  if (!$("key-dialog").open) $("key-dialog").showModal();
  if (firstRun) $("new-key-passphrase").focus();
  else if (sandbox.recovery?.waitingForUnlock) $("key-passphrase").focus();
  else $("close-key-options").focus();
}

function maybeShowFirstRun() {
  if (!state.accessSetupRequired || state.emergencyLocked) return;
  if ($("startup-key-dialog").open) $("startup-key-dialog").close();
  if (!keyProtection.firstRunVisible || !$("key-dialog").open) openKeyOptions();
}

function renderEmergencyControls() {
  const enabled = $("enable-emergency-deletion");
  enabled.disabled = !state.emergencyShortcutsNative || state.emergencyDeletionArmed;
  $("arm-emergency-deletion").disabled = !enabled.checked || !state.emergencyShortcutsNative
    || !state.keyHasFile || state.busy || state.emergencyLocked || state.emergencyDeletionArmed;
  $("arm-emergency-deletion").textContent = state.emergencyDeletionArmed ? "Deletion armed" : "Arm key deletion";
  $("disarm-emergency-deletion").hidden = !state.emergencyDeletionArmed;
  const path = state.emergencyDeletionPath || state.keyPath;
  $("emergency-deletion-path").hidden = !path;
  $("emergency-deletion-path").textContent = path || "";
  $("emergency-deletion-status").textContent = state.emergencyDeletionMessage
    || (state.emergencyDeletionArmed ? "Armed for the next reconnection only."
      : !state.emergencyShortcutsNative ? "Held deletion shortcuts are available on Windows." : "");
}

let emergencyUnlockPending = false;
async function unlockEmergency() {
  if (!state.emergencyLocked || emergencyUnlockPending || state.busy || state.selectionBusy || keyProtection.operation) return;
  if ($("startup-key-dialog").open) $("startup-key-dialog").close();
  if (!$("key-dialog").open) openKeyOptions();
  emergencyUnlockPending = true;
  clearAlert();
  renderControls();
  let failed = false;
  try {
    applyStatus(await invokeWithPassphrase("emergency_unlock"), true);
    clearAlert();
  } catch (error) {
    failed = true;
    if ($("startup-key-dialog").open) $("startup-key-dialog").close();
    openKeyOptions();
    const message = normalizeError(error);
    showAlert(message === KEY_READ_ERROR ? "The key reference could not be checked." : message);
  } finally {
    emergencyUnlockPending = false;
    renderControls();
    if (failed) $("key-passphrase").focus();
  }
}

function resetKeyProtection() {
  const token = keyProtection.token;
  keyProtection.token = null;
  keyProtection.firstRun = false;
  keyProtection.generation++;
  for (const id of ["key-passphrase", "new-key-passphrase", "confirm-key-passphrase", "key-recovery-code", "new-recovery-code"]) $(id).value = "";
  $("recovery-code-saved").checked = false;
  $("access-recovery-result").hidden = true;
  $("key-protection-status").textContent = "";
  if (token) invoke("cancel_key_protection", { token }).catch(() => {});
}

function renderKeyProtection() {
  const busy = state.busy || state.selectionBusy || emergencyUnlockPending || Boolean(keyProtection.operation);
  const pending = Boolean(keyProtection.token);
  const firstRun = state.accessSetupRequired && !state.emergencyLocked;
  const recovering = $("access-recovery").open;
  const preparing = keyProtection.operation === "prepare";
  const saving = keyProtection.operation === "save";
  $("key-unlock-loading").hidden = !emergencyUnlockPending;
  $("current-reference-field").setAttribute("aria-busy", String(emergencyUnlockPending));
  $("key-protection-loading").hidden = !keyProtection.operation;
  $("key-protection-loading-title").textContent = saving ? "Saving emergency access…" : "Preparing emergency access…";
  $("access-fields").setAttribute("aria-busy", String(preparing));
  $("access-recovery-result").setAttribute("aria-busy", String(saving));
  $("current-reference-field").hidden = firstRun || recovering;
  $("key-location-field").hidden = firstRun;
  $("access-fields").hidden = firstRun && (pending || preparing);
  $("key-reference-label").textContent = firstRun ? "Current password" : "Key reference";
  $("key-passphrase").placeholder = "Enter reference, if required";
  $("key-reference-hint").textContent = "Used only to leave emergency mode or update access. Cleared after use.";
  $("new-reference-label").textContent = recovering ? "New password" : firstRun ? "Password" : "New reference";
  $("confirm-reference-label").textContent = recovering ? "Confirm new password" : firstRun ? "Confirm password" : "Repeat reference";
  $("new-reference-hint").textContent = recovering ? "Choose one new emergency password of at least 12 characters. Enter that same password in both boxes." : firstRun && state.accessSetupRequiresCurrentReference ? "Use your previous password, or open Use recovery code above if you only have its recovery code." : "Use at least 12 characters. Normal key loading and reconnection stay automatic.";
  $("first-run-location").hidden = !firstRun || Boolean(state.keyPath);
  $("choose-first-run-location").disabled = busy || pending;
  $("first-run-key-path").disabled = busy || pending;
  if (firstRun) {
    $("key-dialog-heading").textContent = pending ? "Save your recovery code" : state.accessSetupIsUpgrade || state.accessSetupRequiresCurrentReference ? "Update emergency access" : "Create your password";
    $("key-dialog-description").textContent = pending ? "Keep this code somewhere safe, separate from this device." : state.accessSetupRequiresCurrentReference ? recovering ? "Use your recovery code to set a new emergency password. Your encryption key will stay the same." : "Enter your existing emergency password once to restore automatic key loading." : "You'll only use this password to leave emergency mode.";
  }
  $("prepare-key-protection").disabled = busy || pending || state.emergencyLocked;
  $("prepare-key-protection").hidden = recovering;
  $("prepare-key-protection").textContent = preparing ? "Preparing…" : firstRun ? "Continue" : "Update access";
  $("commit-key-protection").textContent = saving ? "Saving…" : state.accessSetupRequired ? "Finish setup" : "Save access";
  $("cancel-key-protection").textContent = state.accessSetupRequired ? "Start over" : "Cancel setup";
  $("access-recovery").hidden = firstRun && !state.accessSetupRequiresCurrentReference;
  if (state.accessSetupRequired && state.keyPath) $("set-path").disabled = true;
  $("access-setup-guidance").hidden = firstRun;
  $("recover-key-protection").disabled = busy || pending;
  $("recover-key-protection").hidden = !recovering;
  $("recover-key-protection").textContent = "Set new emergency password";
  $("commit-key-protection").disabled = busy || !pending || !$("recovery-code-saved").checked;
  $("cancel-key-protection").disabled = busy;
  for (const id of ["key-passphrase", "new-key-passphrase", "confirm-key-passphrase", "key-recovery-code"]) $(id).disabled = busy || pending;
  $("recovery-code-saved").disabled = busy;
}

async function runKeyProtection(work, updatePathOnSuccess, operation) {
  if (state.busy || state.selectionBusy || keyProtection.operation) return;
  keyProtection.operation = operation;
  try {
    return await run(work, updatePathOnSuccess);
  } finally {
    keyProtection.operation = null;
    renderKeyProtection();
  }
}

async function prepareKeyProtection(recovery = false) {
  if (state.busy || state.selectionBusy || keyProtection.operation || keyProtection.token) return;
  const firstRun = state.accessSetupRequired && (!state.emergencyLocked || recovery);
  const args = {
    passphrase: recovery ? "" : $("key-passphrase").value,
    newPassphrase: $("new-key-passphrase").value,
    confirmation: $("confirm-key-passphrase").value,
    recoveryCode: recovery ? $("key-recovery-code").value : null,
    path: firstRun ? state.keyPath || $("first-run-key-path").value : $("key-path").value,
  };
  if (recovery) {
    let message, field;
    if (!args.recoveryCode.trim()) {
      message = "Enter your saved recovery code.";
      field = "key-recovery-code";
    } else if ([...args.newPassphrase.trim()].length < 12) {
      message = "Choose a new emergency password of at least 12 characters. You don't need your old password.";
      field = "new-key-passphrase";
    } else if (args.newPassphrase !== args.confirmation) {
      message = "Enter the same new password in Confirm new password.";
      field = "confirm-key-passphrase";
    }
    if (message) { showAlert(message); $(field).focus(); return; }
  }
  if ([...args.newPassphrase.trim()].length < 12 || args.newPassphrase !== args.confirmation) {
    showAlert(firstRun ? "Enter matching passwords of at least 12 characters." : "Enter matching new references of at least 12 characters.");
    return;
  }
  for (const id of ["key-passphrase", "new-key-passphrase", "confirm-key-passphrase", "key-recovery-code"]) $(id).value = "";
  const generation = keyProtection.generation;
  const revision = state.keyRevision;
  const path = state.keyPath;
  const prepared = await runKeyProtection(() => invoke(firstRun ? "prepare_first_run" : "prepare_key_protection", args), false, "prepare");
  args.passphrase = args.newPassphrase = args.confirmation = args.recoveryCode = "";
  if (!prepared) return;
  if (keyProtection.generation !== generation || state.keyRevision !== revision || state.keyPath !== path) {
    prepared.recoveryCode = "";
    await invoke("cancel_key_protection", { token: prepared.token }).catch(() => {});
    return;
  }
  keyProtection.token = prepared.token;
  keyProtection.firstRun = firstRun;
  $("new-recovery-code").value = prepared.recoveryCode;
  prepared.recoveryCode = "";
  $("access-recovery-result").hidden = false;
  $("recovery-code-saved").checked = false;
  $("key-protection-status").textContent = firstRun
    ? "Save this code, check the box, then finish setup."
    : "Emergency access has not changed yet. Save the code, then save access.";
  if (prepared.migrationBackupPath) {
    $("key-protection-status").textContent += ` Your existing encryption key will be preserved. Before updating its file, the app will save an exact backup at ${prepared.migrationBackupPath}.`;
  }
  renderKeyProtection();
}

async function commitKeyProtection() {
  if (state.busy || state.selectionBusy || keyProtection.operation || !keyProtection.token || !$("recovery-code-saved").checked) return;
  const firstRun = keyProtection.firstRun;
  const result = await runKeyProtection(() => invoke("commit_key_protection", {
    token: keyProtection.token, recoverySaved: true,
    activationCode: firstRun ? $("new-recovery-code").value : null,
  }), firstRun, "save");
  if (!result) return; // Keep the displayed code if publication failed or was uncertain.
  resetKeyProtection();
  if (firstRun) {
    if ($("key-dialog").open) $("key-dialog").close();
    return;
  }
  $("key-protection-status").textContent = state.emergencyLocked
    ? "Access updated. Enter the new reference above, then use the unlock shortcut."
    : "Emergency access updated. Normal key loading stays automatic.";
  renderKeyProtection();
}

function handleEmergencyShortcut(event) {
  if (!event.ctrlKey || !event.shiftKey || event.altKey || !["F11", "F12"].includes(event.key)) return;
  event.preventDefault();
  if (event.repeat || state.emergencyShortcutsNative) return;
  if (event.key === "F11") return unlockEmergency();
  return invoke("emergency_lock").then((status) => applyStatus(status, false)).catch((error) => showAlert(normalizeError(error)));
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
  entries: [], folders: new Map(), categoryCounts: {},
  folder: "", category: "", query: "", view: "grid", sort: "name",
  history: [{ folder: "", category: "" }], historyIndex: 0,
  selectedKey: null, openedItemId: null, contextEntry: null, hiddenClosures: 0,
  searchTimer: null, sortedEntries: null, visibleEntries: null, rootLinks: [],
};
const sandboxNameCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
const sandboxRootCollator = new Intl.Collator(undefined, { numeric: true });
const sandboxTypeCollator = new Intl.Collator();
const SANDBOX_TYPES = {
  text: { label: "Text files", singular: "Text document", icon: "text" },
  image: { label: "Images", singular: "Image", icon: "image" },
  audio: { label: "Audio", singular: "Audio file", icon: "audio" },
  video: { label: "Video", singular: "Video file", icon: "video" },
  unsupported: { label: "Other files", singular: "File", icon: "file" },
};

function sandboxIcon(kind) {
  const icon = document.createElement("span");
  const name = kind === "folder" ? "folder" : SANDBOX_TYPES[kind]?.icon || "file";
  icon.className = `explorer-type-icon explorer-type-${name}`;
  icon.setAttribute("aria-hidden", "true");
  // Only fixed Lucide symbol names enter markup; file names use textContent.
  icon.innerHTML = EXPLORER_ICONS[name];
  return icon;
}

function sandboxFileType(item) {
  if (item.kind === "folder") return "Folder";
  const extension = item.name.split(/[\\/]/).pop().match(/\.([^.]+)$/)?.[1].toUpperCase();
  return extension ? `${extension} ${item.kind === "image" ? "image" : "file"}` : SANDBOX_TYPES[item.kind]?.singular || "File";
}

function indexSandboxFiles() {
  sandbox.folders = new Map([["", { path: "", label: "All files", folders: [], files: [], count: 0 }]]);
  sandbox.categoryCounts = {};
  sandbox.entries = sandbox.items.map((item) => {
    const parts = item.name.split(/[\\/]/).filter(Boolean);
    const label = parts.pop() || item.name;
    let parent = "";
    const ancestors = [sandbox.folders.get("")];
    for (const part of parts) {
      const path = parent ? `${parent}/${part}` : part;
      if (!sandbox.folders.has(path)) {
        const folder = { path, parent, label: part, folders: [], files: [], count: 0, kind: "folder" };
        sandbox.folders.set(path, folder);
        sandbox.folders.get(parent).folders.push(folder);
      }
      parent = path;
      ancestors.push(sandbox.folders.get(path));
    }
    const kind = SANDBOX_TYPES[item.kind] ? item.kind : "unsupported";
    const entry = { ...item, kind, label, parent, path: [...parts, label].join("/") };
    entry.searchPath = entry.path.toLocaleLowerCase();
    entry.fileType = sandboxFileType(entry);
    sandbox.folders.get(parent).files.push(entry);
    for (const folder of ancestors) folder.count++;
    sandbox.categoryCounts[kind] = (sandbox.categoryCounts[kind] || 0) + 1;
    return entry;
  });
  sandbox.sortedEntries = null;
  sandbox.visibleEntries = null;
  sandbox.rootLinks = [...sandbox.folders.get("").folders].sort((a, b) => sandboxRootCollator.compare(a.label, b.label));
}

function sandboxVisibleEntries() {
  const query = sandbox.query.trim().toLocaleLowerCase();
  const folder = sandbox.folders.get(sandbox.folder);
  const scope = query || sandbox.category ? "all" : sandbox.folder;
  if (sandbox.visibleEntries?.scope === scope && sandbox.visibleEntries.query === query
      && sandbox.visibleEntries.category === sandbox.category && sandbox.visibleEntries.sort === sandbox.sort) {
    return sandbox.visibleEntries.items;
  }
  const compare = (a, b) => {
    if (a.kind === "folder" && b.kind !== "folder") return -1;
    if (b.kind === "folder" && a.kind !== "folder") return 1;
    if (sandbox.sort === "type") {
      const typeOrder = sandboxTypeCollator.compare(a.fileType || sandboxFileType(a), b.fileType || sandboxFileType(b));
      if (typeOrder) return typeOrder;
    }
    const order = sandboxNameCollator.compare(a.label, b.label);
    return sandbox.sort === "name-desc" ? -order : order;
  };
  let entries;
  if (query || sandbox.category) {
    if (sandbox.sortedEntries?.sort !== sandbox.sort) {
      sandbox.sortedEntries = { sort: sandbox.sort, items: [...sandbox.entries].sort(compare) };
    }
    entries = sandbox.sortedEntries.items.filter((item) => (!sandbox.category || item.kind === sandbox.category)
      && (!query || item.searchPath.includes(query)));
  } else {
    entries = [...(folder?.folders || []), ...(folder?.files || [])].sort(compare);
  }
  sandbox.visibleEntries = { scope, query, category: sandbox.category, sort: sandbox.sort, items: entries };
  return entries;
}

function navigateSandbox(folder = "", category = "", record = true) {
  if (folder && !sandbox.folders.has(folder)) return;
  clearTimeout(sandbox.searchTimer);
  sandbox.searchTimer = null;
  const changed = sandbox.folder !== folder || sandbox.category !== category;
  if (changed || sandbox.query) {
    sandbox.selection++;
    sandbox.currentItemId = null;
    sandbox.selectedKey = null;
    hideSandboxContextMenu();
    if (sandbox.sessionId) $("sandbox-status").textContent = "Double-click a file to open a private preview window.";
  }
  sandbox.folder = folder;
  sandbox.category = category;
  sandbox.query = "";
  $("sandbox-search").value = "";
  if (record && changed) {
    sandbox.history = sandbox.history.slice(0, sandbox.historyIndex + 1);
    sandbox.history.push({ folder, category });
    sandbox.historyIndex = sandbox.history.length - 1;
  }
  if (pagedLists.has("sandbox-list")) pagedLists.get("sandbox-list").page = 0;
  renderSandboxExplorer();
}

function stepSandboxHistory(delta) {
  const index = sandbox.historyIndex + delta;
  if (index < 0 || index >= sandbox.history.length) return;
  sandbox.historyIndex = index;
  const location = sandbox.history[index];
  navigateSandbox(location.folder, location.category, false);
}

function sandboxNavButton(label, kind, count, active, action) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "explorer-sidebar-button";
  button.classList.toggle("is-active", active);
  if (active) button.setAttribute("aria-current", "page");
  const name = document.createElement("span");
  name.textContent = label;
  const badge = document.createElement("span");
  badge.className = "explorer-count";
  badge.textContent = String(count);
  button.append(sandboxIcon(kind), name, badge);
  button.addEventListener("click", action);
  return button;
}

function renderSandboxNavigation() {
  const home = !sandbox.folder && !sandbox.category && !sandbox.query;
  $("sandbox-home").classList.toggle("is-active", home);
  if (home) $("sandbox-home").setAttribute("aria-current", "page");
  else $("sandbox-home").removeAttribute("aria-current");
  $("sandbox-total").textContent = String(sandbox.items.length);
  const categories = document.createDocumentFragment();
  for (const [kind, type] of Object.entries(SANDBOX_TYPES)) {
    categories.append(sandboxNavButton(type.label, kind, sandbox.categoryCounts[kind] || 0,
      sandbox.category === kind, () => navigateSandbox("", kind)));
  }
  $("sandbox-categories").replaceChildren(categories);
  const roots = sandbox.folders.get("")?.folders || [];
  const folderLinks = document.createDocumentFragment();
  // The complete folder collection is browsable in the main pane. Keep the
  // sidebar bounded, including the current root even in very large catalogues.
  const sorted = sandbox.rootLinks;
  const currentRoot = roots.find((folder) => sandbox.folder === folder.path || sandbox.folder.startsWith(folder.path + "/"));
  const visible = sorted.slice(0, 7);
  if (currentRoot && !visible.includes(currentRoot)) visible.push(currentRoot);
  for (const folder of visible) {
    const button = sandboxNavButton(folder.label, "folder", folder.count,
      !sandbox.category && !sandbox.query && sandbox.folder === folder.path, () => navigateSandbox(folder.path));
    button.title = folder.path;
    folderLinks.append(button);
  }
  if (roots.length > visible.length) {
    const more = document.createElement("button");
    more.type = "button";
    more.className = "explorer-more-folders";
    more.textContent = `View all ${roots.length} folders`;
    more.addEventListener("click", () => navigateSandbox());
    folderLinks.append(more);
  }
  $("sandbox-folders").replaceChildren(folderLinks);
  $("sandbox-folder-section").hidden = roots.length === 0;
  const crumbs = document.createDocumentFragment();
  const addCrumb = (label, folder, category = "", last = false) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "explorer-crumb";
    button.textContent = label;
    button.title = label;
    if (last) button.setAttribute("aria-current", "location");
    button.addEventListener("click", () => navigateSandbox(folder, category));
    crumbs.append(button);
    if (!last) {
      const separator = document.createElement("span");
      separator.className = "explorer-crumb-separator";
      separator.setAttribute("aria-hidden", "true");
      separator.innerHTML = EXPLORER_ICONS.chevron;
      crumbs.append(separator);
    }
  };
  addCrumb("Sandbox", "", "", home || (!sandbox.folder && !sandbox.category && !sandbox.query));
  if (sandbox.query) addCrumb("Search results", sandbox.folder, sandbox.category, true);
  else if (sandbox.category) addCrumb(SANDBOX_TYPES[sandbox.category].label, "", sandbox.category, true);
  else if (sandbox.folder) {
    const parts = sandbox.folder.split("/");
    parts.forEach((part, index) => addCrumb(part, parts.slice(0, index + 1).join("/"), "", index === parts.length - 1));
  }
  $("sandbox-breadcrumbs").replaceChildren(crumbs);
  $("sandbox-back").disabled = sandbox.historyIndex === 0;
  $("sandbox-forward").disabled = sandbox.historyIndex >= sandbox.history.length - 1;
  $("sandbox-up").disabled = !sandbox.folder && !sandbox.category && !sandbox.query;
  $("sandbox-clear-search").hidden = !sandbox.query;
}

function renderSandboxExplorer() {
  renderSandboxNavigation();
  const entries = sandboxVisibleEntries();
  const folderCount = entries.filter((entry) => entry.kind === "folder").length;
  const fileCount = entries.length - folderCount;
  $("sandbox-location-name").textContent = sandbox.query ? "Search results"
    : sandbox.category ? SANDBOX_TYPES[sandbox.category].label
    : sandbox.folders.get(sandbox.folder)?.label || "All files";
  $("sandbox-location-summary").textContent = sandbox.query ? `Matches for “${sandbox.query}” across the sandbox`
    : sandbox.category ? "Across your encrypted workspace"
    : sandbox.folder ? "Browse this encrypted folder" : "Your encrypted workspace, in one place";
  $("sandbox-item-count").textContent = [folderCount ? `${folderCount} ${folderCount === 1 ? "folder" : "folders"}` : "",
    `${fileCount} ${fileCount === 1 ? "file" : "files"}`].filter(Boolean).join(" · ");
  $("sandbox-list").className = sandbox.view === "grid" ? "explorer-grid" : "explorer-details";
  $("sandbox-list-heading").hidden = sandbox.view !== "details";
  for (const view of ["grid", "details"]) {
    $("sandbox-" + view).classList.toggle("is-active", sandbox.view === view);
    $("sandbox-" + view).setAttribute("aria-pressed", String(sandbox.view === view));
  }
  renderPaged("sandbox-list", "sandbox-pages", entries, (entry) => {
    const row = document.createElement("li");
    const button = document.createElement("button");
    const isFolder = entry.kind === "folder";
    button.type = "button";
    button.className = "sandbox-file";
    button.title = `Double-click to ${isFolder ? "open folder" : "preview"}: ${entry.path}`;
    button.sandboxItemId = isFolder ? null : entry.id;
    button.sandboxEntryKey = sandboxEntryKey(entry);
    const active = button.sandboxEntryKey === sandbox.selectedKey;
    button.setAttribute("aria-pressed", String(active));
    button.classList.toggle("is-selected", active);
    const label = document.createElement("span");
    label.className = "explorer-file-label";
    label.textContent = entry.label;
    const detail = document.createElement("span");
    detail.className = "explorer-file-detail";
    detail.textContent = isFolder ? `${entry.count} ${entry.count === 1 ? "file" : "files"}`
      : sandbox.query || sandbox.category ? entry.parent || "Sandbox" : sandboxFileType(entry);
    const type = document.createElement("span");
    type.className = "explorer-file-type";
    type.textContent = isFolder ? "Folder" : sandboxFileType(entry);
    button.append(sandboxIcon(entry.kind), label, detail, type);
    button.addEventListener("click", () => selectSandboxEntry(entry));
    button.addEventListener("dblclick", () => openSandboxEntry(entry));
    button.addEventListener("keydown", (event) => {
      if (event.key === "Enter") { event.preventDefault(); openSandboxEntry(entry); }
    });
    button.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      selectSandboxEntry(entry);
      showSandboxContextMenu(entry, event.clientX, event.clientY, button);
    });
    sandbox.buttons.push(button);
    row.append(button);
    return row;
  }, 48);
  $("sandbox-browser-empty").hidden = entries.length > 0;
  $("sandbox-empty-title").textContent = sandbox.query ? "No matching files" : sandbox.category ? "No files of this type" : "No files to show";
  $("sandbox-empty-message").textContent = sandbox.query ? "Try a different name or file extension."
    : sandbox.sessionId ? "Choose another folder or file type to keep exploring." : "Your files appear here once the sandbox is unlocked.";
  $("sandbox-reset-filter").hidden = !sandbox.query && !sandbox.category && !sandbox.folder;
  $("sandbox-key-state").textContent = sandbox.sessionId ? "Key connected" : "Viewer locked";
  $("sandbox-key-indicator").classList.toggle("is-connected", Boolean(sandbox.sessionId));
  $("sandbox-status-dot").classList.toggle("is-connected", Boolean(sandbox.sessionId));
}

function sandboxEntryKey(entry) {
  return entry.kind === "folder" ? `folder:${entry.path}` : `file:${entry.id}`;
}

function selectSandboxEntry(entry) {
  sandbox.selectedKey = sandboxEntryKey(entry);
  sandbox.currentItemId = entry.kind === "folder" ? null : entry.id;
  updateSandboxSelection();
  $("sandbox-status").textContent = `${entry.label || entry.name} · ${sandboxFileType(entry)} · Double-click to open`;
}

function updateSandboxSelection() {
  for (const button of sandbox.buttons) {
    const active = button.sandboxEntryKey === sandbox.selectedKey;
    button.classList.toggle("is-selected", active);
    button.setAttribute("aria-pressed", String(active));
  }
}

function openSandboxEntry(entry) {
  hideSandboxContextMenu();
  if (entry.kind === "folder") navigateSandbox(entry.path);
  else return viewSandboxFile(entry);
}

function hideSandboxContextMenu() {
  $("sandbox-context-menu").hidden = true;
  $("sandbox-context-menu").replaceChildren();
  sandbox.contextEntry = null;
}

function showSandboxContextMenu(entry, x, y, anchor) {
  const menu = $("sandbox-context-menu");
  hideSandboxContextMenu();
  sandbox.contextEntry = entry;
  sandbox.contextAnchor = anchor;
  const addAction = (label, icon, action) => {
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("role", "menuitem");
    const symbol = document.createElement("span");
    symbol.setAttribute("aria-hidden", "true");
    symbol.innerHTML = EXPLORER_ICONS[icon];
    const text = document.createElement("span");
    text.textContent = label;
    button.append(symbol, text);
    button.addEventListener("click", () => { hideSandboxContextMenu(); action(); });
    menu.append(button);
  };
  addAction(entry.kind === "folder" ? "Open folder" : "Open preview", entry.kind === "folder" ? "folder" : "eye", () => openSandboxEntry(entry));
  if (entry.kind !== "folder") addAction("Show containing folder", "folder", () => {
    navigateSandbox(entry.parent || "");
    selectSandboxEntry(entry);
  });
  addAction("Properties", "info", () => showSandboxProperties(entry));
  menu.hidden = false;
  const bounds = $("sandbox-dialog").getBoundingClientRect();
  const origin = anchor.getBoundingClientRect();
  const left = x || origin.left + 12;
  const top = y || origin.bottom;
  menu.style.left = `${Math.max(bounds.left + 8, Math.min(left, bounds.right - menu.offsetWidth - 8))}px`;
  menu.style.top = `${Math.max(bounds.top + 8, Math.min(top, bounds.bottom - menu.offsetHeight - 8))}px`;
  menu.children[0]?.focus();
}

function showSandboxProperties(entry) {
  $("sandbox-property-name").textContent = entry.label || entry.name;
  $("sandbox-property-type").textContent = entry.kind === "folder" ? `Folder · ${entry.count} files` : sandboxFileType(entry);
  $("sandbox-property-location").textContent = entry.parent || "Sandbox";
  $("sandbox-property-icon").replaceChildren(sandboxIcon(entry.kind));
  $("sandbox-properties").showModal();
  $("close-sandbox-properties").focus();
}

async function viewSandboxFile(item) {
  const sessionId = sandbox.sessionId;
  if (!sessionId || sandbox.loading) return;
  const generation = sandbox.generation;
  selectSandboxEntry(item);
  sandbox.loading = true;
  $("sandbox-status").textContent = "Opening private preview window…";
  try {
    await invoke("open_sandbox_preview", { sessionId, itemId: item.id });
    if (generation !== sandbox.generation) return;
    sandbox.openedItemId = item.id;
    $("sandbox-status").textContent = "Preview opened in a separate read-only window.";
  } catch (error) {
    if (generation !== sandbox.generation) return;
    const message = normalizeError(error);
    if (message.startsWith("Sandbox locked")) lockSandbox(message);
    else $("sandbox-status").textContent = message;
  } finally {
    if (generation === sandbox.generation) sandbox.loading = false;
  }
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
  sandbox.selectedKey = null;
  sandbox.openedItemId = null;
  sandbox.entries = [];
  sandbox.folders.clear();
  sandbox.categoryCounts = {};
  clearTimeout(sandbox.searchTimer);
  sandbox.searchTimer = null;
  sandbox.sortedEntries = sandbox.visibleEntries = null;
  sandbox.rootLinks = [];
  sandbox.folder = sandbox.category = sandbox.query = "";
  sandbox.history = [{ folder: "", category: "" }];
  sandbox.historyIndex = 0;
  $("sandbox-search").value = "";
  hideSandboxContextMenu();
  sandbox.contextAnchor = null;
  if ($("sandbox-properties").open) $("sandbox-properties").close();
  for (const id of ["sandbox-property-name", "sandbox-property-type", "sandbox-property-location"]) $(id).textContent = "";
  $("sandbox-property-icon").replaceChildren();
  cancelSandboxRecovery();
  clearTimeout(sandbox.timer);
  sandbox.timer = null;
  renderSandboxExplorer();
  $("sandbox-warnings").textContent = "";
  $("sandbox-status").textContent = "";
  if (sessionId) invoke("close_sandbox", { sessionId }).catch(() => {});
}

function lockSandbox(message = "Sandbox locked because key-file access was lost or changed.", canResume = true) {
  // Recovery keeps encrypted source paths, a fingerprint, and an item index.
  // Plaintext, decrypted names, and the revoked session are always discarded.
  const recovery = canResume ? sandbox.recovery || (sandbox.paths.length && sandbox.fingerprint ? {
    paths: [...sandbox.paths], fingerprint: sandbox.fingerprint,
    itemId: sandbox.openedItemId, ready: false, waitingForUnlock: false,
  } : null) : null;
  resetSandbox();
  sandbox.recovery = recovery;
  const dialog = $("sandbox-dialog");
  if (dialog.open && (recovery || state.keyDisconnected)) {
    // Closing removes the modal backdrop. Its close event can arrive after
    // recovery has reopened the explorer, so consume only this automatic close.
    sandbox.hiddenClosures++;
    dialog.close();
  }
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
  if (!sandbox.recovery || sandbox.recovery.waitingForUnlock) return;
  sandbox.recoveryTimer = setTimeout(checkSandboxRecovery, 1000);
}

async function checkSandboxRecovery() {
  sandbox.recoveryTimer = null;
  const recovery = sandbox.recovery;
  if (!recovery) return;
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
  if (state.emergencyLocked) return;
  const recovery = sandbox.recovery;
  if (!recovery?.ready || state.busy || state.selectionBusy || !state.sandboxAvailable
      || $("key-dialog").open || $("startup-key-dialog").open) return;
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
  if (state.busy || state.selectionBusy || !state.sandboxAvailable || !paths.length) return;
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
    indexSandboxFiles();
    renderSandboxExplorer();
    $("sandbox-status").textContent = "Double-click a file to open a private preview window.";
    scheduleSandboxCheck();
    const previous = sandbox.items.find((item) => item.id === options.itemId);
    if (previous) {
      const entry = sandbox.entries.find((item) => item.id === previous.id);
      navigateSandbox(entry.parent);
      await viewSandboxFile(entry);
    }
  } catch (error) {
    if (generation === sandbox.generation) {
      const message = normalizeError(error);
      lockSandbox(message, state.keyDisconnected || message.startsWith("Sandbox locked"));
    }
  } finally {
    state.busy = false;
    renderControls();
    maybeResumeSandbox();
    startAutomaticVerification();
  }
}

async function init() {
  const currentWindow = window.__TAURI__?.window?.getCurrentWindow?.();
  if (currentWindow?.onCloseRequested) {
    await currentWindow.onCloseRequested(async (event) => {
      if (!savedSelection.dirty && !savedSelection.writing) return;
      event.preventDefault();
      await flushSelectedFiles();
      await currentWindow.destroy();
    });
  }
  document.addEventListener("keydown", handleEmergencyShortcut, true);
  $("current-key-icon").innerHTML = EXPLORER_ICONS.needsKey;
  $("key-disconnected-icon").innerHTML = EXPLORER_ICONS.unplug;
  try {
    await window.__TAURI__?.event?.listen("key-status-changed", ({ payload }) => {
      applyStatus(payload, false);
    });
    await window.__TAURI__?.event?.listen("emergency-unlock-requested", unlockEmergency);
    await window.__TAURI__?.event?.listen("emergency-action-failed", ({ payload }) => showAlert(payload));
    await window.__TAURI__?.event?.listen("sandbox-locked", ({ payload }) => {
      if (payload === sandbox.sessionId) lockSandbox();
    });
    await window.__TAURI__?.event?.listen("sandbox-preview-closed", ({ payload }) => {
      if (payload.sessionId !== sandbox.sessionId) return;
      if (payload.locked) lockSandbox();
      else if (payload.itemId === sandbox.openedItemId) sandbox.openedItemId = null;
    });
    await window.__TAURI__?.event?.listen("sandbox-preview-navigated", ({ payload }) => {
      if (payload.sessionId === sandbox.sessionId) sandbox.openedItemId = payload.itemId;
    });
    await window.__TAURI__?.event?.listen("job-progress", ({ payload }) => {
      const { processedBytes, totalBytes, currentFile, fileIndex, fileCount, stage } = payload;
      const percentage = totalBytes ? Math.min(100, Math.round((processedBytes / totalBytes) * 100)) : 0;
      $("job-progress").value = percentage;
      $("progress-label").textContent = `${stage}: ${baseName(currentFile)} (${fileIndex}/${fileCount}) · ${percentage}%`;
    });
    await window.__TAURI__?.webview?.getCurrentWebview()?.onDragDropEvent((event) => {
      if (event.payload.type === "drop" && !selectionBlocked()) {
        selectFiles(() => invoke("expand_dropped_paths", { paths: event.payload.paths }));
      }
      document.body.classList.toggle("drag-over", event.payload.type === "enter" || event.payload.type === "over");
    });
  } catch (error) {
    showAlert(normalizeError(error));
  }
  $("open-key-options").addEventListener("click", openKeyOptions);
  $("enable-emergency-deletion").addEventListener("change", renderEmergencyControls);
  $("arm-emergency-deletion").addEventListener("click", () => {
    if (!$("enable-emergency-deletion").checked || $("arm-emergency-deletion").disabled) return;
    run(() => invoke("arm_emergency_deletion", { enabled: true }), false);
  });
  $("disarm-emergency-deletion").addEventListener("click", () => {
    run(() => invoke("arm_emergency_deletion", { enabled: false }), false);
  });
  $("sandbox-key-options").addEventListener("click", openKeyOptions);
  $("prepare-key-protection").addEventListener("click", () => prepareKeyProtection());
  $("choose-first-run-location").addEventListener("click", async () => {
    if (!state.accessSetupRequired || state.keyPath) return;
    const path = await run(() => invoke("pick_save_path"), false);
    if (path) $("first-run-key-path").value = path;
  });
  $("recover-key-protection").addEventListener("click", () => prepareKeyProtection(true));
  $("access-recovery").addEventListener("toggle", () => {
    renderKeyProtection();
    if ($("access-recovery").open && !state.busy && !keyProtection.token) {
      clearAlert();
      $("key-recovery-code").focus();
    }
  });
  $("commit-key-protection").addEventListener("click", commitKeyProtection);
  $("recovery-code-saved").addEventListener("change", renderKeyProtection);
  $("cancel-key-protection").addEventListener("click", () => { resetKeyProtection(); renderKeyProtection(); });
  $("close-key-options").addEventListener("click", () => $("key-dialog").close());
  $("key-dialog").addEventListener("cancel", (event) => {
    if (state.accessSetupRequired && !state.emergencyLocked) event.preventDefault();
  });
  $("startup-key-dialog").addEventListener("cancel", (event) => event.preventDefault());
  $("startup-key-dialog").addEventListener("close", () => {
    if (!$("key-dialog").open) {
      if ($("sandbox-dialog").open) $("close-sandbox").focus();
      else $("open-key-options").focus();
    }
    maybeResumeSandbox();
  });
  $("choose-recovery-key").addEventListener("click", () => {
    $("startup-key-dialog").close();
  });
  $("key-dialog").addEventListener("close", () => {
    $("key-text").value = "";
    $("key-passphrase").value = "";
    resetKeyProtection();
    keyProtection.firstRunVisible = false;
    if ($("sandbox-dialog").open) $("close-sandbox").focus();
    else $("open-key-options").focus();
    maybeResumeSandbox();
    maybeShowFirstRun();
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
    run(() => invoke("browse_key"), true);
  });

  $("generate").addEventListener("click", () => {
    run(
      () => invoke("generate_key", { path: $("key-path").value }),
      true,
    );
  });

  $("load").addEventListener("click", () => {
    runKeyOption(() => invoke("load_key", { path: $("key-path").value }), true);
  });

  $("unload").addEventListener("click", () => {
    runKeyOption(() => invoke("unload_key"), false);
  });

  $("save-typed").addEventListener("click", () => {
    runKeyOption(async () => {
      const keyText = $("key-text").value;
      $("key-text").value = "";
      const status = await invoke("save_typed_key", {
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

  $("backup-key").addEventListener("click", () => runKeyOption(() => invoke("backup_key"), false));
  $("check-backup").addEventListener("click", () =>
    runKeyOption(() => invoke("check_key_backup"), false));

  $("rotate-key").addEventListener("click", async () => {
    if (state.busy || !state.keyLoaded || !state.files.length) return;
    $("key-dialog").close();
    state.jobRunning = true;
    invalidatePreview();
    resetFileVerification();
    $("progress-panel").hidden = false;
    $("job-progress").value = 0;
    $("progress-label").textContent = "Choose a new key-file path...";
    try {
      await run(async () => {
        const report = await invoke("rotate_key", {
          paths: [...state.files],
          outputDir: $("output-dir").value,
          removeOriginal: $("remove-original").checked,
        });
        if (report) {
          renderResults(report.results, "rotate");
          applyStatus(report.status, true);
          if (report.notice) showAlert(report.notice);
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

  $("add-files").addEventListener("click", () => selectFiles(() => invoke("pick_input_files")));

  $("file-empty").addEventListener("click", () => $("add-files").click());
  $("file-empty").addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      $("add-files").click();
    }
  });

  $("add-folder").addEventListener("click", () => selectFiles(() => invoke("pick_input_folder")));

  $("clear-files").addEventListener("click", () => {
    if (selectionBlocked()) return;
    state.files = [];
    state.fileSet.clear();
    state.folderRoots.clear();
    resetFileVerification();
    cancelSandboxRecovery();
    invalidatePreview();
    rememberSelectedFiles();
    renderFiles();
  });

  $("encrypt").addEventListener("click", () => prepareJob("encrypt"));
  $("decrypt").addEventListener("click", () => prepareJob("decrypt"));
  $("view-sandbox").addEventListener("click", openSandbox);
  $("sandbox-home").addEventListener("click", () => navigateSandbox());
  $("sandbox-reset-filter").addEventListener("click", () => navigateSandbox());
  $("sandbox-back").addEventListener("click", () => stepSandboxHistory(-1));
  $("sandbox-forward").addEventListener("click", () => stepSandboxHistory(1));
  $("sandbox-up").addEventListener("click", () => navigateSandbox(sandbox.query || sandbox.category ? "" : sandbox.folders.get(sandbox.folder)?.parent || ""));
  const searchSandbox = () => {
    sandbox.query = $("sandbox-search").value;
    if (pagedLists.has("sandbox-list")) pagedLists.get("sandbox-list").page = 0;
    renderSandboxExplorer();
  };
  $("sandbox-search").addEventListener("input", () => {
    clearTimeout(sandbox.searchTimer);
    sandbox.searchTimer = setTimeout(() => { sandbox.searchTimer = null; searchSandbox(); }, 120);
  });
  $("sandbox-clear-search").addEventListener("click", () => {
    clearTimeout(sandbox.searchTimer);
    sandbox.searchTimer = null;
    $("sandbox-search").value = "";
    searchSandbox();
    $("sandbox-search").focus();
  });
  $("sandbox-sort").addEventListener("change", () => {
    sandbox.sort = $("sandbox-sort").value;
    if (pagedLists.has("sandbox-list")) pagedLists.get("sandbox-list").page = 0;
    renderSandboxExplorer();
  });
  for (const view of ["grid", "details"]) {
    $("sandbox-" + view).addEventListener("click", () => {
      sandbox.view = view;
      renderSandboxExplorer();
    });
  }
  $("close-sandbox-properties").addEventListener("click", () => $("sandbox-properties").close());
  $("sandbox-context-menu").addEventListener("keydown", (event) => {
    const menu = $("sandbox-context-menu");
    const buttons = Array.from(menu.children);
    const index = buttons.indexOf(document.activeElement);
    if (["ArrowDown", "ArrowUp", "Home", "End", "Escape", "Tab"].includes(event.key)) {
      if (event.key !== "Tab") event.preventDefault();
      event.stopPropagation();
      if (event.key === "Escape" || event.key === "Tab") {
        const anchor = sandbox.contextAnchor;
        hideSandboxContextMenu();
        if (event.key === "Escape") anchor?.focus();
      } else {
        const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1
          : (index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length;
        buttons[next]?.focus();
      }
    }
  });
  $("sandbox-dialog").addEventListener("pointerdown", (event) => {
    if (!$("sandbox-context-menu").contains(event.target)) hideSandboxContextMenu();
    if (event.target === $("sandbox-list") || event.target === $("sandbox-file-scroll")) {
      sandbox.selectedKey = null;
      sandbox.currentItemId = null;
      updateSandboxSelection();
    }
  });
  $("sandbox-file-scroll").addEventListener("scroll", hideSandboxContextMenu);
  $("sandbox-dialog").addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
      event.preventDefault();
      $("sandbox-search").focus();
    } else if (event.altKey && ["ArrowLeft", "ArrowRight", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      if (event.key === "ArrowUp") $("sandbox-up").click();
      else stepSandboxHistory(event.key === "ArrowLeft" ? -1 : 1);
    } else if (event.key === "Escape" && !$("sandbox-context-menu").hidden) {
      event.preventDefault();
      hideSandboxContextMenu();
    }
  });
  $("sandbox-list").addEventListener("keydown", (event) => {
    const index = sandbox.buttons.indexOf(document.activeElement);
    if (index < 0 || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const columns = sandbox.view === "grid" ? window.getComputedStyle($("sandbox-list")).gridTemplateColumns.split(" ").length : 1;
    const delta = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -columns, ArrowDown: columns }[event.key] || 0;
    const next = event.key === "Home" ? 0 : event.key === "End" ? sandbox.buttons.length - 1
      : Math.max(0, Math.min(sandbox.buttons.length - 1, index + delta));
    sandbox.buttons[next]?.focus();
  });
  $("close-sandbox").addEventListener("click", () => $("sandbox-dialog").close());
  $("sandbox-dialog").addEventListener("close", () => {
    if (sandbox.hiddenClosures) {
      sandbox.hiddenClosures--;
      return;
    }
    resetSandbox();
    $("view-sandbox").focus();
  });
  window.addEventListener("pagehide", () => { void flushSelectedFiles(); resetSandbox(); });
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
  savedSelection.ready = true;
  if (!savedSelection.pending && savedSelection.revision) rememberSelectedFiles();
  else await maybeRestoreSelectedFiles();
  renderFiles();
  fileVerification.ready = true;
  startAutomaticVerification();
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
  if (state.accessSetupRequired || state.busy || !state.keyLoaded || !job?.preview?.canRun || job.revision !== state.planRevision) return;
  invalidatePreview();
  state.jobRunning = true;
  resetFileVerification();
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
