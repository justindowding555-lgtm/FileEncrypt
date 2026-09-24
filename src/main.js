const state = {
  files: [],
  folderRoots: new Map(),
  busy: false,
  keyLoaded: false,
  keyFingerprint: null,
  pendingJob: null,
  jobRunning: false,
  updatesConfigured: false,
  updateAvailable: false,
};

const $ = (id) => document.getElementById(id);

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
  const alert = $("alert");
  alert.hidden = false;
  alert.textContent = message;
}

function clearAlert() {
  const alert = $("alert");
  alert.hidden = true;
  alert.textContent = "";
}

function invalidatePreview() {
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
    if (!state.files.includes(path)) {
      state.files.push(path);
      changed = true;
    }
  }
  if (changed) invalidatePreview();
  renderFiles();
}

function applyStatus(status, updatePath) {
  if (state.keyFingerprint !== null && state.keyFingerprint !== status.fingerprint) {
    invalidatePreview();
  }
  state.keyFingerprint = status.fingerprint;
  state.keyLoaded = Boolean(status.keyLoaded);
  state.updatesConfigured = Boolean(status.updatesConfigured);
  if (!state.updatesConfigured) $("update-status").textContent = "Signed updates are not configured in this build.";
  $("fingerprint").classList.toggle("is-loaded", state.keyLoaded);
  if (updatePath && status.keyPath) {
    $("key-path").value = status.keyPath;
  }
  if (updatePath && typeof status.outputDir === "string") {
    $("output-dir").value = status.outputDir;
  }
  $("fingerprint").textContent = status.keyLoaded
    ? `Key loaded · ${status.fingerprint}`
    : "No key loaded";
  $("key-message").textContent =
    status.message ||
    (status.keyLoaded
      ? "Ready to encrypt or decrypt your files."
      : "Choose a key to get started.");
  renderControls();
}

function renderControls() {
  const noFiles = state.files.length === 0;
  const blocked = state.busy || !state.keyLoaded || noFiles;
  $("encrypt").disabled = blocked;
  $("decrypt").disabled = blocked;
  $("verify").disabled = blocked;
  $("add-files").disabled = state.busy;
  $("add-folder").disabled = state.busy;
  $("clear-files").disabled = state.busy || noFiles;
  $("generate").disabled = state.busy;
  $("load").disabled = state.busy;
  $("unload").disabled = state.busy || !state.keyLoaded;
  $("set-path").disabled = state.busy;
  $("browse-load").disabled = state.busy;
  $("backup-key").disabled = state.busy || !state.keyLoaded;
  $("check-backup").disabled = state.busy || !state.keyLoaded;
  $("rotate-key").disabled = blocked;
  $("save-typed").disabled = state.busy;
  $("choose-output").disabled = state.busy;
  $("clear-output").disabled = state.busy || $("output-dir").value.trim() === "";
  $("zip").disabled = state.busy;
  $("compress").disabled = state.busy || !$("zip").checked;
  $("review-first").disabled = state.busy;
  $("overwrite").disabled = state.busy;
  $("remove-original").disabled = state.busy;
  $("output-dir").disabled = state.busy;
  $("start-job").disabled = state.busy || !state.pendingJob?.preview?.canRun;
  $("cancel-job").disabled = !state.jobRunning;
  $("check-update").disabled = state.busy || !state.updatesConfigured;
  $("install-update").disabled = state.busy || !state.updateAvailable;
  $("file-count").textContent = noFiles ? "" : `(${state.files.length})`;
  $("action-hint").textContent = state.busy
    ? "Working. Please wait…"
    : !state.keyLoaded && noFiles
      ? "Load a key and add files to get started."
      : !state.keyLoaded
        ? "Load a key to continue."
        : noFiles
          ? "Add files to continue."
          : `${state.files.length} ${state.files.length === 1 ? "file" : "files"} ready to encrypt, decrypt, or verify.`;
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
    const where = dir ? `in ${dir}` : "beside the first selected file";
    $("output-hint").textContent = `When encrypting, one randomly named ZIP is saved ${where}. Add that ZIP later to decrypt its files directly.`;
  } else {
    const where = dir ? `in ${dir}` : "beside each original";
    $("output-hint").textContent = `Saved ${where} under a random name. Decrypt restores the original file name.`;
  }
}

function renderFiles() {
  const list = $("file-list");
  const empty = $("file-empty");
  list.replaceChildren();
  empty.hidden = state.files.length > 0;
  for (const [index, path] of state.files.entries()) {
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
    remove.addEventListener("click", () => {
      state.files.splice(index, 1);
      state.folderRoots.delete(path);
      invalidatePreview();
      renderFiles();
      renderControls();
    });

    item.append(text, remove);
    list.append(item);
  }
  renderControls();
}

function renderResults(results) {
  const list = $("results");
  list.replaceChildren();
  const succeeded = results.filter((result) => result.ok).length;
  $("result-summary").textContent = `${succeeded} succeeded, ${results.length - succeeded} failed`;
  for (const result of results) {
    const item = document.createElement("li");
    item.className = result.ok ? "result ok" : "result fail";
    const text = document.createElement("div");
    text.className = "result-text";
    const title = document.createElement("div");
    title.className = "result-title";
    title.textContent = result.output
      ? `${baseName(result.input)} → ${baseName(result.output)}`
      : baseName(result.input);
    title.title = result.output ? `${result.input} → ${result.output}` : result.input;
    const message = document.createElement("div");
    message.className = "result-msg";
    message.textContent = result.output
      ? `${result.message} · ${result.output}`
      : result.message;
    text.append(title, message);
    item.append(text);
    list.append(item);
  }
}

async function run(work, updatePathOnSuccess) {
  if (state.busy) return;
  state.busy = true;
  renderControls();
  renderFiles();
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
    renderFiles();
  }
}

async function init() {
  try {
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
    run(() => invokeWithPassphrase("load_key", { path: $("key-path").value }), true);
  });

  $("unload").addEventListener("click", () => {
    run(() => invoke("unload_key"), false);
  });

  $("save-typed").addEventListener("click", () => {
    run(async () => {
      const keyText = $("key-text").value;
      $("key-text").value = "";
      const status = await invokeWithPassphrase("save_typed_key", {
        path: $("key-path").value,
        keyText,
      });
      return status;
    }, true);
  });

  $("backup-key").addEventListener("click", () => run(() => invokeWithPassphrase("backup_key"), false));
  $("check-backup").addEventListener("click", () =>
    run(() => invokeWithPassphrase("check_key_backup"), false));

  $("rotate-key").addEventListener("click", async () => {
    if (state.busy || !state.keyLoaded || !state.files.length) return;
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
          renderResults(report.results);
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

  $("add-folder").addEventListener("click", () => {
    run(async () => {
      addSelectedFiles(await invoke("pick_input_folder"));
      return null;
    }, false);
  });

  $("clear-files").addEventListener("click", () => {
    state.files = [];
    state.folderRoots.clear();
    invalidatePreview();
    renderFiles();
  });

  $("encrypt").addEventListener("click", () => prepareJob("encrypt"));
  $("decrypt").addEventListener("click", () => prepareJob("decrypt"));
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
    applyStatus(await invoke("get_status"), true);
  } catch (error) {
    showAlert(normalizeError(error));
    renderControls();
  }
  renderFiles();
}

async function prepareJob(operation) {
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
  if (!preview) return;
  state.pendingJob = { request, preview };
  if (preview.canRun && !$("review-first").checked) {
    await startJob();
    return;
  }
  const list = $("preview-list");
  list.replaceChildren();
  for (const item of preview.items) {
    const row = document.createElement("li");
    row.className = item.issue ? "preview-issue" : "";
    row.textContent = `${baseName(item.input)} → ${item.output}${item.issue ? ` · ${item.issue}` : ""}`;
    row.title = item.input;
    list.append(row);
  }
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
  if (!job?.preview?.canRun) return;
  invalidatePreview();
  state.jobRunning = true;
  $("progress-panel").hidden = false;
  $("job-progress").value = 0;
  $("progress-label").textContent = "Preparing...";
  try {
    await run(async () => {
      const results = await invoke("run_job", { request: job.request });
      renderResults(results);
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
