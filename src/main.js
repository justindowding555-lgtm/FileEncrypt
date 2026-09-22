const state = {
  files: [],
  busy: false,
  keyLoaded: false,
};

const $ = (id) => document.getElementById(id);

function invoke(command, args) {
  const call = window.__TAURI__?.core?.invoke;
  if (!call) {
    throw new Error("FileEncrypt commands are only available in the desktop window.");
  }
  return call(command, args);
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

function applyStatus(status, updatePath) {
  state.keyLoaded = Boolean(status.keyLoaded);
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
  $("add-files").disabled = state.busy;
  $("clear-files").disabled = state.busy || noFiles;
  $("generate").disabled = state.busy;
  $("load").disabled = state.busy;
  $("unload").disabled = state.busy || !state.keyLoaded;
  $("set-path").disabled = state.busy;
  $("browse-load").disabled = state.busy;
  $("save-typed").disabled = state.busy;
  $("choose-output").disabled = state.busy;
  $("clear-output").disabled = state.busy || $("output-dir").value.trim() === "";
  $("file-count").textContent = noFiles ? "" : `(${state.files.length})`;
  $("action-hint").textContent = state.busy
    ? "Working. Please wait…"
    : !state.keyLoaded && noFiles
      ? "Load a key and add files to get started."
      : !state.keyLoaded
        ? "Load a key to continue."
        : noFiles
          ? "Add files to continue."
          : `${state.files.length} ${state.files.length === 1 ? "file" : "files"} ready to encrypt or decrypt.`;
  renderOutputHint();
}

function plannedName(path) {
  const name = baseName(path);
  if (name.length > 5 && name.toLowerCase().endsWith(".fenc")) {
    return "original name from inside the file";
  }
  return "a random .fenc name";
}

function renderOutputHint() {
  const dir = $("output-dir").value.trim();
  const where = dir ? `in ${dir}` : "beside each original";
  $("output-hint").textContent = `Saved ${where} under a random name. Decrypt restores the original file name.`;
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
    full.textContent = `Saves as ${plannedName(path)}`;
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
    run(() => invoke("load_key", { path: $("key-path").value }), true);
  });

  $("unload").addEventListener("click", () => {
    run(() => invoke("unload_key"), false);
  });

  $("save-typed").addEventListener("click", () => {
    run(async () => {
      const status = await invoke("save_typed_key", {
        path: $("key-path").value,
        keyText: $("key-text").value,
      });
      if (String(status.message).startsWith("Key written")) {
        $("key-text").value = "";
      }
      return status;
    }, true);
  });

  $("output-dir").addEventListener("input", () => {
    renderControls();
  });

  $("choose-output").addEventListener("click", () => {
    run(async () => {
      const picked = await invoke("pick_output_dir");
      if (picked) $("output-dir").value = picked;
      renderOutputHint();
      return null;
    }, false);
  });

  $("clear-output").addEventListener("click", () => {
    $("output-dir").value = "";
    run(() => invoke("set_output_dir", { path: "" }), true);
  });

  $("add-files").addEventListener("click", () => {
    run(async () => {
      const picked = await invoke("pick_input_files");
      for (const path of picked) {
        if (!state.files.includes(path)) state.files.push(path);
      }
      return null;
    }, false);
  });

  $("clear-files").addEventListener("click", () => {
    state.files = [];
    renderFiles();
  });

  $("encrypt").addEventListener("click", () => processFiles("encrypt_files"));
  $("decrypt").addEventListener("click", () => processFiles("decrypt_files"));

  try {
    applyStatus(await invoke("get_status"), true);
  } catch (error) {
    showAlert(normalizeError(error));
    renderControls();
  }
  renderFiles();
}

function processFiles(command) {
  run(async () => {
    const results = await invoke(command, {
      paths: state.files,
      outputDir: $("output-dir").value,
      overwrite: $("overwrite").checked,
      removeOriginal: $("remove-original").checked,
    });
    renderResults(results);
    return invoke("get_status");
  }, false);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    init();
  });
} else {
  init();
}
