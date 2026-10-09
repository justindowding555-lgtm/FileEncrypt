const previewWindow = { generation: 0, sessionId: null, timer: null, closed: false, loading: false, frame: null, decoded: null, info: null, kind: null, scale: null };
const previewElement = (id) => document.getElementById(id);
const previewInvoke = (command, args) => window.__TAURI__.core.invoke(command, args);

function setPrivatePreviewMessage(state, title, detail = "") {
  const message = previewElement("preview-message");
  message.hidden = false;
  message.setAttribute("data-state", state);
  previewElement("preview-state-icon").innerHTML = state === "loading" ? "" : EXPLORER_ICONS[state === "locked" ? "lock" : "info"];
  previewElement("preview-message-title").textContent = title;
  previewElement("preview-message-detail").textContent = detail;
  previewElement("retry-private-preview").hidden = state !== "error";
  previewElement("retry-private-preview").disabled = previewWindow.loading;
}

function previewDeadline(promise) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Key-file access could not be confirmed.")), 1500);
    promise.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}

function clearPrivatePreview(keepNavigation = false) {
  previewWindow.generation++;
  clearTimeout(previewWindow.timer);
  previewWindow.timer = null;
  if (previewWindow.decoded) {
    clearTimeout(previewWindow.decoded.timer);
    previewWindow.decoded.reject(new Error("Preview cancelled."));
    previewWindow.decoded = null;
  }
  previewWindow.frame = null;
  previewWindow.scale = null;
  previewElement("preview-content").replaceChildren();
  previewElement("preview-content").hidden = true;
  if (!keepNavigation) {
    previewWindow.info = null;
    previewWindow.kind = null;
    previewElement("preview-image-toolbar").hidden = true;
    previewElement("preview-image-name").textContent = "";
    previewElement("preview-image-position").textContent = "";
  }
  document.title = "Private preview - FileEncrypt";
}

function closePrivatePreview(locked = false) {
  if (previewWindow.closed) return;
  previewWindow.closed = true;
  previewWindow.loading = false;
  clearPrivatePreview();
  setPrivatePreviewMessage("locked", "Preview locked", "The saved key or sandbox is no longer available.");
  return previewInvoke("close_sandbox_preview", { locked }).catch(() => {});
}

function schedulePrivatePreviewCheck() {
  clearTimeout(previewWindow.timer);
  if (previewWindow.closed || !previewWindow.sessionId) return;
  previewWindow.timer = setTimeout(async () => {
    try {
      await previewDeadline(previewInvoke("check_sandbox", { sessionId: previewWindow.sessionId }));
      schedulePrivatePreviewCheck();
    } catch { closePrivatePreview(true); }
  }, 500);
}

function updatePrivatePreviewToolbar(info, kind = info.item.kind) {
  previewWindow.info = info;
  previewWindow.kind = kind;
  const navigation = info.navigation || {};
  previewElement("preview-image-toolbar").hidden = kind !== "image";
  previewElement("preview-previous-image").disabled = previewWindow.loading || !navigation.previous;
  previewElement("preview-next-image").disabled = previewWindow.loading || !navigation.next;
  previewElement("preview-image-position").textContent = navigation.total ? `${navigation.index} / ${navigation.total}` : "";
  previewElement("preview-image-name").textContent = info.item.name.split(/[\\/]/).pop();
  previewElement("preview-image-zoom").disabled = previewWindow.loading;
  previewElement("preview-zoom-in").disabled = previewWindow.loading || previewWindow.scale >= 4;
  previewElement("preview-zoom-out").disabled = previewWindow.loading || (previewWindow.scale !== null && previewWindow.scale <= 0.05);
}

function sendPrivatePreviewZoom(detail) {
  if (previewWindow.closed || previewWindow.loading || previewWindow.kind !== "image") return;
  previewWindow.frame?.contentWindow?.postMessage({ channel: "fileencrypt-preview", type: "zoom", ...detail }, "*");
}

function updatePrivatePreviewZoom(scale, fit) {
  if (!Number.isFinite(scale) || scale <= 0 || scale > 4 || typeof fit !== "boolean") return;
  const select = previewElement("preview-image-zoom");
  previewWindow.scale = scale;
  const custom = previewElement("preview-zoom-custom");
  const preset = SANDBOX_IMAGE_ZOOMS.find((zoom) => Math.abs(scale - zoom / 100) < 0.00001);
  custom.hidden = fit || Boolean(preset);
  custom.value = String(scale);
  custom.textContent = `${Math.round(scale * 100)}%`;
  select.value = fit ? "fit" : preset ? String(preset / 100) : String(scale);
  previewElement("preview-zoom-out").disabled = previewWindow.loading || scale <= 0.05;
  previewElement("preview-zoom-in").disabled = previewWindow.loading || scale >= 4;
}

function waitForPrivatePreviewDecode(generation) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("This file could not be decoded in time. Try again or open another file.")), 15000);
    previewWindow.decoded = { generation, resolve, reject, timer };
  });
}

async function showPrivatePreviewError(message) {
  clearPrivatePreview(true);
  const generation = previewWindow.generation;
  previewWindow.loading = true;
  setPrivatePreviewMessage("error", "Preview unavailable", message);
  schedulePrivatePreviewCheck();
  await previewInvoke("cancel_sandbox_preview_read").catch(() => {});
  if (previewWindow.closed || generation !== previewWindow.generation) return;
  previewWindow.loading = false;
  previewElement("retry-private-preview").disabled = false;
  if (previewWindow.info) updatePrivatePreviewToolbar(previewWindow.info, previewWindow.kind);
  for (const id of ["preview-image-zoom", "preview-zoom-in", "preview-zoom-out"]) previewElement(id).disabled = true;
}

function handlePrivatePreviewMessage(event) {
  if (previewWindow.closed || !event.source || event.source !== previewWindow.frame?.contentWindow || event.origin !== "null" || event.data?.channel !== "fileencrypt-preview") return;
  const data = event.data;
  if (data.type === "ready" && data.kind === previewWindow.kind) previewWindow.decoded?.resolve();
  else if (data.type === "error" && data.kind === previewWindow.kind) {
    const message = data.kind === "image" ? "This image is damaged or cannot be displayed. Try another image."
      : "This media file is damaged or its codec is not supported by the system viewer.";
    if (previewWindow.decoded) previewWindow.decoded.reject(new Error(message));
    else void showPrivatePreviewError(message);
  } else if (data.type === "close") closePrivatePreview();
  else if (data.type === "navigate" && (data.direction === -1 || data.direction === 1)) navigatePrivatePreview(data.direction);
  else if (data.type === "zoom" && previewWindow.kind === "image") updatePrivatePreviewZoom(data.scale, data.fit);
}

function navigatePrivatePreview(direction) {
  if (direction !== -1 && direction !== 1) return;
  if (previewWindow.closed || previewWindow.loading || previewWindow.kind !== "image") return;
  if (!(direction === -1 ? previewWindow.info?.navigation?.previous : previewWindow.info?.navigation?.next)) return;
  return loadPrivatePreview(direction);
}

async function loadPrivatePreview(direction = 0) {
  if (previewWindow.closed || previewWindow.loading) return;
  previewWindow.loading = true;
  clearPrivatePreview(Boolean(direction));
  const generation = previewWindow.generation;
  setPrivatePreviewMessage("loading", "Preparing your file");
  let content;
  try {
    await previewInvoke("cancel_sandbox_preview_read");
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    const info = await previewDeadline(previewInvoke(direction ? "navigate_sandbox_preview" : "sandbox_preview_info", direction ? { direction } : undefined));
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    previewWindow.sessionId = info.sessionId;
    schedulePrivatePreviewCheck();
    document.title = `${info.item.name.split(/[\\/]/).pop()} - FileEncrypt`;
    updatePrivatePreviewToolbar(info);
    content = await previewInvoke("read_sandbox_preview");
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    await previewDeadline(previewInvoke("check_sandbox", { sessionId: info.sessionId, fresh: true }));
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    updatePrivatePreviewToolbar(info, content.kind);
    const frame = createSandboxFrame(content, info.item.name);
    previewWindow.frame = frame;
    const decoded = waitForPrivatePreviewDecode(generation);
    // Let the frame load at its actual viewport size underneath the spinner.
    previewElement("preview-content").replaceChildren(frame);
    previewElement("preview-content").setAttribute("aria-hidden", "true");
    previewElement("preview-content").classList.add("is-preparing");
    previewElement("preview-content").hidden = false;
    await decoded;
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    clearTimeout(previewWindow.decoded.timer);
    previewWindow.decoded = null;
    await previewDeadline(previewInvoke("check_sandbox", { sessionId: info.sessionId, fresh: true }));
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    previewElement("preview-content").removeAttribute("aria-hidden");
    previewElement("preview-content").classList.remove("is-preparing");
    previewElement("preview-message").hidden = true;
  } catch (error) {
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    const message = typeof error === "string" ? error : String(error?.message || "Unable to open this preview.");
    if (message.startsWith("Sandbox locked") || /Key-file access/.test(message)) closePrivatePreview(true);
    else {
      await showPrivatePreviewError(message);
    }
  } finally {
    if (content) content.data = "";
    if (generation === previewWindow.generation) {
      previewWindow.loading = false;
      if (previewWindow.info) updatePrivatePreviewToolbar(previewWindow.info, previewWindow.kind);
    }
  }
}

async function initPrivatePreview() {
  const options = ["fit", ...SANDBOX_IMAGE_ZOOMS.map((zoom) => String(zoom / 100))].map((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value === "fit" ? "Fit to window" : `${Math.round(Number(value) * 100)}%`;
    return option;
  });
  const custom = document.createElement("option");
  custom.id = "preview-zoom-custom";
  custom.hidden = true;
  previewElement("preview-image-zoom").replaceChildren(...options, custom);
  previewElement("preview-image-zoom").addEventListener("change", (event) => sendPrivatePreviewZoom({ value: event.target.value === "fit" ? "fit" : Number(event.target.value) }));
  previewElement("preview-zoom-in").addEventListener("click", () => sendPrivatePreviewZoom({ direction: 1 }));
  previewElement("preview-zoom-out").addEventListener("click", () => sendPrivatePreviewZoom({ direction: -1 }));
  previewElement("preview-previous-image").addEventListener("click", () => navigatePrivatePreview(-1));
  previewElement("preview-next-image").addEventListener("click", () => navigatePrivatePreview(1));
  window.addEventListener("message", handlePrivatePreviewMessage);
  // Wheel events inside the opaque frame are handled by its viewer. Cancel
  // browser zoom over the toolbar or loading/error screen as well.
  window.addEventListener("wheel", (event) => {
    if (event.ctrlKey) event.preventDefault();
  }, { passive: false });
  previewElement("retry-private-preview").addEventListener("click", () => loadPrivatePreview());
  window.addEventListener("pagehide", () => { clearPrivatePreview(); void previewInvoke("cancel_sandbox_preview_read").catch(() => {}); });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closePrivatePreview();
    else if (!event.altKey && (event.ctrlKey || event.metaKey) && ["+", "=", "-", "0"].includes(event.key)) {
      event.preventDefault();
      if (event.key === "0") sendPrivatePreviewZoom({ value: "fit" });
      else sendPrivatePreviewZoom({ direction: event.key === "-" ? -1 : 1 });
    }
    else if (!event.altKey && !event.ctrlKey && !event.metaKey && !["SELECT", "INPUT", "TEXTAREA"].includes(event.target?.tagName)) {
      if (event.key === "ArrowLeft" || event.key === "ArrowRight") navigatePrivatePreview(event.key === "ArrowRight" ? 1 : -1);
    }
  }, true);
  await window.__TAURI__.event.listen("sandbox-locked", ({ payload }) => {
    if (!previewWindow.sessionId || payload === previewWindow.sessionId) closePrivatePreview(true);
  });
  await window.__TAURI__.event.listen("key-status-changed", ({ payload }) => {
    if (!payload.sandboxAvailable) closePrivatePreview(true);
  });
  await loadPrivatePreview();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initPrivatePreview);
else initPrivatePreview();
