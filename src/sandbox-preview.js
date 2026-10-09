const previewWindow = { generation: 0, sessionId: null, timer: null, closed: false, loading: false };
const previewElement = (id) => document.getElementById(id);
const previewInvoke = (command, args) => window.__TAURI__.core.invoke(command, args);

function previewDeadline(promise) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Key-file access could not be confirmed.")), 1500);
    promise.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}

function clearPrivatePreview() {
  previewWindow.generation++;
  clearTimeout(previewWindow.timer);
  previewWindow.timer = null;
  previewElement("preview-content").replaceChildren();
  previewElement("preview-content").hidden = true;
  document.title = "Private preview - FileEncrypt";
}

function closePrivatePreview(locked = false) {
  if (previewWindow.closed) return;
  previewWindow.closed = true;
  clearPrivatePreview();
  previewElement("preview-message").hidden = false;
  previewElement("preview-message-title").textContent = "Preview locked";
  previewElement("preview-message-detail").textContent = "The saved key or sandbox is no longer available.";
  previewElement("retry-private-preview").hidden = true;
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

async function loadPrivatePreview() {
  if (previewWindow.closed || previewWindow.loading) return;
  previewWindow.loading = true;
  clearPrivatePreview();
  const generation = previewWindow.generation;
  previewElement("preview-message").hidden = false;
  previewElement("preview-message-title").textContent = "Preparing your preview";
  previewElement("preview-message-detail").textContent = "Authenticating and opening this file in memory.";
  previewElement("retry-private-preview").hidden = true;
  let content;
  try {
    const info = await previewDeadline(previewInvoke("sandbox_preview_info"));
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    previewWindow.sessionId = info.sessionId;
    schedulePrivatePreviewCheck();
    document.title = `${info.item.name.split(/[\\/]/).pop()} - FileEncrypt`;
    content = await previewInvoke("read_sandbox_preview");
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    await previewDeadline(previewInvoke("check_sandbox", { sessionId: info.sessionId }));
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    previewElement("preview-content").replaceChildren(createSandboxFrame(content, info.item.name));
    previewElement("preview-content").hidden = false;
    previewElement("preview-message").hidden = true;
  } catch (error) {
    if (previewWindow.closed || generation !== previewWindow.generation) return;
    const message = typeof error === "string" ? error : error.message;
    if (message.startsWith("Sandbox locked") || /Key-file access/.test(message)) closePrivatePreview(true);
    else {
      previewElement("preview-message-title").textContent = "Preview unavailable";
      previewElement("preview-message-detail").textContent = message;
      previewElement("retry-private-preview").hidden = false;
    }
  } finally {
    if (content) content.data = "";
    previewWindow.loading = false;
  }
}

async function initPrivatePreview() {
  previewElement("preview-message-icon").innerHTML = EXPLORER_ICONS.shield;
  previewElement("retry-private-preview").addEventListener("click", loadPrivatePreview);
  window.addEventListener("pagehide", clearPrivatePreview);
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") closePrivatePreview(); });
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
