// Only this application-authored script runs in the opaque preview frame.
// Keep its exact SHA-256 in sandbox-content.js and tauri.conf.json.
const SANDBOX_VIEWER_SCRIPT = String.raw`(() => {
  "use strict";
  const channel = "fileencrypt-preview";
  const kind = document.body.dataset.kind;
  const media = document.getElementById("preview-media");
  const stage = document.getElementById("preview-stage");
  let ready = false, failed = false, fit = true, scale = 1, gestureScale = null;
  const send = (type, detail = {}) => parent.postMessage({ channel, type, ...detail }, "*");
  const fail = () => { if (!failed) { failed = true; send("error", { kind }); } };
  const fitScale = () => Math.min(1, Math.max(1, stage.clientWidth - 48) / media.naturalWidth, Math.max(1, stage.clientHeight - 48) / media.naturalHeight);
  function zoom(value, point) {
    if (kind !== "image" || !ready || failed) return;
    const bounds = stage.getBoundingClientRect();
    const x = point?.x ?? bounds.left + stage.clientWidth / 2;
    const y = point?.y ?? bounds.top + stage.clientHeight / 2;
    const before = media.getBoundingClientRect();
    const imageX = (x - before.left) / scale;
    const imageY = (y - before.top) / scale;
    fit = value === "fit";
    scale = fit ? fitScale() : Math.max(Math.min(0.05, fitScale()), Math.min(4, value));
    media.style.width = (media.naturalWidth * scale) + "px";
    media.style.height = (media.naturalHeight * scale) + "px";
    if (fit) { stage.scrollLeft = 0; stage.scrollTop = 0; }
    else {
      const after = media.getBoundingClientRect();
      stage.scrollLeft += after.left + imageX * scale - x;
      stage.scrollTop += after.top + imageY * scale - y;
    }
    send("zoom", { scale, fit });
  }
  function loaded() {
    if (ready || failed) return;
    if (kind === "image" && (!media.naturalWidth || media.naturalWidth > 16384 || media.naturalHeight > 16384 || media.naturalWidth * media.naturalHeight > 40000000)) { fail(); return; }
    ready = true;
    if (kind === "image") { zoom("fit"); media.style.visibility = "visible"; }
    send("ready", { kind });
  }
  window.addEventListener("message", (event) => {
    if (event.source !== parent || event.data?.channel !== channel) return;
    const data = event.data;
    if (data.type === "zoom" && kind === "image") {
      if (data.value === "fit") zoom("fit");
      else if (Number.isFinite(data.value)) zoom(data.value);
      else if (data.direction === -1 || data.direction === 1) zoom(scale * (data.direction === 1 ? 1.25 : 0.8));
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.preventDefault(); send("close"); }
    else if (kind === "image" && !event.altKey && !event.ctrlKey && !event.metaKey) {
      if (fit && (event.key === "ArrowLeft" || event.key === "ArrowRight")) {
        event.preventDefault(); send("navigate", { direction: event.key === "ArrowRight" ? 1 : -1 });
      } else if (event.key === "+" || event.key === "=") { event.preventDefault(); zoom(scale * 1.25); }
      else if (event.key === "-") { event.preventDefault(); zoom(scale * 0.8); }
      else if (event.key === "0") { event.preventDefault(); zoom("fit"); }
    }
  }, true);
  if (media) {
    media.addEventListener("error", fail);
    if (kind === "image") {
      media.addEventListener("load", loaded);
      if (media.complete) loaded();
      // Precision-trackpad pinch arrives as a Ctrl+wheel event in WebView2.
      stage.addEventListener("wheel", (event) => {
        if (!event.ctrlKey || !ready || failed) return;
        event.preventDefault();
        const unit = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? stage.clientHeight : 1;
        const delta = Math.max(-100, Math.min(100, event.deltaY * unit));
        zoom(scale * Math.exp(-delta * 0.01), { x: event.clientX, y: event.clientY });
      }, { passive: false });
      stage.addEventListener("gesturestart", (event) => { event.preventDefault(); gestureScale = scale; }, { passive: false });
      stage.addEventListener("gesturechange", (event) => {
        event.preventDefault();
        if (gestureScale !== null && Number.isFinite(event.scale)) zoom(gestureScale * event.scale, { x: event.clientX, y: event.clientY });
      }, { passive: false });
      stage.addEventListener("gestureend", (event) => { event.preventDefault(); gestureScale = null; }, { passive: false });
      new ResizeObserver(() => { if (fit && ready) zoom("fit"); }).observe(stage);
    } else {
      media.addEventListener("loadedmetadata", loaded);
      if (media.error) fail();
      else if (media.readyState >= 1) loaded();
    }
  } else loaded();
})();`;

const SANDBOX_VIEWER_SCRIPT_HASH = "sha256-69QcX2tUZWI4GABTIsqj810FhMbwKT7kZ/G/LQrAqkA=";
