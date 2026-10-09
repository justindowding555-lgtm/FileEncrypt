// Keep this exact stylesheet's SHA-256 in tauri.conf.json and the preview CSP.
const SANDBOX_IMAGE_ZOOMS = [25, 50, 75, 100, 125, 150, 200, 300, 400];
const SANDBOX_STYLE = "html{color-scheme:light dark}body{margin:16px;font:14px system-ui,sans-serif}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px ui-monospace,monospace}img,video{display:block;max-width:100%;max-height:85vh;margin:auto}audio{width:100%}" + `
  body[data-kind="image"]{height:100vh;margin:0;overflow:hidden;background:light-dark(#f6f7f8,#151719)}
  #preview-stage{height:100%;overflow:auto;outline-offset:-3px}
  .image-surface{display:flex;box-sizing:border-box;min-width:100%;min-height:100%;width:max-content;height:max-content;padding:24px}
  .image-surface img{flex:none;max-width:none;max-height:none;margin:auto;visibility:hidden}
`;
const SANDBOX_STYLE_HASH = "sha256-WoisBQe0FAesjdVAjzZrTC4cTxcvlcXlPzCdXwxtD1k=";

function escapeSandboxText(text) {
  return text.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function sandboxImageBody(url) {
  return `<main id="preview-stage" tabindex="0" aria-label="Image preview. Pinch to zoom; scroll to pan."><div class="image-surface"><img src="${url}" id="preview-media" alt="File preview" draggable="false"></div></main>`;
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
      ? sandboxImageBody(url)
      : `<${content.kind} src="${url}" id="preview-media" preload="metadata" controls controlslist="nodownload noremoteplayback" disablepictureinpicture disableremoteplayback></${content.kind}>`;
  }
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; media-src data:; script-src '${SANDBOX_VIEWER_SCRIPT_HASH}'; style-src '${SANDBOX_STYLE_HASH}'; base-uri 'none'; form-action 'none'"><style>${SANDBOX_STYLE}</style></head><body data-kind="${content.kind}">${body}<script>${SANDBOX_VIEWER_SCRIPT}</script></body></html>`;
}

function createSandboxFrame(content, name) {
  const frame = document.createElement("iframe");
  frame.setAttribute("sandbox", "allow-scripts");
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.setAttribute("allow", "camera 'none'; microphone 'none'; geolocation 'none'; clipboard-write 'none'");
  frame.title = `Read-only preview: ${name}`;
  frame.srcdoc = sandboxDocument(content);
  return frame;
}
