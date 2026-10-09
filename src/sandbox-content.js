// Keep this exact stylesheet's SHA-256 in tauri.conf.json and the preview CSP.
const SANDBOX_STYLE = "html{color-scheme:light dark}body{margin:16px;font:14px system-ui,sans-serif}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px ui-monospace,monospace}img,video{display:block;max-width:100%;max-height:85vh;margin:auto}audio{width:100%}";
const SANDBOX_STYLE_HASH = "sha256-+d/I4iYM/9I6DotUkT3YfqOsiHrpFkzcIQG8DqehNDo=";

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

function createSandboxFrame(content, name) {
  const frame = document.createElement("iframe");
  frame.setAttribute("sandbox", "");
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.setAttribute("allow", "camera 'none'; microphone 'none'; geolocation 'none'; clipboard-write 'none'");
  frame.title = `Read-only preview: ${name}`;
  frame.srcdoc = sandboxDocument(content);
  return frame;
}
