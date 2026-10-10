// scripts/build-csp.mjs hashes this exact stylesheet for the preview CSP.
const SANDBOX_IMAGE_ZOOMS = [25, 50, 75, 100, 125, 150, 200, 300, 400];
const SANDBOX_STYLE = "html{color-scheme:light dark}body{margin:16px;font:14px system-ui,sans-serif}[hidden]{display:none !important}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px ui-monospace,monospace}img,video{display:block;max-width:100%;max-height:85vh;margin:auto}" + `
  html[data-theme="light"]{color-scheme:light}html[data-theme="dark"]{color-scheme:dark}
  body[data-kind="image"]{height:100vh;margin:0;overflow:hidden;background:light-dark(#f6f7f8,#151719)}
  #preview-stage{height:100%;overflow:auto;outline-offset:-3px}
  .image-surface{display:flex;box-sizing:border-box;min-width:100%;min-height:100%;width:max-content;height:max-content;padding:24px}
  .image-surface img{flex:none;max-width:none;max-height:none;margin:auto;visibility:hidden}
  body[data-kind="audio"]{min-height:100vh;margin:0;display:grid;place-items:center;box-sizing:border-box;padding:20px;background:light-dark(#f6f7f8,#151719);color:light-dark(#24272d,#e9eaed);font:14px "Segoe UI",system-ui,sans-serif}
  .player{position:relative;box-sizing:border-box;width:min(480px,100%);min-width:0;padding:24px;border:1px solid light-dark(#e3e5e8,#34373c);border-radius:14px;background:light-dark(#fff,#1c1e21);box-shadow:0 12px 34px light-dark(#2026300c,#0003),0 2px 6px light-dark(#20263006,#0000)}
  .player:focus-visible{outline:2px solid light-dark(#5d7cba,#94b5f5);outline-offset:4px}
  .player audio{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
  .player-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;color:light-dark(#686e78,#a0a5af)}
  .player-eyebrow{font-size:10px;font-weight:650;letter-spacing:.12em}
  .player-private{display:inline-flex;align-items:center;gap:5px;font-size:11px;white-space:nowrap}
  .player-private svg{width:13px;height:13px}
  .player-name{margin:0;font-size:18px;font-weight:600;letter-spacing:-.025em;line-height:1.4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .player-art{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;box-sizing:border-box;height:clamp(130px,29vh,190px);margin:20px 0 16px;padding:18px 22px 30px;border:1px solid light-dark(#e3e5e8,#34373c);border-radius:10px;background:repeating-linear-gradient(90deg,transparent 0 31px,light-dark(#e3e5e850,#34373c60) 31px 32px),light-dark(#f8f9fa,#202326);overflow:hidden}
  .player-art::before{position:absolute;left:22px;right:22px;top:calc(50% - 6px);height:1px;background:light-dark(#e3e5e8,#34373c);content:""}
  .player-wave{position:relative;display:block;width:100%;height:100%;max-height:112px;color:light-dark(#4269b4,#9dbbfa);opacity:.5;transition:opacity 180ms ease}
  .player.is-playing .player-wave{opacity:1}
  .player-wave rect{fill:currentColor}
  .player-state{position:absolute;bottom:12px;display:flex;align-items:center;gap:6px;margin:0;color:light-dark(#686e78,#a0a5af);font-size:11px}
  .player-state::before{width:5px;height:5px;border-radius:50%;background:light-dark(#a0a5af,#686e78);content:""}
  .player.is-playing .player-state::before{background:light-dark(#287451,#81c7a1)}
  .player-help{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
  .player-times{display:flex;justify-content:space-between;margin:0 2px 2px;color:light-dark(#686e78,#a0a5af);font-size:11px;font-variant-numeric:tabular-nums}
  .range{position:relative;display:grid;align-items:center;height:22px}
  .range-rail{position:absolute;left:7px;right:7px;height:4px;border-radius:999px;background:light-dark(#e3e5e8,#34373c);overflow:hidden;pointer-events:none}
  .range-buffer,.range-fill{position:absolute;left:0;top:0;bottom:0;width:0}
  .range-buffer{background:light-dark(#ced9ee,#465774)}
  .range-fill{background:light-dark(#4269b4,#9dbbfa)}
  .range input{position:relative;z-index:1;width:100%;height:22px;margin:0;background:transparent;cursor:pointer;appearance:none}
  .range input::-webkit-slider-runnable-track{height:4px;background:transparent}
  .range input::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;margin-top:-5px;border:0;border-radius:50%;background:light-dark(#343b48,#e9eaed);box-shadow:0 1px 3px #0005}
  .range input::-moz-range-track{height:4px;background:transparent;border:0}
  .range input::-moz-range-thumb{width:14px;height:14px;border:0;border-radius:50%;background:light-dark(#343b48,#e9eaed)}
  .range input:focus-visible{outline:2px solid light-dark(#5d7cba,#94b5f5);outline-offset:2px;border-radius:4px}
  .range input:focus-visible::-webkit-slider-thumb{box-shadow:0 0 0 3px light-dark(#5d7cba,#94b5f5)}
  .range input:disabled{cursor:default;opacity:.45}
  .player-controls{display:flex;align-items:center;justify-content:center;gap:20px;margin:16px 0 20px}
  .player button{appearance:none;padding:0;border:0;background:transparent;color:inherit;font:inherit;cursor:pointer}
  .player button:disabled{opacity:.35;cursor:default}
  .player button:focus-visible{outline:2px solid light-dark(#5d7cba,#94b5f5);outline-offset:3px}
  .player .player-skip{display:grid;place-items:center;width:40px;height:40px;border-radius:8px;color:light-dark(#686e78,#a0a5af)}
  .player-skip svg{width:26px;height:26px}
  .player-skip text{fill:currentColor;stroke:none;font:600 8px "Segoe UI",sans-serif}
  .player .player-skip:hover:not(:disabled){background:light-dark(#f8f9fa,#202326);color:inherit}
  .player .player-play{display:flex;align-items:center;justify-content:center;gap:8px;width:112px;height:46px;border-radius:8px;background:light-dark(#343b48,#e1e5ec);color:light-dark(#fff,#202630);font-size:13px;font-weight:600;box-shadow:0 3px 8px light-dark(#20263014,#0003);transition:background 160ms ease,transform 160ms ease}
  .player .player-play:hover{background:light-dark(#202630,#fff)}
  .player .player-play:active{transform:scale(.96)}
  .player-play svg{width:20px;height:20px;flex:none}
  .player-tools{display:flex;align-items:center;gap:8px;padding-top:12px;border-top:1px solid light-dark(#e3e5e8,#34373c)}
  .player .player-mute{display:grid;place-items:center;width:32px;height:32px;flex:none;border-radius:6px;color:light-dark(#686e78,#a0a5af)}
  .player .player-mute:hover{background:light-dark(#f8f9fa,#202326);color:inherit}
  .player-mute svg{width:18px;height:18px}
  .player-volume{flex:1;max-width:112px}
  .player-volume .range-rail{left:6px;right:6px;height:3px}
  .player-volume .range-fill{background:light-dark(#343b48,#e1e5ec)}
  .player-volume input::-webkit-slider-thumb{width:12px;height:12px;margin-top:-4.5px}
  .player-volume input::-moz-range-thumb{width:12px;height:12px}
  .player .player-rate{display:inline-flex;align-items:center;justify-content:center;min-width:48px;height:32px;margin-left:auto;padding:0 8px;border:1px solid light-dark(#e3e5e8,#34373c);border-radius:6px;font-size:11px;font-weight:600;font-variant-numeric:tabular-nums}
  .player .player-rate:hover{background:light-dark(#f8f9fa,#202326)}
  @media (max-width:380px){body[data-kind="audio"]{padding:12px}.player{padding:16px}.player-art{padding-left:14px;padding-right:14px}}
  @media (max-height:480px){body[data-kind="audio"]{padding:12px}.player{padding:16px}.player-heading{margin-bottom:8px}.player-name{font-size:16px}.player-art{height:96px;margin:12px 0 10px;padding:12px 18px 24px}.player-state{bottom:8px}.player-controls{margin:6px 0 8px}.player .player-play{width:104px;height:40px}.player-tools{padding-top:8px}}
  @media (prefers-reduced-motion:reduce){.player-wave,.player .player-play{transition:none}.player .player-play:active{transform:none}}
`;

function escapeSandboxText(text) {
  return text.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function sandboxImageBody(url) {
  return `<main id="preview-stage" tabindex="0" aria-label="Image preview. Pinch to zoom; scroll to pan."><div class="image-surface"><img src="${url}" id="preview-media" alt="File preview" draggable="false"></div></main>`;
}

function sandboxAudioName(name) {
  const base = String(name ?? "").split(/[\\/]/).pop()?.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return escapeSandboxText(base || "Audio");
}

function sandboxAudioBody(url, name) {
  const label = sandboxAudioName(name);
  const stroke = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"';
  const bars = Array.from({ length: 56 }, (_, index) => `<rect x="${index * 6 + 1}" y="56" width="4" height="0" rx="2"/>`).join("");
  return `<main class="player" id="player" tabindex="0" aria-label="Audio player">
    <audio id="preview-media" src="${url}" preload="metadata" disableremoteplayback aria-hidden="true" tabindex="-1"></audio>
    <div class="player-heading"><span class="player-eyebrow">AUDIO PREVIEW</span><span class="player-private"><svg ${stroke}><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11"/><path d="m9 12 2 2 4-4"/></svg>Read only</span></div>
    <h1 class="player-name" title="${label}">${label}</h1>
    <div class="player-art"><svg class="player-wave" id="player-wave" viewBox="0 0 336 112" preserveAspectRatio="none" aria-hidden="true">${bars}</svg><p class="player-state" id="player-state" role="status" aria-live="polite">Ready to play</p></div>
    <p class="player-help">Space plays and pauses. Arrow keys seek by 5 seconds or change volume. M mutes.</p>
    <div class="player-times"><span id="player-current">0:00</span><span id="player-duration">0:00</span></div>
    <div class="range"><div class="range-rail"><div class="range-buffer" id="player-buffer"></div><div class="range-fill" id="player-fill"></div></div><input id="player-seek" type="range" min="0" max="1000" value="0" step="1" aria-label="Playback position" disabled></div>
    <div class="player-controls">
      <button type="button" class="player-skip" id="player-back" aria-label="Back 10 seconds" title="Back 10 seconds" disabled><svg ${stroke}><path d="M3 10a9 9 0 1 1 1 8M3 4v6h6"/><text x="12" y="16" text-anchor="middle">10</text></svg></button>
      <button type="button" class="player-play" id="player-play" aria-label="Play" aria-pressed="false" aria-keyshortcuts="Space" title="Play (Space)"><svg class="icon-play" id="player-play-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M5 5a2 2 0 0 1 3.008-1.728l11.997 6.998a2 2 0 0 1 .003 3.458l-12 7A2 2 0 0 1 5 19z"/></svg><svg class="icon-pause" id="player-pause-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" hidden><rect x="6" y="4" width="4.2" height="16" rx="1.2"/><rect x="13.8" y="4" width="4.2" height="16" rx="1.2"/></svg><span id="player-play-label">Play</span></button>
      <button type="button" class="player-skip" id="player-forward" aria-label="Forward 10 seconds" title="Forward 10 seconds" disabled><svg ${stroke}><path d="M21 10a9 9 0 1 0-1 8M21 4v6h-6"/><text x="12" y="16" text-anchor="middle">10</text></svg></button>
    </div>
    <div class="player-tools">
      <button type="button" class="player-mute" id="player-mute" aria-label="Mute" aria-pressed="false" aria-keyshortcuts="M" title="Mute (M)"><svg id="player-volume-on" ${stroke}><path d="M11 4.702a.705.705 0 0 0-1.203-.498L6.413 7.587A1.4 1.4 0 0 1 5.416 8H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2.416a1.4 1.4 0 0 1 .997.413l3.383 3.384A.705.705 0 0 0 11 19.298z"/><path d="M16 9a5 5 0 0 1 0 6"/><path d="M19.364 18.364a9 9 0 0 0 0-12.728"/></svg><svg id="player-volume-off" ${stroke} hidden><path d="M11 4.702a.7.7 0 0 0-1.203-.498L6.413 7.587A1.4 1.4 0 0 1 5.416 8H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2.416a1.4 1.4 0 0 1 .997.413l3.383 3.384A.7.7 0 0 0 11 19.298z"/><path d="m16.5 14.5 5-5"/><path d="m16.5 9.5 5 5"/></svg></button>
      <div class="range player-volume"><div class="range-rail"><div class="range-fill" id="player-level"></div></div><input id="player-volume" type="range" min="0" max="100" value="100" step="1" aria-label="Volume"></div>
      <button type="button" class="player-rate" id="player-rate" aria-label="Playback speed 1×" title="Playback speed">1×</button>
    </div>
  </main>`;
}

function sandboxDocument(content, name = "") {
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
    body = content.kind === "image" ? sandboxImageBody(url)
      : content.kind === "audio" ? sandboxAudioBody(url, name)
      : `<video src="${url}" id="preview-media" preload="metadata" controls controlslist="nodownload noremoteplayback" disablepictureinpicture disableremoteplayback></video>`;
  }
  const theme = document.documentElement?.dataset?.theme;
  const themeAttribute = theme === "light" || theme === "dark" ? ` data-theme="${theme}"` : "";
  return `<!doctype html><html${themeAttribute}><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; media-src data:; script-src '${SANDBOX_VIEWER_SCRIPT_HASH}'; style-src '${SANDBOX_STYLE_HASH}'; base-uri 'none'; form-action 'none'"><style>${SANDBOX_STYLE}</style></head><body data-kind="${content.kind}">${body}<script>${SANDBOX_VIEWER_SCRIPT}</script></body></html>`;
}

function createSandboxFrame(content, name) {
  const frame = document.createElement("iframe");
  frame.setAttribute("sandbox", "allow-scripts");
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.setAttribute("allow", "camera 'none'; microphone 'none'; geolocation 'none'; clipboard-write 'none'");
  frame.title = `Read-only preview: ${name}`;
  frame.srcdoc = sandboxDocument(content, name);
  return frame;
}
