// Only this application-authored script runs in the opaque preview frame.
// scripts/build-csp.mjs hashes it for Tauri and the preview CSP.
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
  function formatClock(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return "0:00";
    const whole = Math.floor(seconds);
    const hours = Math.floor(whole / 3600);
    const minutes = Math.floor((whole % 3600) / 60);
    const secs = String(whole % 60).padStart(2, "0");
    return hours ? hours + ":" + String(minutes).padStart(2, "0") + ":" + secs : minutes + ":" + secs;
  }
  function bindAudioVisualizer() {
    const wave = document.getElementById("player-wave");
    const bars = Array.from(wave?.children || []);
    const motion = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    const levels = new Float32Array(bars.length);
    let context = null, analyser = null, source = null, bins = null, bands = [];
    let frame = null, unavailable = false, disposed = false, active = false;
    const canAnimate = () => active && !disposed && !motion?.matches && !document.hidden && !media.paused && !media.ended && !media.muted && media.volume > 0 && media.readyState >= 2 && !media.seeking && !failed;
    function rest() {
      bars.forEach((bar) => {
        bar.setAttribute("height", "0");
        bar.setAttribute("y", "56");
      });
      levels.fill(0);
      bins?.fill(0);
    }
    function stop() {
      active = false;
      if (frame !== null) window.cancelAnimationFrame(frame);
      frame = null;
      rest();
    }
    function draw() {
      frame = null;
      if (!canAnimate() || context.state !== "running") { stop(); return; }
      analyser.getByteFrequencyData(bins);
      bars.forEach((bar, index) => {
        // Give each stationary bar a distinct band, from bass to treble.
        // Smooth vertical movement without shifting or reflecting the bars.
        const band = bands[index];
        let peak = 0;
        for (let bin = band.start; bin < band.end; bin++) peak = Math.max(peak, bins[bin]);
        const target = Math.pow(peak / 255, 1.4) * 104;
        levels[index] += (target - levels[index]) * (target > levels[index] ? 0.45 : 0.18);
        if (levels[index] < 0.2) levels[index] = 0;
        const height = levels[index];
        bar.setAttribute("height", height.toFixed(2));
        bar.setAttribute("y", (56 - height / 2).toFixed(2));
      });
      frame = window.requestAnimationFrame(draw);
    }
    function start() {
      active = true;
      if (!bars.length || !canAnimate() || unavailable || frame !== null) return;
      if (!context) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) { unavailable = true; return; }
        try {
          // Created on Play, inside the user gesture. Keep playback connected
          // directly to the output; the analyser is a separate read-only branch.
          context = new AudioContext();
          analyser = context.createAnalyser();
          analyser.fftSize = 4096;
          analyser.minDecibels = -85;
          analyser.maxDecibels = -20;
          analyser.smoothingTimeConstant = 0.5;
          bins = new Uint8Array(analyser.frequencyBinCount);
          const count = bars.length;
          const last = Math.min(bins.length, Math.ceil(Math.min(16000, context.sampleRate / 2) * analyser.fftSize / context.sampleRate));
          const first = Math.min(last - count, Math.max(1, Math.floor(40 * analyser.fftSize / context.sampleRate)));
          let cursor = first;
          bands = Array.from({ length: count }, (_, index) => {
            const end = Math.min(last - (count - index - 1), Math.max(cursor + 1, Math.ceil(first * (last / first) ** ((index + 1) / count))));
            const band = { start: cursor, end };
            cursor = end;
            return band;
          });
          source = context.createMediaElementSource(media);
          source.connect(context.destination);
          source.connect(analyser);
        } catch {
          unavailable = true;
          if (!source && context) { void context.close().catch(() => {}); context = null; }
          return;
        }
      }
      if (context.state === "running") frame = window.requestAnimationFrame(draw);
      else void context.resume().then(() => {
        if (canAnimate() && frame === null) frame = window.requestAnimationFrame(draw);
      }).catch(() => { media.pause(); stop(); });
    }
    function refresh() {
      const wasActive = active;
      stop();
      if (wasActive) start();
    }
    motion?.addEventListener("change", refresh);
    document.addEventListener("visibilitychange", refresh);
    media.addEventListener("error", stop);
    window.addEventListener("pagehide", () => {
      disposed = true;
      stop();
      media.pause();
      source?.disconnect();
      analyser?.disconnect();
      if (context) void context.close().catch(() => {});
      bins?.fill(0);
    });
    return { start, stop };
  }
  function bindAudioPlayer() {
    const player = document.getElementById("player");
    const current = document.getElementById("player-current");
    const durationLabel = document.getElementById("player-duration");
    const buffer = document.getElementById("player-buffer");
    const fill = document.getElementById("player-fill");
    const seek = document.getElementById("player-seek");
    const playButton = document.getElementById("player-play");
    const playIcon = document.getElementById("player-play-icon");
    const pauseIcon = document.getElementById("player-pause-icon");
    const playLabel = document.getElementById("player-play-label");
    const back = document.getElementById("player-back");
    const forward = document.getElementById("player-forward");
    const mute = document.getElementById("player-mute");
    const volumeOn = document.getElementById("player-volume-on");
    const volumeOff = document.getElementById("player-volume-off");
    const volume = document.getElementById("player-volume");
    const level = document.getElementById("player-level");
    const rate = document.getElementById("player-rate");
    const status = document.getElementById("player-state");
    if (!player || !seek || !playButton || !volume) return;
    const visualizer = bindAudioVisualizer();
    const rates = [1, 1.25, 1.5, 2, 0.75];
    let scrubbing = false, remembered = 1, waiting = false, started = false, playbackError = false, playbackRequest = 0;
    const span = () => Number.isFinite(media.duration) && media.duration > 0 ? media.duration : 0;
    const bufferedRatio = () => {
      if (!span() || !media.buffered || !media.buffered.length) return 0;
      let end = 0;
      for (let index = 0; index < media.buffered.length; index++) end = Math.max(end, media.buffered.end(index));
      return Math.min(1, end / span());
    };
    function syncPlayback() {
      const active = media.paused === false && !media.ended;
      const playing = active && !waiting && !media.seeking && media.readyState >= 2;
      player.classList.toggle("is-playing", playing);
      playIcon.toggleAttribute("hidden", active);
      pauseIcon.toggleAttribute("hidden", !active);
      const action = active ? "Pause" : media.ended ? "Replay" : "Play";
      playLabel.textContent = action;
      playButton.setAttribute("aria-label", action);
      playButton.setAttribute("title", action + " (Space)");
      playButton.setAttribute("aria-pressed", active ? "true" : "false");
      const message = playbackError ? "Could not start playback. Try again." : media.ended ? "Playback finished" : active ? (!playing ? "Buffering…" : media.muted || !media.volume ? "Muted" : "Playing") : started || media.currentTime > 0 ? "Paused" : "Ready to play";
      if (status && status.textContent !== message) status.textContent = message;
      if (playing && !media.muted && media.volume > 0) visualizer.start();
      else visualizer.stop();
    }
    function syncVolume() {
      const silent = Boolean(media.muted) || !media.volume;
      const shown = silent ? 0 : media.volume;
      if (document.activeElement !== volume) volume.value = String(Math.round(shown * 100));
      level.style.width = (shown * 100) + "%";
      volumeOn.toggleAttribute("hidden", silent);
      volumeOff.toggleAttribute("hidden", !silent);
      mute.setAttribute("aria-label", silent ? "Unmute" : "Mute");
      mute.setAttribute("title", (silent ? "Unmute" : "Mute") + " (M)");
      mute.setAttribute("aria-pressed", silent ? "true" : "false");
      volume.setAttribute("aria-valuetext", Math.round(shown * 100) + "%");
    }
    function paint(time) {
      const shown = Number.isFinite(time) ? time : (media.currentTime || 0);
      const length = span();
      const ratio = length ? Math.min(1, Math.max(0, shown / length)) : 0;
      current.textContent = formatClock(shown);
      durationLabel.textContent = length ? formatClock(length) : "0:00";
      fill.style.width = (ratio * 100) + "%";
      buffer.style.width = (bufferedRatio() * 100) + "%";
      if (!scrubbing) seek.value = String(Math.round(ratio * 1000));
      seek.disabled = !length;
      back.disabled = !length || shown <= 0;
      forward.disabled = !length || shown >= length;
      seek.setAttribute("aria-valuetext", formatClock(shown) + (length ? " of " + formatClock(length) : ""));
      const speed = (Number(media.playbackRate) || 1) + "×";
      rate.textContent = speed;
      rate.setAttribute("aria-label", "Playback speed " + speed);
      rate.setAttribute("title", "Playback speed " + speed + ". Click to change.");
      syncPlayback();
      syncVolume();
    }
    function seekTo(ratio) {
      const length = span();
      const time = length ? Math.min(length, Math.max(0, ratio * length)) : 0;
      if (length) media.currentTime = time;
      paint(time);
    }
    function skip(delta) {
      seekTo(span() ? ((media.currentTime || 0) + delta) / span() : 0);
    }
    function setVolume(value) {
      const next = Math.round(Math.min(1, Math.max(0, value)) * 100) / 100;
      if (next > 0) remembered = next;
      media.volume = next;
      media.muted = next === 0;
      syncVolume();
      syncPlayback();
    }
    function toggleMute() {
      if (media.muted || !media.volume) {
        media.muted = false;
        media.volume = remembered || 1;
      } else {
        remembered = media.volume;
        media.muted = true;
      }
      syncVolume();
      syncPlayback();
    }
    function togglePlayback() {
      const request = ++playbackRequest;
      playbackError = false;
      if (!media.paused && !media.ended) { media.pause(); waiting = false; syncPlayback(); return; }
      if (media.ended) media.currentTime = 0;
      started = true;
      waiting = false;
      const pending = media.play();
      syncPlayback();
      if (pending && typeof pending.catch === "function") pending.catch(() => {
        if (request !== playbackRequest) return;
        media.pause();
        playbackError = true;
        paint();
      });
    }
    playButton.addEventListener("click", togglePlayback);
    back.addEventListener("click", () => skip(-10));
    forward.addEventListener("click", () => skip(10));
    mute.addEventListener("click", toggleMute);
    rate.addEventListener("click", () => {
      const currentRate = Number(media.playbackRate) || 1;
      const index = rates.findIndex((item) => Math.abs(item - currentRate) < 0.001);
      const next = rates[(index + 1) % rates.length];
      media.playbackRate = next;
      paint();
    });
    seek.addEventListener("pointerdown", () => { scrubbing = true; });
    seek.addEventListener("input", () => { scrubbing = true; seekTo(Number(seek.value) / 1000); });
    for (const eventName of ["change", "pointerup", "pointercancel", "blur"]) {
      seek.addEventListener(eventName, () => { scrubbing = false; paint(); });
    }
    volume.addEventListener("input", () => setVolume(Number(volume.value) / 100));
    for (const eventName of ["loadedmetadata", "play", "playing", "waiting", "pause", "ended", "seeking", "seeked", "durationchange", "timeupdate", "progress", "volumechange", "ratechange"]) {
      media.addEventListener(eventName, () => {
        if (eventName === "waiting") waiting = true;
        else if (["playing", "pause", "ended"].includes(eventName)) waiting = false;
        if (eventName === "play") started = true;
        if (eventName !== "timeupdate" || !scrubbing) paint();
      });
    }
    player.audioKeys = { skip, setVolume, togglePlayback, toggleMute };
    paint();
  }
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.preventDefault(); send("close"); }
    else if (kind === "image" && !event.altKey) {
      if (!event.ctrlKey && !event.metaKey && fit && (event.key === "ArrowLeft" || event.key === "ArrowRight")) {
        event.preventDefault(); send("navigate", { direction: event.key === "ArrowRight" ? 1 : -1 });
      } else if (event.key === "+" || event.key === "=") { event.preventDefault(); zoom(scale * 1.25); }
      else if (event.key === "-") { event.preventDefault(); zoom(scale * 0.8); }
      else if (event.key === "0") { event.preventDefault(); zoom("fit"); }
    } else if (kind === "audio" && !event.altKey && !event.ctrlKey && !event.metaKey) {
      const field = event.target?.tagName === "INPUT";
      const keys = document.getElementById("player")?.audioKeys;
      if (!keys) return;
      if (event.key === " " && event.target?.tagName !== "BUTTON") { event.preventDefault(); keys.togglePlayback(); }
      else if (!field && event.key === "ArrowLeft") { event.preventDefault(); keys.skip(-5); }
      else if (!field && event.key === "ArrowRight") { event.preventDefault(); keys.skip(5); }
      else if (!field && event.key === "ArrowUp") { event.preventDefault(); keys.setVolume((media.muted ? 0 : media.volume) + 0.05); }
      else if (!field && event.key === "ArrowDown") { event.preventDefault(); keys.setVolume((media.muted ? 0 : media.volume) - 0.05); }
      else if (!field && (event.key === "m" || event.key === "M")) { event.preventDefault(); keys.toggleMute(); }
    }
  }, true);
  if (media) {
    media.addEventListener("error", fail);
    if (kind === "image") {
      media.addEventListener("load", loaded);
      if (media.complete) loaded();
      // WebView2 must have native pinch enabled to deliver trackpad gestures.
      // Cancel its Ctrl+wheel default so only the image, not the page, zooms.
      stage.addEventListener("wheel", (event) => {
        if (!event.ctrlKey) return;
        event.preventDefault();
        if (!ready || failed) return;
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
      if (kind === "audio") bindAudioPlayer();
      media.addEventListener("loadedmetadata", loaded);
      if (media.error) fail();
      else if (media.readyState >= 1) loaded();
    }
  } else loaded();
})();`;
