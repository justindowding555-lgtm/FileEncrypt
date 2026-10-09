(() => {
  const storageKey = "fileencrypt.theme";
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const validTheme = (value) => value === "light" || value === "dark";
  let preference = null;
  let nativeTheme = null;

  try {
    const saved = window.localStorage.getItem(storageKey);
    if (validTheme(saved)) preference = saved;
  } catch {
    // The toggle still works if storage is unavailable.
  }

  function syncWindowTheme(theme) {
    const currentWindow = window.__TAURI__?.window?.getCurrentWindow?.();
    if (!currentWindow || nativeTheme === theme) return;
    nativeTheme = theme;
    currentWindow.setTheme(theme).catch((error) => {
      nativeTheme = null;
      console.warn("Could not update the native window theme.", error);
    });
  }

  function applyTheme() {
    const theme = preference || (systemTheme.matches ? "dark" : "light");
    document.documentElement.dataset.theme = theme;
    syncWindowTheme(theme);
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    const next = theme === "dark" ? "light" : "dark";
    button.setAttribute("aria-label", `Switch to ${next} mode`);
    button.title = `Switch to ${next} mode`;
    document.getElementById("theme-toggle-label").textContent = next === "dark" ? "Dark mode" : "Light mode";
  }

  // Apply the saved preference before the stylesheet loads to avoid a flash.
  applyTheme();

  function initToggle() {
    document.getElementById("theme-toggle")?.addEventListener("click", () => {
      preference = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      applyTheme();
      try {
        window.localStorage.setItem(storageKey, preference);
      } catch {
        // Keep the selected theme for this window even if it cannot be saved.
      }
    });
    applyTheme();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initToggle);
  else initToggle();

  systemTheme.addEventListener("change", () => {
    if (!preference) applyTheme();
  });
  window.addEventListener("storage", (event) => {
    if (event.key !== storageKey && event.key !== null) return;
    preference = validTheme(event.newValue) ? event.newValue : null;
    applyTheme();
  });
})();
