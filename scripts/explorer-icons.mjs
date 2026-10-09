import { readFile, writeFile } from "node:fs/promises";

// Ship only the Lucide icons used by the explorer. The generated SVG is checked
// in so Tauri's static frontend needs neither a bundler nor a runtime icon loader.
const icons = {
  folder: "folder-closed", file: "file", text: "file-text", image: "image",
  audio: "music-2", video: "film", home: "house", shield: "shield-check",
  lock: "lock-keyhole", search: "search", back: "arrow-left", forward: "arrow-right",
  up: "arrow-up", chevron: "chevron-right", grid: "layout-grid", list: "list",
  expand: "maximize-2", collapse: "minimize-2", close: "x", info: "info", eye: "scan-eye",
  verified: "circle-check", checking: "loader-circle", pending: "circle-dashed", failed: "circle-x",
  disconnected: "circle-minus", unplug: "unplug",
  needsKey: "key-round", unencrypted: "shield",
};
const bodies = await Promise.all(Object.entries(icons).map(async ([id, name]) => {
  const svg = await readFile(new URL(`../node_modules/lucide-static/icons/${name}.svg`, import.meta.url), "utf8");
  const body = svg.match(/<svg\b[^>]*>([\s\S]*?)<\/svg>/)?.[1];
  if (!body) throw new Error(`Invalid Lucide icon: ${name}`);
  return [id, body];
}));
const attributes = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"';
const symbols = bodies.map(([id, body]) => `  <symbol id="${id}" ${attributes}>${body}  </symbol>`);
const inlineIcons = Object.fromEntries(bodies.map(([id, body]) => [id, `<svg ${attributes}>${body}</svg>`]));
await writeFile(new URL("../src/explorer-icons.js", import.meta.url),
  `// Lucide icons. License: explorer-icons.LICENSE.txt\nconst EXPLORER_ICONS = Object.freeze(${JSON.stringify(inlineIcons, null, 2)});\n`);
const license = await readFile(new URL("../node_modules/lucide-static/LICENSE", import.meta.url), "utf8");
await writeFile(new URL("../src/explorer-icons.svg", import.meta.url),
  `<!-- Lucide icons. License: explorer-icons.LICENSE.txt -->\n<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">\n${symbols.join("\n")}\n</svg>\n`);
await writeFile(new URL("../src/explorer-icons.LICENSE.txt", import.meta.url), license);
