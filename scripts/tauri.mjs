import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildSandboxCsp } from "./build-csp.mjs";

// Generate before the CLI reads its configuration (hooks run after that read).
if (["dev", "build", "bundle"].includes(process.argv[2])) buildSandboxCsp();

const cli = fileURLToPath(new URL("../node_modules/@tauri-apps/cli/tauri.js", import.meta.url));
const args = [cli, ...process.argv.slice(2)];
const result = process.platform === "win32"
  ? spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
      fileURLToPath(new URL("with-msvc.ps1", import.meta.url)), process.execPath, ...args], { stdio: "inherit" })
  : spawnSync(process.execPath, args, { stdio: "inherit" });
if (result.error) { console.error(result.error.message); process.exitCode = 1; }
else process.exitCode = result.status ?? 1;
