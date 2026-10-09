import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cwd = fileURLToPath(new URL("../src-tauri/", import.meta.url));
const args = ["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"];
const result = process.platform === "win32"
  ? spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
      fileURLToPath(new URL("with-msvc.ps1", import.meta.url)), "cargo", ...args], { cwd, stdio: "inherit" })
  : spawnSync("cargo", args, { cwd, stdio: "inherit" });
if (result.error) { console.error(result.error.message); process.exitCode = 1; }
else process.exitCode = result.status ?? 1;
