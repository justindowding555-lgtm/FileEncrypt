import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function verifyUpdate(installer, signature, publicKey, version, manifest) {
  const publicLines = Buffer.from(publicKey.trim(), "base64").toString("utf8").trim().split(/\r?\n/);
  const publicBytes = Buffer.from(publicLines[1], "base64");
  assert.equal(publicBytes.length, 42, "Invalid updater public key");
  const lines = Buffer.from(signature.trim(), "base64").toString("utf8").trim().split(/\r?\n/);
  assert.equal(lines.length, 4, "Invalid updater signature format");
  const signatureBytes = Buffer.from(lines[1], "base64");
  assert.equal(signatureBytes.length, 74, "Invalid updater signature length");
  assert.equal(signatureBytes.subarray(0, 2).toString("ascii"), "ED", "Expected a prehashed Minisign signature");
  assert.ok(publicBytes.subarray(2, 10).equals(signatureBytes.subarray(2, 10)), "Signature was made with a different signing key");
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicBytes.subarray(10)]),
    format: "der", type: "spki",
  });
  const artifactSignature = signatureBytes.subarray(10);
  assert.ok(verify(null, createHash("blake2b512").update(installer).digest(), key, artifactSignature), "Installer signature verification failed");
  assert.ok(lines[2].startsWith("trusted comment: "), "Signature has no trusted comment");
  const comment = lines[2].slice("trusted comment: ".length);
  assert.ok(verify(null, Buffer.concat([artifactSignature, Buffer.from(comment)]), key, Buffer.from(lines[3], "base64")), "Signed metadata verification failed");
  assert.ok(comment.split("\t").includes(`version:${version}`), "Signed version does not match the release version");
  if (manifest) {
    assert.equal(manifest.version, version, "Manifest version mismatch");
    assert.equal(manifest.platforms["windows-x86_64"].signature, signature.trim(), "Manifest signature mismatch");
  }
  return createHash("sha256").update(installer).digest("hex");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  assert.ok(process.argv[2], "Usage: node scripts/verify-update.mjs <installer-path> [manifest-path] [owner/repository]");
  const config = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url)));
  const release = JSON.parse(readFileSync(new URL("../src-tauri/tauri.release.conf.json", import.meta.url)));
  const installerPath = resolve(process.argv[2]);
  const manifest = process.argv[3] ? JSON.parse(readFileSync(resolve(process.argv[3]))) : undefined;
  if (manifest) {
    const repository = process.argv[4] ?? "justindowding555-lgtm/FileEncrypt";
    const expectedUrl = `https://github.com/${repository}/releases/download/v${config.version}/${encodeURIComponent(basename(installerPath))}`;
    assert.equal(manifest.platforms["windows-x86_64"].url, expectedUrl, "Manifest installer URL mismatch");
  }
  const hash = verifyUpdate(readFileSync(installerPath), readFileSync(installerPath + ".sig", "utf8"), release.plugins.updater.pubkey, config.version, manifest);
  console.log(`Verified installer signature and signed version ${config.version}. SHA-256: ${hash}`);
}
