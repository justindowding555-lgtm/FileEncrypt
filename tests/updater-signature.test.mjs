import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { verifyUpdate } from "../scripts/verify-update.mjs";

function signedArtifact() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const installer = Buffer.from("test installer bytes");
  const id = Buffer.from("01234567");
  const key = publicKey.export({format:"der",type:"spki"}).subarray(-32);
  const encodedKey = Buffer.from(`untrusted comment: minisign public key\n${Buffer.concat([Buffer.from("Ed"),id,key]).toString("base64")}\n`).toString("base64");
  const artifactSignature = sign(null,createHash("blake2b512").update(installer).digest(),privateKey);
  const comment = "timestamp:1\tfile:test.exe\tversion:0.1.1";
  const metadataSignature = sign(null,Buffer.concat([artifactSignature,Buffer.from(comment)]),privateKey);
  const signature = Buffer.from(`untrusted comment: signature from minisign secret key\n${Buffer.concat([Buffer.from("ED"),id,artifactSignature]).toString("base64")}\ntrusted comment: ${comment}\n${metadataSignature.toString("base64")}\n`).toString("base64");
  return {installer,signature,encodedKey};
}

test("update verification accepts matching artifact and authenticated release version", () => {
  const {installer,signature,encodedKey} = signedArtifact();
  const manifest = {version:"0.1.1",platforms:{"windows-x86_64":{signature}}};
  assert.equal(verifyUpdate(installer,signature,encodedKey,"0.1.1",manifest),createHash("sha256").update(installer).digest("hex"));
});

test("update verification rejects tampered installers, keys, and signed metadata", () => {
  const {installer,signature,encodedKey} = signedArtifact();
  assert.throws(()=>verifyUpdate(Buffer.from("changed installer"),signature,encodedKey,"0.1.1"),/Installer signature verification failed/);
  assert.throws(()=>verifyUpdate(installer,signature,signedArtifact().encodedKey,"0.1.1"),/Installer signature verification failed/);
  const changed = Buffer.from(Buffer.from(signature,"base64").toString("utf8").replace("version:0.1.1","version:0.1.2")).toString("base64");
  assert.throws(()=>verifyUpdate(installer,changed,encodedKey,"0.1.2"),/Signed metadata verification failed/);
});

test("update verification rejects manifest versions and signatures that do not match", () => {
  const {installer,signature,encodedKey} = signedArtifact();
  assert.throws(()=>verifyUpdate(installer,signature,encodedKey,"0.1.2"),/Signed version does not match/);
  assert.throws(()=>verifyUpdate(installer,signature,encodedKey,"0.1.1",{version:"0.1.2",platforms:{"windows-x86_64":{signature}}}),/Manifest version mismatch/);
  assert.throws(()=>verifyUpdate(installer,signature,encodedKey,"0.1.1",{version:"0.1.1",platforms:{"windows-x86_64":{signature:"different"}}}),/Manifest signature mismatch/);
});
