# FileEncrypt

Desktop app that encrypts files with AEGIS-256. You choose the files in the window, and the 256-bit key is stored in a file the window can create or overwrite.

## Run

Install dependencies once, then start the desktop window:

```
npm install
npm run tauri dev
```

Windows needs the WebView2 runtime, which is already present on Windows 11.

The app icon is drawn in `src/icon.svg` and used in the window header. Desktop PNG, ICO, and ICNS sizes in `src-tauri/icons/` are generated from that source with `npm run tauri -- icon src/icon.svg -o src-tauri/icons`.

## What the window does

- **Add files…** selects several files. **Add folder** includes files in its subfolders. You can also drop files or folders onto the window. Symbolic links are skipped when expanding folders.
- **Encrypt** writes a random `.fenc` name. The original file name is encrypted inside the file, so it is not visible on disk. **Decrypt** restores that name.
- **Bundle encrypted files into one ZIP** puts selected files into a randomly named `.zip`. Each entry is an encrypted `.fenc` file. New bundles restore the selected files' relative folder paths. **Compress files before encryption** reduces the size of compressible data inside the bundle. Add one of these ZIPs to decrypt or verify it directly. Older FileEncrypt ZIPs remain readable. Other ZIP layouts are not supported. With **Save to** empty, the ZIP is placed beside the first selected file.
- Without ZIP, leave **Save to** empty and each result stays in the same folder as its original. Choose a folder to put every result there. The choice is remembered for the next launch.
- Older files, whose names were visible, still decrypt. A `.fenc` file from the first version restores the name with that suffix removed.
- **Encrypt**, **Decrypt**, and **Verify** start after automatic checks for duplicates, output collisions, key-file conflicts, and existing outputs. Turn on **Review plan before starting** to see the planned output paths and start manually. If a check finds a conflict, the preview shows the problem and blocks the job. Progress shows bytes and the current file, and **Cancel job** stops at a chunk boundary. Already completed files remain.
- **Verify** authenticates encrypted files without creating plaintext copies. For ZIPs, it checks each encrypted entry.
- Originals stay on disk unless **Delete originals after success** is checked. Deletion happens only after the new file is written. This is ordinary filesystem deletion, **not secure erasure**. A ZIP source is removed only after all of its entries decrypt successfully.
- Decrypt uses the original filename, so turn on **Replace an existing output file** when that file is still there.

## Key file

**Generate and save** creates a random key and writes it to the path in the box. If the path is empty, a save dialog asks where to put it. **Set path…** only chooses the location. **Browse and load…** opens an existing key file. **Load** reads the path you typed. To protect a newly saved key file, enter a passphrase under **Key options** first. Enter that passphrase again before opening or checking the protected key file. The passphrase field clears after use.

**Back up key** writes a copy to a new location and checks it byte for byte. **Check backup** opens a chosen key file and confirms that it contains the currently loaded key. Enter the passphrase before either action if the key file is protected. Keep the backup and its passphrase in separate safe locations.

**Rotate selected encrypted files to a new key** asks for a new, unused key-file path, writes a fresh master key there, and re-encrypts the selected `.fenc` files or FileEncrypt ZIPs. Plaintext is streamed in memory during rotation. The old encrypted inputs and old key file remain unless **Delete originals after success** is checked. If any file fails, the old key remains loaded; successful new outputs need the new key file named in the status message. Keep the old key for encrypted files you did not select. The passphrase field, if filled, protects the *new* key file.

The file looks like this:

```
FileEncrypt-Key-v1
<32-byte key in standard base64>
```

A 64-character hex line is also accepted. The app remembers the path, not the key itself, under its config directory so the next launch can load the same file.

Protected key files use `FileEncrypt-Key-v2`, PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt, then AEGIS-256 to seal the same 256-bit master key. Existing v1 key files remain readable. A protected key is not loaded automatically at startup because its passphrase is not saved.

Anyone who can read the key file can decrypt. Losing the file means the encrypted files cannot be opened. Replacing a key file does not re-encrypt older files; they still need the previous key.

Typed keys pass through the window. Prefer **Generate and save** when you do not already have a key.

## Tests

```
cargo test --manifest-path src-tauri/Cargo.toml
```

The ZIP directory parser also has a `cargo-fuzz` target under `fuzz/` and a short Linux CI fuzz run. The seed corpus is generated by `python fuzz/generate_corpus.py`. See [the recovery smoke test](docs/RECOVERY_SMOKE_TEST.md) before a release.

## Signed GitHub updates

The app checks `https://github.com/justindowding555-lgtm/FileEncrypt/releases/latest/download/latest.json` only when **Check for updates** is pressed. An update can be installed only after Tauri verifies its signature. Development and ordinary local builds show updates as unconfigured because they have no trusted public key.

Before the first public update, generate an updater signing key **outside this repository** with `npm run tauri signer generate -- -w <private-key-path>`. Choose a non-empty password when prompted. Back up the private key and its password securely; never commit or upload the private key. The public key is written to `<private-key-path>.pub`. Build a signed Windows installer with:

```powershell
.\scripts\build-release.ps1 -PrivateKeyPath <private-key-path> -PublicKeyPath <private-key-path>.pub
```

The script prompts for the signing key password without putting it in the command line, supplies the public key to the compiled app, enables signed updater artifacts, and builds NSIS. Increment the matching versions in `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json` before building. Then create `latest.json` from the generated installer and `.sig`:

```powershell
.\scripts\create-update-manifest.ps1 -Version 0.2.0 -InstallerPath <path-to-setup.exe>
```

Create a GitHub Release tagged `v0.2.0` and attach the installer, its `.sig`, and `latest.json`. Publish the release after testing the installer and a recovery flow. This Tauri update signature verifies the app artifact; Windows publisher code signing is a separate step.

The generated public key is recorded in `src-tauri/tauri.release.conf.json`. If you generate a different keypair, update that value before building. Alternatively, set repository secrets `TAURI_SIGNING_PRIVATE_KEY` (the private key file's contents) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, then run **Draft signed Windows release** in GitHub Actions. It reads the public key from the release configuration, builds the installer, and creates a draft release with all three assets. Inspect the draft and run the recovery smoke test before publishing it.

## File format

New files use AEGIS-256 with a 256-bit authentication tag. That is the authenticated cipher recommended for machines with AES hardware: a 256-bit key, a 256-bit nonce, and a key-committing tag. The saved key is a master key. HKDF-SHA256 derives a wrap key from it, and that wrap key seals a fresh file key. The file body is split into 64 KiB chunks. The last chunk is marked final, so a truncated or edited file fails decryption instead of returning partial plaintext. Bundle entries use format v4 for relative paths or v5 for relative paths with zlib compression before encryption. The path and the original size of compressed entries are authenticated metadata.

This build uses the pure Rust AEGIS implementation, so it does not need a C compiler. Files created by the first version of this app used AES-256-GCM and still decrypt with the same key. New files hide their names, but approximate sizes remain visible. Legacy files may expose their names.
