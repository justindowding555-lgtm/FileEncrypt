# FileEncrypt

Desktop app that encrypts files with AEGIS-256. You choose the files in the window, and the 256-bit key is stored in a file the window can create or overwrite.

## Run

Install dependencies once, then start the desktop window:

```
npm install
npm run tauri dev
```

Windows needs the WebView2 runtime, which is already present on Windows 11, and the Visual Studio C++ build tools. The Tauri command initializes the installed MSVC compiler when clang-cl is unavailable. This setup is local to the command process.

Building requires Rust 1.98 or newer. Sandbox identifiers use the standard library's buffered integer formatting API introduced in 1.98; Rust 1.99 is supported.

The app icon is drawn in `src/icon.svg` and used in the window header. Desktop PNG, ICO, and ICNS sizes in `src-tauri/icons/` are generated from that source with `npm run tauri -- icon src/icon.svg -o src-tauri/icons`.

## What the window does

- The **Files** selection is remembered between launches and restored when a saved file key is loaded. Protected keys restore it after unlocking. Adding, removing, and clearing files updates the remembered list, including folder paths used for ZIP bundles. Only the selected paths are saved, in `selected-files.json` under the app's config directory; file contents, keys, passphrases, and job plans are not included.
- **Add files…** selects several files. **Add folder** includes files in its subfolders. You can also drop files or folders onto the window. Symbolic links are skipped when expanding folders and rejected as direct file inputs.
- **Encrypt** writes a random `.fenc` name. The original file name is encrypted inside the file, so it is not visible on disk. **Decrypt** restores that name.
- **Bundle encrypted files into one ZIP** puts selected files into a randomly named `.zip`. Each entry is an encrypted `.fenc` file. New bundles restore the selected files' relative folder paths. **Compress files before encryption** reduces the size of compressible data inside the bundle. Add one of these ZIPs to decrypt or verify it directly. New ZIPs authenticate the complete file list as well as each encrypted entry. Older FileEncrypt ZIPs remain readable, but their completeness cannot be authenticated and their sources are retained after restoration or rotation. Other ZIP layouts are not supported. With **Save to** empty, the ZIP is placed beside the first selected file.
- Without ZIP, leave **Save to** empty and each result stays in the same folder as its original. Choose a folder to put every result there. The choice is remembered for the next launch.
- Older files, whose names were visible, still decrypt. A `.fenc` file from the first version restores the name with that suffix removed.
- **Encrypt** and **Decrypt** start after automatic checks for duplicates, output collisions, key-file conflicts, and existing outputs. Turn on **Review plan before starting** to see the planned output paths and start manually. If a check finds a conflict, the preview shows the problem and blocks the job. Progress shows bytes and the current file, and **Cancel job** stops at a chunk boundary. Already completed files remain.
- Encrypted files and FileEncrypt ZIPs are verified automatically when added, including files added through folders or restored between launches. With a key loaded, a circled checkmark appears to the left of each successfully authenticated file. Hover over the icon for verification details or errors. ZIP verification checks every encrypted entry and, for new ZIPs, the authenticated file list. Older ZIPs show an amber checkmark explaining the completeness limitation. Verification creates no plaintext copies and leaves Activity results in place.
- Originals stay on disk unless **Delete originals after success** is checked. On Windows, checking it requests deletion after the saved outputs are flushed and kept protected through cleanup. A source ZIP is removed only after its authenticated file list and every entry pass restoration, with all restored files protected throughout cleanup. Deletion bypasses the Recycle Bin. This is ordinary filesystem deletion, **not secure erasure**.
- Results report copy success separately from originals **removed**, **retained**, or **deletion pending**. **Original removed** confirms removal; **Original retained** means cleanup did not remove it; **Deletion pending** means Windows accepted deletion but completion is unconfirmed. Pending deletions are checked automatically in the background while their results remain displayed; no confirmation button is needed. Checks pause during other actions and stop once all pending receipts are resolved. Closing open readers lets Windows finish. These checks only confirm an already accepted deletion, so they do not require saved outputs to remain unchanged or need a loaded key.
- Windows briefly retries sharing conflicts. For a retained original, **Retry deletion** makes the app check the original and every saved output by file identity, size, and SHA256 before trying removal again, without repeating encryption or needing a loaded key. A changed or replaced file blocks a new deletion request.
- Retry receipts last until new results replace the current report or the app closes. A failed job that leaves the old results displayed preserves their receipts. Confirmed automatic checks are cached for that report so a delayed or lost response can recover the result. Each report supports up to 10,000 receipts; reaching the limit is explained in the result. Close programs holding retained files, or resolve read-only attributes/permissions, before retrying.
- Files with additional Windows data streams, including NTFS alternate data streams, retain their originals with an explanation. The encrypted format preserves only the main file contents. If stream enumeration cannot establish that deletion is safe, the original is also retained. This applies to encryption, decryption, ZIP creation/restoration, rotation, and explicit retries.
- Automatic original deletion is enabled only on Windows, where sharing protection prevents concurrent writes to the main file contents and replacement. Other platforms retain originals, because metadata checks cannot close the race between a final check and unlinking. Failed temporary plaintext cleanup reports its exact path. Existing outputs are replaced atomically without creating overwrite backup files.
- Deletion-enabled jobs also read the source and saved outputs to create bounded-memory retry receipts. A bundle's saved-output receipt is reused across its source files. Cancellation is checked during these reads and immediately before each original removal; completed copies remain available.
- Decrypt uses the original filename, so turn on **Replace an existing output file** when that file is still there.

## Read-only sandbox

Select encrypted `.fenc` files or FileEncrypt ZIPs, load their saved key file, and click **View in sandbox** as an alternative to **Decrypt files**. Choose a file in the viewer to authenticate and preview it in memory. The app does not create decrypted files, extract ZIP contents, delete originals, or launch another application for this operation. Save-to and deletion options do not apply to viewing.

The sandbox requires the loaded key's actual file to stay readable. Both the backend and viewer check access every 500 milliseconds while open. Every check reopens the key path and hashes all of its bytes against the snapshot validated when the key was loaded. Removal, access denial, changed bytes, unloading, or switching keys revokes the session. When the key disconnects, the sandbox hides and discards decrypted names and contents. If a key check stalls or IPC fails, the viewer locks after its 1.5-second check deadline. Reconnecting and loading the same key automatically reopens the sandbox in a fresh session and authenticates the previous preview again. Recovery remembers only encrypted source paths, a fingerprint, and an item index. Explicitly unloading the key or loading a different key cancels recovery. Session-only typed keys cannot enable the sandbox. The emergency password is independent of the file key. Normal saved keys reconnect automatically without a password. Emergency mode keeps them locked until the emergency password is verified.

Supported previews are UTF-8 text (up to 2 MiB), PNG/JPEG/GIF/WebP/BMP/ICO images, common audio, and MP4/WebM/Ogg video (up to 32 MiB per file, with codec support supplied by the system webview). PDF, Office documents, and other unsupported types stay encrypted and show an explanation. HTML, SVG, and source files display as escaped plain text. A ZIP's authenticated manifest and file names are checked before listing; the selected file's entire contents are authenticated before display. Older ZIPs retain their existing completeness warning. Compressed previews have the same memory limits. Lists are paged and allow up to 10,000 files including ZIP entries.

Image previews start fitted to the window. Use the zoom buttons, the zoom selector, or a two-finger trackpad pinch over the image to zoom in and out. Normal two-finger scrolling pans an enlarged image. The selector offers 25%–400% of the natural image size, and **Fit to window** resets the view. Pinch supports intermediate zoom levels. Previous/next buttons browse images from the sandbox in the same window; left/right arrows also navigate while fitted, while arrows pan a zoomed image. **+**, **-**, and **0** zoom in, zoom out, and fit; **Escape** closes any preview, including when its content has focus. Zooming stays inside the isolated preview and does not decrypt the file again.

Images are checked before reaching the webview and are limited to 40 megapixels and 16,384 pixels per side. Up to eight preview windows can be open. A shared 512 MiB accounting budget estimates encoded data copies and decoded image surfaces; it is released when a preview closes, fails, or navigates. This budget does not measure or guarantee the webview process's actual memory use, including animated-image caches. Closed or navigated previews cancel queued reads and stop active decryption at the next chunk boundary. Damaged images, unsupported media codecs, and decode timeouts show an explanation with retry and image navigation controls.

Previews use an opaque-origin iframe with network requests, forms, popups, downloads, and same-origin access blocked. Its CSP permits only the exact hash of FileEncrypt's fixed viewer script, which handles image gestures, decoder errors, and keyboard events; file-supplied scripts remain blocked and HTML/SVG/source files remain escaped text. Messages are accepted only from the current preview frame. This is an application-level read-only viewer, not an operating-system sandbox or secure-erasure guarantee. It cannot prevent screenshots, manual transcription, a compromised system, OS paging/crash dumps, or residual browser memory. FileEncrypt's owned Rust file-content buffers are zeroized on release; temporary parser allocations and the webview's memory lifetime are managed by their libraries and the browser.

File selections, folder grouping, and chosen options stay in memory during a key disconnection. Files can be added or removed without a loaded key, including while a cancelled operation is winding down after disconnection. Before a key is loaded, each file shows a blue key icon. Disconnected files show yellow Lucide circled minus icons until the key returns. Selected paths are remembered between launches; sandbox recovery stays in memory only. Clearing the list is respected. Automatic recovery resumes read-only viewing with the same key after fresh authentication. Interrupted encryption, decryption, rotation, and deletion jobs stay stopped. Key changes invalidate job plans, including delayed previews that finish after a disconnect. Click the file action again to run fresh checks before starting another job.

## Key file

Emergency controls are under **Key options → Emergency controls**. On Windows the shortcuts work while FileEncrypt is running, including when a preview or another app has focus:

- **Ctrl+Shift+F12** locks key access, unloads the stored key, cancels active work, and closes previews. The app shows **Unable to read the saved key**. Reconnecting the drive or restarting the app does not clear this lock. **Browse and load** still opens the picker, but selecting a key returns the same read error without reading it or changing the remembered key path. Selected encrypted paths remain available; sandbox recovery is cancelled.
- **Ctrl+Shift+F11** checks the saved key and unlocks only after that check succeeds. Enter the emergency password in the discreet **Key reference** field in Key options and press the shortcut again. This check is required even when the key file is unprotected. Failed checks leave the persistent lock in place. Emergency unlock and access setup serialize credential checks and apply a one-minute cooldown after five failures in the running process; this does not prevent offline guessing of stolen key files.
- **Ctrl+Alt+Shift+D**, held while reconnecting, deletes the key file only after **Enable emergency key deletion for this session** is checked and **Arm key deletion** is pressed. The configured path is shown before arming. Deletion requires an observed removal followed by reconnection, and matching file identity, USB volume, and contents. Hold the shortcut until the reconnection is detected. The first reconnection disarms the action even when the shortcut is not held; changing or unloading keys and closing the app also disarm it. Arming is never saved between launches. A sharing/access error alone does not count as drive removal.

Emergency deletion targets only that armed key file and also locks access. It does not delete backups or encrypted files, and is not secure erasure. Without another copy of the key, encrypted files may become permanently inaccessible. Emergency locking is an application control, not protection against someone modifying the app or its local configuration. Keyboard monitoring reads only the shortcut keys' current held states; it does not record typed input. Other platforms support lock/unlock shortcuts in the focused main window; held deletion is Windows only.

**Generate and save** creates a random key and writes it to the path in the box. If the path is empty, a save dialog asks where to put it. **Set path…** only chooses the location. **Browse and load…** opens an existing key file. **Load** reads the path you typed. The **Key reference** field is for emergency access only; generating, loading, backing up, and rotating keys do not use it. The field clears after emergency use.

The first launch requires one **Password** and **Confirm password** (at least 12 characters), followed by **Continue**. This password is only for leaving emergency mode. Save the recovery code separately, check the acknowledgement, and choose **Finish setup**. Normal key loading and reconnection stay automatic. Setup preserves an existing master key or creates a normal key file on a fresh installation. Existing and development profiles complete this setup once.

Emergency credentials are stored in `emergency-access.verifier` in the app configuration directory, separate from the file key. It contains a random salt, PBKDF2-HMAC-SHA256 settings (600,000 iterations), and separate HMAC-SHA256 verifiers for the derived password key and random 256-bit recovery secret. Comparisons use HMAC's constant-time verification. The raw password and recovery code are never saved. `access-setup.complete` contains no credentials; a valid verifier file determines whether setup is complete.

Profiles from the earlier implementation, which incorrectly protected the file key with the emergency password, are prompted to enter that same password once. Setup restores the original key-file format while preserving the exact master key, so old encrypted files keep working and automatic loading returns. Before replacing a protected file, migration writes and verifies an exact backup beside it, at the path shown during setup. If backup fails, the original is left unchanged. It does not create a second password. The earlier recovery code can also migrate that protected key if its password was forgotten; save the replacement emergency recovery code afterwards. A migration during emergency recovery does not clear the lock or activate the key.

To change the emergency password, open **Key options ? Emergency controls ? Access settings**, enter the current reference above, and enter the new reference twice. **Update access** prepares a replacement verifier without changing the key file. Save the replacement recovery code before choosing **Save access**. Setup expires after ten minutes; closing Key options cancels unfinished changes.

If you forget the password, open **Access settings ? Use recovery code**, enter the saved code, choose one new emergency password, repeat it in **Confirm new password**, then choose **Set new emergency password**. Save the replacement code and apply it. Recovery updates only emergency access; emergency mode stays locked until you enter the new reference and use the unlock shortcut. Old credentials stop working for the updated verifier. Recovery of emergency access does not replace or recover a lost encryption key file.

**Back up key** captures the validated key-file bytes, writes those same bytes to a new location, then reopens the copy to check its contents and key against the loaded key. **Check backup** opens a chosen key file and confirms that it contains the currently loaded key. Keep the backup and its passphrase in separate safe locations.

**Rotate selected encrypted files to a new key** asks for a new, unused key-file path, writes a fresh master key there, and re-encrypts the selected `.fenc` files or FileEncrypt ZIPs. Plaintext is streamed in memory during rotation. The old encrypted inputs remain unless **Delete originals after success** is checked and cleanup succeeds. The old key file always remains on disk. If any file fails, the old key remains loaded; successful new outputs need the new key file named in the status message. Keep the old key for encrypted files you did not select. The emergency reference is not used to protect the new key file.

The file looks like this:

```
FileEncrypt-Key-v1
<32-byte key in standard base64>
```

A 64-character hex line is also accepted. The app remembers the path, not the key itself, under its config directory so the next launch can load the same file.

FileEncrypt checks the loaded key file every second. If it is removed or becomes unreadable, the app unloads the key from memory, cancels any active file job, and shows **Key disconnected**. The dialog shows the saved path, with a single **Back to files** button to dismiss the popup. Choose a different key from the main window. Picker and loading errors appear in the main window. FileEncrypt also watches a saved key that was missing at startup. When the same file returns, the popup closes automatically and an unprotected key reloads. A hidden sandbox reopens with the same key. The emergency password is not requested during normal reconnection. A changed or damaged file keeps its specific error and requires a manual load. Explicitly unloaded keys and session-only typed keys do not reload automatically.

Protected key files use `FileEncrypt-Key-v2`, PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt, then AEGIS-256 to seal the same 256-bit master key. Existing v1 key files remain readable. Legacy protected key files still require their file credential unless migrated by emergency setup; new emergency setup does not protect the file key.

Legacy `FileEncrypt-Key-v3` files remain readable for migration and existing backups. Pending migration holds only authenticated ciphertext of the key, unlocked with the newly displayed recovery code at commit. Rust-owned secret buffers are zeroized when released; the webview's transient memory is browser-managed.

Emergency mode is an application lock. Its password verifier does not encrypt the normally readable key file, so it does not protect that key from someone reading the disk outside the app. Appropriate OS security and full-disk encryption are needed for protection against device theft. Replacing an older protected key file is not secure erasure of historical disk blocks, backups, or OS memory.

Anyone who can read the key file can decrypt. Losing the file means the encrypted files cannot be opened. Replacing a key file does not re-encrypt older files; they still need the previous key.

Typed keys pass through the window. Prefer **Generate and save** when you do not already have a key.

Under **Key options → Use a specific key**, **Use in app only** loads a manually entered key for the current session without writing a key file. The input is cleared after use, and the key is kept in a zeroizing memory buffer that is cleared when the main window closes or the app exits. The previous remembered key-file path is cleared, so reopening starts without a key. The saved output-folder preference is retained. **Write key to file** remains available if you want a saved copy instead. Session keys support encryption, decryption, verification, and rotation; **Back up key** requires a saved key file.

## Tests

Run `npm run lint` from the repository root to execute `cargo clippy --all-targets --all-features -- -D warnings` in `src-tauri/`. On Windows, it initializes the compiler environment through the same helper used for development.

Run frontend unit tests with `npm test`. Run Rust unit tests on Windows with the compiler environment helper:

```powershell
.\scripts\with-msvc.ps1 cargo test --manifest-path src-tauri/Cargo.toml --lib --locked
```

On other platforms, use `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked` with the platform's C compiler and Tauri prerequisites installed. Development checking uses `cargo check` or `cargo clippy` through the same Windows helper. The helper respects an explicitly configured `CC`.

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

New files use AEGIS-256 with a 256-bit authentication tag. That is the authenticated cipher recommended for machines with AES hardware: a 256-bit key, a 256-bit nonce, and a key-committing tag. The saved key is a master key. HKDF-SHA256 derives a wrap key from it, and that wrap key seals a fresh file key. The file body is split into 64 KiB chunks. The last chunk is marked final, so a truncated or edited file fails decryption instead of returning partial plaintext. New bundle entries use format v6 for relative paths or v7 for relative paths with zlib compression before encryption. The encrypted metadata contains the path, bundle identity, expected entry count, and the original size of compressed entries. An HMAC-SHA256 manifest in the ZIP comment authenticates the bundle identity, entry count, and a SHA256 digest of the ordered ciphertext entry names, sizes, and CRCs. Removing the manifest or moving entries into a different bundle fails verification. Older v4/v5 bundles remain readable with per-entry authentication.

This build uses the native AEGIS backend, which selects AES hardware at runtime and has a software fallback. It requires a C compiler when building the app. Cipher compatibility is unchanged for existing files. ZIP creation, verification, restoration, and rotation stream entries directly, without staging ciphertext copies. Lists show 100 rows per page so large selections, previews, and result sets keep bounded DOM work. Files created by the first version of this app used AES-256-GCM and still decrypt with the same key. New files hide their names, but approximate sizes remain visible. Legacy files may expose their names.
