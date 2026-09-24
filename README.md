# FileEncrypt

Desktop app that encrypts files with AEGIS-256. You choose the files in the window, and the 256-bit key is stored in a file the window can create or overwrite.

## Run

Install dependencies once, then start the desktop window:

```
npm install
npm run tauri dev
```

Windows needs the WebView2 runtime, which is already present on Windows 11.

## What the window does

- **Add files…** selects several files.
- **Encrypt** writes a random `.fenc` name. The original file name is encrypted inside the file, so it is not visible on disk. **Decrypt** restores that name.
- **Group encrypted files into one ZIP** puts all selected files into a single randomly named `.zip`. Each entry is an encrypted `.fenc` file; extract the ZIP before selecting those entries for decryption. With **Save to** empty, the ZIP is placed beside the first selected file.
- Without ZIP, leave **Save to** empty and each result stays in the same folder as its original. Choose a folder to put every result there. The choice is remembered for the next launch.
- Older files, whose names were visible, still decrypt. A `.fenc` file from the first version restores the name with that suffix removed.
- Originals stay on disk unless **Delete original files after success** is checked. Deletion happens only after the new file is written.
- Decrypt uses the original filename, so turn on **Replace an existing output file** when that file is still there.

## Key file

**Generate and save** creates a random key and writes it to the path in the box. If the path is empty, a save dialog asks where to put it. **Set path…** only chooses the location. **Browse and load…** opens an existing key file. **Load** reads the path you typed.

The file looks like this:

```
FileEncrypt-Key-v1
<32-byte key in standard base64>
```

A 64-character hex line is also accepted. The app remembers the path, not the key itself, under its config directory so the next launch can load the same file.

Anyone who can read the key file can decrypt. Losing the file means the encrypted files cannot be opened. Replacing a key file does not re-encrypt older files; they still need the previous key.

Typed keys pass through the window. Prefer **Generate and save** when you do not already have a key.

## Tests

```
cargo test --manifest-path src-tauri/Cargo.toml
```

## File format

New files use AEGIS-256 with a 256-bit authentication tag. That is the authenticated cipher recommended for machines with AES hardware: a 256-bit key, a 256-bit nonce, and a key-committing tag. The saved key is a master key. HKDF-SHA256 derives a wrap key from it, and that wrap key seals a fresh file key. The file body is split into 64 KiB chunks. The last chunk is marked final, so a truncated or edited file fails decryption instead of returning partial plaintext.

This build uses the pure Rust AEGIS implementation, so it does not need a C compiler. Files created by the first version of this app used AES-256-GCM and still decrypt with the same key. File names and approximate sizes are not hidden.
