# Packaged-app recovery smoke test

Run this on the Windows installer built from the release configuration. Use disposable data only. Do not start the development server.

1. Install the NSIS package and launch FileEncrypt from the installed shortcut. Confirm the window opens and **Check for updates** is enabled in a signed release build.
2. Create a new protected key file with a passphrase. Back it up to a different folder using **Back up key**, then use **Check backup** to open the copy.
3. Make a folder with `north/same.txt`, `south/same.txt`, an empty file, and a file larger than 64 KiB. Add the folder, enable **Bundle encrypted files into one ZIP** and compression, and encrypt. Keep the originals for this pass.
4. Add the ZIP, run **Verify**, then decrypt to an empty restore folder. Compare every restored file byte for byte with its original and check that both `same.txt` files appear under their original relative paths.
5. Close FileEncrypt. Move the primary key file out of the way, reopen the app, and load the backup key with its passphrase. Verify and decrypt the ZIP again to a second empty folder. Confirm the bytes match.
6. Select the ZIP and rotate it to a new key file. Confirm the old ZIP still verifies with the old key; the new ZIP verifies with the new key and fails with the old key. Decrypt the new ZIP to a third empty folder and compare contents.
7. Repeat one encryption with **Delete originals after success** using disposable copies. Confirm the encrypted result verifies before treating the originals as disposable. Cancel a larger job and check that no partial output is published for the interrupted file.
8. If testing an updater release, publish a newer signed release with `latest.json`, then use **Check for updates** and **Install update**. Verify the installed version after restart.

The automated Rust tests cover key-file recovery, old file formats, nested bundle paths, compression, rotation, tampering, and interrupted writes. This checklist covers the installed window, dialogs, persistence across launch, and installer/updater behavior that the unit tests cannot exercise.
