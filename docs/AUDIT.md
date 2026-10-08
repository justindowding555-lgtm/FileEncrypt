# FileEncrypt project audit

Date: October 7, 2026. Reviewed commit: `a4dc655`, with a clean working tree before the audit. Application source was not changed during the initial audit. Correctness was reviewed first, followed by performance. The findings below describe the reviewed commit; all findings have since been implemented as described in the completion notes.

**Validation and limits**

- `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked --offline`: all 37 existing unit tests passed, in the development/test profile.
- `node --check src/main.js`: passed.
- Four temporary Rust regression probes against the actual source all failed their safety assertions, confirming findings B1 (two cases), B2, and B3 below. The temporary test file was removed; these failures are separate from the passing existing suite.
- A focused Node VM probe with a minimal DOM stub counted 100,000 nodes created by `run(async () => null, false)` with 10,000 selected files. This measures allocation work, not browser frame rate.
- The installed `aegis` 0.9.19 source and current Cargo fingerprint were inspected for backend selection. The build uses `pure-rust`, has no Rust compiler flags, and the default target has no `aes` feature.
- No dev server, application smoke test, production build, installer, release package, fuzz run, or live update was started. Performance opportunities below are based on code paths and operation counts; throughput and end-to-end latency were not benchmarked.

**Bugs, ordered by priority**

1. **B1 — P1: deleting originals can discard content changed during encryption. Confirmed by two regressions.**

   References: [crypto.rs:529](../src-tauri/src/crypto.rs#L529), [crypto.rs:638](../src-tauri/src/crypto.rs#L638), [crypto.rs:241](../src-tauri/src/crypto.rs#L241), [archive.rs:158](../src-tauri/src/archive.rs#L158), [archive.rs:165](../src-tauri/src/archive.rs#L165).

   Ordinary encryption does not check that the source remained unchanged. After publishing the ciphertext, `finish_job` deletes the current file at the original path. Another program can edit or replace that file after its bytes have been read, and the new content is deleted even though it is absent from the ciphertext. A same-length edit injected after the final data read reproduced successful encryption followed by deletion of the modified source.

   Bundled encryption checks only byte count and length at the end of encrypting each entry. The bundle then spends additional time encrypting other entries and packaging the ZIP before deleting all originals. An edit injected at the packaging callback reproduced the same loss, even with a changed length. Same-length edits also evade the per-entry length check.

   Recommendation: treat source stability and deletion as one operation. Hold handles with appropriate sharing restrictions on Windows, track source identity and relevant metadata, and keep originals if any check fails. Revalidate immediately before deletion; length alone cannot detect in-place edits. Apply the same discipline to encrypted inputs during rotation and ZIP restoration.

2. **B2 — P1: bundle membership is unauthenticated, so omitted files can go undetected. Confirmed; deletion consequence follows from execution code.**

   References: [archive_read.rs:61](../src-tauri/src/archive_read.rs#L61), [archive_read.rs:89](../src-tauri/src/archive_read.rs#L89), [archive_read.rs:203](../src-tauri/src/archive_read.rs#L203), [commands.rs:1085](../src-tauri/src/commands.rs#L1085), [commands.rs:1154](../src-tauri/src/commands.rs#L1154).

   The ZIP entry count and directory are trusted without an authenticated bundle manifest. In a generated two-file bundle, changing the directory count to one and shortening its advertised size caused the parser to return only `left.txt`. CRC checking and cryptographic verification of that remaining entry both passed. The other encrypted entry was still physically present in the archive but was ignored. Decryption with deletion enabled considers all enumerated entries successful and then removes the ZIP, including the ignored data.

   Individual entry authentication remains effective; this finding concerns completeness of the bundle. Checking directory boundaries would reject this particular malformed example, but a fully rebuilt ZIP containing a subset of intact entries would still pass per-entry authentication.

   Recommendation: add an authenticated manifest binding bundle identity, entry membership, and expected count, and validate it before successful restoration or rotation. Strengthen directory-layout checks as well. Preserve compatibility with older bundles while making their per-entry-only verification guarantee explicit; do not imply that their completeness has been authenticated.

3. **B3 — P2: valid long filenames encrypt successfully but cannot be restored. Confirmed on Windows.**

   References: [crypto.rs:1284](../src-tauri/src/crypto.rs#L1284), [crypto.rs:1317](../src-tauri/src/crypto.rs#L1317), [crypto.rs:1511](../src-tauri/src/crypto.rs#L1511).

   Temporary output names append `.partial-` plus a 37-character random `.fenc` name to the full destination filename. This adds 46 characters to a filesystem component. A valid 224-character filename encrypted successfully, but decryption failed with Windows error 123 (`InvalidFilename`) when creating its 270-character temporary component. On filesystems with a 255-character component limit, names above 209 characters can fail. Overwrite backups use an even longer suffix. Renaming the ciphertext does not help because its original name is authenticated metadata.

   Recommendation: use a short independent random basename for temporary files and replacement backups in the same destination directory. Add regressions near the component-length limit for restore, overwrite, and key-file writes.

4. **B4 — P2: a backup can contain a different key than the loaded key while reporting success. Code inspection.**

   References: [commands.rs:531](../src-tauri/src/commands.rs#L531), [commands.rs:539](../src-tauri/src/commands.rs#L539), [commands.rs:551](../src-tauri/src/commands.rs#L551), [commands.rs:558](../src-tauri/src/commands.rs#L558).

   `backup_key` opens and validates the source key, waits for the save dialog, then reads the source again for copying. If the source is edited, replaced, or a removable drive reconnects with different contents during that interval, the second read may contain a different key. The final comparison only checks that the destination equals those newly read bytes; it does not establish that the backup contains the loaded key. The user can therefore receive a successful backup message for an unusable recovery key.

   Recommendation: read one bounded snapshot, validate that exact snapshot against the loaded key, and copy those same bytes. Reopen the published backup and validate its key as the final check.

5. **B5 — P2: a later ZIP setup error discards the report for completed files. Code inspection.**

   References: [commands.rs:1085](../src-tauri/src/commands.rs#L1085), [commands.rs:1102](../src-tauri/src/commands.rs#L1102), [main.js:584](../src/main.js#L584).

   ZIP parsing and temporary-directory creation inside the execution loop use `?`, aborting the entire command rather than adding a failed `FileOutcome`. If an earlier input succeeds, and a later ZIP becomes corrupt or unavailable after preflight, the command returns an error and drops all accumulated outcomes. Earlier outputs remain and earlier originals may already have been deleted. The frontend renders results only on a successful command return, leaving the user without the completed-file report and potentially showing stale activity.

   Recommendation: turn per-input setup failures into outcomes and continue according to cancellation policy. Reserve command-level errors for failures before processing starts, or return a structured partial report alongside a fatal error.

**Performance opportunities, ordered by likely impact**

1. **P1 — Replace quadratic bundle duplicate detection.**

   References: [archive.rs:121](../src-tauri/src/archive.rs#L121), [archive.rs:181](../src-tauri/src/archive.rs#L181).

   For each source, the bundle writer compares it with every preceding source, canonicalizing both paths on every comparison. At 10,000 distinct inputs, that is 49,995,000 comparisons and approximately 99,990,000 canonicalization calls, before encryption. These checks also have no cancellation callback. The command planner already uses a set, but the archive implementation repeats the expensive work.

   Canonicalize once per input and insert the normalized path into a `HashSet`. If hard-link identity matters, use filesystem identities rather than treating canonical paths as file identity. Retain archive-level validation for direct callers and check cancellation during long preparation phases.

2. **P1 — Use AES hardware through a portable backend strategy.**

   Reference: [Cargo.toml:25](../src-tauri/Cargo.toml#L25). Evidence: installed `aegis-0.9.19/src/pure_rust/mod.rs`, its README, and current Cargo fingerprints.

   The pure Rust implementation selects AES-NI using compile-time `target_feature = "aes"`; otherwise it selects `aes_soft`. The inspected default Windows build has no AES target feature and no Rust flags, so AES-capable machines still execute software AES. The release script and workflow do not supply an AES feature either. This is a potentially large CPU-throughput improvement for large files, though no speedup was measured in this audit.

   Prefer a backend with runtime hardware dispatch and a supported fallback. If a hardware-only build is intentional, document and enforce its CPU baseline. Do not distribute a `target-cpu=native` binary blindly: it inherits the build machine's instruction requirements. Changing the backend need not change the file format.

3. **P1 — Stream ZIP entries to avoid full ciphertext staging and repeated disk I/O.**

   References: [archive.rs:131](../src-tauri/src/archive.rs#L131), [archive.rs:161](../src-tauri/src/archive.rs#L161), [archive.rs:225](../src-tauri/src/archive.rs#L225), [archive_read.rs:239](../src-tauri/src/archive_read.rs#L239), [commands.rs:1098](../src-tauri/src/commands.rs#L1098).

   Bundle creation writes every encrypted file into `.zip.work`, synchronizes each file, rereads all ciphertext, and writes the final ZIP. It temporarily needs roughly twice the final bundle size beyond the source data. ZIP verification and decryption extract each full encrypted entry into the system temp directory, synchronize it, then reread it to authenticate. Verification therefore requires writable disk space proportional to the largest entry even though it publishes no output. ZIP rotation keeps both extracted old ciphertext and newly rotated ciphertext until packaging finishes.

   Expose bounded reader/writer interfaces for the cryptographic stream. Encrypt directly into a ZIP entry with a counting CRC writer and a data descriptor; authenticate directly from a bounded ZIP entry reader. Keep the final archive or plaintext output behind the existing temporary-publication boundary. Validate CRC and final cryptographic authentication before publishing plaintext, and retain cancellation and cleanup behavior.

4. **P2 — Avoid rebuilding the entire file list for unrelated UI actions.**

   References: [main.js:85](../src/main.js#L85), [main.js:192](../src/main.js#L192), [main.js:261](../src/main.js#L261).

   `run` recreates all rows both when setting busy and when clearing it, even for key loading or checking updates. Each file row creates five elements. The focused DOM-stub probe counted 100,000 elements created for one no-op action with 10,000 selected files. Removing one row rebuilds the entire list again. Selection also uses `files.includes` for each incoming path, making bulk deduplication quadratic.

   Use a set for membership checks, update existing controls when busy changes, and render only changed rows. For the advertised maximum selection size, use pagination or virtualization. Apply the same bounded rendering approach to large preview and result lists. Batching with a fragment helps insertion but does not eliminate the full rebuild cost.

5. **P2 — Throttle rotation progress events.**

   References: [commands.rs:732](../src-tauri/src/commands.rs#L732), [crypto.rs:174](../src-tauri/src/crypto.rs#L174), [commands.rs:1008](../src-tauri/src/commands.rs#L1008).

   Normal jobs throttle event emission to about once every 80 ms. Rotation emits an event for every callback, including callbacks with zero bytes. A 1 GiB stream in 64 KiB reads produces roughly 32,768 callbacks before small header and final checks; ZIP extraction adds another comparable set. Every emitted event serializes the filename and schedules a frontend update.

   Reuse a throttled reporter for rotation, forcing emissions only for stage transitions and completion. Keep cheap cancellation checks on every callback. In the normal reporter, check the timer before cloning the current filename and stage, so callbacks suppressed by throttling avoid those allocations.

6. **P2 — Reuse chunk buffers and encrypt in place.**

   References: [crypto.rs:719](../src-tauri/src/crypto.rs#L719), [crypto.rs:785](../src-tauri/src/crypto.rs#L785), [crypto.rs:1101](../src-tauri/src/crypto.rs#L1101), [crypto.rs:1254](../src-tauri/src/crypto.rs#L1254).

   `read_up_to` allocates and initializes a new vector per chunk. Encryption then copies the plaintext into a second vector in `seal`, and appending the authentication tag can grow that vector again. With 64 KiB chunks, a 1 GiB file processes about 16,384 chunks. Rotation adds allocated channel messages and further copies.

   Keep two reusable buffers for lookahead, reserve tag capacity once, and seal in place. Recycle rotation buffers where practical. Preserve zeroization of plaintext and all failure paths, and measure this after addressing backend selection and redundant disk passes.

**Suggested implementation order**

Fix source preservation and filename restoration first, then bundle completeness, backup consistency, and partial result reporting. For performance, remove the quadratic filesystem work and avoid full UI rerenders, then choose the cipher backend and streaming ZIP approach. Finish with progress throttling and buffer reuse. Each change should retain focused regressions for the behavior it protects; none of the existing passing tests cover the confirmed failures above.


**Implementation completed ? October 7, 2026**

All five bug fixes and all six performance improvements are implemented:

| Finding | Implementation |
| --- | --- |
| B1 | Stable source handles span the first read, publication, and removal. Windows denies edits and replacement and deletes the exact opened file by handle. Metadata and identity checks preserve changed sources on Unix. ZIP creation retains source handles until the archive is published. |
| B2 | New v6/v7 entries bind bundle identity and count in authenticated metadata; an HMAC manifest authenticates ordered entry membership. The ZIP parser rejects unlisted or overlapping physical entries and inconsistent directories. Legacy bundles remain readable and are retained after restoration or rotation. |
| B3 | Partial files and overwrite backups use short independent random names in the destination directory. Regression coverage restores and overwrites 224- and 255-character filenames and writes equally long key filenames. |
| B4 | Backup uses one bounded, validated, zeroizing snapshot across the save dialog. The published copy is reopened and checked against that snapshot and the loaded key. |
| B5 | ZIP setup and entry failures become file outcomes, preserving the report for earlier successes. |
| Performance 1 | Bundle duplicate detection canonicalizes once per input, uses a set, and checks cancellation during preparation. |
| Performance 2 | Native AEGIS runtime dispatch selects AES hardware with a software fallback. Windows development tooling initializes installed MSVC when needed; no machine-specific Rust CPU baseline is introduced. |
| Performance 3 | ZIP entries stream directly through bounded readers/writers for encryption, verification, restoration, and rotation. CRC and final authentication complete before plaintext publication. |
| Performance 4 | Selection membership uses a set, busy changes update existing controls, and file/preview/result lists render at most 100 rows per page. |
| Performance 5 | Rotation progress is throttled to 80 ms with immediate cancellation checks and forced completion events. Normal suppressed callbacks avoid cloning display strings. |
| Performance 6 | AEGIS chunk processing reuses lookahead buffers and encrypts in place; rotation recycles zeroized channel buffers. |

Compatibility: existing standalone files and older bundles remain readable. New bundle formats require this updated reader. Removing originals from a legacy ZIP is deliberately disabled because its complete membership cannot be authenticated. Unix metadata checks detect changes but cannot provide Windows-style mandatory sharing restrictions against a concurrent external writer.

Validation: all 49 Rust unit tests and all 3 frontend unit tests pass. They cover the regressions, legacy compatibility, authenticated manifest tampering and stripping, long names, source edits during reads/publication, backup snapshot changes, partial result preservation, streaming CRC/authentication failures, compressed restoration and rotation, cancellation cleanup, and bounded frontend rendering. Development checking and strict library Clippy checks pass. No application smoke test, fuzz run, production build, installer, release package, or dev server was run. Throughput has not been benchmarked; performance claims describe the eliminated work and backend selection.
