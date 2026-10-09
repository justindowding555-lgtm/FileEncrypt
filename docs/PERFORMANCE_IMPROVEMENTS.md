# Performance improvements

The performance audit changes are implemented without changing ciphertext formats, authentication requirements, or explicit deletion retry checks.

| Area | Change |
| --- | --- |
| Sandbox sorting | Reuse locale collators; cache the visible result and global sorted entries. Cache sidebar root order for the session. |
| Sandbox search | Normalize paths once, filter the cached order, and debounce input for 120 ms. Clear catalog caches and pending search callbacks on reset. |
| ZIP preview reads | Parse and authenticate the directory and names once on Windows, retaining a protected source handle for the session. Authenticate each selected body and CRC on every read. Other platforms revalidate the catalog on every read. |
| Deletion receipts | Hash protected sources and output writes during existing streams. Include skipped ZIP headers and any unread footer once. Reuse the ZIP output receipt. Explicit retries still reopen and fully hash all files. |
| Compressed rotation | Forward authenticated compressed bytes directly into encryption while validating the zlib checksum and decoded size. Preserve compression choices and avoid recompression. |
| Folder enumeration | Run blocking traversal off the async command thread. Stream directory iterators, visit overlapping roots once, and bound files (10,000), visited entries (100,000), path text (16 MiB), and iterator depth (1,024). |
| Key polling | Share the backend key-file observation across sandbox windows. Check its key revision and one-second freshness; retain fresh reads before showing previews and the existing IPC deadline. |
| Preview allocations | Reserve from ciphertext size within existing preview limits. Grow compressed previews only as needed and wipe the old plaintext allocation before replacement. |
| Preflight | Cache path normalization and shared-parent metadata within one plan. Discard these caches before the next plan. |
| Selection persistence | Coalesce rapid changes over 150 ms, serialize writes, and retain revision ordering. Main-window close waits for the final pending save. |

## Catalog measurement

Run the actual frontend catalog functions with 10,000 synthetic files:

```powershell
node scripts/benchmark-sandbox.mjs --baseline 4416d8f
```

The script asserts numeric filename ordering and result counts. It reports seven-sample medians after warming each workload. The fresh-sort workload clears both caches; the search workload clears the visible result while retaining the global sort. No dev server, webview, or private files are used.

Measured on this Windows development environment with Node v24.14.1:

| Workload | Before | After |
| --- | ---: | ---: |
| Fresh name sort | 518.9 ms | 46.6 ms |
| Repeated view | 540.9 ms | 0.013 ms |
| Search filter, all names match | 1,170.3 ms | 0.473 ms |

These are JavaScript catalog measurements, not full UI timings or encryption throughput benchmarks. Runtime, locale, and machine load affect the results.

## Validation

- Frontend unit tests: 100 passed.
- Rust library unit tests: 142 passed, including streaming receipt hashing, protected ZIP catalogs, heartbeat expiry, compressed rotation, bounded traversal, and fresh preflight caches.
- Strict Clippy checks: passed for all targets and features on Windows.

Validation used development checks and unit tests. No smoke tests, production builds, installers, or release packages were run. Windows sharing protection is required for the ZIP cache and streamed deletion receipts; cross-platform fallback behavior was reviewed but not executed on another platform.
