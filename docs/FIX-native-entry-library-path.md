# Native guest reentry library search order

The full quick regression failed in `RUN_HOST_ENTER.sh` because the old test expected only `/guest/lib:/guest/usr/lib`. Commit `2e1fcca` added rootfs-prefixed host-visible directories so the native loader can resolve dependencies before guest preload path hooks exist. Keeping those directories is necessary; reverting to the old guest-only string would undo that bootstrap fix.

The remaining implementation issue was order: the generated defaults preceded the saved `_LIBRARY_PATH`, silently taking priority over explicitly selected custom libraries. This patch keeps the saved string and its internal order first, then appends the four host-visible defaults:

```
SAVED:ROOT/usr/lib/aarch64-linux-gnu:ROOT/lib/aarch64-linux-gnu:ROOT/lib:ROOT/usr/lib
```

Missing or empty saved values produce only the four defaults, without an extra empty component. Host-process `LD_LIBRARY_PATH` remains filtered out and cannot substitute for the sealed session's saved value. Saved entries are preserved as written; this change does not introduce a new guest/bind path conversion policy or token expansion.

The corresponding test now checks the complete hex-encoded environment field, including the exact ordering. Additional actual-exec cases cover custom host-visible paths, an empty saved value, and a missing saved value. No substring-only or optional-match relaxation was added.

Validation:

```
sh test/RUN_HOST_ENTER.sh
RUN: static helper actual exec integration
RESULT: PASS bx-enter checks=118 failures=0
RUN: native PIE helper actual exec integration (Linux interpreter)
RESULT: PASS bx-enter checks=118 failures=0
```

`git diff --check` also passes. These integration cases execute the helper and capture its loader-chain environment via a fixture trampoline. They verify argument/environment construction and the actual static/native helper exec boundary, but do not claim to validate Android bionic loader namespaces or guest library ABI compatibility.
