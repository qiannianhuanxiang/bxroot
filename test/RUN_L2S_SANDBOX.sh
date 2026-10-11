#!/bin/sh
# Safe replacement for L2S E2E in a PRoot/link2symlink host.
# It never runs host link/symlink probes and never mounts/chroots/scans syscall numbers.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$ROOT/test/RUN_L2S_MOCK.sh"
for script in \
    RUN_L2S_E2E.sh RUN_L2S_GIT.sh RUN_SYSCALL_TABLE_AUDIT.sh RUN_TRAP_PARITY.sh \
    RUN_AUDIT_FIXES.sh RUN_STATIC_ELF.sh RUN_ALT_ROOTFS.sh RUN_ESCAPE.sh RUN_FUZZ_PATH.sh; do
    [ -f "$ROOT/test/$script" ] || continue
    sh -n "$ROOT/test/$script" || { echo "FAIL: syntax $script"; exit 1; }
done
printf '%s\n' 'SYNTAX_AUDIT: selected high-risk runners parse successfully'
if command -v unshare >/dev/null 2>&1; then
    rc=0
    unshare -Urmpf true >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo 'NAMESPACE_PROBE: user+mount+pid namespace creation allowed (no mounts performed)'
    else
        echo "NAMESPACE_PROBE: unavailable rc=$rc (no isolation claim)"
    fi
else
    echo 'NAMESPACE_PROBE: unshare unavailable (no isolation claim)'
fi
cat <<'EOF'
BLOCKED: RUN_L2S_E2E.sh and RUN_L2S_GIT.sh require a disposable rootfs/backing and a real non-PRoot loader.
BLOCKED: RUN_SYSCALL_TABLE_AUDIT.sh and RUN_TRAP_PARITY.sh perform mount/chroot or broad raw syscall scans; not executed.
BLOCKED: RUN_AUDIT_FIXES.sh contains mount/pivot_root paths; compile/source review only.
BLOCKED: RUN_STATIC_ELF.sh, RUN_ALT_ROOTFS.sh, RUN_ESCAPE.sh and RUN_FUZZ_PATH.sh can touch shared paths; not executed.
RESULT: L2S_SANDBOX_AUDIT_PASS (mock logic verified; host E2E remains explicitly blocked)
EOF
