#!/usr/bin/env bash
# External native AArch64 CI only. Never execute audits directly on this host.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
MODE=run
IMAGE=${BXROOT_AUDIT_IMAGE:-}
OUTPUT=${BXROOT_AUDIT_OUTPUT:-}
usage() {
    printf '%s\n' 'usage: RUN_ISOLATED_AUDITS.sh --dry-run | --run --image LOCAL_IMAGE --output EXISTING_DIR' \
        'Exit: 0=dry-run only, 1=harness/build/test failure, 2=restricted observations or missing prerequisites; never native-kernel e2e PASS.'
}
while (($#)); do
    case "$1" in
        --dry-run) MODE=dry-run; shift ;;
        --run) MODE=run; shift ;;
        --image) (($# >= 2)) || { usage; exit 1; }; IMAGE=$2; shift 2 ;;
        --output) (($# >= 2)) || { usage; exit 1; }; OUTPUT=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
if [[ $MODE == dry-run ]]; then
    printf '%s\n' \
        'DRY_RUN_ONLY: no Docker calls, builds, probes or namespace operations executed.' \
        'Run requires CI=true, native Linux AArch64, no DSHA/Android/PRoot ancestry or mappings.' \
        'Local preloaded image; local Unix Docker context; built-in seccomp enabled; no pull.' \
        'Container: nonroot 65532:65532; read-only image; source bind read-only; private /work,/tmp,/run tmpfs.' \
        'No host PID/IPC/network/user namespaces; network none; cap-drop ALL; no-new-privileges.' \
        'No host sockets/devices supplied; no privileged mode; no entrypoint from image.' \
        'Limits: pids=128 memory=1g swap=1g CPUs=1 outer timeout=900s inner per-audit=180s.' \
        'Whitelist: RUN_SYSCALL_TABLE_AUDIT.sh, RUN_TRAP_PARITY.sh, RUN_AUDIT_FIXES.sh.' \
        'Each audit gets a fresh container. Copy only src/, tools/, and its selected runner/probe.' \
        'Docker stdout/stderr and exact rc retained in unique output directory; container removed by exact name.' \
        'seccomp/capability denial is restricted evidence, not native-kernel semantics or Android runtime e2e.'
    exit 0
fi
fail() { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
[[ ${CI:-} == true ]] || fail 'execution is allowed only in explicitly declared external CI (CI=true)'
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] || fail 'native Linux AArch64 is required; do not use QEMU/binfmt emulation'
for variable in DSH_HOME DSH_SESSION_ID DSH_PERMISSION_MODE DSHA_WORKSPACE_DOCUMENTS DSHA_PRELOAD_PREVIOUS PROROOT_ROOTFS PROOT_TMP_DIR BXROOT_ROOTFS; do
    [[ ! -v $variable ]] || fail "device/guest marker $variable is present"
done
[[ ! -e /root/.dsh/.bridge_headers && ! -e /system/bin/app_process && ! -d /apex ]] || fail 'DSHA or Android filesystem detected'
command -v python3 >/dev/null || fail 'python3 required for environment/source validation'
# Scan ourselves AND all readable ancestors. Raw syscalls/static libc are still
# intercepted by a parent PRoot; checking LD_PRELOAD alone is insufficient.
python3 - "$ROOT" <<'PY'
import os,pathlib,re,sys
root=pathlib.Path(sys.argv[1])
needle=re.compile(rb'(?:libproot|libproroot|proroot|/dsh(?:\x00|\s)|deepseek-ai/dsh|/system/bin|/data/app/)')
pid=os.getpid()
seen=set()
while pid>0 and pid not in seen:
    seen.add(pid)
    base=pathlib.Path('/proc')/str(pid)
    try:
        cmd=(base/'cmdline').read_bytes()
        maps=(base/'maps').read_bytes()
        status=(base/'status').read_text()
    except (OSError,ValueError) as exc:
        sys.exit('REFUSED: cannot validate process ancestry: '+str(exc))
    if needle.search(cmd+b'\n'+maps):
        sys.exit('REFUSED: DSHA/Android/PRoot process or mapping in ancestry')
    pid=int(re.search(r'^PPid:\s*(\d+)',status,re.M).group(1))
# Do not dereference symlinks pointing outside the read-only source mount.
for tree in ('src','tools'):
    base=root/tree
    if base.is_symlink() or not base.is_dir():sys.exit('REFUSED: missing/nonregular source tree '+tree)
    for parent,dirs,files in os.walk(base,followlinks=False):
        for name in dirs+files:
            path=pathlib.Path(parent)/name
            if path.is_symlink():sys.exit('REFUSED: source symlink '+str(path))
PY
[[ -n $IMAGE && $IMAGE != -* && -n $OUTPUT && -d $OUTPUT ]] || fail '--image and an existing --output directory are required'
[[ -z ${DOCKER_HOST:-} && -z ${DOCKER_TLS_VERIFY:-} && -z ${DOCKER_CERT_PATH:-} ]] || fail 'remote/custom Docker connection forbidden'
command -v docker >/dev/null || fail 'Docker is unavailable (dry-run remains supported)'
command -v timeout >/dev/null || fail 'GNU timeout required'
ENDPOINT=$(docker context inspect --format '{{.Endpoints.docker.Host}}') || fail 'Docker context inspection failed'
[[ $ENDPOINT == unix:///* ]] || fail 'only a local Unix Docker daemon is supported'
# Docker defaults can be altered globally. Require the built-in seccomp profile.
SECURITY=$(docker info --format '{{json .SecurityOptions}}') || fail 'Docker daemon inspection failed'
python3 - "$SECURITY" <<'PY'
import json,sys
opts=json.loads(sys.argv[1])
if not any('name=seccomp' in v and 'profile=builtin' in v for v in opts):
    sys.exit('REFUSED: Docker built-in seccomp must be enabled; unconfined/custom profile is not accepted')
if not any('name=userns' in v or 'name=rootless' in v for v in opts):
    sys.exit('REFUSED: Docker must use userns-remap or rootless user namespace isolation')
PY
DIGEST=$(docker image inspect --format '{{.Id}}' "$IMAGE") || fail 'image must already be loaded locally; no image pull is performed'
ARCH=$(docker image inspect --format '{{.Architecture}}' "$DIGEST")
[[ $ARCH == arm64 ]] || fail 'image must be native arm64'
VOLUMES=$(docker image inspect --format '{{json .Config.Volumes}}' "$DIGEST")
[[ $VOLUMES == null || $VOLUMES == '{}' ]] || fail 'image-declared volumes are forbidden'
OUTPUT=$(CDPATH= cd -- "$OUTPUT" && pwd -P)
RESULT_DIR=$(mktemp -d "$OUTPUT/bxroot-isolated-audits-XXXXXXXX") || fail 'cannot create private output directory'
NAME=''
cleanup() {
    # NAME is an exact name from the fixed prefix and mktemp-generated suffix.
    if [[ -n $NAME ]]; then
        case "$NAME" in bxroot-audit-*) docker rm --force "$NAME" >/dev/null 2>&1 || true ;; esac
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'image=%s\nsource=%s\nclassification=restricted-docker-observations-not-native-e2e\n' "$DIGEST" "$ROOT" >"$RESULT_DIR/metadata.txt"
overall=2
for audit in syscall-table trap-parity audit-fixes; do
    case "$audit" in
        syscall-table) RUNNER=RUN_SYSCALL_TABLE_AUDIT.sh; PROBE=test_syscall_table_audit.c ;;
        trap-parity) RUNNER=RUN_TRAP_PARITY.sh; PROBE=probe_trap_enum.c ;;
        audit-fixes) RUNNER=RUN_AUDIT_FIXES.sh; PROBE=probe_audit_fixes.c ;;
    esac
    [[ -f $ROOT/test/$RUNNER && ! -L $ROOT/test/$RUNNER && -f $ROOT/test/$PROBE && ! -L $ROOT/test/$PROBE ]] || fail 'selected test must be a regular nonsymlink file'
    suffix=${RESULT_DIR##*/}
    NAME="bxroot-audit-${suffix#bxroot-isolated-audits-}-$audit"
    rc=0
    timeout --kill-after=10 900 docker run --interactive --rm --pull=never --name "$NAME" \
        --network=none --pid="" --ipc=private --cgroupns=private \
        --user=65532:65532 --read-only --cap-drop=ALL \
        --security-opt=no-new-privileges=true \
        --pids-limit=128 --memory=1g --memory-swap=1g --cpus=1 \
        --ulimit=core=0:0 --ulimit=nofile=256:256 \
        --mount "type=bind,source=$ROOT/src,target=/input/src,readonly,bind-propagation=rprivate,bind-recursive=disabled" \
        --mount "type=bind,source=$ROOT/tools,target=/input/tools,readonly,bind-propagation=rprivate,bind-recursive=disabled" \
        --mount "type=bind,source=$ROOT/test/$RUNNER,target=/input/runner,readonly,bind-propagation=rprivate,bind-recursive=disabled" \
        --mount "type=bind,source=$ROOT/test/$PROBE,target=/input/probe,readonly,bind-propagation=rprivate,bind-recursive=disabled" \
        --tmpfs /work:rw,nosuid,nodev,size=512m,mode=1777 \
        --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 \
        --tmpfs /run:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
        --workdir=/work --entrypoint=/bin/sh "$DIGEST" -s -- "$audit" <<'CONTAINER' >"$RESULT_DIR/$audit.log" 2>&1 || rc=$?
set -eu
case "$1" in
    syscall-table) runner=RUN_SYSCALL_TABLE_AUDIT.sh; probe=test_syscall_table_audit.c ;;
    trap-parity) runner=RUN_TRAP_PARITY.sh; probe=probe_trap_enum.c ;;
    audit-fixes) runner=RUN_AUDIT_FIXES.sh; probe=probe_audit_fixes.c ;;
    *) exit 1 ;;
esac
mkdir -p /work/repo/test
command -v python3 >/dev/null 2>&1 || { echo 'PREREQUISITE_MISSING:python3'; exit 2; }
python3 - <<'COPY_SOURCE'
import pathlib,shutil
base=pathlib.Path('/input/src')
for source in base.rglob('*'):
    if source.is_file() and source.suffix in ('.c','.h','.S','.s','.inc','.ld','.sh'):
        target=pathlib.Path('/work/repo/src')/source.relative_to(base)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
pathlib.Path('/work/repo/tools').mkdir(parents=True,exist_ok=True)
shutil.copyfile('/input/tools/bxroot-run','/work/repo/tools/bxroot-run')
pathlib.Path('/work/repo/tools/bxroot-run').chmod(0o700)
COPY_SOURCE
cp /input/runner "/work/repo/test/$runner"
cp /input/probe "/work/repo/test/$probe"
cd /work/repo
export TMPDIR=/tmp
for tool in gcc python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 || { echo "PREREQUISITE_MISSING:$tool"; exit 2; }
done
case "$1" in
    trap-parity) gcc -O0 -Wall -Wextra -o /tmp/compile-probe "test/$probe" ;;
    *) gcc -std=c11 -O1 -D_GNU_SOURCE -Wall -Wextra -o /tmp/compile-probe "test/$probe" ;;
esac
printf 'COMPILE_OK:%s\n' "$1"
# Original Android comparison runners cannot run natively without their loaders.
# Keep their explicit rc=2 prerequisite results; never inject a fake PRoot marker.
rc=0
timeout --kill-after=5 180 sh "test/$runner" || rc=$?
printf 'AUDIT_RETURN_CODE=%s\n' "$rc"
printf 'EVIDENCE_SCOPE=restricted-docker; seccomp and dropped capabilities change errno/availability\n'
exit "$rc"
CONTAINER
    cleanup
    NAME=''
    printf '%s|rc=%s|scope=restricted-docker-not-native-e2e\n' "$audit" "$rc" >>"$RESULT_DIR/results.txt"
    case "$rc" in 0|2) ;; *) overall=1 ;; esac
    printf '%s rc=%s log=%s\n' "$audit" "$rc" "$RESULT_DIR/$audit.log"
done
printf 'RESULT: INCOMPLETE_NATIVE_E2E (restricted evidence only) directory=%s\n' "$RESULT_DIR"
exit "$overall"
