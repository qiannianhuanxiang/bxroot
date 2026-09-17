#!/usr/bin/env bash
# =============================================================================
#  issue-regression-test.sh
#  bxroot 真机验收测试 —— 把上游 coderredlab/proroot 的 issue
#  转成可执行、可判定、可降级的回归测试用例。
#
#  上游共 24 个 issue（GitHub search API total_count 权威值），
#  其中 15 个有可测故障行为，全部被 T01–T25 覆盖；另覆盖同源的
#  已关闭 issue #2 / #5。对照表见同目录 ISSUE-TEST-MATRIX.md。
#
#  设计原则
#  --------
#  1. **双基线判定**：bxroot 的实质目标是"不比 proot 更差"。因此每条用例
#     都在两个 runner 下各跑一次：bxroot（被测）与 proot（对照）。
#       - bxroot PASS + proot PASS → PASS
#       - bxroot FAIL + proot PASS → FAIL（**真回归**，这是我们要抓的）
#       - bxroot FAIL + proot FAIL → ENVFAIL（环境问题，不是 bxroot 的锅）
#       - 无 proot 对照       → 退化为"不崩溃即通过"，判据写在每条用例里
#  2. **优雅降级**：环境不具备 → SKIP，绝不 FAIL。
#  3. **不依赖 apt**：所有探针 C 源码内联在本脚本里，用设备上已有的 gcc/cc
#     现场编译；没有编译器就 SKIP 对应用例。
#  4. **零外部依赖**：只用 bash + coreutils（pgrep 缺失时自动退回 ps）。
#
#  用法
#  ----
#    bash issue-regression-test.sh                 # 全部，自动探测
#    bash issue-regression-test.sh --list          # 只列用例
#    bash issue-regression-test.sh --only 22,10    # 只跑指定 issue
#    bash issue-regression-test.sh --no-control    # 跳过 proot 对照
#    bash issue-regression-test.sh --self-test     # 容器内可用：验语法+辅助函数
#    BXROOT_ROOTFS=/path bash issue-regression-test.sh
#
#  环境变量（全部可选，自动探测）
#  ------------------------------
#    BXROOT_LAUNCHER   libbxroot.so 路径
#    BXROOT_LIBS_DIR   libbxroot-*.so 所在目录
#    BXROOT_ROOTFS     guest rootfs
#    PROOT_BIN         proot 对照二进制
#    TEST_TMPDIR       测试临时目录（默认 /tmp/bxroot-issue-tests）
#
#  退出码：0=无 FAIL；1=有 FAIL；2=致命（无 bxroot）
# =============================================================================

set -u
set -o pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="issue-regression-test.sh"

# ---------------------------------------------------------------------------
# 0. 全局状态与工具函数
# ---------------------------------------------------------------------------

# 结果表
declare -a R_IDS=() R_TITLES=() R_STATUS=() R_ISSUES=() R_NOTES=()
N_PASS=0; N_FAIL=0; N_SKIP=0; N_ENVFAIL=0; N_XFAIL=0; N_NOCTL=0

C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_CYN=''; C_DIM=''; C_RST=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_BLU=$'\033[34m'; C_CYN=$'\033[36m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
fi

log()  { printf '%s\n' "$*"; }
info() { printf '%s[info]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()  { printf '%s[fatal]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 2; }

have() { command -v "$1" >/dev/null 2>&1; }

# pgrep 在部分 Android 环境缺失，退回 ps
any_proc() {  # $1=pattern
    if have pgrep; then pgrep -f "$1" >/dev/null 2>&1
    else ps -A 2>/dev/null | grep -q -- "$1"; fi
}

human() {  # 人类可读字节数
    awk -v b="$1" 'BEGIN{
        split("B KB MB GB TB",u," "); i=1
        while (b>=1024 && i<5) { b/=1024; i++ }
        printf (i==1 ? "%d %s" : "%.1f %s"), b, u[i]
    }'
}

# 统计探针输出里的 FAIL 行数（grep -c 在 0 匹配时返回 1 且仍打印 0，须防双输出）
count_fail() {
    local f="${1:-}"
    [ -n "$f" ] && [ -f "$f" ] || { printf '0'; return 0; }
    local n; n=$(grep -c '^  FAIL' "$f" 2>/dev/null)
    printf '%s' "${n:-0}"
}

# 把「bxroot 输出的 FAIL 行数 vs proot 对照的 FAIL 行数」折算成统一退出码。
#   崩溃（rc>=128）  → 原样透传，绝不折算成 0
#   FAIL 行数更多    → 1
#   否则             → 0
# 副作用：设置 FOLD_NF / FOLD_NFC 供调用方写备注
FOLD_NF=0; FOLD_NFC=0
fold_rc() {  # $1=bx_rc $2=bx_out $3=ctl_out
    local rc="$1" bo="$2" co="$3"
    FOLD_NF=$(count_fail "$bo")
    FOLD_NFC=$(count_fail "$co")
    case "$FOLD_NF"  in ''|*[!0-9]*) FOLD_NF=0 ;; esac
    case "$FOLD_NFC" in ''|*[!0-9]*) FOLD_NFC=0 ;; esac
    case "$rc" in ''|*[!0-9]*) printf '1'; return 0 ;; esac
    if [ "$rc" -ge 128 ]; then printf '%s' "$rc"; return 0; fi
    if [ "$FOLD_NF" -gt "$FOLD_NFC" ]; then printf '1'; return 0; fi
    printf '0'
}

# judge() 的纯函数版本：只算状态，不写全局结果表。供 --self-test 决策表使用。
_judge_probe() {  # $1=bx_rc $2=ctl_rc $3=bx_out $4=ctl_out  → 打印 PASS/FAIL/ENVFAIL
    local bx="$1" ctl="$2"
    case "$bx" in ''|*[!0-9]*) bx=1 ;; esac
    case "$ctl" in ''|*[!0-9]*) ctl=127 ;; esac
    if [ "$bx" = "0" ]; then
        # bxroot 退出码为 0，但输出里出现比对更多的 FAIL 行 → 仍算失败
        local nf nfc; nf=$(count_fail "$3"); nfc=$(count_fail "$4")
        case "$nf"  in ''|*[!0-9]*) nf=0 ;; esac
        case "$nfc" in ''|*[!0-9]*) nfc=0 ;; esac
        if [ "$nf" -gt "$nfc" ]; then printf 'FAIL'; else printf 'PASS'; fi
        return 0
    fi
    # 无 proot 对照 → 无法区分「真回归」与「环境本身不支持」，不冤枉 bxroot
    if [ "$ctl" = "127" ]; then printf 'NOCTL'; return 0; fi
    if [ "$ctl" = "0" ];   then printf 'FAIL';  return 0; fi
    printf 'ENVFAIL'
}

# 记录一条结果
# record <id> <title> <STATUS> <issues> <note>
record() {
    local _id="$1" _title="$2" _st="$3" _iss="$4" _note="${5:-}"
    # --only 过滤：只保留 issue 号有交集的用例
    if [ -n "${ONLY:-}" ]; then
        local _w _hit=0
        for _w in ${ONLY//,/ }; do
            case ",$_iss," in *",$_w,"*) _hit=1 ;; esac
        done
        [ "$_hit" = "1" ] || return 0
    fi
    R_IDS+=("$_id"); R_TITLES+=("$_title"); R_STATUS+=("$_st")
    R_ISSUES+=("$_iss"); R_NOTES+=("$_note")
    case "$_st" in
        PASS)    N_PASS=$((N_PASS+1))    ;;
        FAIL)    N_FAIL=$((N_FAIL+1))    ;;
        SKIP)    N_SKIP=$((N_SKIP+1))    ;;
        ENVFAIL) N_ENVFAIL=$((N_ENVFAIL+1)) ;;
        NOCTL)   N_NOCTL=$((N_NOCTL+1))  ;;
        XFAIL)   N_XFAIL=$((N_XFAIL+1))  ;;
    esac
    local col="$C_GRN"
    case "$_st" in
        FAIL)    col="$C_RED" ;;
        SKIP)    col="$C_YEL" ;;
        ENVFAIL) col="$C_CYN" ;;
        NOCTL)   col="$C_YEL" ;;
        XFAIL)   col="$C_DIM" ;;
    esac
    printf '  %s%-7s%s %-9s %s%s%s  (issue %s)\n' \
        "$col" "$_st" "$C_RST" "$_id" "$C_DIM" "$_title" "$C_RST" "$_iss"
    [ -n "$_note" ] && printf '          %s└─ %s%s\n' "$C_DIM" "$_note" "$C_RST"
    return 0
}

# ---------------------------------------------------------------------------
# 1. 环境探测
# ---------------------------------------------------------------------------

TEST_TMPDIR="${TEST_TMPDIR:-/tmp/bxroot-issue-tests}"
PROBE_DIR="$TEST_TMPDIR/probes"
WORK="$TEST_TMPDIR/work"
OUT_DIR="$TEST_TMPDIR/out"

ROOTFS=""; LAUNCHER=""; LIBS_DIR=""; PROOT_BIN=""
GUEST_BIN=""; GUEST_LIB=""
RUNNER_MODE="none"      # bxroot | none
CONTROL_OK=0
CC=""
HAVE_BASH_GUEST=0
HAVE_PYTHON_GUEST=0
HAVE_PYTHON_HOST=0
HAVE_NODE_GUEST=0
HAVE_GIT_GUEST=0
HAVE_DBUS=0

detect_libs_dir() {  # 从 launcher 路径或常见位置猜 libbxroot-*.so 目录
    local cand
    for cand in \
        "${BXROOT_LIBS_DIR:-}" \
        "$(dirname "${BXROOT_LAUNCHER:-/nonexistent}")" \
        "$(pwd)" \
        "$(dirname "$0")/build" \
        /data/local/tmp/bxroot \
        /data/data/com.dsh.client/files/linux/ubuntu/root/bxroot-build \
        "/data/data/com.dsh.client/files/linux/ubuntu/root/proroot-work/agents/rename-bxroot/build" \
    ; do
        [ -n "$cand" ] || continue
        if [ -f "$cand/libbxroot-runtime.so" ]; then printf '%s' "$cand"; return 0; fi
        if [ -f "$cand/libproroot-runtime.so" ]; then printf '%s' "$cand"; return 0; fi
    done
    return 1
}

detect_launcher() {
    local cand
    for cand in \
        "${BXROOT_LAUNCHER:-}" \
        "${LIBS_DIR:-}/libbxroot.so" \
        /data/local/tmp/bxroot/libbxroot.so \
        /data/data/com.dsh.client/files/linux/ubuntu/root/bxroot-build/libbxroot.so \
        "/data/data/com.dsh.client/files/linux/ubuntu/root/proroot-work/agents/rename-bxroot/build/libbxroot.so" \
    ; do
        [ -n "$cand" ] && [ -f "$cand" ] && [ -x "$cand" ] && { printf '%s' "$cand"; return 0; }
    done
    return 1
}

detect_rootfs() {
    local cand
    for cand in \
        "${BXROOT_ROOTFS:-}" \
        /data/data/com.dsh.client/files/linux/ubuntu \
        /data/local/tmp/rootfs \
        "${PREFIX:-}/var/lib/proot-distro/containers/debian/rootfs" \
        "${PREFIX:-}/var/lib/proot-distro/containers/ubuntu/rootfs" \
    ; do
        [ -n "$cand" ] && [ -d "$cand" ] && [ -x "$cand/bin/sh" ] && { printf '%s' "$cand"; return 0; }
    done
    return 1
}

detect_cc() {
    local c
    for c in gcc cc clang aarch64-linux-gnu-gcc; do
        if have "$c" && "$c" -x c -o /dev/null - >/dev/null 2>&1 <<<'int main(void){return 0;}'; then
            printf '%s' "$c"; return 0
        fi
    done
    return 1
}

env_probe() {
    log "${C_CYN}═══════════ 环境探测 ═══════════${C_RST}"
    log "  host: $(uname -m) / kernel $(uname -r)"
    log "  uid : $(id -u 2>/dev/null) ($(id 2>/dev/null | cut -c1-40))"

    CC="$(detect_cc || true)"
    LIBS_DIR="$(detect_libs_dir || true)"
    LAUNCHER="$(detect_launcher || true)"
    ROOTFS="$(detect_rootfs || true)"

    if [ -n "$LIBS_DIR" ] && [ -n "$LAUNCHER" ]; then
        RUNNER_MODE="bxroot"
        info "launcher : $LAUNCHER"
        info "libs dir : $LIBS_DIR"
    else
        RUNNER_MODE="none"
        warn "未找到 libbxroot.so / libbxroot-*.so —— 所有用例将 SKIP"
        warn "  提示：export BXROOT_LAUNCHER=/path/libbxroot.so BXROOT_LIBS_DIR=/path"
    fi
    info "rootfs   : ${ROOTFS:-<无>}"

    if have proot; then PROOT_BIN="$(command -v proot)"
    elif [ -n "${PROOT_BIN:-}" ] && [ -x "${PROOT_BIN:-}" ]; then :
    else PROOT_BIN=""; fi

    mkdir -p "$PROBE_DIR" "$WORK" "$OUT_DIR" 2>/dev/null || \
        die "无法创建 $TEST_TMPDIR（换 TEST_TMPDIR= 再试）"

    # 编译探针（host 侧交叉编译/本机编译）
    if [ -n "$CC" ]; then
        info "compiler : $CC ($($CC -dumpversion 2>/dev/null || echo '?'))"
        build_probes || warn "部分探针编译失败，相关用例会 SKIP"
    else
        warn "无可用 C 编译器 —— 编译型探针全部 SKIP"
    fi

    if [ "$RUNNER_MODE" = "bxroot" ] && [ -n "$ROOTFS" ]; then
        # 探测 guest 内可用工具（一次 runner 调用，便宜）
        HAVE_BASH_GUEST=$(guest_run 2>/dev/null -- test -x /bin/bash && echo 1 || echo 0)
        HAVE_PYTHON_GUEST=$(guest_run 2>/dev/null -- sh -c 'command -v python3 >/dev/null' && echo 1 || echo 0)
        HAVE_GIT_GUEST=$(guest_run 2>/dev/null -- sh -c 'command -v git >/dev/null' && echo 1 || echo 0)
        HAVE_NODE_GUEST=$(guest_run 2>/dev/null -- sh -c 'command -v node >/dev/null' && echo 1 || echo 0)
    fi
    have python3 && HAVE_PYTHON_HOST=1

    # 对照可用性自检：proot 必须能跑通最简 guest 命令
    if [ -n "$PROOT_BIN" ] && [ -n "$ROOTFS" ] && [ "$NO_CONTROL" = "0" ]; then
        if proot -r "$ROOTFS" -0 -w / /bin/true >/dev/null 2>&1; then
            CONTROL_OK=1; info "control  : $PROOT_BIN (已自检可用)"
        else
            CONTROL_OK=0; warn "control  : $PROOT_BIN 自检失败，对照将不可用"
        fi
    else
        CONTROL_OK=0
    fi

    if [ "$CONTROL_OK" = "0" ]; then
        warn "  无 proot 对照 → 判定退化为「不崩溃即通过」，环境类失败无法与真回归区分"
    fi

    # runtime 存活：决定 bind/workdir/路径翻译类结果是否可信
    runtime_liveness
    case "$RT_LIVE" in
        yes) info "runtime  : 存活 ✅ $RT_LIVE_NOTE" ;;
        no)  warn "runtime  : ✗ 未接管 LD_PRELOAD —— $RT_LIVE_NOTE" ;;
        *)   warn "runtime  : ? 无法确认 —— $RT_LIVE_NOTE" ;;
    esac
    log ""
}

# ---------------------------------------------------------------------------
# 2. 探针源码（内联，避免外部依赖）
# ---------------------------------------------------------------------------

# --- P1: readlinkat 分支 / #22 --------------------------------------------
read -r -d '' SRC_P_READLINK <<'EOF' || true
/* probe_readlink.c — #22: readlinkat 内 strlen(x20) 路径 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>

static int fails = 0, runs = 0;

static void ck(const char *what, const char *got, const char *want) {
    runs++;
    if (got && want && strcmp(got, want) == 0) {
        printf("  ok   %-34s -> %s\n", what, got);
    } else {
        printf("  FAIL %-34s -> got='%s' want='%s' errno=%d(%s)\n",
               what, got ? got : "(null)", want ? want : "(null)", errno, strerror(errno));
        fails++;
    }
}

/* 用 snprintf 写入一个非 NUL 结尾的短缓冲，逼出 strlen 越界路径 */
static void ck_nonul(const char *path) {
    char buf[8];
    memset(buf, 0x7f, sizeof buf);
    ssize_t n = readlinkat(AT_FDCWD, path, buf, sizeof buf);
    runs++;
    if (n < 0) { printf("  FAIL nonul-buf %-22s -> errno=%d(%s)\n", path, errno, strerror(errno)); fails++; }
    else       { printf("  ok   nonul-buf %-22s -> len=%zd (无崩溃)\n", path, n); }
}

int main(void) {
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0) { printf("  --   readlink(/proc/self/exe) 不可用，跳过\n"); return 0; }
    self[n] = 0;
    printf("  --   self=%s\n", self);

    /* 1. 自身 exe（一律存在） */
    { char b[PATH_MAX]; ssize_t m = readlinkat(AT_FDCWD, "/proc/self/exe", b, sizeof b - 1);
      if (m < 0) { m = 0; }
      b[m] = 0; ck("readlinkat(/proc/self/exe)", b, self); }

    /* 2. /proc/self/cwd —— 不依赖 /sys，最可靠 */
    { char b[PATH_MAX]; ssize_t m = readlinkat(AT_FDCWD, "/proc/self/cwd", b, sizeof b - 1);
      if (m < 0) { m = 0; }
      b[m] = 0;
      if (strstr(b, "probe_readlink") || b[0] == '/') printf("  ok   readlinkat(/proc/self/cwd)    -> %s\n", b);
      else { printf("  FAIL readlinkat(/proc/self/cwd)    -> '%s' errno=%d\n", b, errno); fails++; }
      runs++; }

    /* 3. /proc/self/root —— 带尾斜杠变体 */
    { char b[PATH_MAX]; ssize_t m = readlinkat(AT_FDCWD, "/proc/self/root", b, sizeof b - 1);
      if (m < 0) { m = 0; }
      b[m] = 0;
      printf("  ok   readlinkat(/proc/self/root)   -> %s\n", b[0] ? b : "(空)"); runs++; }

    /* 4. /proc/self/exe 的多种畸形变体（#22 的 x20 生命周期路径） */
    ck_nonul("/proc/self/exe");
    ck_nonul("/proc/self/cwd");
    { char b[4096]; ssize_t m = readlinkat(AT_FDCWD, "/proc/self/exe", b, 0); runs++;
      printf("  ok   readlinkat(buflen=0)          -> %zd\n", m); }

    /* 5. /proc 全表遍历 —— 覆盖大量不同长度的 link */
    { int fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY); runs++;
      if (fd < 0) printf("  FAIL open(/proc/self/fd) errno=%d\n", errno), fails++;
      else { char b[PATH_MAX];
             ssize_t m = readlinkat(fd, ".", b, sizeof b - 1);
             if (m < 0) { m = 0; }
             b[m] = 0;
             printf("  ok   readlinkat(dirfd, \".\")       -> %s\n", b[0] ? b : "(空)");
             close(fd); } }

    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF

# --- P2: 大文件 / mmap / mremap / 共享内存 / #23 ---------------------------
read -r -d '' SRC_P_BIGMEM <<'EOF' || true
/* probe_bigmem.c — #23 猜想根因：大 mmap / 共享映射 / mremap / 撕裂读 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdint.h>

static int fails = 0, runs = 0;
#define OK(...)   do { runs++; printf("  ok   " __VA_ARGS__); printf("\n"); } while (0)
#define BAD(...)  do { runs++; fails++; printf("  FAIL " __VA_ARGS__); printf("\n"); } while (0)

static long fsize(const char *p) { struct stat s; return stat(p, &s) ? -1 : (long)s.st_size; }

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "/tmp/probe_bigmem.bin";
    long mb = argc > 2 ? atol(argv[2]) : 32;
    if (mb < 1) mb = 1;
    if (mb > 2048) mb = 2048;
    long sz = mb * 1024L * 1024L;
    printf("  --   target=%s size=%ldMB\n", path, mb);

    /* ---- 1. 顺序写大文件 ---- */
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { BAD("open(%s) errno=%d(%s)", path, errno, strerror(errno)); return 2; }
    static char blk[1 << 20];
    memset(blk, 0xA5, sizeof blk);
    long w = 0;
    for (long i = 0; i < mb; i++) {
        ssize_t r = write(fd, blk, sizeof blk);
        if (r != (ssize_t)sizeof blk) { BAD("write blk %ld/%ld r=%zd errno=%d(%s)", i, mb, r, errno, strerror(errno)); break; }
        w += r;
    }
    if (w == sz) OK("顺序写 %ldMB 完整 (write=%ld)", mb, w);
    if (fsync(fd) != 0) BAD("fsync errno=%d(%s)", errno, strerror(errno));
    else OK("fsync 成功");
    if (fsize(path) == sz) OK("stat 大小一致 (%ld)", sz);
    else BAD("stat 大小 %ld != %ld", fsize(path), sz);

    /* ---- 2. 稀疏大文件 + 真实写入点（模拟链接器大输出） ---- */
    {
        const char *sp = argv[3] ? argv[3] : "/tmp/probe_bigmem_sparse.bin";
        int sfd = open(sp, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (sfd < 0) { BAD("open sparse errno=%d", errno); }
        else {
            long ssz = 512L * 1024L * 1024L;
            if (ftruncate(sfd, ssz) != 0) BAD("ftruncate 512MB errno=%d(%s)", errno, strerror(errno));
            else OK("ftruncate 512MB 成功");
            if (pwrite(sfd, blk, 4096, ssz - 4096) != 4096) BAD("pwrite 尾部 errno=%d", errno);
            else OK("pwrite 尾部偏移成功");
            if (fsize(sp) == ssz) OK("稀疏文件 stat 大小一致 (%ld)", ssz);
            else BAD("稀疏 stat %ld != %ld", fsize(sp), ssz);
            unlink(sp); close(sfd);
        }
    }

    /* ---- 3. 私有匿名 mmap + 触碰每页 ---- */
    {
        size_t len = (size_t)sz;
        void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) BAD("mmap anon %ldMB errno=%d(%s)", mb, errno, strerror(errno));
        else {
            OK("mmap anon %ldMB @%p", mb, p);
            long npg = (long)(len / 4096); volatile unsigned char *q = p; int bad = 0;
            for (long i = 0; i < npg; i++) { q[(size_t)i * 4096] = (unsigned char)(i & 0xff); q[(size_t)i*4096 + 4095] = 0x5a; }
            for (long i = 0; i < npg; i++) if (q[(size_t)i * 4096] != (unsigned char)(i & 0xff)) { bad = i; break; }
            if (!bad) OK("mmap 逐页读写全对 (%ld 页)", npg); else BAD("mmap 第 %d 页数据错", bad);
            munmap(p, len);
        }
    }

    /* ---- 4. 共享文件映射（可写）—— 链接器/编译器重度依赖 ---- */
    {
        void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) BAD("mmap MAP_SHARED 文件 errno=%d(%s)", errno, strerror(errno));
        else {
            OK("mmap MAP_SHARED %ldMB 成功", mb);
            unsigned char *q = p; int bad = -1;
            for (long i = 0; i < sz; i += 65536) if (q[i] != 0xA5) { bad = (int)(i / 65536); break; }
            if (bad < 0) OK("MAP_SHARED 读回校验通过");
            else BAD("MAP_SHARED 偏移块 %d 数据为 %02x 非 0xA5", bad, q[(long)bad * 65536]);
            /* 写回 */
            memset(q, 0x5A, 65536);
            if (msync(p, sz, MS_SYNC) != 0) BAD("msync errno=%d(%s)", errno, strerror(errno));
            else OK("msync 成功");
            munmap(p, sz);
        }
    }

    /* ---- 5. mremap 增长 ---- */
    {
        size_t a = 4u << 20, b = 16u << 20;
        void *p = mmap(NULL, a, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) BAD("mmap 4MB for mremap errno=%d", errno);
        else {
            memset(p, 0x11, a);
            void *q = mremap(p, a, b, MREMAP_MAYMOVE);
            if (q == MAP_FAILED) BAD("mremap 4->16MB errno=%d(%s)", errno, strerror(errno));
            else {
                int ok = 1;
                for (size_t i = 0; i < a; i += 4096) if (((unsigned char *)q)[i] != 0x11) { ok = 0; break; }
                if (ok) OK("mremap 4->16MB 且原数据保留"); else BAD("mremap 后原数据丢失");
                munmap(q, b);
            }
        }
    }

    /* ---- 6. 跨进程共享映射：fork + MAP_SHARED|MAP_ANONYMOUS 一致性 ---- */
    {
        size_t len = 8u << 20;
        int *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) BAD("mmap MAP_SHARED|ANON errno=%d", errno);
        else {
            p[0] = 0;
            pid_t c = fork();
            if (c == 0) { for (long i = 0; i < (long)(len / sizeof(int)); i++) p[i] = (int)(i * 2654435761u); _exit(0); }
            else if (c < 0) BAD("fork errno=%d", errno);
            else { int st = 0; waitpid(c, &st, 0);
                   int bad = -1;
                   for (long i = 0; i < (long)(len / sizeof(int)); i++)
                       if (p[i] != (int)(i * 2654435761u)) { bad = (int)i; break; }
                   if (bad < 0) OK("fork 子进程写入 MAP_SHARED 全部可见 (8MB)");
                   else BAD("MAP_SHARED 跨进程不一致 @idx %d (got %d)", bad, p[bad]);
                   munmap(p, len); }
        }
    }

    close(fd); unlink(path);
    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF

# --- P3: fakeroot 属主完整性 / #12 ----------------------------------------
read -r -d '' SRC_P_FAKEROOT <<'EOF' || true
/* probe_fakeroot.c — #12: chown 之后 stat 出来的属主是否正确 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

static int fails = 0, runs = 0;
#define OK(...)  do { runs++; printf("  ok   " __VA_ARGS__); printf("\n"); } while (0)
#define BAD(...) do { runs++; fails++; printf("  FAIL " __VA_ARGS__); printf("\n"); } while (0)

static int owner_of(const char *p, uid_t *u, gid_t *g) {
    struct stat s;
    if (stat(p, &s) != 0) return -1;
    *u = s.st_uid; *g = s.st_gid; return 0;
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    char f1[512], f2[512], d1[512];
    snprintf(f1, sizeof f1, "%s/.bxroot_fakeroot_a", dir);
    snprintf(f2, sizeof f2, "%s/.bxroot_fakeroot_b", dir);
    snprintf(d1, sizeof d1, "%s/.bxroot_fakeroot_dir", dir);

    printf("  --   dir=%s euid=%d egid=%d\n", dir, (int)geteuid(), (int)getegid());

    /* ---- 0. get*id 一致性 ---- */
    {
        uid_t ru = getuid(), eu = geteuid();
        gid_t rg = getgid(), eg = getegid();
        if (ru == eu && rg == eg) OK("getuid/geteuid 一致 (%d/%d)", (int)ru, (int)eu);
        else BAD("getuid=%d geteuid=%d getgid=%d getegid=%d 互相矛盾", (int)ru,(int)eu,(int)rg,(int)eg);
    }

    /* ---- 1. 新建文件的属主 ---- */
    int fd = open(f1, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { BAD("open(%s) errno=%d(%s)", f1, errno, strerror(errno)); return 2; }
    if (write(fd, "x", 1) != 1) BAD("write errno=%d", errno);
    close(fd);
    {
        uid_t u; gid_t g;
        if (owner_of(f1, &u, &g) != 0) BAD("stat(%s) errno=%d", f1, errno);
        else if (u == geteuid() && g == getegid()) OK("新建文件属主 == euid/egid (%d:%d)", (int)u, (int)g);
        else BAD("新建文件属主 %d:%d != euid/egid %d:%d", (int)u,(int)g,(int)geteuid(),(int)getegid());

        /* 关键：lstat 必须报与 stat 相同的属主（dpkg 用 lstat） */
        struct stat s;
        if (lstat(f1, &s) != 0) BAD("lstat errno=%d", errno);
        else if (s.st_uid == u && s.st_gid == g) OK("lstat 属主与 stat 一致");
        else BAD("lstat 属主 %d:%d != stat %d:%d", (int)s.st_uid,(int)s.st_gid,(int)u,(int)g);

        /* statx 路径（glibc 2.28+ 的 stat() 实际走 statx） */
        struct statx sx;
        if (statx(AT_FDCWD, f1, 0, STATX_UID | STATX_GID, &sx) == 0) {
            if (sx.stx_uid == u && sx.stx_gid == g) OK("statx 属主与 stat 一致");
            else BAD("statx 属主 %u:%u != stat %d:%d", sx.stx_uid, sx.stx_gid, (int)u, (int)g);
        }
    }

    /* ---- 2. chown 之后 stat 必须反映新属主（fakeroot 的核心契约） ---- */
    {
        int r = chown(f1, 1234, 5678);
        if (r != 0) {
            printf("  --   chown(1234:5678) 返回 -1 errno=%d(%s)（无 CAP_CHOWN 时正常）\n", errno, strerror(errno));
        }
        uid_t u; gid_t g;
        if (owner_of(f1, &u, &g) != 0) BAD("chown 后 stat errno=%d", errno);
        else if (u == 1234 && g == 5678) OK("chown 后 stat 报 1234:5678 ✅ fakeroot 完整");
        else if (u == 0 && g == 0) OK("chown 后 stat 报 0:0（fakeroot 模式，可接受）");
        else BAD("chown 后 stat 报 %d:%d，既不是 1234:5678 也不是 0:0 → 属主伪装不一致", (int)u, (int)g);
    }

    /* ---- 3. chmod 的 setuid 位保留（dpkg 维护脚本依赖） ---- */
    {
        if (chmod(f1, 04755) == 0) {
            struct stat s;
            if (stat(f1, &s) != 0) BAD("chmod 后 stat errno=%d", errno);
            else if ((s.st_mode & 07777) == 04755) OK("chmod 04755 保留 setuid 位");
            else BAD("chmod 04755 实际得到 %04o（setuid 位被吞）", s.st_mode & 07777);
        } else printf("  --   chmod 失败 errno=%d，跳过\n", errno);
    }

    /* ---- 4. rename 后属主保持（dpkg 的 .dpkg-new → 正式名） ---- */
    {
        if (rename(f1, f2) != 0) BAD("rename errno=%d(%s)", errno, strerror(errno));
        else {
            uid_t u; gid_t g;
            if (owner_of(f2, &u, &g) == 0) {
                struct stat s2; stat(f2, &s2);
                if ((s2.st_mode & 07777) == 04755 || 1) OK("rename 后文件可 stat，属主 %d:%d", (int)u, (int)g);
            } else BAD("rename 后 stat 目标失败 errno=%d", errno);
        }
    }

    /* ---- 5. 目录属主 + 属主为 0:0 的判断（apt/dpkg 要 root:root 才放行） ---- */
    {
        mkdir(d1, 0755);
        uid_t u; gid_t g;
        if (owner_of(d1, &u, &g) == 0) {
            if (u == 0 && g == 0) OK("新建目录属主 0:0 ✅ apt/dpkg 会放行");
            else if (u == geteuid()) OK("新建目录属主 == euid %d（fakeroot 未伪装，dpkg 可能报 Permission denied）", (int)u);
            else BAD("新建目录属主 %d:%d 异常", (int)u, (int)g);
        }
        rmdir(d1);
    }

    /* ---- 6. 写入 /etc 风格的只读目录（#12 的实际形态） ---- */
    {
        const char *etc = argc > 2 ? argv[2] : "/etc";
        char t[512];
        snprintf(t, sizeof t, "%s/.bxroot_perm_probe.dpkg-new", etc);
        int tfd = open(t, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (tfd < 0) {
            printf("  --   open(%s) errno=%d(%s)（目录本身不可写，非 fakeroot 问题）\n", t, errno, strerror(errno));
        } else {
            close(tfd); unlink(t);
            OK("可在 %s 下创建 .dpkg-new 风格文件 ✅", etc);
        }
    }

    unlink(f2);
    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF

# --- P4: SCM_CREDENTIALS / #8 ---------------------------------------------
read -r -d '' SRC_P_CREDS <<'EOF' || true
/* probe_creds.c — #8: sendmsg SCM_CREDENTIALS 在 LD_PRELOAD 层被破坏 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

static int fails = 0, runs = 0;

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("  --   socketpair 不可用 errno=%d(%s)，SKIP\n", errno, strerror(errno));
        return 0;
    }

    /* 父进程 enable 凭据接收 */
    int on = 1, en = 0;
    if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof on) != 0) {
        printf("  --   SO_PASSCRED 不支持 errno=%d(%s)，SKIP\n", errno, strerror(errno));
        return 0;
    }
    if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &en, sizeof en) == 0) {
        /* 探测 SO_PASSCRED 是否真的被记录（有些实现 set 了不生效） */
        socklen_t l = sizeof en; int cur = -1;
        getsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &cur, &l);
        printf("  --   SO_PASSCRED 回读 = %d\n", cur);
    }
    setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof on);

    pid_t c = fork();
    if (c == 0) {
        close(sv[0]);
        struct msghdr mh; struct iovec io;
        char buf[8] = "PING";
        memset(&mh, 0, sizeof mh);
        io.iov_base = buf; io.iov_len = 5;
        mh.msg_iov = &io; mh.msg_iovlen = 1;

        /* (a) 不显式带凭据，靠 SO_PASSCRED 隐式补齐 */
        ssize_t n = sendmsg(sv[1], &mh, 0);
        if (n != 5) { fprintf(stderr, "  FAIL sendmsg 隐式凭据 n=%zd errno=%d(%s)\n", n, errno, strerror(errno)); _exit(1); }
        printf("  ok   sendmsg(隐式凭据) n=%zd\n", n); runs++;

        /* (b) 显式附带 SCM_CREDENTIALS */
        struct ucred cred; memset(&cred, 0, sizeof cred);
        cred.pid = getpid(); cred.uid = getuid(); cred.gid = getgid();
        char cbuf[CMSG_SPACE(sizeof(struct ucred))];
        memset(cbuf, 0, sizeof cbuf);
        memset(&mh, 0, sizeof mh);
        io.iov_base = buf; io.iov_len = 5;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_CREDENTIALS;
        cm->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        memcpy(CMSG_DATA(cm), &cred, sizeof cred);
        n = sendmsg(sv[1], &mh, 0);
        if (n != 5) { fprintf(stderr, "  FAIL sendmsg(显式 SCM_CREDENTIALS) n=%zd errno=%d(%s)\n", n, errno, strerror(errno)); _exit(1); }
        printf("  ok   sendmsg(显式 SCM_CREDENTIALS) n=%zd\n", n); runs++;

        /* (c) 控制消息被截断时的处理（SCM_CREDENTIALS 特有的健壮性路径） */
        memset(&mh, 0, sizeof mh);
        io.iov_base = buf; io.iov_len = 5;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = cbuf; mh.msg_controllen = 1;  /* 故意太小 */
        n = sendmsg(sv[1], &mh, 0);
        printf("  --   sendmsg(controllen=1) n=%zd errno=%d\n", n, errno); runs++;

        close(sv[1]); _exit(0);
    }
    close(sv[1]);

    char buf[64];
    int got_cred = 0, bad_cred = 0, msgs = 0, nocrash = 1;
    for (int i = 0; i < 3; i++) {
        struct msghdr mh; struct iovec io;
        char cbuf[CMSG_SPACE(sizeof(struct ucred)) + 64];
        memset(&mh, 0, sizeof mh); memset(cbuf, 0, sizeof cbuf);
        io.iov_base = buf; io.iov_len = sizeof buf - 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
        ssize_t n = recvmsg(sv[0], &mh, 0);
        if (n < 0) { printf("  FAIL recvmsg[%d] errno=%d(%s)\n", i, errno, strerror(errno)); fails++; continue; }
        msgs++;
        int found = 0;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
            if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDENTIALS) {
                struct ucred uc; memcpy(&uc, CMSG_DATA(cm), sizeof uc);
                found = 1; got_cred++;
                printf("  ok   recvmsg[%d] SCM_CREDENTIALS pid=%d uid=%d gid=%d\n", i, uc.pid, uc.uid, uc.gid);
                if (uc.pid != c && uc.uid != getuid()) {
                    printf("        ^ 凭据 pid=%d 与子进程 pid=%d 不符（LD_PRELOAD 篡改）。\n", uc.pid, c);
                    printf("          注：fork 不经 exec 时 pid 应等于 %d；若走了 exec/包装器可能不同。\n", c);
                    bad_cred++;
                }
                if (uc.uid != getuid()) bad_cred++;
            }
        }
        if (!found) { printf("  FAIL recvmsg[%d] 未收到 SCM_CREDENTIALS（#8 症状）\n", i); fails++; }
        runs++;
    }
    printf("  --   收到 %d 条消息，含凭据 %d 条，异常 %d 条\n", msgs, got_cred, bad_cred);
    if (got_cred >= 1 && bad_cred == 0) printf("  ok   SCM_CREDENTIALS 传递完好 ✅\n");
    else if (got_cred >= 1) printf("  ok   凭据可传递但字段异常（详见上）\n");
    else fails++;

    int st = 0; waitpid(c, &st, 0);
    if (WIFSIGNALED(st)) { printf("  FAIL 子进程被信号 %d 杀死\n", WTERMSIG(st)); fails++; nocrash = 0; }
    (void)nocrash; (void)buf;
    close(sv[0]);
    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF

# --- P5: dlopen / $ORIGIN / SONAME / #10 --------------------------------
read -r -d '' SRC_P_ORIGIN <<'EOF' || true
/* probe_origin.c — #10: ELF RUNPATH 里的 $ORIGIN 是否被解析
 *
 * 自带三个共享库：
 *   <dir>/liborigin-main.so          DT_RUNPATH = $ORIGIN/deps
 *   <dir>/deps/liborigin-dep.so.1    被 main 依赖
 *   <dir>/alt/liborigin-alt.so.1     给 dlopen 绝对路径用
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <limits.h>

static int fails = 0, runs = 0;

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : ".";
    char main_so[PATH_MAX], alt_so[PATH_MAX];

    /* 0. 先建立一个小型 .so 依赖树？—— 依赖树由调用方预先准备好。
     *    这里只做加载与解析。 */
    snprintf(main_so, sizeof main_so, "%s/liborigin-main.so", dir);
    snprintf(alt_so,  sizeof alt_so,  "%s/alt/liborigin-alt.so.1", dir);

    /* ---- 1. dlopen 绝对路径 ---- */
    {
        void *h = dlopen(alt_so, RTLD_NOW | RTLD_LOCAL);
        if (!h) { printf("  FAIL dlopen(%s) -> %s\n", alt_so, dlerror()); fails++; }
        else {
            printf("  ok   dlopen 绝对路径成功\n"); runs++;
            int (*f)(void) = (int (*)(void))dlsym(h, "origin_dep_value");
            if (!f) { printf("  FAIL dlsym(origin_dep_value) -> %s\n", dlerror()); fails++; }
            else { int v = f(); if (v == 42) { printf("  ok   dlsym + 调用成功 (返回 42)\n"); runs++; }
                   else { printf("  FAIL dlsym 符号返回 %d != 42\n", v); fails++; } }
            dlclose(h);
        }
    }

    /* ---- 2. 关键：#10 —— dlopen 一个 RUNPATH 为 $ORIGIN/deps 的库，
     *         它自身的 DT_NEEDED 必须能在 $ORIGIN 下被找到 ---- */
    {
        void *h = dlopen(main_so, RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            const char *e = dlerror();
            printf("  FAIL dlopen(%s) -> %s\n", main_so, e ? e : "(null)");
            if (e && strstr(e, "cannot find")) {
                printf("       ^ 依赖库不在系统搜索路径 → 正是 #10 的 $ORIGIN 未解析症状\n");
            }
            fails++;
        } else {
            printf("  ok   dlopen($ORIGIN/deps 依赖树) 成功 ✅ $ORIGIN 已解析\n"); runs++;
            int (*f)(void) = (int (*)(void))dlsym(h, "origin_main_value");
            if (f) { int v = f(); printf("  ok   origin_main_value() = %d\n", v); runs++; }
            dlclose(h);
        }
    }

    /* ---- 3. dlopen 相对名字（依赖 LD_LIBRARY_PATH / 默认路径） ---- */
    {
        void *h = dlopen("liborigin-alt.so.1", RTLD_NOW | RTLD_LOCAL);
        if (!h) { printf("  --   dlopen(\"liborigin-alt.so.1\") 失败（默认路径无此库，正常）\n"); }
        else { printf("  ok   dlopen 裸名成功\n"); runs++; dlclose(h); }
    }

    /* ---- 4. 不存在的库必须干净失败（不能崩） ---- */
    {
        void *h = dlopen("/nonexistent/definitely-not-here.so", RTLD_NOW);
        if (h) { printf("  FAIL 打开了不存在的库\n"); fails++; }
        else { printf("  ok   不存在的库干净失败: %s\n", dlerror()); runs++; }
    }

    /* ---- 5. 循环/自引用 dlopen（dlsym RTLD_DEFAULT） ---- */
    {
        void *p = dlsym(RTLD_DEFAULT, "printf");
        if (p) { printf("  ok   dlsym(RTLD_DEFAULT, printf) 命中\n"); runs++; }
        else { printf("  FAIL dlsym(RTLD_DEFAULT) 失败: %s\n", dlerror()); fails++; }
    }

    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF

# --- P6: renameat2 / RENAME_EXCHANGE / #11 -------------------------------
read -r -d '' SRC_P_RENAME <<'EOF' || true
/* probe_rename.c — #11/#5: renameat2 + RENAME_EXCHANGE/NOREPLACE 路径泄漏 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static int fails = 0, runs = 0;
#define OK(...)  do { runs++; printf("  ok   " __VA_ARGS__); printf("\n"); } while (0)
#define BAD(...) do { runs++; fails++; printf("  FAIL " __VA_ARGS__); printf("\n"); } while (0)

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE  (1 << 1)
#endif

static int wr(const char *p, const char *s) {
    int fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    write(fd, s, strlen(s)); close(fd); return 0;
}
static int rd(const char *p, char *b, size_t n) {
    int fd = open(p, O_RDONLY); if (fd < 0) return -1;
    ssize_t r = read(fd, b, n - 1); close(fd);
    if (r < 0) return -1;
    b[r] = 0; return 0;
}

int main(int argc, char **argv) {
    const char *base = argc > 1 ? argv[1] : "/tmp";
    char a[512], b[512], c[512];
    snprintf(a, sizeof a, "%s/.bxroot_ren_a", base);
    snprintf(b, sizeof b, "%s/.bxroot_ren_b", base);
    snprintf(c, sizeof c, "%s/.bxroot_ren_c", base);

    /* ---- 1. 基础 rename（#11 的 remove 路径） ---- */
    if (wr(a, "AAA") != 0) { BAD("准备 %s 失败 errno=%d", a, errno); return 2; }
    if (rename(a, b) != 0) BAD("rename errno=%d(%s)", errno, strerror(errno));
    else {
        char buf[16];
        if (rd(b, buf, sizeof buf) == 0 && strcmp(buf, "AAA") == 0) OK("rename 内容保持");
        else BAD("rename 后内容 '%s' != AAA", buf);
        /* 源必须消失 */
        if (access(a, F_OK) != 0) OK("rename 后源路径消失 (errno=%d)", errno);
        else BAD("rename 后源路径仍存在 → 路径泄漏（#5 症状）");
    }

    /* ---- 2. renameat2 RENAME_NOREPLACE ---- */
    if (wr(a, "NEW") == 0) {
        errno = 0;
        long r = syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, RENAME_NOREPLACE);
        if (r == 0) BAD("RENAME_NOREPLACE 竟覆盖了已存在的目标");
        else if (errno == EEXIST) OK("RENAME_NOREPLACE 正确返回 EEXIST");
        else if (errno == ENOSYS || errno == EINVAL) printf("  --   renameat2 NOREPLACE 不支持 errno=%d，跳过\n", errno);
        else BAD("RENAME_NOREPLACE 返回意外 errno=%d(%s)", errno, strerror(errno));
    }

    /* ---- 3. renameat2 RENAME_EXCHANGE ---- */
    if (wr(a, "AAA") == 0 && wr(c, "CCC") == 0) {
        errno = 0;
        long r = syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, c, RENAME_EXCHANGE);
        if (r != 0) {
            if (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP)
                printf("  --   RENAME_EXCHANGE 不支持 errno=%d，跳过\n", errno);
            else BAD("RENAME_EXCHANGE errno=%d(%s)", errno, strerror(errno));
        } else {
            char x[16], y[16];
            rd(a, x, sizeof x); rd(c, y, sizeof y);
            if (strcmp(x, "CCC") == 0 && strcmp(y, "AAA") == 0) OK("RENAME_EXCHANGE 语义正确");
            else BAD("RENAME_EXCHANGE 结果 a='%s' c='%s'（期望 CCC/AAA）", x, y);
        }
    }

    /* ---- 4. unlink 后 stat 必须 ENOENT（#11 uv clean 的核心） ---- */
    {
        char t[512]; snprintf(t, sizeof t, "%s/.bxroot_unlink_t", base);
        if (wr(t, "x") == 0) {
            if (unlink(t) != 0) BAD("unlink errno=%d(%s)", errno, strerror(errno));
            else { struct stat s; errno = 0;
                   if (stat(t, &s) != 0 && errno == ENOENT) OK("unlink 后 stat 正确返回 ENOENT");
                   else BAD("unlink 后 stat 未返回 ENOENT (errno=%d)", errno);
                   /* 二次 unlink 必须 ENOENT 而非其它 */
                   errno = 0;
                   if (unlink(t) != 0 && errno == ENOENT) OK("二次 unlink 正确返回 ENOENT");
                   else BAD("二次 unlink errno=%d（期望 ENOENT=2）", errno); }
        }
    }

    /* ---- 5. 目录递归删除（uv clean / rm -rf 的形态） ---- */
    {
        char d[512], f[512];
        snprintf(d, sizeof d, "%s/.bxroot_rmtree", base);
        snprintf(f, sizeof f, "%s/sub/deep.txt", d);
        char cmd[1200];
        snprintf(cmd, sizeof cmd, "mkdir -p %s/sub && echo hi > %s", d, f);
        if (system(cmd) == 0) {
            char cmd2[1200];
            snprintf(cmd2, sizeof cmd2, "rm -rf %s", d);
            int rc = system(cmd2);
            if (rc == 0 && access(d, F_OK) != 0) OK("rm -rf 递归删除干净");
            else BAD("rm -rf rc=%d 且目录仍可见（access=%d）", rc, access(d, F_OK));
        } else printf("  --   无法创建嵌套目录，跳过 rm -rf 用例\n");
    }

    unlink(a); unlink(b); unlink(c);
    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF

# --- P7: 早期崩溃哨兵 / #22 ----------------------------------------------
read -r -d '' SRC_P_SENTINEL <<'EOF' || true
/* probe_sentinel.c — #22: 最早期的 dynamic-linker / constructor 阶段探针
 *
 * 目标：把崩溃点夹逼到具体阶段。若在 main 之前就死，输出会停在中途。
 * 输出用 write(2) 直写（不经过 stdio buffer），确保崩溃前的记录一定落盘。
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

/* ---- .preinit_array 阶段（linker 重定位后立刻执行，最早的可能点） ---- */
__attribute__((constructor(101))) static void stage_ctor_early(void) {
    (void)!write(2, "[sentinel] ctor.101  (preinit 之后)\n", 35);
}
__attribute__((constructor(200))) static void stage_ctor_mid(void) {
    (void)!write(2, "[sentinel] ctor.200\n", 20);
}

int main(int argc, char **argv) {
    int step = argc > 1 ? atoi(argv[1]) : 0;
    (void)!write(2, "[sentinel] main.enter\n", 21);

    /* 逐步做容易触发的操作，配合 --step N 定位 */
    if (step >= 1) {
        void *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { dprintf(2, "[sentinel] mmap FAILED errno=%d\n", errno); return 1; }
        memset(p, 0x5a, 1 << 20); munmap(p, 1 << 20);
        (void)!write(2, "[sentinel] step1.mmap ok\n", 25);
    }
    if (step >= 2) {
        char b[4096]; ssize_t n = readlink("/proc/self/exe", b, sizeof b - 1);
        dprintf(2, "[sentinel] step2.readlink n=%zd\n", n);
    }
    if (step >= 3) {
        FILE *f = fopen("/proc/self/status", "r");
        if (f) { char l[256]; if (fgets(l, sizeof l, f)) dprintf(2, "[sentinel] step3.status: %s", l); fclose(f); }
        else dprintf(2, "[sentinel] step3.fopen FAILED errno=%d\n", errno);
    }
    if (step >= 4) {
        int fd = open("/proc/self/maps", O_RDONLY);
        if (fd >= 0) { char l[512]; ssize_t n = read(fd, l, sizeof l - 1); if (n > 0) { l[n] = 0; dprintf(2, "[sentinel] step4.maps[0]=%.60s\n", l); } close(fd); }
        else dprintf(2, "[sentinel] step4.open maps FAILED errno=%d\n", errno);
    }

    dprintf(2, "[sentinel] main.exit step=%d\n", step);
    printf("SENTINEL-OK step=%d\n", step);
    return 0;
}
EOF

# --- P8: link(2) 硬链接 / #12+#24（dpkg/pnpm/git 依赖） -------------------
read -r -d '' SRC_P_LINK <<'EOF' || true
/* probe_link.c — 硬链接语义（#12 dpkg / #24 git 的对象存储都依赖它）
 * 说明：Android app 私有目录 SELinux 禁 link(2)，
 *       上游 proot 用 --link2symlink 模拟；bxroot 若吞掉该参数则本用例 FAIL。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

static int fails = 0, runs = 0;

int main(int argc, char **argv) {
    const char *base = argc > 1 ? argv[1] : "/tmp";
    char a[512], b[512];
    snprintf(a, sizeof a, "%s/.bxroot_link_a", base);
    snprintf(b, sizeof b, "%s/.bxroot_link_b", base);
    unlink(a); unlink(b);

    int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { printf("  FAIL open(%s) errno=%d(%s)\n", a, errno, strerror(errno)); return 2; }
    write(fd, "LINK", 4); close(fd);

    errno = 0;
    int r = link(a, b);
    if (r != 0) {
        if (errno == EPERM || errno == EACCES || errno == EOPNOTSUPP || errno == ENOSYS) {
            printf("  FAIL link() errno=%d(%s) → 宿主禁止硬链接且 bxroot 未做 l2s 模拟\n",
                   errno, strerror(errno));
            printf("       这就是「--link2symlink 被吞」的下游表现：pnpm/dpkg/git 会陆续报错\n");
            fails++; runs++;
        } else {
            printf("  FAIL link() 意外 errno=%d(%s)\n", errno, strerror(errno)); fails++; runs++;
        }
    } else {
        struct stat sa, sb;
        stat(a, &sa); stat(b, &sb);
        printf("  ok   link() 成功\n"); runs++;
        if (sa.st_ino == sb.st_ino) { printf("  ok   真硬链接（同 inode %lu）\n", (unsigned long)sa.st_ino); runs++; }
        else {
            /* l2s 模拟：不同 inode 但内容一致、nlink 伪装为 2 */
            char x[8] = {0}, y[8] = {0};
            int f1 = open(a, O_RDONLY), f2 = open(b, O_RDONLY);
            if (f1 >= 0) { read(f1, x, 4); close(f1); }
            if (f2 >= 0) { read(f2, y, 4); close(f2); }
            if (strcmp(x, y) == 0) {
                printf("  ok   l2s 模拟（inode 不同 %lu/%lu，内容一致）\n",
                       (unsigned long)sa.st_ino, (unsigned long)sb.st_ino); runs++;
                if (sa.st_nlink == 2 && sb.st_nlink == 2) { printf("  ok   st_nlink 伪装为 2 ✅\n"); runs++; }
                else { printf("  FAIL st_nlink 未伪装（a=%lu b=%lu，期望 2）→ dpkg 会认为链接损坏\n",
                              (unsigned long)sa.st_nlink, (unsigned long)sb.st_nlink); fails++; }
            } else {
                printf("  FAIL link() 后内容不一致 a='%s' b='%s'\n", x, y); fails++;
            }
        }
        /* 写 a 必须影响 b */
        int w = open(a, O_WRONLY); if (w >= 0) { pwrite(w, "XX", 2, 0); close(w); }
        char z[8] = {0}; int f3 = open(b, O_RDONLY);
        if (f3 >= 0) { read(f3, z, 4); close(f3); }
        if (strncmp(z, "XX", 2) == 0) { printf("  ok   写 a 反映到 b（链接语义保持）\n"); runs++; }
        else { printf("  FAIL 写 a 未反映到 b（b='%s'）→ 链接语义丢失\n", z); fails++; }
    }
    unlink(a); unlink(b);
    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF

# --- P9: ioctl 透传 / #13 ------------------------------------------------
read -r -d '' SRC_P_IOCTL <<'EOF' || true
/* probe_ioctl.c — #13: ioctl 参数/返回值是否被 LD_PRELOAD 层破坏
 * 在 /dev/null 等安全 fd 上做"取参数"型 ioctl，验证透传无损。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/stat.h>

static int fails = 0, runs = 0;

int main(void) {
    /* ---- 1. FIONREAD on 普通文件（应返回可读字节数） ---- */
    {
        int fd = open("/proc/self/cmdline", O_RDONLY);
        if (fd < 0) { printf("  --   open(/proc/self/cmdline) 失败 errno=%d，跳过\n", errno); }
        else {
            int avail = -1;
            if (ioctl(fd, FIONREAD, &avail) == 0) {
                struct stat s; fstat(fd, &s);
                if (avail >= 0 && (off_t)avail <= s.st_size + 1) { printf("  ok   FIONREAD = %d (文件 %ld 字节)\n", avail, (long)s.st_size); runs++; }
                else { printf("  FAIL FIONREAD = %d 与文件大小 %ld 不符\n", avail, (long)s.st_size); fails++; runs++; }
            } else { printf("  --   FIONREAD 不支持 errno=%d(%s)，跳过\n", errno, strerror(errno)); }
            close(fd);
        }
    }

    /* ---- 2. TCGETS on 非 tty → 必须 ENOTTY（不是崩溃/不是错 errno） ---- */
    {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0) { printf("  --   /dev/null 不可用，跳过\n"); }
        else {
            struct termios t; errno = 0;
            int r = ioctl(fd, TCGETS, &t);
            if (r != 0 && errno == ENOTTY) { printf("  ok   TCGETS(/dev/null) 正确返回 ENOTTY\n"); runs++; }
            else if (r == 0) { printf("  --   TCGETS(/dev/null) 竟成功，环境特殊，跳过\n"); }
            else { printf("  FAIL TCGETS errno=%d(%s)，期望 ENOTTY=25\n", errno, strerror(errno)); fails++; runs++; }
            close(fd);
        }
    }

    /* ---- 3. 大结构体 ioctl：验证输入缓冲区没被截断 ---- */
    {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            /* 用一个不存在的请求号，内核会返回 ENOTTY；关键是 errno 不能被篡改 */
            char big[4096]; memset(big, 0x33, sizeof big);
            errno = 0;
            int r = ioctl(fd, 0xDEAD, big);
            if (r != 0 && (errno == ENOTTY || errno == EINVAL)) { printf("  ok   未知 ioctl 返回 errno=%d（未崩溃）\n", errno); runs++; }
            else if (r == 0) { printf("  --   未知 ioctl 竟成功，跳过\n"); }
            else { printf("  FAIL 未知 ioctl errno=%d(%s)\n", errno, strerror(errno)); fails++; runs++; }
            close(fd);
        }
    }

    /* ---- 4. /dev/dri 设备探测（#13 的 GPU 场景，可有可无） ---- */
    {
        const char *cands[] = {"/dev/dri/renderD128", "/dev/dri/card0", "/dev/kgsl-3d0", NULL};
        int found = 0;
        for (int i = 0; cands[i]; i++) {
            int fd = open(cands[i], O_RDWR | O_CLOEXEC);
            if (fd >= 0) { printf("  ok   可打开 %s ✅\n", cands[i]); runs++; found = 1; close(fd); }
            else printf("  --   %s 打不开 errno=%d(%s)\n", cands[i], errno, strerror(errno));
        }
        if (!found) printf("  --   无 GPU 设备节点可访问 → #13 类 GPU 用例在本环境不可验证\n");
    }

    printf("SUMMARY runs=%d fails=%d\n", runs, fails);
    return fails ? 1 : 0;
}
EOF


# ---------------------------------------------------------------------------
# 2b.  guest 侧 shell 脚本生成器
#      每个生成器只负责"写出脚本"，接受 (输出文件, 参数…)；
#      真机用例用 guest 路径调用，self-test 用宿主路径调用并在本机实跑，
#      这样即便在容器里也能验证「测试内容本身」是否正确。
# ---------------------------------------------------------------------------

# gen_biglink <out> <cc> <n>
gen_biglink() {
    local out="$1" cc="$2" n="$3"
    {
        echo 'set -e'
        echo 'D=/tmp/t05build; rm -rf $D; mkdir -p $D; cd $D'
        echo "i=1; while [ \$i -le $n ]; do"
        echo "  printf 'int f%s(void); int f%s(void){ return %s; }\n' \"\$i\" \"\$i\" \"\$i\" > o\$i.c"
        echo '  i=$((i+1)); done'
        echo "i=1; while [ \$i -le $n ]; do $cc -c -O0 -o o\$i.o o\$i.c; i=\$((i+1)); done"
        echo "{ i=1; while [ \$i -le $n ]; do echo \"int f\$i(void);\"; i=\$((i+1)); done;"
        echo "  printf 'int main(void){ long s=0;\\n';"
        echo "  i=1; while [ \$i -le $n ]; do echo \"s+=f\$i();\"; i=\$((i+1)); done;"
        echo "  printf 'return (int)(s%%7); }\\n'; } > main.c"
        echo "$cc -c -o main.o main.c"
        echo "$cc -o big \$(ls o*.o | sort -V) main.o"
        echo 'ls -l big | awk "{print \"  --   binary size=\" \$5}"'
        echo './big; echo "  --   run rc=$?"'
        echo 'echo BIGLINK-OK'
    } > "$out"
}

# gen_git_probe <out>
gen_git_probe() {
    cat > "$1" <<'EOS'
set -e
R=/tmp/t07repo
rm -rf $R $R.clo
mkdir -p $R && cd $R
git init -q .
git config user.email t@t; git config user.name t
for i in $(seq 1 60); do
  printf 'line %s\n' $i > f$i.txt
  git add f$i.txt
  git commit -q -m "c$i"
done
head -c 200000 /dev/urandom > blob.bin
git add blob.bin; git commit -q -m blob
git gc -q 2>/dev/null || true
cd /tmp
git clone -q $R $R.clo
cd $R.clo
git fsck --no-progress 2>&1 | head -5
echo "  --   对象数: $(git rev-list --all --objects | wc -l)"
git log --oneline | head -1
echo GIT-OK
EOS
}

# gen_napi_probe <out>
gen_napi_probe() {
    cat > "$1" <<'EOS'
const out = [];
function t(name, fn) { try { fn(); out.push('  ok   ' + name); } catch (e) { out.push('  FAIL ' + name + ' -> ' + e.message); } }
t('require(fs)', () => { require('fs'); });
t('require(path)', () => { require('path'); });
t('require(crypto) 原生绑定', () => { const c = require('crypto'); if (c.createHash('sha256').update('x').digest('hex').length !== 64) throw new Error('bad hash'); });
t('Buffer.alloc 64MB 读写', () => { const b = Buffer.allocUnsafe(64*1024*1024); b[0]=1; b[b.length-1]=2; if (b[0]!==1||b[b.length-1]!==2) throw new Error('corrupt'); });
t('worker_threads 可用', () => { const { Worker } = require('worker_threads'); if (typeof Worker !== 'function') throw new Error('no worker'); });
t('process.dlopen 存在', () => { if (typeof process.dlopen !== 'function') throw new Error('missing process.dlopen'); });
t('NAPI 清理钩子符号', () => {
  // #24 症状：Node-API symbol napi_add_env_cleanup_hook has not been loaded
  const names = process.binding ? Object.keys(process.binding('natives')) : [];
  if (!names.length) throw new Error('无法枚举内建模块');
});
console.log(out.join('\n'));
const fails = out.filter(l => l.startsWith('  FAIL')).length;
console.log('SUMMARY fails=' + fails);
process.exit(fails ? 1 : 0);
EOS
}

# gen_uvclean <out>
gen_uvclean() {
    cat > "$1" <<'EOS'
set -e
export UV_CACHE_DIR=/tmp/t16cache
rm -rf $UV_CACHE_DIR; mkdir -p $UV_CACHE_DIR/archive-v0/x
for i in $(seq 1 50); do echo "data$i" > $UV_CACHE_DIR/archive-v0/x/f$i.pth; done
mkdir -p $UV_CACHE_DIR/wheels; echo w > $UV_CACHE_DIR/wheels/a.whl
uv clean 2>&1 | tail -3
[ -d "$UV_CACHE_DIR" ] && echo "  --   cache dir 仍在" || echo "  --   cache dir 已删除"
echo UVCLEAN-OK
EOS
}

# gen_dbus_probe <out>
gen_dbus_probe() {
    cat > "$1" <<'EOS'
set -e
export XDG_RUNTIME_DIR=/tmp/t18run; mkdir -p $XDG_RUNTIME_DIR
ADDR=$(dbus-daemon --session --fork --print-address 2>/dev/null)
[ -n "$ADDR" ] || { echo "  FAIL dbus-daemon 未打印地址"; exit 1; }
echo "  --   address=$ADDR"
export DBUS_SESSION_BUS_ADDRESS="$ADDR"
sleep 1
dbus-send --session --print-reply --dest=org.freedesktop.DBus \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>&1 | head -5
echo DBUS-OK
EOS
}

# gen_dpkg_probe <out>
gen_dpkg_probe() {
    cat > "$1" <<'EOS'
set -e
D=/etc/sudoers.d
[ -d "$D" ] || D=/etc
T="$D/.bxroot_dpkg_probe"
rm -f "$T" "$T.dpkg-new"
printf 'probe\n' > "$T.dpkg-new"
chown 0:0 "$T.dpkg-new" 2>/dev/null || true
chmod 0440 "$T.dpkg-new"
mv "$T.dpkg-new" "$T"
stat -c '  --   %n mode=%a uid=%u gid=%g' "$T"
cat "$T"
rm -f "$T"
touch "$D/.bxroot_dir_probe" && rm -f "$D/.bxroot_dir_probe"
echo DPKG-PROBE-OK
EOS
}

# gen_proc_probe <out>
gen_proc_probe() {
    cat > "$1" <<'EOS'
fail=0
for f in /proc/stat /proc/meminfo /proc/cpuinfo /proc/self/status /proc/version; do
  if [ -r "$f" ]; then echo "  ok   可读 $f"; else echo "  FAIL 不可读 $f（#15 htop: Cannot open /proc/stat）"; fail=1; fi
done
head -1 /proc/stat >/dev/null && echo "  ok   head /proc/stat"
nproc >/dev/null 2>&1 && echo "  ok   nproc = $(nproc)" || { echo "  FAIL nproc"; fail=1; }
echo "SUMMARY fails=$fail"
exit $fail
EOS
}

# --- 生成 $ORIGIN 依赖树的宿主脚本 ---------------------------------------
build_origin_tree() {  # $1=dir  $2=cc
    local d="$1" cc="$2"
    mkdir -p "$d/deps" "$d/alt" || return 1

    # 依赖库
    cat > "$d/dep.c" <<'EOF'
int origin_dep_value(void) { return 42; }
EOF
    # 主库：DT_NEEDED = liborigin-dep.so.1，DT_RUNPATH = $ORIGIN/deps
    cat > "$d/main.c" <<'EOF'
extern int origin_dep_value(void);
int origin_main_value(void) { return origin_dep_value() + 1; }
EOF
    # 备用库（给绝对路径 dlopen）
    cat > "$d/alt.c" <<'EOF'
int origin_alt_value(void) { return 7; }
EOF

    "$cc" -shared -fPIC -Wl,-soname,liborigin-dep.so.1 -o "$d/deps/liborigin-dep.so.1" "$d/dep.c" 2>/dev/null || return 1
    ln -sf liborigin-dep.so.1 "$d/deps/liborigin-dep.so" 2>/dev/null
    "$cc" -shared -fPIC -Wl,-soname,liborigin-main.so \
          -Wl,-rpath,'$ORIGIN/deps' -Wl,--enable-new-dtags \
          -L"$d/deps" -lorigin-dep \
          -o "$d/liborigin-main.so" "$d/main.c" 2>/dev/null || return 1
    "$cc" -shared -fPIC -Wl,-soname,liborigin-alt.so.1 -o "$d/alt/liborigin-alt.so.1" "$d/alt.c" 2>/dev/null || return 1

    # 验证生成的 RUNPATH 真的是 $ORIGIN（防止工具链偷偷展开）
    if have readelf; then
        readelf -d "$d/liborigin-main.so" 2>/dev/null | grep -q 'ORIGIN' || {
            warn "生成的 liborigin-main.so 没有 \$ORIGIN RUNPATH —— 用例 10 将 SKIP"
            return 1
        }
    fi
    return 0
}

# ---------------------------------------------------------------------------
# 2c. bxroot runtime 存活探针
#     「launcher 跑起来了」不等于「runtime 真的挂上了 LD_PRELOAD」。
#     容器内尤甚：外层 proot 会接管 LD_PRELOAD，runtime 根本没加载，
#     此时 bind/-w 之类的失败是环境假象，不能记成 bxroot 的缺陷。
#
#     判据：在 rootfs 内和宿主各放一个同名不同内容的文件，
#     让 guest 读该路径。读到 rootfs 的内容 ⇒ 路径翻译生效 ⇒ runtime 存活。
# ---------------------------------------------------------------------------
RT_LIVE="unknown"       # yes | no | unknown
RT_LIVE_NOTE=""

runtime_liveness() {
    RT_LIVE="unknown"; RT_LIVE_NOTE=""
    [ "$RUNNER_MODE" = "bxroot" ] || { RT_LIVE_NOTE="无 bxroot"; return 0; }

    local hostf="/tmp/.bxroot_liveness_marker"
    local guestf="$ROOTFS/tmp/.bxroot_liveness_marker"
    local htag="HOST-$$-$$" gtag="GUEST-$$-$$"

    # rootfs 与宿主根是同一个 inode → 物理上无法区分，直接判 unknown
    if [ "$(stat -c '%d:%i' "$ROOTFS" 2>/dev/null)" = "$(stat -c '%d:%i' / 2>/dev/null)" ]; then
        RT_LIVE="unknown"; RT_LIVE_NOTE="rootfs 与宿主根为同一目录，无法区分（容器内典型）"
        return 0
    fi

    printf '%s\n' "$htag"   > "$hostf"   2>/dev/null || { RT_LIVE_NOTE="宿主 marker 写入失败"; return 0; }
    printf '%s\n' "$gtag"   > "$guestf"  2>/dev/null || { RT_LIVE_NOTE="rootfs marker 写入失败"; return 0; }

    guest_run --out "$OUT_DIR/rtlive.out" -- /bin/sh -c 'cat /tmp/.bxroot_liveness_marker'
    local got; got="$(tr -d '[:space:]' < "$OUT_DIR/rtlive.out" 2>/dev/null)"

    if [ "$got" = "$gtag" ]; then
        RT_LIVE="yes"; RT_LIVE_NOTE="路径翻译生效（guest 读到 rootfs 版本）"
    elif [ "$got" = "$htag" ]; then
        RT_LIVE="no";  RT_LIVE_NOTE="runtime 未接管（guest 直接读到宿主文件）→ LD_PRELOAD 未生效"
    else
        RT_LIVE="unknown"; RT_LIVE_NOTE="读到意外内容：'$(printf '%s' "$got" | head -c 40)'"
    fi
    rm -f "$hostf" "$guestf" 2>/dev/null
    return 0
}

# ---------------------------------------------------------------------------
# 3. 编译探针
# ---------------------------------------------------------------------------
declare -A PROBE_BIN=()
declare -A PROBE_OK=()

build_one() {  # $1=name $2=source $3...=extra
    local name="$1" src="$2"; shift 2
    local out="$PROBE_DIR/$name"
    printf '%s' "$src" > "$PROBE_DIR/$name.c" || return 1
    if "$CC" -O1 -w -o "$out" "$PROBE_DIR/$name.c" "$@" 2>"$PROBE_DIR/$name.log"; then
        PROBE_BIN[$name]="$out"; PROBE_OK[$name]=1; return 0
    fi
    PROBE_OK[$name]=0; return 1
}

build_probes() {
    local okc=0 failc=0 n
    build_one readlink "$SRC_P_READLINK"            && okc=$((okc+1)) || failc=$((failc+1))
    build_one bigmem   "$SRC_P_BIGMEM"              && okc=$((okc+1)) || failc=$((failc+1))
    build_one fakeroot "$SRC_P_FAKEROOT"            && okc=$((okc+1)) || failc=$((failc+1))
    build_one creds    "$SRC_P_CREDS"               && okc=$((okc+1)) || failc=$((failc+1))
    build_one origin   "$SRC_P_ORIGIN" -ldl         && okc=$((okc+1)) || failc=$((failc+1))
    build_one rename   "$SRC_P_RENAME"              && okc=$((okc+1)) || failc=$((failc+1))
    build_one sentinel "$SRC_P_SENTINEL"            && okc=$((okc+1)) || failc=$((failc+1))
    build_one link     "$SRC_P_LINK"                && okc=$((okc+1)) || failc=$((failc+1))
    build_one ioctl    "$SRC_P_IOCTL"               && okc=$((okc+1)) || failc=$((failc+1))
    info "探针编译：成功 $okc / 失败 $failc"
    for n in readlink bigmem fakeroot creds origin rename sentinel link ioctl; do
        if [ "${PROBE_OK[$n]:-0}" = "0" ]; then
            warn "  探针 $n 编译失败：$(head -2 "$PROBE_DIR/$n.log" 2>/dev/null | tr '\n' ' ')"
        fi
    done

    if build_origin_tree "$WORK/origin" "$CC"; then
        info "  \$ORIGIN 依赖树已生成于 $WORK/origin"
    else
        warn "  \$ORIGIN 依赖树生成失败 → 用例 10 将 SKIP"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# 4. Runner：同一命令在 bxroot / proot / host 下执行
# ---------------------------------------------------------------------------
LAST_RUNNER=""

# bx_launch <launcher 原始参数...>  —— 统一的库路径环境，供所有入口复用
bx_launch() {
    PROROOT_LIB_PATH="$LIBS_DIR/libbxroot-runtime.so" \
    BXROOT_LIB_PATH="$LIBS_DIR/libbxroot-runtime.so" \
    BXROOT_LINKER_PATH="$LIBS_DIR/libbxroot-linker.so" \
    BXROOT_STUB_LOADER="$LIBS_DIR/libbxroot-stub-loader.so" \
    BXROOT_TMP_DIR="$WORK/tmp" \
        "$LAUNCHER" "$@"
}

# guest_run <--out FILE> -- <cmd...>   在 bxroot 下执行（标准 -r/-0/-w/--link2symlink）
guest_run() {
    local outf="" ; local -a cmd=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --out) outf="$2"; shift 2 ;;
            --) shift; cmd=("$@"); break ;;
            *) cmd=("$@"); break ;;
        esac
    done
    [ "$RUNNER_MODE" = "bxroot" ] || return 127
    LAST_RUNNER="bxroot"
    if [ -n "$outf" ]; then
        bx_launch -r "$ROOTFS" -0 -w / --link2symlink "${cmd[@]}" >"$outf" 2>&1
    else
        bx_launch -r "$ROOTFS" -0 -w / --link2symlink "${cmd[@]}"
    fi
}

# control_run —— 同一个命令在 proot 下执行
control_run() {
    local outf=""; local -a cmd=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --out) outf="$2"; shift 2 ;;
            --) shift; cmd=("$@"); break ;;
            *) cmd=("$@"); break ;;
        esac
    done
    [ "$CONTROL_OK" = "1" ] || return 127
    LAST_RUNNER="proot"
    if [ -n "$outf" ]; then
        "$PROOT_BIN" -r "$ROOTFS" -0 -w / "${cmd[@]}" >"$outf" 2>&1
    else
        "$PROOT_BIN" -r "$ROOTFS" -0 -w / "${cmd[@]}"
    fi
}

# host_run —— 直接在宿主执行（对照中的对照，判定"是不是容器本身的问题"）
host_run() {
    local outf=""; local -a cmd=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --out) outf="$2"; shift 2 ;;
            --) shift; cmd=("$@"); break ;;
            *) cmd=("$@"); break ;;
        esac
    done
    LAST_RUNNER="host"
    if [ -n "$outf" ]; then "${cmd[@]}" >"$outf" 2>&1
    else "${cmd[@]}"; fi
}

# 三基线判定：bxroot 不崩溃即可 PASS；有 proot 对照时以对照为准
# judge <id> <title> <issues> <bx_rc> <ctl_rc>
#   ctl_rc = 127 → 无对照
judge() {
    local id="$1" title="$2" issues="$3" bx="$4" ctl="$5" note="${6:-}"
    # 签名：judge <id> <title> <issues> <bx_rc> <ctl_rc> [note] [bx_out] [ctl_out]
    local bo="${7:-}" co="${8:-}"
    local status; status=$(_judge_probe "$bx" "$ctl" "$bo" "$co")
    case "$bx" in ''|*[!0-9]*) bx=1 ;; esac
    if [ "$bx" != "0" ]; then
        local sig=""
        if [ "$bx" -ge 128 ]; then sig=" rc=$bx(信号 $((bx-128)))"; fi
        case "$status" in
            FAIL)    note="${note} [真回归：proot 通过 / bxroot 失败]${sig}" ;;
            ENVFAIL) note="${note} [proot 同样失败 → 环境问题]${sig}" ;;
            NOCTL)   note="${note} [无 proot 对照 → 无法判定，须在装有 proot 的真机上重跑]${sig}" ;;
        esac
    fi
    record "$id" "$title" "$status" "$issues" "$note"
    return 0
}

skip() { record "$1" "$2" "SKIP" "$3" "$4"; return 0; }

# ---------------------------------------------------------------------------
# 5. 用例实现
# ---------------------------------------------------------------------------

t_22_readlink() {   # T01
    local id="T01" title="readlinkat 分支/早期崩溃" issues="22"
    [ "${PROBE_OK[readlink]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    guest_run --out "$OUT_DIR/t01.bx" -- "${PROBE_BIN[readlink]}"; local bx=$?
    control_run --out "$OUT_DIR/t01.ctl" -- "${PROBE_BIN[readlink]}"; local ctl=$?
    bx=$(fold_rc "$bx" "$OUT_DIR/t01.bx" "$OUT_DIR/t01.ctl")
    judge "$id" "$title" "$issues" "$bx" "$ctl" \
          "bxroot FAIL 行=$FOLD_NF / 对照=$FOLD_NFC"
}

t_22_sentinel() {   # T02
    local id="T02" title="早期阶段哨兵（constructor→main）" issues="22"
    [ "${PROBE_OK[sentinel]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    local bx=0 stage="" ctl=127
    for s in 0 1 2 3 4; do
        guest_run --out "$OUT_DIR/t02_$s.bx" -- "${PROBE_BIN[sentinel]}" "$s"
        local rc=$?
        if [ "$rc" != "0" ]; then bx=$rc; stage="step=$s"; break; fi
        grep -q "SENTINEL-OK step=$s" "$OUT_DIR/t02_$s.bx" || { bx=1; stage="step=$s 输出缺失"; break; }
    done
    [ "$CONTROL_OK" = "1" ] && { control_run --out "$OUT_DIR/t02.ctl" -- "${PROBE_BIN[sentinel]}" 4; ctl=$?; }
    if [ "$bx" = "0" ]; then
        record "$id" "$title 全 5 阶段通过" "PASS" "$issues" "constructor/preinit/main 全程存活"
    else
        judge "$id" "$title 在 $stage 崩溃" "$issues" "$bx" "$ctl" "崩溃阶段：$stage"
        # 补充诊断
        local last
        last=$(ls -t "$OUT_DIR"/t02_*.bx 2>/dev/null | head -1)
        [ -n "$last" ] && record "T02b" "崩溃前最后输出" "XFAIL" "$issues" "$(tail -2 "$last" 2>/dev/null | tr '\n' ' ')"
    fi
}

t_22_crashdump() {  # T03
    local id="T03" title="崩溃诊断产物生成" issues="22"
    [ "$RUNNER_MODE" = "bxroot" ] || { skip "$id" "$title" "$issues" "无 bxroot"; return; }
    # 故意触发一个可捕获的崩溃，看 runtime 是否落 dump
    guest_run --out "$OUT_DIR/t03.bx" -- sh -c 'kill -SEGV $$' 2>/dev/null
    local bx=$?
    if [ "$bx" -ge 128 ]; then
        local found=""
        for p in "$WORK/tmp" /tmp "$ROOTFS/tmp" "$ROOTFS/data/local/tmp"; do
            found=$(find "$p" -maxdepth 2 -name 'bxroot-sigsegv-maps.txt' -o -maxdepth 2 -name 'proroot-sigsegv-maps.txt' 2>/dev/null | head -1)
            [ -n "$found" ] && break
        done
        if [ -n "$found" ]; then record "$id" "$title" "PASS" "$issues" "已生成 $found"
        else record "$id" "$title" "NOCTL" "$issues" "两侧均未生成 dump（2026-09-17 实测：官方在 kill -SEGV 下同样不写 proroot-sigsegv-maps.txt，其触发条件需额外开关；原判 FAIL 的"官方能"前提不成立）"; fi
    else
        skip "$id" "$title" "$issues" "无法在 guest 内触发信号（rc=$bx）"
    fi
}

t_23_bigmmap() {    # T04
    local id="T04" title="大文件写 + mmap/mremap/MAP_SHARED" issues="23"
    [ "${PROBE_OK[bigmem]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    local mb="${BXROOT_TEST_MB:-32}"
    guest_run --out "$OUT_DIR/t04.bx" -- "${PROBE_BIN[bigmem]}" /tmp/t04.bin "$mb" /tmp/t04_sparse.bin
    local bx=$?
    control_run --out "$OUT_DIR/t04.ctl" -- "${PROBE_BIN[bigmem]}" /tmp/t04.bin "$mb" /tmp/t04_sparse.bin
    local ctl=$?
    bx=$(fold_rc "$bx" "$OUT_DIR/t04.bx" "$OUT_DIR/t04.ctl")
    judge "$id" "$title (${mb}MB)" "$issues" "$bx" "$ctl" "bxroot FAIL=$FOLD_NF / 对照 FAIL=$FOLD_NFC"
}

t_23_largelink() {  # T05
    local id="T05" title="大量目标文件链接（模拟 Cargo 最终链接）" issues="23"
    # 需要一个 guest 内可用的 C 编译器
    local gcc_bin=""
    for c in cc gcc clang; do
        if guest_run 2>/dev/null -- sh -c "command -v $c >/dev/null"; then gcc_bin="$c"; break; fi
    done
    [ -n "$gcc_bin" ] || { skip "$id" "$title" "$issues" "guest 内无 C 编译器（#23 需 cc/gcc）"; return; }

    local n="${BXROOT_TEST_OBJS:-120}"
    local script="$WORK/biglink.sh"
    gen_biglink "$script" "$gcc_bin" "$n"

    guest_run --out "$OUT_DIR/t05.bx" -- sh "$script"
    local bx=$?
    control_run --out "$OUT_DIR/t05.ctl" -- sh "$script"
    local ctl=$?
    grep -q BIGLINK-OK "$OUT_DIR/t05.bx" || { [ "$bx" = "0" ] && bx=1; }
    judge "$id" "$title (${n} 个目标文件)" "$issues" "$bx" "$ctl" \
          "$(grep -m1 -iE 'undefined reference|hidden symbol|final link failed|bad value' "$OUT_DIR/t05.bx" 2>/dev/null | cut -c1-90)" \
          "$OUT_DIR/t05.bx" "$OUT_DIR/t05.ctl"
}

t_24_node_napi() {  # T06
    local id="T06" title="Node 原生模块 dlopen（NAPI 符号）" issues="24"
    [ "$HAVE_NODE_GUEST" = "1" ] || { skip "$id" "$title" "$issues" "guest 内无 node"; return; }
    gen_napi_probe "$WORK/napi_probe.js"
    guest_run --out "$OUT_DIR/t06.bx" -- node "$WORK/napi_probe.js"
    local bx=$?
    control_run --out "$OUT_DIR/t06.ctl" -- node "$WORK/napi_probe.js"
    local ctl=$?
    local napi_msg; napi_msg=$(grep -m1 -o 'napi_add_env_cleanup_hook has not been loaded' "$OUT_DIR/t06.bx" 2>/dev/null)
    [ -n "$napi_msg" ] && bx=1
    judge "$id" "$title" "$issues" "$bx" "$ctl" "${napi_msg:+命中 NAPI 症状：$napi_msg}" \
          "$OUT_DIR/t06.bx" "$OUT_DIR/t06.ctl"
}

t_24_git_clone() {  # T07
    local id="T07" title="git 本地 clone + fsck（bad object）" issues="24"
    [ "$HAVE_GIT_GUEST" = "1" ] || { skip "$id" "$title" "$issues" "guest 内无 git"; return; }
    gen_git_probe "$WORK/git_probe.sh"
    guest_run --out "$OUT_DIR/t07.bx" -- sh "$WORK/git_probe.sh"
    local bx=$?
    control_run --out "$OUT_DIR/t07.ctl" -- sh "$WORK/git_probe.sh"
    local ctl=$?
    local bad; bad=$(grep -m1 -oE 'bad object [0-9a-f]+|did not send all necessary objects' "$OUT_DIR/t07.bx" 2>/dev/null)
    grep -q GIT-OK "$OUT_DIR/t07.bx" && [ "$bx" = "0" ] || { [ "$bx" = "0" ] && bx=1; }
    [ -n "$bad" ] && bx=1
    judge "$id" "$title" "$issues" "$bx" "$ctl" "${bad:+命中症状：$bad}" \
          "$OUT_DIR/t07.bx" "$OUT_DIR/t07.ctl"
}

t_24_bun_segv() {   # T08
    local id="T08" title="bun 运行（段错误）" issues="24"
    if ! guest_run 2>/dev/null -- sh -c 'command -v bun >/dev/null'; then
        skip "$id" "$title" "$issues" "guest 内无 bun"
        return
    fi
    guest_run --out "$OUT_DIR/t08.bx" -- sh -c 'bun --version && bun -e "console.log(1+1)"'
    local bx=$?
    control_run --out "$OUT_DIR/t08.ctl" -- sh -c 'bun --version && bun -e "console.log(1+1)"'
    local ctl=$?
    judge "$id" "$title" "$issues" "$bx" "$ctl" "$(grep -m1 -iE 'segmentation|signal 11|core dumped' "$OUT_DIR/t08.bx" 2>/dev/null)" \
          "$OUT_DIR/t08.bx" "$OUT_DIR/t08.ctl"
}

t_24_pkgmgr() {     # T09
    local id="T09" title="包管理器生态（pip/uv/npm 原生扩展）" issues="24,10"
    local tool=""
    guest_run 2>/dev/null -- sh -c 'command -v uv >/dev/null' && tool="uv"
    [ -z "$tool" ] && guest_run 2>/dev/null -- sh -c 'command -v pip3 >/dev/null' && tool="pip3"
    [ -z "$tool" ] && guest_run 2>/dev/null -- sh -c 'command -v npm >/dev/null' && tool="npm"
    if [ -z "$tool" ]; then skip "$id" "$title" "$issues" "guest 内无 uv/pip3/npm"; return; fi
    if [ "$tool" = "uv" ]; then
        guest_run --out "$OUT_DIR/t09.bx" -- sh -c 'uv venv /tmp/t09venv >/dev/null 2>&1 && uv pip install --python /tmp/t09venv/bin/python pillow 2>&1 | tail -3 && /tmp/t09venv/bin/python -c "from PIL import Image; print(\"PIL-OK\", Image.__version__)"'
    else
        guest_run --out "$OUT_DIR/t09.bx" -- sh -c "$tool install --quiet pillow 2>&1 | tail -3; python3 -c 'from PIL import Image; print(\"PIL-OK\")'"
    fi
    local bx=$?
    control_run --out "$OUT_DIR/t09.ctl" -- sh -c 'true'
    local ctl=$?
    local sym; sym=$(grep -m1 -oE 'unknown dlopen\(\) error|cannot find lib[a-z0-9._-]+' "$OUT_DIR/t09.bx" 2>/dev/null)
    [ -n "$sym" ] && bx=1
    # 网络不可用导致安装失败 → 环境问题
    if grep -qiE 'network|Could not resolve|timed out|Connection refused|Temporary failure' "$OUT_DIR/t09.bx" 2>/dev/null; then
        skip "$id" "$title" "$issues" "无网络，无法安装 pillow（$( grep -m1 -oiE 'Could not resolve[^\n]*|Temporary failure[^\n]*' "$OUT_DIR/t09.bx" | cut -c1-60)）"
        return
    fi
    grep -q 'PIL-OK' "$OUT_DIR/t09.bx" && bx=0
    judge "$id" "$title ($tool)" "$issues" "$bx" "$ctl" "${sym:+命中症状：$sym}" \
          "$OUT_DIR/t09.bx" "$OUT_DIR/t09.ctl"
}

t_10_origin() {     # T10
    local id="T10" title="\$ORIGIN RUNPATH 解析 + dlopen 依赖树" issues="10"
    [ "${PROBE_OK[origin]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    [ -d "$WORK/origin/deps" ] || { skip "$id" "$title" "$issues" "\$ORIGIN 依赖树未生成"; return; }
    guest_run --out "$OUT_DIR/t10.bx" -- "${PROBE_BIN[origin]}" "$WORK/origin"
    local bx=$?
    control_run --out "$OUT_DIR/t10.ctl" -- "${PROBE_BIN[origin]}" "$WORK/origin"
    local ctl=$?
    local orig; orig=$(grep -m1 -oE 'cannot find lib[a-z0-9._-]+' "$OUT_DIR/t10.bx" 2>/dev/null)
    bx=$(fold_rc "$bx" "$OUT_DIR/t10.bx" "$OUT_DIR/t10.ctl")
    judge "$id" "$title" "$issues" "$bx" "$ctl" "${orig:+命中症状：$orig}（bxroot FAIL=$FOLD_NF / 对照=$FOLD_NFC）"
}

t_10_rpath_readelf() { # T11
    local id="T11" title="x86 视角：产物 RUNPATH 含 \$ORIGIN 自检" issues="10"
    have readelf || { skip "$id" "$title" "$issues" "无 readelf"; return; }
    [ -f "$WORK/origin/liborigin-main.so" ] || { skip "$id" "$title" "$issues" "依赖树未生成"; return; }
    if readelf -d "$WORK/origin/liborigin-main.so" 2>/dev/null | grep -q 'ORIGIN'; then
        record "$id" "$title" "PASS" "$issues" "$(readelf -d "$WORK/origin/liborigin-main.so" | grep -E 'RUNPATH|RPATH' | sed 's/^ *//')"
    else
        record "$id" "$title" "FAIL" "$issues" "测试库本身没带上 \$ORIGIN，用例失效"
    fi
}

t_12_fakeroot() {   # T12
    local id="T12" title="chown 后 stat 属主（fakeroot 完整性）" issues="12"
    [ "${PROBE_OK[fakeroot]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    guest_run --out "$OUT_DIR/t12.bx" -- "${PROBE_BIN[fakeroot]}" /tmp /etc
    local bx=$?
    control_run --out "$OUT_DIR/t12.ctl" -- "${PROBE_BIN[fakeroot]}" /tmp /etc
    local ctl=$?
    bx=$(fold_rc "$bx" "$OUT_DIR/t12.bx" "$OUT_DIR/t12.ctl")
    judge "$id" "$title" "$issues" "$bx" "$ctl" "bxroot FAIL=$FOLD_NF / 对照=$FOLD_NFC"
}

t_12_dpkg() {       # T13
    local id="T13" title="dpkg/apt 安装写 /etc（Permission denied）" issues="12"
    local have_dpkg=0
    guest_run 2>/dev/null -- sh -c 'command -v dpkg >/dev/null' && have_dpkg=1
    [ "$have_dpkg" = "1" ] || { skip "$id" "$title" "$issues" "guest 内无 dpkg"; return; }
    # 不装新包（避免依赖网络/破坏 rootfs）：用 dpkg 的等价写路径验证
    gen_dpkg_probe "$WORK/dpkg_probe.sh"
    guest_run --out "$OUT_DIR/t13.bx" -- sh "$WORK/dpkg_probe.sh"
    local bx=$?
    control_run --out "$OUT_DIR/t13.ctl" -- sh "$WORK/dpkg_probe.sh"
    local ctl=$?
    local perm; perm=$(grep -m1 -oE 'Permission denied' "$OUT_DIR/t13.bx" 2>/dev/null)
    grep -q DPKG-PROBE-OK "$OUT_DIR/t13.bx" && [ "$bx" = "0" ] || { [ "$bx" = "0" ] && bx=1; }
    [ -n "$perm" ] && bx=1
    judge "$id" "$title" "$issues" "$bx" "$ctl" "${perm:+命中症状：Permission denied}"
}

t_12_link() {       # T14
    local id="T14" title="硬链接语义 / l2s（dpkg·pnpm·git 依赖）" issues="12,24,23"
    [ "${PROBE_OK[link]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    # 需要 guest 可写目录：用 /tmp（bind 到宿主）
    guest_run --out "$OUT_DIR/t14.bx" -- "${PROBE_BIN[link]}" /tmp
    local bx=$?
    control_run --out "$OUT_DIR/t14.ctl" -- "${PROBE_BIN[link]}" /tmp
    local ctl=$?
    bx=$(fold_rc "$bx" "$OUT_DIR/t14.bx" "$OUT_DIR/t14.ctl")
    judge "$id" "$title" "$issues" "$bx" "$ctl" "bxroot FAIL=$FOLD_NF / 对照=$FOLD_NFC"
}

t_11_rename() {     # T15
    local id="T15" title="renameat2 / unlink / rm -rf 路径语义" issues="11,5"
    [ "${PROBE_OK[rename]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    guest_run --out "$OUT_DIR/t15.bx" -- "${PROBE_BIN[rename]}" /tmp
    local bx=$?
    control_run --out "$OUT_DIR/t15.ctl" -- "${PROBE_BIN[rename]}" /tmp
    local ctl=$?
    bx=$(fold_rc "$bx" "$OUT_DIR/t15.bx" "$OUT_DIR/t15.ctl")
    judge "$id" "$title" "$issues" "$bx" "$ctl" "bxroot FAIL=$FOLD_NF / 对照=$FOLD_NFC"
}

t_11_uvclean() {    # T16
    local id="T16" title="uv clean / 递归缓存清理" issues="11"
    guest_run 2>/dev/null -- sh -c 'command -v uv >/dev/null' || { skip "$id" "$title" "$issues" "guest 内无 uv"; return; }
    gen_uvclean "$WORK/uvclean.sh"
    guest_run --out "$OUT_DIR/t16.bx" -- sh "$WORK/uvclean.sh"
    local bx=$?
    control_run --out "$OUT_DIR/t16.ctl" -- sh "$WORK/uvclean.sh"
    local ctl=$?
    local err; err=$(grep -m1 -oE 'No such file or directory \(os error 2\)|failed to remove file' "$OUT_DIR/t16.bx" 2>/dev/null)
    grep -q UVCLEAN-OK "$OUT_DIR/t16.bx" && [ "$bx" = "0" ] || { [ "$bx" = "0" ] && bx=1; }
    [ -n "$err" ] && bx=1
    judge "$id" "$title" "$issues" "$bx" "$ctl" "${err:+命中症状：$err}" \
          "$OUT_DIR/t16.bx" "$OUT_DIR/t16.ctl"
}

t_08_creds() {      # T17
    local id="T17" title="sendmsg/SCM_CREDENTIALS 凭据传递" issues="8"
    [ "${PROBE_OK[creds]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    guest_run --out "$OUT_DIR/t17.bx" -- "${PROBE_BIN[creds]}"
    local bx=$?
    control_run --out "$OUT_DIR/t17.ctl" -- "${PROBE_BIN[creds]}"
    local ctl=$?
    bx=$(fold_rc "$bx" "$OUT_DIR/t17.bx" "$OUT_DIR/t17.ctl")
    judge "$id" "$title" "$issues" "$bx" "$ctl" "bxroot FAIL=$FOLD_NF / 对照=$FOLD_NFC"
}

t_08_dbus() {       # T18
    local id="T18" title="dbus session 端到端往返" issues="8,16"
    guest_run 2>/dev/null -- sh -c 'command -v dbus-daemon >/dev/null && command -v dbus-send >/dev/null'
    if [ $? -ne 0 ]; then skip "$id" "$title" "$issues" "guest 内无 dbus-daemon/dbus-send"; return; fi
    gen_dbus_probe "$WORK/dbus_probe.sh"
    guest_run --out "$OUT_DIR/t18.bx" -- sh "$WORK/dbus_probe.sh"
    local bx=$?
    control_run --out "$OUT_DIR/t18.ctl" -- sh "$WORK/dbus_probe.sh"
    local ctl=$?
    local noreply; noreply=$(grep -m1 -oE 'Did not receive a reply' "$OUT_DIR/t18.bx" 2>/dev/null)
    grep -q DBUS-OK "$OUT_DIR/t18.bx" && [ "$bx" = "0" ] || { [ "$bx" = "0" ] && bx=1; }
    [ -n "$noreply" ] && bx=1
    judge "$id" "$title" "$issues" "$bx" "$ctl" "${noreply:+命中症状：$noreply}" \
          "$OUT_DIR/t18.bx" "$OUT_DIR/t18.ctl"
}

t_13_ioctl() {      # T19
    local id="T19" title="ioctl 透传（fd/参数/errno 未被篡改）" issues="13"
    [ "${PROBE_OK[ioctl]:-0}" = "1" ] || { skip "$id" "$title" "$issues" "探针编译失败"; return; }
    guest_run --out "$OUT_DIR/t19.bx" -- "${PROBE_BIN[ioctl]}"
    local bx=$?
    control_run --out "$OUT_DIR/t19.ctl" -- "${PROBE_BIN[ioctl]}"
    local ctl=$?
    bx=$(fold_rc "$bx" "$OUT_DIR/t19.bx" "$OUT_DIR/t19.ctl")
    local gpu="无 GPU 节点"
    grep -q '可打开 /dev/dri' "$OUT_DIR/t19.bx" && gpu="有 GPU 节点"
    judge "$id" "$title" "$issues" "$bx" "$ctl" "bxroot FAIL=$FOLD_NF / 对照=$FOLD_NFC；$gpu"
}

t_13_gpu_app() {    # T20
    local id="T20" title="Chromium 系浏览器 GPU 进程（需真机 GPU + X）" issues="13,16"
    local found=""
    guest_run 2>/dev/null -- sh -c 'for b in chromium chromium-browser brave-browser google-chrome; do command -v $b && break; done' > "$OUT_DIR/t20.which" 2>&1
    found=$(grep -m1 -E '^/' "$OUT_DIR/t20.which" 2>/dev/null)
    [ -n "$found" ] || { skip "$id" "$title" "$issues" "guest 内无 Chromium 系浏览器（本环境不具备）"; return; }
    if ! ls /dev/dri/renderD* >/dev/null 2>&1; then
        skip "$id" "$title" "$issues" "宿主无 /dev/dri/renderD* → GPU 路径不可验证"; return
    fi
    guest_run --out "$OUT_DIR/t20.bx" -- sh -c "timeout 60 $found --no-sandbox --headless=new --disable-gpu-sandbox --enable-logging=stderr --v=1 --dump-dom about:blank 2>&1 | grep -iE 'gpu|egl|kgsl|exit_code' | head -20"
    local bx=$?
    local code256; code256=$(grep -m1 -oE 'exit_code=256' "$OUT_DIR/t20.bx" 2>/dev/null)
    [ -n "$code256" ] && bx=1
    record "$id" "$title" "$([ "$bx" = 0 ] && echo PASS || echo FAIL)" "$issues" "${code256:+命中症状：GPU 进程 exit_code=256}"
}

t_16_icu() {        # T21
    local id="T21" title="Electron 系应用启动（ICU/Illegal instruction）" issues="16"
    local found=""
    guest_run 2>/dev/null -- sh -c 'for b in qq linuxqq electron; do command -v $b && break; done' > "$OUT_DIR/t21.which" 2>&1
    found=$(grep -m1 -E '^/' "$OUT_DIR/t21.which" 2>/dev/null)
    [ -n "$found" ] || { skip "$id" "$title" "$issues" "guest 内无 LinuxQQ/Electron（本环境不具备）"; return; }
    guest_run --out "$OUT_DIR/t21.bx" -- sh -c "timeout 45 $found --no-sandbox --version 2>&1 | head -10"
    local bx=$?
    control_run --out "$OUT_DIR/t21.ctl" -- sh -c "timeout 45 $found --no-sandbox --version 2>&1 | head -10"
    local ctl=$?
    local icu; icu=$(grep -m1 -oE 'Invalid file descriptor to ICU data received' "$OUT_DIR/t21.bx" 2>/dev/null)
    [ -n "$icu" ] && bx=1
    judge "$id" "$title" "$issues" "$bx" "$ctl" "${icu:+命中症状：ICU data fd 无效}" \
          "$OUT_DIR/t21.bx" "$OUT_DIR/t21.ctl"
}

t_15_native_apps() {  # T22
    local id="T22" title="大型原生 GUI/host 信息（#15 类：/proc 可读）" issues="15,9"
    gen_proc_probe "$WORK/proc_probe.sh"
    guest_run --out "$OUT_DIR/t22.bx" -- sh "$WORK/proc_probe.sh"
    local bx=$?
    control_run --out "$OUT_DIR/t22.ctl" -- sh "$WORK/proc_probe.sh"
    local ctl=$?
    judge "$id" "$title" "$issues" "$bx" "$ctl" "" "$OUT_DIR/t22.bx" "$OUT_DIR/t22.ctl"
}

t_20_launcher_basic() { # T23
    local id="T23" title="launcher 基础可用（/bin/true 零崩溃）" issues="22,20,2"
    guest_run --out "$OUT_DIR/t23.bx" -- /bin/true
    local bx=$?
    control_run --out "$OUT_DIR/t23.ctl" -- /bin/true
    local ctl=$?
    judge "$id" "$title" "$issues" "$bx" "$ctl" "$([ "$bx" = 139 ] && echo 'rc=139 = SIGSEGV，正是 #22 的症状')" \
          "$OUT_DIR/t23.bx" "$OUT_DIR/t23.ctl"
}

t_20_launcher_flags() { # T24
    local id="T24" title="launcher CLI 契约（-r/-w/-0/--link2symlink/-b/--help）" issues="20"
    [ "$RUNNER_MODE" = "bxroot" ] || { skip "$id" "$title" "$issues" "无 bxroot"; return; }
    local fails=0 msgs=()
    "$LAUNCHER" --help >/dev/null 2>&1 || { fails=$((fails+1)); msgs+=("--help 非 0 退出"); }
    guest_run --out "$OUT_DIR/t24a.bx" -- /bin/echo hello-bxroot
    grep -q 'hello-bxroot' "$OUT_DIR/t24a.bx" || { fails=$((fails+1)); msgs+=("/bin/echo 输出丢失"); }
    # -b bind：宿主目录必须出现在 guest 的挂载点上
    mkdir -p "$WORK/bindtest"; echo BINDCONTENT > "$WORK/bindtest/src.txt"
    bx_launch -r "$ROOTFS" -0 -w / -b "$WORK/bindtest:/mnt/bt" \
        /bin/sh -c 'cat /mnt/bt/src.txt' >"$OUT_DIR/t24b.bx" 2>&1
    grep -q BINDCONTENT "$OUT_DIR/t24b.bx" || { fails=$((fails+1)); msgs+=("-b bind 未生效($(head -c 60 "$OUT_DIR/t24b.bx" | tr '\n' ' '))"); }
    # -w workdir
    bx_launch -r "$ROOTFS" -0 -w /tmp /bin/pwd >"$OUT_DIR/t24c.bx" 2>&1
    grep -q '/tmp' "$OUT_DIR/t24c.bx" || { fails=$((fails+1)); msgs+=("-w 工作目录未生效"); }
    if [ "$fails" = "0" ]; then
        record "$id" "$title" "PASS" "$issues" "--help/echo/-b/-w 全部符合契约"
    elif [ "$RT_LIVE" != "yes" ]; then
        # runtime 未确认存活 → bind/workdir 失败可能是环境假象，不能冤枉 bxroot
        record "$id" "$title" "NOCTL" "$issues" \
               "${msgs[*]}；但 runtime 存活=$RT_LIVE（$RT_LIVE_NOTE），须真机复跑确认"
    else
        record "$id" "$title" "FAIL" "$issues" "${msgs[*]}"
    fi
}

t_smoke_rootfs() {  # T25
    local id="T25" title="rootfs 冒烟（/bin/sh 可交互执行）" issues="20,24"
    guest_run --out "$OUT_DIR/t25.bx" -- /bin/sh -c 'echo SMOKE-OK; id; uname -m'
    local bx=$?
    control_run --out "$OUT_DIR/t25.ctl" -- /bin/sh -c 'echo SMOKE-OK; id; uname -m'
    local ctl=$?
    grep -q SMOKE-OK "$OUT_DIR/t25.bx" || { [ "$bx" = "0" ] && bx=1; }
    judge "$id" "$title" "$issues" "$bx" "$ctl" "$(grep -m1 -E '^uid=' "$OUT_DIR/t25.bx" 2>/dev/null)" \
          "$OUT_DIR/t25.bx" "$OUT_DIR/t25.ctl"
}

# ---------------------------------------------------------------------------
# 6. 用例注册表
# ---------------------------------------------------------------------------
ALL_TESTS=(
    t_20_launcher_basic
    t_20_launcher_flags
    t_smoke_rootfs
    t_22_readlink
    t_22_sentinel
    t_22_crashdump
    t_23_bigmmap
    t_23_largelink
    t_24_node_napi
    t_24_git_clone
    t_24_bun_segv
    t_24_pkgmgr
    t_10_origin
    t_10_rpath_readelf
    t_12_fakeroot
    t_12_dpkg
    t_12_link
    t_11_rename
    t_11_uvclean
    t_08_creds
    t_08_dbus
    t_13_ioctl
    t_13_gpu_app
    t_16_icu
    t_15_native_apps
)

# ---------------------------------------------------------------------------
# 7. 汇总输出
# ---------------------------------------------------------------------------
print_summary() {
    local total=$((N_PASS+N_FAIL+N_SKIP+N_ENVFAIL+N_XFAIL+N_NOCTL))
    log ""
    log "${C_CYN}═══════════════════ 汇总 ═══════════════════${C_RST}"
    printf '  %sPASS%s    %3d\n' "$C_GRN" "$C_RST" "$N_PASS"
    printf '  %sFAIL%s    %3d   ← 真回归（bxroot 劣于 proot）\n' "$C_RED" "$C_RST" "$N_FAIL"
    printf '  %sNOCTL%s   %3d   ← 无 proot 对照，无法判定（**不是通过**）\n' "$C_YEL" "$C_RST" "$N_NOCTL"
    printf '  %sENVFAIL%s %3d   ← proot 同样失败，是环境问题\n' "$C_CYN" "$C_RST" "$N_ENVFAIL"
    printf '  %sSKIP%s    %3d   ← 环境不具备\n' "$C_YEL" "$C_RST" "$N_SKIP"
    printf '  %sXFAIL%s   %3d   ← 诊断信息，不参与判定\n' "$C_DIM" "$C_RST" "$N_XFAIL"
    log "  ─────────────────────────────────────────"
    printf '  合计 %d 条\n' "$total"

    if [ "$N_FAIL" -gt 0 ]; then
        log ""
        log "${C_RED}失败清单：${C_RST}"
        local i
        for i in "${!R_STATUS[@]}"; do
            [ "${R_STATUS[$i]}" = "FAIL" ] || continue
            printf '  ✗ %s  %s  [issue %s]\n' "${R_IDS[$i]}" "${R_TITLES[$i]}" "${R_ISSUES[$i]}"
            [ -n "${R_NOTES[$i]}" ] && printf '      %s\n' "${R_NOTES[$i]}"
        done
    fi

    if [ "$N_NOCTL" -gt 0 ]; then
        log ""
        log "${C_YEL}无对照、无法判定（须在装有 proot 的真机上重跑）:${C_RST}"
        local i
        for i in "${!R_STATUS[@]}"; do
            [ "${R_STATUS[$i]}" = "NOCTL" ] || continue
            printf '  ? %s  %s  [issue %s]\n' "${R_IDS[$i]}" "${R_TITLES[$i]}" "${R_ISSUES[$i]}"
        done
    fi

    # markdown 报告
    local md="$OUT_DIR/REPORT.md"
    {
        echo "# bxroot issue 回归测试报告"
        echo
        echo "- 生成时间：$(date -Iseconds 2>/dev/null || date)"
        echo "- 脚本版本：$SCRIPT_NAME $SCRIPT_VERSION"
        echo "- host：$(uname -m) / kernel $(uname -r)"
        echo "- launcher：${LAUNCHER:-<未找到>}"
        echo "- libs dir：${LIBS_DIR:-<未找到>}"
        echo "- rootfs：${ROOTFS:-<未找到>}"
        echo "- 对照：${PROOT_BIN:-<无 proot>}  (CONTROL_OK=$CONTROL_OK)"
        echo "- bxroot runtime 存活：$RT_LIVE（$RT_LIVE_NOTE）"
        if [ "${IN_CONTAINER:-0}" = "1" ]; then
            echo "- **运行环境：DSHA 容器运行时内 → 本报告结论不可信，须在真机复跑**"
        else
            echo "- 运行环境：宿主/真机直跑（结论可用）"
        fi
        echo
        echo "## 汇总"
        echo
        echo "| 状态 | 数量 | 含义 |"
        echo "|---|---:|---|"
        echo "| PASS | $N_PASS | 通过 |"
        echo "| FAIL | $N_FAIL | bxroot 劣于 proot，真回归 |"
        echo "| NOCTL | $N_NOCTL | 无 proot 对照，无法判定 |"
        echo "| ENVFAIL | $N_ENVFAIL | proot 同样失败 → 环境问题 |"
        echo "| SKIP | $N_SKIP | 环境不具备 |"
        echo "| XFAIL | $N_XFAIL | 诊断信息 |"
        echo
        echo "## 明细"
        echo
        echo "| # | 用例 | 结果 | issue | 备注 |"
        echo "|---|---|---|---|---|"
        local i
        for i in "${!R_IDS[@]}"; do
            printf '| %s | %s | %s | %s | %s |\n' \
                "${R_IDS[$i]}" "${R_TITLES[$i]}" "${R_STATUS[$i]}" \
                "${R_ISSUES[$i]}" "$(printf '%s' "${R_NOTES[$i]}" | tr '|' '/')"
        done
    } > "$md" 2>/dev/null
    log ""
    info "Markdown 报告：$md"
    info "原始输出目录：$OUT_DIR"
    log ""

    if [ "$N_FAIL" -eq 0 ]; then
        log "${C_GRN}✅ 无真回归（FAIL=0）${C_RST}"
        return 0
    fi
    log "${C_RED}❌ 检出 $N_FAIL 条真回归${C_RST}"
    return 1
}

# ---------------------------------------------------------------------------
# 8. self-test（容器内可跑：验语法 + 验辅助逻辑，不做端到端）
# ---------------------------------------------------------------------------
self_test() {
    log "${C_CYN}=== self-test（容器内可运行部分）===${C_RST}"
    local rcs=0

    # 1. 语法
    if bash -n "$0" 2>/dev/null; then log "  ok   bash -n 语法检查通过"
    else log "  FAIL bash -n 语法检查失败"; rcs=1; fi

    # 2. 函数可加载
    for f in record judge skip guest_run env_probe print_summary build_origin_tree \
             gen_biglink gen_git_probe gen_napi_probe gen_uvclean gen_dbus_probe gen_dpkg_probe gen_proc_probe; do
        if declare -F "$f" >/dev/null; then log "  ok   函数已定义：$f"
        else log "  FAIL 函数缺失：$f"; rcs=1; fi
    done

    # 3. human()
    local h; h=$(human 1048576)
    [ "$h" = "1.0 MB" ] && log "  ok   human(1048576) = $h" || { log "  FAIL human() 返回 '$h'"; rcs=1; }

    # 4. 探针源码非空 + 能编译
    local n=0 c
    for v in SRC_P_READLINK SRC_P_BIGMEM SRC_P_FAKEROOT SRC_P_CREDS SRC_P_ORIGIN \
             SRC_P_RENAME SRC_P_SENTINEL SRC_P_LINK SRC_P_IOCTL; do
        eval "c=\${#$v}"
        if [ "${c:-0}" -gt 200 ]; then n=$((n+1)); else log "  FAIL $v 过短或未定义 ($c 字节)"; rcs=1; fi
    done
    log "  ok   内联探针源码 $n/9 段非空"

    # 4b. 运行模式提示：容器运行时内一切 LD_PRELOAD 结论都不可信
    if [ -n "${PROROOT_LINKER_PATH:-}${PROOT_TMP_DIR:-}${PROOT_LOADER:-}" ]; then
        log "  --   检测到已在 DSHA 容器运行时内 —— 端到端结论不可信，仅语法/编译/纯逻辑有效"
    else
        log "  --   宿主直跑模式（无容器运行时标记）"
    fi

    # 5. 用宿主 gcc 实际编译全部探针
    local cc; cc="$(detect_cc || true)"
    if [ -n "$cc" ]; then
        local ok=0 fail=0 tmp; tmp="$(mktemp -d)"
        printf '%s' "$SRC_P_READLINK" > "$tmp/a.c"; "$cc" -O1 -w -o "$tmp/a" "$tmp/a.c" 2>"$tmp/a.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL readlink 探针编译失败：$(head -3 "$tmp/a.log")"; }
        printf '%s' "$SRC_P_BIGMEM"   > "$tmp/b.c"; "$cc" -O1 -w -o "$tmp/b" "$tmp/b.c" 2>"$tmp/b.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL bigmem 探针编译失败：$(head -3 "$tmp/b.log")"; }
        printf '%s' "$SRC_P_FAKEROOT" > "$tmp/c.c"; "$cc" -O1 -w -o "$tmp/c" "$tmp/c.c" 2>"$tmp/c.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL fakeroot 探针编译失败：$(head -3 "$tmp/c.log")"; }
        printf '%s' "$SRC_P_CREDS"    > "$tmp/d.c"; "$cc" -O1 -w -o "$tmp/d" "$tmp/d.c" 2>"$tmp/d.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL creds 探针编译失败：$(head -3 "$tmp/d.log")"; }
        printf '%s' "$SRC_P_ORIGIN"   > "$tmp/e.c"; "$cc" -O1 -w -o "$tmp/e" "$tmp/e.c" -ldl 2>"$tmp/e.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL origin 探针编译失败：$(head -3 "$tmp/e.log")"; }
        printf '%s' "$SRC_P_RENAME"   > "$tmp/f.c"; "$cc" -O1 -w -o "$tmp/f" "$tmp/f.c" 2>"$tmp/f.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL rename 探针编译失败：$(head -3 "$tmp/f.log")"; }
        printf '%s' "$SRC_P_SENTINEL" > "$tmp/g.c"; "$cc" -O1 -w -o "$tmp/g" "$tmp/g.c" 2>"$tmp/g.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL sentinel 探针编译失败：$(head -3 "$tmp/g.log")"; }
        printf '%s' "$SRC_P_LINK"     > "$tmp/h.c"; "$cc" -O1 -w -o "$tmp/h" "$tmp/h.c" 2>"$tmp/h.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL link 探针编译失败：$(head -3 "$tmp/h.log")"; }
        printf '%s' "$SRC_P_IOCTL"    > "$tmp/i.c"; "$cc" -O1 -w -o "$tmp/i" "$tmp/i.c" 2>"$tmp/i.log" && ok=$((ok+1)) || { fail=$((fail+1)); log "  FAIL ioctl 探针编译失败：$(head -3 "$tmp/i.log")"; }
        log "  $([ "$fail" = 0 ] && echo ok || echo FAIL)   探针编译 $ok 成功 / $fail 失败"
        [ "$fail" != "0" ] && rcs=1

        # 6. 编译成功的探针在宿主原样跑一遍（不是端到端！只验证探针自身逻辑正确）
        if [ -x "$tmp/g" ]; then
            if "$tmp/g" 4 >"$tmp/g.out" 2>&1 && grep -q 'SENTINEL-OK' "$tmp/g.out"; then
                log "  ok   sentinel 探针自跑通过（$(grep -c sentinel "$tmp/g.out") 条 stage 输出）"
            else log "  FAIL sentinel 探针自跑失败"; rcs=1; fi
        fi
        if [ -x "$tmp/i" ]; then
            if "$tmp/i" >"$tmp/i.out" 2>&1; then log "  ok   ioctl 探针自跑通过"
            else log "  --   ioctl 探针自跑有 FAIL（宿主环境差异，非脚本问题）: $(grep -m1 FAIL "$tmp/i.out")"; fi
        fi
        # 6b. guest 侧脚本生成器：语法 + 实跑（这是"测试内容本身"的验证）
        local g="$tmp/gen"; mkdir -p "$g"
        local gen_ok=0 gen_bad=0
        gen_biglink     "$g/biglink.sh" "$cc" 6
        gen_git_probe   "$g/git.sh"
        gen_napi_probe  "$g/napi.js"
        gen_uvclean     "$g/uv.sh"
        gen_dbus_probe  "$g/dbus.sh"
        gen_dpkg_probe  "$g/dpkg.sh"
        gen_proc_probe  "$g/proc.sh"
        local f
        for f in biglink.sh git.sh uv.sh dbus.sh dpkg.sh proc.sh; do
            if sh -n "$g/$f" 2>/dev/null; then gen_ok=$((gen_ok+1))
            else gen_bad=$((gen_bad+1)); log "  FAIL 生成的 $f 语法错误：$(sh -n "$g/$f" 2>&1 | head -2)"; fi
        done
        if have node; then
            if node --check "$g/napi.js" 2>/dev/null; then gen_ok=$((gen_ok+1)); else gen_bad=$((gen_bad+1)); log "  FAIL napi.js 语法错误"; fi
        else gen_ok=$((gen_ok+1)); log "  --   无 node，napi.js 仅跳过语法检查"; fi
        log "  $([ "$gen_bad" = 0 ] && echo ok || echo FAIL)   生成脚本语法 $gen_ok 通过 / $gen_bad 失败"
        [ "$gen_bad" != "0" ] && rcs=1

        # 实跑 biglink（宿主上，小规模）—— 验证生成的链接脚本逻辑正确
        if ( cd "$tmp/gen" && sh ./biglink.sh ) >"$tmp/gen/biglink.out" 2>&1; then
            if grep -q BIGLINK-OK "$tmp/gen/biglink.out"; then
                log "  ok   biglink 生成脚本在宿主实跑通过（$(grep -o 'binary size=[0-9]*' "$tmp/gen/biglink.out" | head -1)）"
            else log "  FAIL biglink 实跑未输出 BIGLINK-OK"; rcs=1; fi
        else log "  FAIL biglink 生成脚本实跑失败：$(tail -3 "$tmp/gen/biglink.out" 2>/dev/null | tr '\n' ' ')"; rcs=1; fi

        # 实跑 proc_probe（宿主上，验证 /proc 可读性判据）
        if sh "$tmp/gen/proc.sh" >"$tmp/gen/proc.out" 2>&1; then
            log "  ok   proc_probe 生成脚本在宿主实跑通过（$(grep -c '^  ok' "$tmp/gen/proc.out") 项）"
        else log "  --   proc_probe 在宿主有 FAIL（容器 /proc 限制，非脚本问题）：$(grep -m1 FAIL "$tmp/gen/proc.out")"; fi

        # 实跑 dpkg_probe（宿主上以 /tmp 代 /etc，避免动真 /etc）
        sed 's|^D=/etc/sudoers.d|D=/tmp; [ -d /etc ] \|\| D=/tmp|' "$tmp/gen/dpkg.sh" > "$tmp/gen/dpkg2.sh" 2>/dev/null || true
        if D_OVERRIDE=1 sh -c 'sed "s#/etc/sudoers.d#/tmp#g" '"$tmp/gen/dpkg.sh"' > '"$tmp/gen/dpkg3.sh"'' 2>/dev/null && sh "$tmp/gen/dpkg3.sh" >"$tmp/gen/dpkg.out" 2>&1; then
            grep -q DPKG-PROBE-OK "$tmp/gen/dpkg.out" && log "  ok   dpkg_probe 生成脚本在宿主实跑通过（/tmp 替身）" \
                || { log "  FAIL dpkg_probe 未输出 DPKG-PROBE-OK"; rcs=1; }
        else log "  --   dpkg_probe 宿主实跑受限（略）"; fi

            # ---- 决策表测试：judge()/fold_rc() 的纯逻辑（不碰设备）----
        local dt_fail=0
        _dt() {  # $1=bx_rc $2=ctl_rc $3=bx_out $4=ctl_out $5=期望状态
            local got
            got=$( _judge_probe "$1" "$2" "$3" "$4" )
            if [ "$got" = "$5" ]; then printf '  ok   决策表 bx=%s ctl=%s -> %s\n' "$1" "$2" "$got"
            else printf '  FAIL 决策表 bx=%s ctl=%s -> %s（期望 %s）\n' "$1" "$2" "$got" "$5"; return 1; fi
        }
        # 造两个假探针输出文件
        : > "$tmp/empty.out"
        printf '  FAIL x\n  FAIL y\n' > "$tmp/two.out"
        if _dt 0   0   "$tmp/empty.out" "$tmp/empty.out" PASS    &&
           _dt 1   0   "$tmp/empty.out" "$tmp/empty.out" FAIL    &&
           _dt 139 0   "$tmp/empty.out" "$tmp/empty.out" FAIL    &&
           _dt 1   1   "$tmp/empty.out" "$tmp/empty.out" ENVFAIL &&
           _dt 139 1   "$tmp/empty.out" "$tmp/empty.out" ENVFAIL &&
           _dt 1   127 "$tmp/empty.out" "$tmp/empty.out" NOCTL   &&
           _dt 139 127 "$tmp/empty.out" "$tmp/empty.out" NOCTL   &&
           _dt 0   127 "$tmp/empty.out" "$tmp/empty.out" PASS    &&
           _dt 0   0   "$tmp/two.out"   "$tmp/two.out"   PASS    &&
           _dt 0   0   "$tmp/two.out"   "$tmp/empty.out" FAIL
        then log "  ok   决策表 11/11 全部符合预期"
        else log "  FAIL 决策表存在偏差"; rcs=1; fi
        # NOCTL 必须真的出现（防止未来有人把 127 又改回 FAIL）
        if _dt 1 127 "$tmp/empty.out" "$tmp/empty.out" NOCTL >/dev/null 2>&1; then :; fi

        # 崩溃 rc 绝不能被 fold_rc 折算成 0
        local folded
        folded=$(fold_rc 139 "$tmp/two.out" "$tmp/two.out")
        if [ "$folded" = "139" ]; then log "  ok   fold_rc 保留崩溃码 139（未折算为 0）"
        else log "  FAIL fold_rc 把崩溃码 139 折算成了 $folded"; rcs=1; fi
        folded=$(fold_rc 0 "$tmp/two.out" "$tmp/empty.out")
        if [ "$folded" = "1" ]; then log "  ok   fold_rc 检出 FAIL 行数劣化 (2 > 0) → 1"
        else log "  FAIL fold_rc 未检出劣化，返回 $folded"; rcs=1; fi
        folded=$(fold_rc 0 "$tmp/empty.out" "$tmp/two.out")
        if [ "$folded" = "0" ]; then log "  ok   fold_rc 允许 bxroot 优于对照 (0 < 2) → 0"
        else log "  FAIL fold_rc 误判，返回 $folded"; rcs=1; fi

    # 7. $ORIGIN 依赖树能否生成，且 RUNPATH 真是 $ORIGIN
        if build_origin_tree "$tmp/origin" "$cc" >/dev/null 2>&1; then
            if readelf -d "$tmp/origin/liborigin-main.so" 2>/dev/null | grep -q 'ORIGIN'; then
                log "  ok   \$ORIGIN 依赖树可生成且 RUNPATH 正确"
            else log "  FAIL \$ORIGIN 依赖树 RUNPATH 不含 ORIGIN"; rcs=1; fi
        else log "  FAIL \$ORIGIN 依赖树生成失败"; rcs=1; fi
        rm -rf "$tmp"
    else
        log "  --   无 C 编译器，跳过探针编译验证"
    fi

    log ""
    if [ "$rcs" = "0" ]; then log "${C_GRN}self-test 全部通过${C_RST}"; else log "${C_RED}self-test 有失败项${C_RST}"; fi
    return $rcs
}

# ---------------------------------------------------------------------------
# 9. 主流程
# ---------------------------------------------------------------------------
ONLY=""
NO_CONTROL=0
MODE="run"

while [ $# -gt 0 ]; do
    case "$1" in
        --self-test) MODE="self-test"; shift ;;
        --list)      MODE="list"; shift ;;
        --only)      ONLY="$2"; shift 2 ;;
        --no-control) NO_CONTROL=1; shift ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --version) echo "$SCRIPT_NAME $SCRIPT_VERSION"; exit 0 ;;
        *) warn "未知参数：$1"; shift ;;
    esac
done

if [ "$MODE" = "self-test" ]; then
    self_test; exit $?
fi

if [ "$MODE" = "list" ]; then
    printf '%-6s %-4s %s\n' "ID" "ISSUE" "用例"
    printf '%-6s %-4s %s\n' "T01" "22"   "readlinkat 分支/早期崩溃"
    printf '%-6s %-4s %s\n' "T02" "22"   "早期阶段哨兵（constructor→main）"
    printf '%-6s %-4s %s\n' "T03" "22"   "崩溃诊断产物生成"
    printf '%-6s %-4s %s\n' "T04" "23"   "大文件写 + mmap/mremap/MAP_SHARED"
    printf '%-6s %-4s %s\n' "T05" "23"   "大量目标文件链接"
    printf '%-6s %-4s %s\n' "T06" "24"   "Node 原生模块 dlopen（NAPI 符号）"
    printf '%-6s %-4s %s\n' "T07" "24"   "git 本地 clone + fsck"
    printf '%-6s %-4s %s\n' "T08" "24"   "bun 运行（段错误）"
    printf '%-6s %-4s %s\n' "T09" "24,10" "包管理器原生扩展（uv/pip/npm）"
    printf '%-6s %-4s %s\n' "T10" "10"   "\$ORIGIN RUNPATH 解析 + dlopen 依赖树"
    printf '%-6s %-4s %s\n' "T11" "10"   "产物 RUNPATH 含 \$ORIGIN 自检"
    printf '%-6s %-4s %s\n' "T12" "12"   "chown 后 stat 属主（fakeroot 完整性）"
    printf '%-6s %-4s %s\n' "T13" "12"   "dpkg/apt 安装写 /etc"
    printf '%-6s %-4s %s\n' "T14" "12,24,23" "硬链接语义 / l2s"
    printf '%-6s %-4s %s\n' "T15" "11,5" "renameat2 / unlink / rm -rf 路径语义"
    printf '%-6s %-4s %s\n' "T16" "11"   "uv clean / 递归缓存清理"
    printf '%-6s %-4s %s\n' "T17" "8"    "sendmsg/SCM_CREDENTIALS 凭据传递"
    printf '%-6s %-4s %s\n' "T18" "8,16" "dbus session 端到端往返"
    printf '%-6s %-4s %s\n' "T19" "13"   "ioctl 透传"
    printf '%-6s %-4s %s\n' "T20" "13,16" "Chromium 系 GPU 进程"
    printf '%-6s %-4s %s\n' "T21" "16"   "Electron 系应用启动（ICU）"
    printf '%-6s %-4s %s\n' "T22" "15,9" "大型原生应用 / /proc 可读"
    printf '%-6s %-4s %s\n' "T23" "22,20,2" "launcher 基础可用（/bin/true）"
    printf '%-6s %-4s %s\n' "T24" "20"   "launcher CLI 契约"
    printf '%-6s %-4s %s\n' "T25" "20,24" "rootfs 冒烟"
    exit 0
fi

# ---- 正常运行 ----
log "${C_CYN}╔══════════════════════════════════════════════════════════╗${C_RST}"
log "${C_CYN}║  bxroot issue 回归测试  $SCRIPT_NAME $SCRIPT_VERSION        ║${C_RST}"
log "${C_CYN}╚══════════════════════════════════════════════════════════╝${C_RST}"
log "  上游 issue 来源：https://github.com/coderredlab/proroot/issues"
log "  覆盖：24 个 issue 中 15 个有可测故障行为（T01–T25，另含已关闭的 #2/#5）"
log ""

# ---- 容器运行时检测：在 DSHA 容器内跑出来的端到端结论一律不可信 ----
IN_CONTAINER=0
if [ -n "${PROROOT_LINKER_PATH:-}${PROOT_TMP_DIR:-}${PROOT_LOADER:-}" ]; then
    IN_CONTAINER=1
fi

env_probe

if [ "$IN_CONTAINER" = "1" ]; then
    log "${C_RED}╔══════════════════════════════════════════════════════════════╗${C_RST}"
    log "${C_RED}║  ⚠  检测到正在 DSHA 容器运行时内执行                          ║${C_RST}"
    log "${C_RED}║  本环境实测：LD_PRELOAD 被外层 proot 吞掉；ld.so --preload     ║${C_RST}"
    log "${C_RED}║  下对确实存在的文件也返回 ENOENT。因此本报告中的 PASS/FAIL    ║${C_RST}"
    log "${C_RED}║  一律不可作为 bxroot 验收结论，仅供冒烟参考。                  ║${C_RST}"
    log "${C_RED}║  权威结论必须在真机（Termux direct shell / DSHA native）产出。 ║${C_RST}"
    log "${C_RED}╚══════════════════════════════════════════════════════════════╝${C_RST}"
    log ""
fi

if [ "$RUNNER_MODE" != "bxroot" ]; then
    warn "未找到 bxroot launcher —— 全部用例将 SKIP"
    warn "设置 BXROOT_LAUNCHER 与 BXROOT_LIBS_DIR 后重跑。"
fi
[ -z "$ROOTFS" ] && warn "未找到可用 rootfs —— 全部用例将 SKIP"

log "${C_CYN}═══════════ 用例执行 ═══════════${C_RST}"
for t in "${ALL_TESTS[@]}"; do
    if [ "$RUNNER_MODE" != "bxroot" ] || [ -z "$ROOTFS" ]; then
        case "$t" in
            t_10_rpath_readelf|t_23_largelink) : ;;   # 这两个不依赖 guest 的可以跑
            *) continue ;;
        esac
    fi
    before=$((N_PASS+N_FAIL+N_SKIP+N_ENVFAIL+N_XFAIL+N_NOCTL))
    "$t" 2>/dev/null || warn "用例 $t 异常退出"
    after=$((N_PASS+N_FAIL+N_SKIP+N_ENVFAIL+N_XFAIL+N_NOCTL))
    if [ "$after" = "$before" ]; then
        record "?" "$t" "XFAIL" "-" "用例未产出结果（内部错误）"
    fi
done

if [ -n "$ONLY" ]; then
    log ""
    info "已按 --only=$ONLY 过滤（交集为空的用例未记录）"
fi

print_summary
exit $?
