#!/bin/sh
# =====================================================================
# RUN_IDMAP.sh —— 任意 -i <uid>:<gid> 身份映射回归（2026-09-27）
# =====================================================================
#
# 背景
# ----
# 上游 proot 的 `-i <uid>:<gid>` 让 guest 内看到的 uid/gid 是指定值。
# bxroot 从前只接受 "0:0"（等价 -0），其它取值明确报错。本次把它做成
# 支持**任意** uid:gid：
#
#   launcher（src/launcher/launcher.c）：`-i A:B` 严格解析出两个整数，
#     开启 fakeroot 记账（BXROOT_FAKEROOT=1）并 setenv BXROOT_FAKE_UID=A /
#     BXROOT_FAKE_GID=B（0:0 不设，用 runtime 默认 0）。
#   runtime（src/runtime/preload.c init_fakeroot）：读 BXROOT_FAKE_UID/GID
#     覆盖 fakeroot 假身份的 r/e/s/fs uid+gid 与补充组主项，于是所有身份
#     查询（getuid/geteuid/getresuid/getgroups、裸 syscall 174-177、
#     id/whoami）都自洽地报告 A:B。
#
# 本测试分两部分：
#   [R] runtime 身份映射：经 bxroot-run 直接设 BXROOT_FAKE_UID/GID +
#       BXROOT_FAKEROOT，验证 id / getresuid / 裸 syscall / getgroups
#       全部报映射值。**判别力**：非 0:0 时 id 必须报映射值而非 0。
#   [L] launcher 解析：编译 launcher.c，验证 `-i 1000:1000` 解析成功、
#       `-i 0:0` 仍等价 -0、非法取值（abc/1000/1000:/:1000/1:2:3）报错。
#
# 退出码：0 通过 / 1 失败 / 2 环境不满足（缺外层 proroot 或缺 build/）
# =====================================================================
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 1; }
BX="$ROOT/tools/bxroot-run"

PASS=0
FAIL=0
FAILED_LIST=""
ok()  { PASS=$((PASS + 1)); printf '  ✅ %-30s %s\n' "$1" "$2"; }
bad() { FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $1"
        printf '  ❌ %-30s %s\n' "$1" "$2"; }

echo "== 任意 -i uid:gid 身份映射回归 =="
echo

# ---------------------------------------------------------------------
# 部分 R：runtime 身份映射（需要外层 proroot 注入链路）
# ---------------------------------------------------------------------
echo "--- R) runtime 身份映射（经 bxroot-run）---"
RUNTIME_OK=1
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "  ⏭️  跳过 runtime 部分：需要外层 proroot（launcher+LD_PRELOAD 在此不可测）"
    RUNTIME_OK=0; }
[ "$RUNTIME_OK" = 1 ] && [ -f "$ROOT/build/libbxroot-runtime.so" ] || {
    [ "$RUNTIME_OK" = 1 ] && { echo "  ⏭️  跳过 runtime 部分：无 build/ 产物"; RUNTIME_OK=0; }
}

if [ "$RUNTIME_OK" = 1 ]; then
    W=$(mktemp -d /tmp/bxroot-idmap-XXXXXX) || W="$ROOT/.tmp-idmap"
    mkdir -p "$W"

    # 身份探针：直接读回 getresuid/getresgid、裸 syscall 174-177、getgroups。
    cat > "$W/idprobe.c" <<'EOF'
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
int main(void) {
    uid_t r, e, s; gid_t gr, ge, gs;
    gid_t g[32]; int n;
    getresuid(&r, &e, &s);
    getresgid(&gr, &ge, &gs);
    n = getgroups(32, g);
    printf("getuid=%u geteuid=%u getgid=%u getegid=%u\n",
           getuid(), geteuid(), getgid(), getegid());
    printf("resuid=%u,%u,%u resgid=%u,%u,%u\n", r, e, s, gr, ge, gs);
    printf("raw=%ld,%ld,%ld,%ld\n",
           syscall(174), syscall(175), syscall(176), syscall(177));
    printf("groups=%d,%u\n", n, n > 0 ? g[0] : 0);
    return 0;
}
EOF
    # gcc 13 间歇性 ICE：循环重试。
    i=1
    while [ "$i" -le 15 ]; do
        if gcc -O0 -o "$W/idprobe" "$W/idprobe.c" 2>"$W/cc.err"; then break; fi
        grep -q 'internal compiler error' "$W/cc.err" || {
            echo "  ❌ idprobe 编译失败（非 ICE）"; head -8 "$W/cc.err"; break; }
        i=$((i + 1))
    done

    if [ -x "$W/idprobe" ]; then
        # R1：映射成 1000:1000 —— 每一项都必须是 1000。
        out=$(BXROOT_FAKE_UID=1000 BXROOT_FAKE_GID=1000 BXROOT_FAKEROOT=1 \
              "$BX" --no-check -- "$W/idprobe" 2>/dev/null)
        if echo "$out" | grep -q '^getuid=1000 geteuid=1000 getgid=1000 getegid=1000$' &&
           echo "$out" | grep -q '^resuid=1000,1000,1000 resgid=1000,1000,1000$' &&
           echo "$out" | grep -q '^raw=1000,1000,1000,1000$' &&
           echo "$out" | grep -q '^groups=1,1000$'; then
            ok "R1 映射 1000:1000" "get*id/resid/裸syscall/groups 全报 1000"
        else
            bad "R1 映射 1000:1000" "身份查询未全部报 1000"
            printf '%s\n' "$out" | sed 's/^/       /'
        fi

        # R2：/usr/bin/id 报映射值（判别力核心：非 0:0 必须不是 0）。
        idout=$(BXROOT_FAKE_UID=1000 BXROOT_FAKE_GID=1000 BXROOT_FAKEROOT=1 \
                "$BX" --no-check -- /usr/bin/id 2>/dev/null | tail -1)
        case "$idout" in
            uid=1000*gid=1000*)
                ok "R2 id 报映射值" "$idout" ;;
            uid=0*)
                bad "R2 id 报映射值" "★ 仍报 uid=0 —— BXROOT_FAKE_UID 未被 runtime 采纳" ;;
            *)
                bad "R2 id 报映射值" "非预期输出: $idout" ;;
        esac

        # R3：不对称映射 uid=1000 gid=2000（uid/gid 不能串味）。
        out3=$(BXROOT_FAKE_UID=1000 BXROOT_FAKE_GID=2000 BXROOT_FAKEROOT=1 \
               "$BX" --no-check -- "$W/idprobe" 2>/dev/null)
        if echo "$out3" | grep -q '^getuid=1000 geteuid=1000 getgid=2000 getegid=2000$' &&
           echo "$out3" | grep -q '^groups=1,2000$'; then
            ok "R3 不对称 1000:2000" "uid=1000 gid=2000 各就各位"
        else
            bad "R3 不对称 1000:2000" "uid/gid 串味或未映射"
            printf '%s\n' "$out3" | sed 's/^/       /'
        fi

        # R4：默认 0:0（不设 FAKE_*）仍是 root —— 保证不回归。
        id0=$(BXROOT_FAKEROOT=1 "$BX" --no-check -- /usr/bin/id 2>/dev/null | tail -1)
        case "$id0" in
            uid=0*gid=0*) ok "R4 默认 fakeroot=root" "$id0" ;;
            *) bad "R4 默认 fakeroot=root" "★ 默认身份不再是 0: $id0" ;;
        esac
    else
        bad "R 探针编译" "无法产出 idprobe"
    fi
    rm -rf "$W"
fi

# ---------------------------------------------------------------------
# 部分 L：launcher CLI 解析（编译 launcher.c 直接跑）
# ---------------------------------------------------------------------
echo
echo "--- L) launcher -i 解析 ---"
CC="${CC:-gcc}"
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "  ⏭️  跳过 launcher 部分：找不到编译器 $CC"
else
    LW=$(mktemp -d /tmp/bxroot-idmap-cli-XXXXXX) || LW="$ROOT/.tmp-idmap-cli"
    mkdir -p "$LW"
    LCH="$LW/launcher"
    i=1
    while [ "$i" -le 15 ]; do
        if "$CC" -static -O1 -Wall -Wextra -Wformat=2 \
            -Wno-nonnull-compare -Wno-unused-parameter \
            -o "$LCH" src/launcher/launcher.c 2>"$LW/cc.err"; then
            break
        fi
        grep -q 'internal compiler error' "$LW/cc.err" || {
            echo "  ❌ launcher.c 编译失败（非 ICE）"; head -15 "$LW/cc.err"; break; }
        i=$((i + 1))
    done

    if [ -x "$LCH" ]; then
        # 判据：解析成功的标志是"没被 -i 自己的错误信息拦下"。因为容器里
        # 没有真 rootfs，合法的 -i 之后会因"找不到命令"失败 —— 那不是
        # -i 的错，反而证明 -i 段被顺利跨过。所以看首行是不是 -i 报错。
        classify_i() {
            timeout 10 "$LCH" -r /tmp -i "$1" /bin/true >"$LW/o" 2>&1
            head -1 "$LW/o"
        }

        # L1：合法映射被接受（首行不是 -i 的报错）。
        for spec in 1000:1000 0:0 65534:65534 1:2; do
            first=$(classify_i "$spec")
            case "$first" in
                *change-id*|*"-i "*) bad "L 合法 -i $spec" "★ 被拒: $first" ;;
                *) ok "L 合法 -i $spec" "被接受（后续因无 rootfs 而止，属预期）" ;;
            esac
        done

        # L2：非法取值必须报错（首行含 change-id 拒绝语）。
        for spec in abc 1000 1000: :1000 1:2:3 ":" ""; do
            first=$(classify_i "$spec")
            case "$first" in
                *change-id*) ok "L 非法 -i '$spec'" "明确拒绝" ;;
                *) bad "L 非法 -i '$spec'" "★ 未报错: $first" ;;
            esac
        done

        # L3：0:0 与 -0 等价 —— 都不 setenv FAKE_UID/GID。用 -v 观测
        #     launcher 交给 runtime 前的环境（这里通过 env 泄漏难测，改为
        #     确认 0:0 被接受即可；映射语义的等价性由 R4 在 runtime 侧钉住）。
        first=$(classify_i "0:0")
        case "$first" in
            *change-id*) bad "L 0:0 等价 -0" "★ 0:0 被拒" ;;
            *) ok "L 0:0 等价 -0" "0:0 接受（runtime 默认身份 0，见 R4）" ;;
        esac
    else
        bad "L launcher 编译" "无法产出可执行文件"
    fi
    rm -rf "$LW"
fi

# ---------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------
echo
echo "----------------------------------------"
echo "通过 $PASS / 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "失败项:$FAILED_LIST"
    echo "RESULT: FAIL"
    exit 1
fi
if [ "$PASS" = 0 ]; then
    echo "⏭️  两部分都被跳过（环境不满足）"
    echo "RESULT: SKIP"
    exit 2
fi
echo "RESULT: PASS"
exit 0
