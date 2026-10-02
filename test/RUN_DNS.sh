#!/bin/sh
# =====================================================================
# RUN_DNS.sh —— DNS/NSS 解析回归（path-relay，2026-09-28）
#
# 缺陷：bxroot 下 getaddrinfo/gethostbyname 恒 gaierror -3
#   (Temporary failure in name resolution)；`getent -s dns hosts <host>`
#   rc=2。官方 proroot runtime 下同样调用正常。
#
# 根因（见 src/runtime/livepatch.c 的 path-relay 段）：glibc 的 resolver
# 经 _IO_fopen→_IO_file_open→__open 最终**内联 svc openat(56)**，带的是
# **未翻译的 guest 路径** /etc/resolv.conf。libc 内部用 bl 直跳自己的
# open 实现、最终内联 svc，既不经 PLT/GOT 也不经导出符号，preload.c 的
# open/openat/fopen 钩子与 syscall_guard 的 syscall() 钩子都拦不到。于是
# 内核按真实根解析 → 真实根 /etc 无 resolv.conf → ENOENT → resolver 拿
# 不到 nameserver → TEMP_FAIL。getservbyname/getprotobyname 同源同因。
#
# 修法：livepatch 第四部分 path-relay 把 libc 里 openat 的内联 svc 改写成
# `bl` 到一个翻译桩，桩里对绝对路径参数调 bxroot_translate_path 加 rootfs
# 前缀，再发真 svc（重入守卫 + fail-open，见 livepatch.c）。
#
# 三组判据（bxroot 成功且与官方一致）：
#   A. getent -s dns ahostsv4 <host>   → 出 IPv4（rc=0）
#   B. python getaddrinfo(<host>)      → 出 IP
#   C. python gethostbyname(<host>)    → 出 IP
#   并附 files 分支不回归：getent hosts localhost 与外层答案一致。
#
# 判别力（F）：BXROOT_NO_PATHRELAY=1 时 res_init 读不到 resolv.conf，
# nameserver 退回 127.0.0.1；开启时读到与外层相同的 nameserver。判据看
# nameserver 而不看"能否解析"——容器 127.0.0.1:53 可能恰有解析服务。
#
# 环境：需要外层 proroot（launcher+LD_PRELOAD 在此不可测）+ build/ 产物 +
# 容器有网。无网时 getent dns 会 rc=2，此时按"环境不满足"跳过（exit 2）。
# 官方基线（/tmp/off-rt.so 或 BXROOT_OFFICIAL_SO）存在则做双基线对照。
#
# 退出码：0 通过 / 1 失败 / 2 环境不满足（缺外层 proroot / 缺 build / 无网）
# =====================================================================
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot（launcher+LD_PRELOAD 在此不可测）"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：无 build/ 产物"; exit 2; }

# 非 aarch64 上 path-relay 的指令编码不适用（与 livepatch 其余部分同理）。
case "$(uname -m)" in
aarch64|arm64) ;;
*) echo "⏭️  跳过：本机非 aarch64（$(uname -m)），path-relay 指令编码不适用"; exit 2 ;;
esac

# 需要 python3 做 getaddrinfo/gethostbyname 判据（rootfs 里通常有）。
HAVE_PY=0
"$BX" -- /usr/bin/python3 -c 'pass' >/dev/null 2>&1 && HAVE_PY=1

# 官方基线（可选）：有则逐条对照增强判别力。
OFFICIAL_SO="${BXROOT_OFFICIAL_SO:-/tmp/off-rt.so}"
HAVE_OFF=0
[ -f "$OFFICIAL_SO" ] && HAVE_OFF=1

# 测试主机名：用两个稳定的公网名，任一解析成功即算有网。
HOST1="pypi.org"
HOST2="github.com"

# --- 先判"容器是否真有网"：直接（外层 proroot，等价官方）问一次 ---
#     若外层都解析不到，说明无网 → 环境不满足，跳过（避免把"无网"误报成回归）。
if ! getent -s dns hosts "$HOST1" >/dev/null 2>&1 && \
   ! getent -s dns hosts "$HOST2" >/dev/null 2>&1; then
    echo "⏭️  跳过：容器无网（外层 getent dns 也解析不到 $HOST1/$HOST2）"; exit 2
fi

FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# 从 getent 输出里抓第一个 IPv4（宽松匹配，避免 IP 段变化写死）。
ipv4() { grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1; }

# ★ A/E 用 ahostsv4，不用 hosts ★
# `getent hosts` 走 gethostbyname2 的 AF_INET6 优先顺序：有 AAAA 的域名
# （pypi.org 走 Fastly，双栈）只返回 IPv6，ipv4() 抓不到 → 误报失败
# （实测：外层与 bxroot 都只出 2a04:4e42::223 等，rc=0）。ahostsv4 只问 A
# 记录，同样经 resolver 读 resolv.conf，对 path-relay 的判别力不变。
echo "--- A) getent -s dns ahostsv4（bxroot 默认，path-relay 开）---"
a_out=$("$BX" -- /usr/bin/getent -s dns ahostsv4 "$HOST1" 2>&1); a_rc=$?
a_ip=$(printf '%s\n' "$a_out" | ipv4)
if [ "$a_rc" = 0 ] && [ -n "$a_ip" ]; then
    good "getent -s dns ahostsv4 $HOST1 → $a_ip (rc=0)"
else
    bad "getent -s dns ahostsv4 $HOST1 失败：rc=$a_rc out=[$a_out]"
fi

if [ "$HAVE_PY" = 1 ]; then
    echo "--- B) python getaddrinfo ---"
    b_ip=$("$BX" -- /usr/bin/python3 -c \
        "import socket;print(socket.getaddrinfo('$HOST1',443,socket.AF_INET)[0][4][0])" 2>&1)
    case "$b_ip" in
    *[0-9].[0-9]*.[0-9]*) good "getaddrinfo($HOST1) → $b_ip" ;;
    *) bad "getaddrinfo($HOST1) 失败：[$b_ip]" ;;
    esac

    echo "--- C) python gethostbyname ---"
    c_ip=$("$BX" -- /usr/bin/python3 -c \
        "import socket;print(socket.gethostbyname('$HOST1'))" 2>&1)
    case "$c_ip" in
    *[0-9].[0-9]*.[0-9]*) good "gethostbyname($HOST1) → $c_ip" ;;
    *) bad "gethostbyname($HOST1) 失败：[$c_ip]" ;;
    esac
else
    echo "--- B/C) 跳过 python 判据（rootfs 无 python3）---"
fi

echo "--- D) files 分支不回归（与外层同答案）---"
# ★ 判据是"与外层一致"，不是"必须出 localhost" ★
# files 分支的答案取决于容器的 /etc/hosts。DSHA 容器里它可能是**空文件**
# （实测 0 字节）—— 那时外层 getent hosts localhost 本身就 rc=2、无输出，
# 要求 bxroot 出 127.0.0.1 等于要求它凭空发明条目。改为与外层逐字比对：
# 外层有就必须一样，外层没有 bxroot 也不能有。
d_host=$(getent hosts localhost 2>&1); d_hrc=$?
d_out=$("$BX" -- /usr/bin/getent hosts localhost 2>&1); d_rc=$?
if [ "$d_rc" = "$d_hrc" ] && [ "$d_out" = "$d_host" ]; then
    good "getent hosts localhost 与外层一致（rc=$d_rc，[$(echo "$d_out" | tr '\n' ' ')]）"
else
    bad "getent hosts localhost 与外层不一致：外层 rc=$d_hrc [$d_host] vs bxroot rc=$d_rc [$d_out]"
fi

# --- 官方双基线对照（可选）：bxroot 的 IP 应与官方一致 ---
if [ "$HAVE_OFF" = 1 ]; then
    echo "--- E) 官方 runtime 双基线对照 ---"
    off_ip=$(BXROOT_RUN_RUNTIME="$OFFICIAL_SO" "$BX" --no-check -- \
        /usr/bin/getent -s dns ahostsv4 "$HOST1" 2>&1 | ipv4)
    if [ -z "$off_ip" ]; then
        echo "  ⏭️  官方基线未解析（可能无网波动），跳过对照"
    elif [ "$a_ip" = "$off_ip" ]; then
        good "bxroot=$a_ip 与官方=$off_ip 一致"
    else
        # DNS 可能返回轮换 IP；只要都成功解析就不算失败，仅提示。
        echo "  ⚠️  bxroot=$a_ip 官方=$off_ip 不同（DNS 轮换/CDN，均成功即可）"
    fi
else
    echo "--- E) 无官方 off-rt.so，跳过双基线对照 ---"
fi

# --- 判别力：关掉 path-relay，resolver 必须读不到 resolv.conf ---
#
# ★ 判据是 res_init 读到的 nameserver，不是"能否解析" ★
# 读不到 resolv.conf 时 glibc 退回默认 nameserver 127.0.0.1。若容器
# 127.0.0.1:53 恰好有解析服务（DSHA 容器实测有），getent 照样 rc=0 ——
# 旧判据"关掉必须 rc!=0"因此误报。真正被 path-relay 决定的是"resolver
# 有没有读到 resolv.conf"：开 → ns0 = resolv.conf 里的地址；关 → 127.0.0.1。
echo "--- F) 判别力：BXROOT_NO_PATHRELAY=1 时 res_init 读不到 resolv.conf ---"
FW=$(mktemp -d /tmp/bxroot-dns-f-XXXXXX)
f_ok=0
i=1
while [ $i -le 10 ]; do
    if gcc -O1 -w -o "$FW/resinit" "$ROOT/test/probe_resinit.c" -lresolv \
        2>"$FW/cc.err"; then f_ok=1; break; fi
    grep -q 'internal compiler error' "$FW/cc.err" || break
    i=$((i + 1))
done
if [ "$f_ok" = 1 ]; then
    f_host=$("$FW/resinit" 2>&1 | sed -n 's/^ns0=//p')
    f_on=$("$BX" --no-check -- "$FW/resinit" 2>&1 | sed -n 's/^ns0=//p')
    f_off=$(BXROOT_NO_PATHRELAY=1 "$BX" --no-check -- "$FW/resinit" 2>&1 | sed -n 's/^ns0=//p')
    if [ -z "$f_host" ] || [ "$f_host" = "127.0.0.1" ]; then
        echo "  ⏭️  外层 resolv.conf 本身就是 127.0.0.1/读不到（ns0=[$f_host]），F 无判别力，跳过"
    elif [ "$f_on" = "$f_host" ] && [ "$f_off" != "$f_host" ]; then
        good "path-relay 开 ns0=$f_on（=外层），关 ns0=${f_off:-空}（读不到 resolv.conf，绿是修复挣来的）"
    elif [ "$f_on" != "$f_host" ]; then
        bad "path-relay 开时 res_init 未读到 resolv.conf：ns0=[$f_on] 期望 [$f_host]"
    else
        bad "关闭 path-relay 后 res_init 仍读到 resolv.conf（ns0=$f_off）—— 判别力不足，绿可能来自别处"
    fi
else
    echo "  ⏭️  跳过 F（probe_resinit 无法编译，可能缺 libresolv-dev）"
fi
rm -rf "$FW"

# --- G) 绝对符号链接布局的 resolv.conf（BUG-D1，systemd-resolved 默认）---
#   /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf（绝对目标）时，
#   resolver 经库内内联 svc openat 走 path-relay。修前 path-relay 只做前缀
#   拼接、不重定向绝对符号链接目标 → 读到的 link 目标从外层内核根解析 →
#   ENOENT → res_init 退化成 127.0.0.1 → DNS 全挂。修后 relay 在 -ENOENT
#   时调 abs-symlink 重定向腿。这里用一棵**专属子 rootfs**，把 resolv.conf
#   做成绝对符号链接，用 res_init 探针读 nscount/ns[0]。
#
#   判别力：把探针读到的 nameserver 和 loopback 默认区分开——绝对符号链接
#   若没修，res_init 只会拿到 127.0.0.1（读空），拿不到我们埋的 198.18.x。
echo "--- G) 绝对符号链接 resolv.conf（systemd 布局，res_init 判据）---"
# 用 res_init 探针（走 resolver 的库内内联 svc openat，正是 BUG-D1 命中的
# 那条路；cat/open 走 exported 钩子有重试腿，测不出来）。探针需 -lresolv。
GW=$(mktemp -d /tmp/bxroot-dns-abssym-XXXXXX)
RESPROBE="$GW/resinit"
gcc_ok=0
i=1
while [ $i -le 10 ]; do
    if gcc -O1 -w -o "$RESPROBE" "$ROOT/test/probe_resinit.c" -lresolv \
        2>"$GW/cc.err"; then gcc_ok=1; break; fi
    grep -q 'internal compiler error' "$GW/cc.err" || break
    i=$((i + 1))
done
if [ "$gcc_ok" = 1 ]; then
    mkdir -p "$GW/etc" "$GW/run/systemd/resolve" "$GW/root" "$GW/tmp"
    for d in usr bin lib lib64 sbin; do
        [ -e "/$d" ] && ln -s "/$d" "$GW/$d" 2>/dev/null
    done
    printf 'hosts: files dns\n' > "$GW/etc/nsswitch.conf"
    printf '127.0.0.1 localhost\n' > "$GW/etc/hosts"
    printf 'nameserver 198.18.0.246\nsearch guestonly.internal\n' \
        > "$GW/run/systemd/resolve/stub-resolv.conf"
    cp "$RESPROBE" "$GW/root/resinit"
    # 绝对符号链接布局（systemd-resolved 默认）
    ln -s /run/systemd/resolve/stub-resolv.conf "$GW/etc/resolv.conf"

    g_out=$(BXROOT_RUN_ROOTFS="$GW" "$BX" --rootfs "$GW" --no-check -- \
        /root/resinit 2>&1 | grep -E 'ns0=|nscount=')
    case "$g_out" in
    *"ns0=198.18.0.246"*)
        good "绝对符号链接 resolv.conf 被 resolver 读到（$(echo "$g_out"|tr '\n' ' ')）" ;;
    *"ns0=127.0.0.1"*)
        bad "res_init 退化成 127.0.0.1（BUG-D1 回归：绝对符号链接未重定向）" ;;
    *)
        bad "res_init 探针输出异常：[$(echo "$g_out"|tr '\n' ' ')]" ;;
    esac

    # 判别力：BXROOT_NO_ABSSYM=1 精准关掉"绝对符号链接展开"这条腿，应回退。
    g2_out=$(BXROOT_NO_ABSSYM=1 BXROOT_RUN_ROOTFS="$GW" "$BX" --rootfs "$GW" \
        --no-check -- /root/resinit 2>&1 | grep -E 'ns0=')
    case "$g2_out" in
    *"ns0=198.18.0.246"*) echo "  ⚠️  关 abs-symlink 后仍读到（该布局或不依赖此腿）" ;;
    *) good "关闭 abs-symlink 展开后 res_init 拿不到 guest ns（判别力成立）" ;;
    esac
else
    echo "  ⏭️  跳过 G（probe_resinit 无法编译，可能缺 libresolv-dev）"
fi
rm -rf "$GW"

echo
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL（$FAIL 项）"; exit 1; fi
echo "RESULT: PASS"
exit 0
