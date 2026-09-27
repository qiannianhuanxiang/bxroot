#!/data/data/com.termux/files/usr/bin/sh
# =====================================================================
# bxroot 真机验证（Termux 版）—— 对应 docs/真机验证清单.md
#
# 这台机器上跑的是 launcher + LD_PRELOAD 路径 —— 正是开发容器里
# 被外层 proroot 吞掉、一直无法验证的那一半。
#
# 用法（Termux 里）：
#   cd ~/bxtm && sh run.sh            # 全部
#   sh run.sh 2>&1 | tee result.txt   # 把 result.txt 发回来
#
# 每项打印  PASS/FAIL/INFO <编号> <说明> ；末尾汇总。
# 只读设备信息，不改系统；所有临时文件在本目录。
# =====================================================================
cd "$(dirname "$0")" || exit 1
HERE=$(pwd)
BX="$HERE/bx/bxroot"
RF="$HERE/rootfs"
export BXROOT_LIB_PATH="$HERE/bx/libbxroot-runtime.so"
# Termux 的 LD_PRELOAD（bionic libtermux-exec）不能漏进 glibc guest
unset LD_PRELOAD
# guest 继承宿主 PATH（与 proot 同语义）；Termux 的 PATH 在 rootfs 里不存在
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# 宿主 cwd 不在 rootfs 内 → launcher 会按上游语义警告并回退 /；脚本显式 -w /
bxw() { "$BX" -w / "$@"; }
P=0; F=0
pass() { P=$((P+1)); echo "PASS $*"; }
fail() { F=$((F+1)); echo "FAIL $*"; }
info() { echo "INFO $*"; }
chmod 755 "$BX" 2>/dev/null
chmod -R u+rwX "$RF" 2>/dev/null

echo "=== 环境 ==="
info env "uid=$(id -u) $(uname -r) $(getprop ro.build.version.release 2>/dev/null)"
info env "seccomp: $(grep -E '^Seccomp:' /proc/self/status)"
info env "termux prefix: $PREFIX"
[ -x "$BX" ] || { fail A0 "launcher 不可执行: $BX"; ls -la "$BX"; exit 1; }
[ -f "$BXROOT_LIB_PATH" ] || { fail A0 "runtime 缺失"; exit 1; }

echo; echo "=== E0 launcher 本身能否运行 ==="
out=$("$BX" -V 2>&1); rc=$?
[ $rc -eq 0 ] && pass E0 "launcher -V: $out" || { fail E0 "launcher -V rc=$rc: $out"; }

echo; echo "=== E1 LD_PRELOAD 注入是否真的生效（最关键）==="
# 判据：/etc/hostname 必须是 rootfs 里那个，而不是 Termux/宿主的
out=$(bxw -r "$RF" /bin/cat /etc/hostname 2>&1); rc=$?
if [ "$out" = "bxroot-guest" ]; then pass E1 "路径翻译生效 (hostname=$out)"; else fail E1 "rc=$rc out=[$out]"; fi
# 判据 2：runtime 出现在 maps 里
out=$(bxw -r "$RF" /bin/cat /proc/self/maps 2>&1 | grep -c libbxroot-runtime)
[ "$out" -gt 0 ] && pass E1b "runtime 已映射到 guest 进程 ($out 段)" || fail E1b "guest 进程 maps 里没有 runtime"

echo; echo "=== E2 子进程 / 孙进程继承 ==="
out=$(bxw -r "$RF" /bin/sh -c '/bin/sh -c "/bin/cat /etc/hostname"' 2>&1); rc=$?
[ "$out" = "bxroot-guest" ] && pass E2 "两层 sh 后仍在 rootfs" || fail E2 "rc=$rc out=[$out]"
out=$(bxw -r "$RF" /bin/sh -c '/bin/true; echo r=$?; (echo sub); /bin/sh -c "/bin/true; echo r2=\$?"' 2>&1); rc=$?
echo "$out" | grep -q "r=0" && echo "$out" | grep -q "r2=0" && echo "$out" | grep -q "^sub" && pass E2b "fork/exec 子孙进程正常" || fail E2b "rc=$rc out=[$out]"

echo; echo "=== A2/A3 fakeroot 身份 ==="
out=$(bxw -0 -r "$RF" /usr/bin/id 2>&1); rc=$?
echo "$out" | grep -q "uid=0(root)" && pass A2 "$out" || fail A2 "rc=$rc out=[$out]"
out=$(bxw -0 -r "$RF" /usr/bin/getent passwd 0 2>&1); rc=$?
echo "$out" | grep -q "^root:" && pass A3 "getent passwd 0 -> $out" || fail A3 "rc=$rc out=[$out]"
out=$(bxw -0 -r "$RF" /usr/bin/whoami 2>&1)
[ "$out" = "root" ] && pass A3b "whoami=root" || fail A3b "whoami=[$out]"

echo; echo "=== A4/A5 comm ==="
cat > "$RF/tmp/cm.sh" <<'EOF'
#!/bin/sh
read c </proc/self/comm; echo "$c"
EOF
chmod +x "$RF/tmp/cm.sh"
out=$(bxw -r "$RF" /tmp/cm.sh 2>&1)
info A4 "comm 直跑脚本 = [$out]（期望 cm.sh）"
[ "$out" = "cm.sh" ] && pass A4 "comm=cm.sh" || fail A4 "comm=[$out]"

echo; echo "=== B1 shebang argv ==="
printf '#!/bin/echo HELLO\n' > "$RF/tmp/sg"; chmod +x "$RF/tmp/sg"
out=$(bxw -r "$RF" /tmp/sg 2>&1)
[ "$out" = "HELLO /tmp/sg" ] && pass B1 "$out" || fail B1 "[$out]（期望 'HELLO /tmp/sg'）"

echo; echo "=== B2 /proc/self/fd 与 exe/cwd 视角 ==="
out=$(bxw -r "$RF" /bin/sh -c 'exec 3</etc/hostname; readlink /proc/self/fd/3' 2>&1)
[ "$out" = "/etc/hostname" ] && pass B2 "fd/3 -> $out" || fail B2 "fd/3 -> [$out]"
out=$(bxw -r "$RF" -w /etc /bin/sh -c 'readlink /proc/self/cwd' 2>&1)
[ "$out" = "/etc" ] && pass B2b "cwd -> $out" || fail B2b "cwd -> [$out]"
out=$(bxw -r "$RF" /bin/sh -c 'readlink /proc/self/exe' 2>&1)
# 上游 test-99999999：子进程 readlink 读的是它自己 → /usr/bin/readlink
[ "$out" = "/usr/bin/readlink" ] && pass B2c "exe -> $out" || fail B2c "exe -> [$out]"
out=$(bxw -r "$RF" /bin/sh -c 'read x </proc/self/cmdline 2>/dev/null; ls -l /proc/$$/exe | sed "s/.*-> //"' 2>&1)
case "$out" in /bin/sh|/usr/bin/dash|/bin/dash) pass B2f "shell 自身 exe -> $out";; *) fail B2f "shell exe -> [$out]";; esac
out=$(bxw -r "$RF" /bin/sh -c 'cat /proc/self/root/etc/hostname' 2>&1)
[ "$out" = "bxroot-guest" ] && pass B2d "/proc/self/root/ 穿透 -> $out" || fail B2d "[$out]"
out=$(bxw -r "$RF" /bin/sh -c '/proc/self/exe -c "echo viaexe"' 2>&1)
[ "$out" = "viaexe" ] && pass B2e "exec /proc/self/exe" || fail B2e "[$out]"

echo; echo "=== B4 realpath / B6 cwd / B7 一致性 ==="
out=$(bxw -r "$RF" /usr/bin/realpath /etc/hostname 2>&1)
[ "$out" = "/etc/hostname" ] && pass B4 "$out" || fail B4 "[$out]"
out=$(bxw -r "$RF" -w /tmp /bin/sh -c 'test "$(pwd -P)" = "$(realpath .)" && echo SAME' 2>&1)
[ "$out" = "SAME" ] && pass B7 "pwd -P == realpath ." || fail B7 "[$out]"
out=$("$BX" -r "$RF" -w /nonexistent /bin/sh -c 'pwd; echo PWD=$PWD' 2>&1)
echo "$out" | grep -q "falling back" && echo "$out" | grep -q "PWD=/" && pass B6 "workdir 回退（$(echo "$out" | head -1)）" || fail B6 "[$out]"

echo; echo "=== C1/C2 -v 静默 / C4 SIGPIPE ==="
out=$(bxw -v -1 -r "$RF" /bin/true 2>&1); rc=$?
[ $rc -eq 0 ] && [ -z "$out" ] && pass C1 "-v -1 静默 rc=0" || fail C1 "rc=$rc out=[$out]"
out=$(bxw -r "$RF" /bin/sh -c 'yes | head -1 >/dev/null; echo done' 2>&1); rc=$?
[ "$out" = "done" ] && pass C4 "yes|head 不挂" || fail C4 "rc=$rc [$out]"

echo; echo "=== L l2s 硬链接模拟 ==="
out=$(bxw -l -r "$RF" /bin/sh -c 'cd /tmp && rm -f a b && echo hi >a && ln a b && stat -c %h a && cat b && rm a && cat b && rm b && ls -a /tmp | grep -c l2s' 2>&1); rc=$?
info L "$(echo "$out" | tr '\n' ' ')"
echo "$out" | sed -n 1p | grep -q "^2$" && echo "$out" | sed -n 3p | grep -q "^hi$" && pass L1 "ln/rm 语义正确（nlink=2，删源后目标仍可读）" || fail L1 "rc=$rc"

echo; echo "=== S seccomp 场景（app 域特有）==="
info S "guest 进程 seccomp: $(bxw -r "$RF" /bin/sh -c 'grep -E "^Seccomp" /proc/self/status | tr "\n" " "' 2>&1)"
out=$(bxw -r "$RF" /bin/sh -c 'timeout 5 /bin/sh -c "for i in 1 2 3; do (/bin/true) & done; wait; echo forks-ok"' 2>&1); rc=$?
[ "$out" = "forks-ok" ] && pass S1 "并发 fork 子进程无 SIGSYS" || fail S1 "rc=$rc [$out]"
out=$(bxw -r "$RF" /usr/bin/find /tmp -maxdepth 1 2>&1 | head -1); rc=$?
[ -n "$out" ] && pass S2 "find（faccessat2/statx 类新调用）rc=$rc" || fail S2 "find 无输出 rc=$rc"
out=$(bxw -r "$RF" /bin/sh -c 'sort --parallel=4 -S 1M </etc/passwd | head -1' 2>&1); rc=$?
[ -n "$out" ] && pass S3 "sort（pthread 多线程）正常" || fail S3 "rc=$rc"

echo; echo "=== K kill-on-exit / 内核版本伪装 ==="
out=$(bxw -k 4.19.0-bx -r "$RF" /usr/bin/uname -r 2>&1)
[ "$out" = "4.19.0-bx" ] && pass K1 "uname -r 伪装 -> $out" || fail K1 "[$out]"

echo; echo "=== G 参数 / 环境 / 嵌套 shebang 边界 ==="
out=$(bxw -r "$RF" /bin/sh -c '/bin/echo $(seq 1 9000) | wc -w' 2>&1)
[ "$out" = "9000" ] && pass G1 "9000 个参数全部送达" || fail G1 "[$out]（期望 9000）"
out=$(bxw -r "$RF" /bin/sh -c 'x=$(head -c 100000 /dev/zero | tr "\0" a); X=$x /bin/sh -c "echo \${#X}"' 2>&1)
[ "$out" = "100000" ] && pass G2 "100 KB 环境变量保留" || fail G2 "[$out]"
printf '#!/bin/sh\necho S1 "$0" "$1" "$2" "$3"\n' > "$RF/tmp/gs1"; printf '#!/tmp/gs1 A1\n' > "$RF/tmp/gs2"; chmod +x "$RF/tmp/gs1" "$RF/tmp/gs2"
out=$(bxw -r "$RF" /bin/sh -c '/tmp/gs2 X' 2>&1)
[ "$out" = "S1 /tmp/gs1 A1 /tmp/gs2 X" ] && pass G3 "两层 shebang" || fail G3 "[$out]"

echo; echo "=== X 沙箱逃逸（需先把 test/probe_escape_*.c 编译为 rootfs/tmp/esc 与 esc2）==="
echo CANARY > "$HERE/canary"; mkdir -p "$HERE/hd"; echo CANARY > "$HERE/hd/canary"
if [ -x "$RF/tmp/esc" ]; then
    out=$(bxw -r "$RF" /tmp/esc "$HERE" 2>&1 | tail -1)
    [ "$out" = "DONE escapes=0" ] && pass X1 "\`..\` 0 逃逸" || fail X1 "$out"
else info X1 "跳过（无 /tmp/esc）"; fi
if [ -x "$RF/tmp/esc2" ]; then
    out=$(bxw -r "$RF" /tmp/esc2 "$HERE/hd" 2>&1 | tail -1)
    [ "$out" = "DONE escapes=0" ] && [ "$(ls "$HERE/hd" | wc -l)" -eq 1 ] && pass X2 "宿主绝对链接 0 逃逸" || fail X2 "$out"
else info X2 "跳过（无 /tmp/esc2）"; fi

echo; echo "=== 详细诊断（FAIL 时看这里）==="
bxw -v 1 -r "$RF" /bin/cat /etc/hostname 2>&1 | head -30

echo; echo "====================================================="
echo " 通过 $P / 失败 $F"
echo "====================================================="
[ $F -eq 0 ]
