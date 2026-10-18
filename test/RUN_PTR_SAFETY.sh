#!/bin/sh
# =====================================================================
# 客户指针安全性探针（2026-10-18 修复 #4 / #5 的回归门禁）
#
# 验证两件事：
#   1. ptr_writable_or_default() 对各类地址的判定正确；
#   2. syscall() 的 fakeroot 输出路径在客户传**不可写指针**时
#      返回 -1/EFAULT 而**不是 SIGSEGV**（修复前是后者）；
#   3. 裸 syscall 入口的**长路径**不会被静默跳过翻译（修复 #3）；
#   4. bind 的 `:ro` 只读标志大小写不敏感（修复 L2）；
#   5. 进程账本在多线程并发下自洽（修复 P1）；
#   6. livepatch 版本表落点形态校验（修复 livepatch 偏移漂移）；
#   7. SysV SHM 段目录被删后自愈（修复 S5）；
#   8. 每个线程都装有自己的备用栈（修复 crash.c sigaltstack）；
#   9. launcher 的 CLI 参数校验：-i 范围 / bind 上限 / -r 绝对化（L3/L4/L5）；
#  10. 账本不可用时 fork 不被中止（P2）；pid 复用后复活（P5）；
#  11. fork 后 SHM 门复位（S3）；
#  12. SHM 失败时返回内核会返回的错误码（S6）；
#  13. bind 畸形规格报错、继承的 BXROOT_BINDS 被清空（L6/L7）；
#  14. launcher 解析畸形 ELF 程序头不越界（L8）；
#  15. shmdt 不拆复用同地址的无关映射（S8）；
#  16. l2s .cnt 的跨进程读-改-写不丢更新。
#
# 判别力（可复跑的对照实验）：
#   用修复前的 syscall_guard.c 编同一探针 → 在 getresuid(0x1) 处 SIGSEGV，
#   退出码 139，故障地址 0x1。修复后返回 -1/EFAULT。
#
# 这两个探针都是**纯用户态单测**，不需要 rootfs、不需要注入，
# 因此在容器/真机上都能跑 —— 补上了此前"只有静态审查"的空白。
# =====================================================================
set -u

SRC=${BXROOT_SRC:-$(cd "$(dirname "$0")/.." && pwd)}
CC=${CC:-gcc}
TMP=${TMPDIR:-/tmp}
FAIL=0

CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE="
INCS="-I$SRC/src/runtime -I$SRC/src/l2s -I$SRC/src/proc"

echo "========================================"
echo " 客户指针安全性探针"
echo "========================================"

# ---------- 探针 1：ptr_writable_or_default ----------
echo
echo "--- A) ptr_writable_or_default 判定 ---"
if ! $CC $CFLAGS $INCS -o "$TMP/probe_ptr_writable" \
        "$SRC/test/probe_ptr_writable.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe1.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe1.err"
    FAIL=1
else
    if "$TMP/probe_ptr_writable"; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL"; FAIL=1
    fi
fi

# ---------- 探针 2：fakeroot 指针安全性 ----------
echo
echo "--- B) fakeroot 输出路径的指针安全性 ---"
if ! $CC $CFLAGS $INCS -o "$TMP/probe_fakeroot_ptr_safety" \
        "$SRC/test/probe_fakeroot_ptr_safety.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe2.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe2.err"
    FAIL=1
else
    _out=$("$TMP/probe_fakeroot_ptr_safety" 2>&1)
    _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    elif [ "$_rc" = 139 ]; then
        echo "  ❌ SIGSEGV —— 这正是修复前的症状（客户指针直接解引用）"
        FAIL=1
    else
        echo "  ❌ FAIL（rc=$_rc）"; FAIL=1
    fi
fi

# ---------- 探针 3：长路径翻译不被跳过 ----------
echo
echo "--- C) 裸 syscall 长路径翻译 ---"
if ! $CC $CFLAGS $INCS -o "$TMP/probe_longpath_translate" \
        "$SRC/test/probe_longpath_translate.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe3.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe3.err"
    FAIL=1
else
    _out=$("$TMP/probe_longpath_translate" 2>&1)
    _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL（rc=$_rc）—— 若同时看到 rc=0/成功，即 fail-open 复现"
        FAIL=1
    fi
fi

# ---------- 探针 4：bind :ro 大小写 ----------
echo
echo "--- D) bind \`:ro\` 大小写不敏感 ---"
if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
        -o "$TMP/probe_bind_ro_case" "$SRC/test/probe_bind_ro_case.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe4.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe4.err"
    FAIL=1
else
    # 源码文本断言需要相对仓库根的路径
    if ( cd "$SRC" && "$TMP/probe_bind_ro_case" ); then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL"; FAIL=1
    fi
fi

# ---------- 探针 5：账本并发自洽 ----------
echo
echo "--- E) 进程账本多线程并发 ---"
if ! $CC -O2 -Wall -Wextra -Wno-unused-parameter -Wno-nonnull-compare \
        -D_GNU_SOURCE= -DPX_PURE_LOGIC=0 -I"$SRC/src/proc" -lpthread \
        -o "$TMP/probe_ledger_concurrency" \
        "$SRC/test/probe_ledger_concurrency.c" "$SRC/src/proc/proc.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe5.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe5.err"
    FAIL=1
else
    _out=$("$TMP/probe_ledger_concurrency" 2>&1)
    _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL（rc=$_rc）—— 134 表示 free() 崩溃，即 UAF 复现"
        FAIL=1
    fi
fi

# ---------- 探针 6：livepatch 站点形态校验 ----------
echo
echo "--- F) livepatch 站点形态校验 ---"
if ! $CC -O2 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE= \
        -I"$SRC/src/runtime" -o "$TMP/probe_livepatch_form" \
        "$SRC/test/probe_livepatch_form.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe6.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe6.err"
    FAIL=1
else
    _out=$("$TMP/probe_livepatch_form" 2>&1)
    _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL —— 形态不符却仍打补丁，即会把无关调用改成恒成功"
        FAIL=1
    fi
fi

# ---------- 探针 7：SHM 段目录自愈 ----------
echo
echo "--- G) SysV SHM 段目录自愈 ---"
if ! $CC -O2 -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation \
        -D_GNU_SOURCE= -I"$SRC/src/runtime" -o "$TMP/probe_shm_dir_heal" \
        "$SRC/test/probe_shm_dir_heal.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe7.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe7.err"
    FAIL=1
else
    _out=$("$TMP/probe_shm_dir_heal" 2>&1)
    _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL —— 段目录删除后无法自愈"
        FAIL=1
    fi
fi

# ---------- 探针 8：每线程备用栈 ----------
echo
echo "--- H) 每线程 sigaltstack ---"
if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
        -I"$SRC/src/runtime" -lpthread -o "$TMP/probe_thread_altstack" \
        "$SRC/test/probe_thread_altstack.c" "$SRC/src/runtime/crash.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe8.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe8.err"
    FAIL=1
else
    _out=$("$TMP/probe_thread_altstack" 2>&1)
    _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL —— 有线程没有备用栈，栈溢出时将无现场"
        FAIL=1
    fi
fi

# ---------- 探针 9：launcher CLI 参数校验 ----------
echo
echo "--- I) launcher CLI 参数校验（-i / bind 上限 / -r）---"
LAUNCHER="$SRC/build/libbxroot.so"
if [ ! -x "$LAUNCHER" ]; then
    echo "  ⏭️  跳过：$LAUNCHER 不存在（先跑 make）"
else
    if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
            -o "$TMP/probe_launcher_cli" "$SRC/test/probe_launcher_cli.c" \
            2>"$TMP/probe9.err"; then
        echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe9.err"
        FAIL=1
    else
        _out=$("$TMP/probe_launcher_cli" "$LAUNCHER" 2>&1)
        _rc=$?
        printf '%s\n' "$_out" | sed 's/^/    /'
        if [ "$_rc" = 0 ]; then
            echo "  ✅ PASS"
        else
            echo "  ❌ FAIL"; FAIL=1
        fi
    fi
fi

# ---------- 探针 10/11：P2 与 P5 ----------
for one in probe_fork_no_ledger:P2-账本缺失 probe_pid_reuse_revive:P5-pid复用; do
    f="${one%%:*}"; label="${one##*:}"
    echo
    echo "--- J) $label ---"
    if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= -DPX_PURE_LOGIC=0 \
            -I"$SRC/src/proc" -lpthread -o "$TMP/$f" \
            "$SRC/test/$f.c" "$SRC/src/proc/proc.c" \
            -Wl,-z,max-page-size=16384 2>"$TMP/$f.err"; then
        echo "  ❌ 编译失败"; sed -n '1,15p' "$TMP/$f.err"
        FAIL=1
    else
        _out=$("$TMP/$f" 2>&1); _rc=$?
        printf '%s\n' "$_out" | sed 's/^/    /'
        if [ "$_rc" = 0 ]; then echo "  ✅ PASS"; else echo "  ❌ FAIL"; FAIL=1; fi
    fi
done

# ---------- 探针 12：fork 后 SHM 门复位（S3）----------
echo
echo "--- K) fork 后 SHM 门复位 ---"
if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
        -I"$SRC/src/runtime" -o "$TMP/probe_shm_fork_gate" \
        "$SRC/test/probe_shm_fork_gate.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe_gate.err"; then
    echo "  ❌ 编译失败"; sed -n '1,15p' "$TMP/probe_gate.err"
    FAIL=1
else
    _out=$("$TMP/probe_shm_fork_gate" 2>&1); _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then echo "  ✅ PASS"; else
        echo "  ❌ FAIL —— 子进程继承了门值，SHM 与 fork 会永久 -EAGAIN"; FAIL=1
    fi
fi

# ---------- 探针 13：SHM 错误码语义（S6）----------
echo
echo "--- L) SHM 错误码语义 ---"
if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
        -I"$SRC/src/runtime" -o "$TMP/probe_shm_errno" \
        "$SRC/test/probe_shm_errno.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe_errno.err"; then
    echo "  ❌ 编译失败"; sed -n '1,15p' "$TMP/probe_errno.err"
    FAIL=1
else
    # 源码判据需要仓库根的相对路径
    if ( cd "$SRC" && "$TMP/probe_shm_errno" ); then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL —— 仍把 EBADF 等内核不返回的错误码抛给客户"; FAIL=1
    fi
fi

# ---------- 探针 14：launcher ELF 程序头解析（L8）----------
echo
echo "--- M) launcher ELF 程序头解析（溢出）---"
if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
        -o "$TMP/probe_launcher_elf" "$SRC/test/probe_launcher_elf.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe_elf.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe_elf.err"
    FAIL=1
else
    _out=$("$TMP/probe_launcher_elf" 2>&1); _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL —— 畸形 ELF 的程序头被当成合法表项（越界读）"; FAIL=1
    fi
fi

# ---------- 探针 15：shmdt 的映射身份校验（S8）----------
echo
echo "--- N) shmdt 不拆无关映射 ---"
if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
        -I"$SRC/src/runtime" -o "$TMP/probe_shm_attach_identity" \
        "$SRC/test/probe_shm_attach_identity.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe_att.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe_att.err"
    FAIL=1
else
    _out=$("$TMP/probe_shm_attach_identity" 2>&1); _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    if [ "$_rc" = 0 ]; then
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL —— 地址被复用时 shmdt 拆掉了无关映射"; FAIL=1
    fi
fi

# ---------- 探针 16：l2s .cnt 跨进程原子性 ----------
echo
echo "--- O) l2s .cnt 跨进程计数 ---"
if ! $CC -O2 -Wall -Wno-unused-parameter -D_GNU_SOURCE= \
        -I"$SRC/src/l2s" -o "$TMP/probe_l2s_cnt_atomic" \
        "$SRC/test/probe_l2s_cnt_atomic.c" \
        -Wl,-z,max-page-size=16384 2>"$TMP/probe_cnt.err"; then
    echo "  ❌ 编译失败"; sed -n '1,20p' "$TMP/probe_cnt.err"
    FAIL=1
else
    _out=$("$TMP/probe_l2s_cnt_atomic" 2>&1); _rc=$?
    printf '%s\n' "$_out" | sed 's/^/    /'
    case "$_rc" in
    0) echo "  ✅ PASS" ;;
    *) echo "  ❌ FAIL —— 并发 +1 丢失（引用计数偏少 → 会提前回收数据）"; FAIL=1 ;;
    esac
fi

rm -f "$TMP/probe_ptr_writable" "$TMP/probe_fakeroot_ptr_safety" \
      "$TMP/probe_longpath_translate" "$TMP/probe_bind_ro_case" \
      "$TMP/probe_ledger_concurrency" "$TMP/probe_livepatch_form" \
      "$TMP/probe_shm_dir_heal" "$TMP/probe_thread_altstack" \
      "$TMP/probe_launcher_cli" "$TMP/probe_fork_no_ledger" \
      "$TMP/probe_pid_reuse_revive" "$TMP/probe_shm_fork_gate" \
      "$TMP/probe_shm_errno" "$TMP/probe_launcher_elf" \
      "$TMP/probe_shm_attach_identity" "$TMP/probe_att.err" \
      "$TMP/probe_l2s_cnt_atomic" "$TMP/probe_cnt.err" \
      "$TMP/probe_elf.err" "$TMP/probe_gate.err" "$TMP/probe_errno.err" \
      "$TMP/probe_fork_no_ledger.err" "$TMP/probe_pid_reuse_revive.err" \
      "$TMP/probe8.err" "$TMP/probe9.err" \
      "$TMP/probe5.err" "$TMP/probe6.err" "$TMP/probe7.err" \
      "$TMP/probe4.err" \
      "$TMP/probe1.err" "$TMP/probe2.err" "$TMP/probe3.err" 2>/dev/null

echo
echo "----------------------------------------"
if [ "$FAIL" = 0 ]; then
    echo "RESULT: PASS"
    exit 0
fi
echo "RESULT: FAIL"
exit 1
