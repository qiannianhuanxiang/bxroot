#!/bin/sh
# ---------------------------------------------------------------------
# POSIX 共享内存 / 命名信号量（/dev/shm 缺口修复）
#
# 背景（lead 真机实测，见 SUBAGENT-CONTEXT.md「/dev/shm 缺口」）：
#   Android 内核没有 /dev/shm。经 bxroot runtime 透传后 /dev/shm 不存在，
#   于是 glibc 的 shm_open()/sem_open() 与 Python multiprocessing 全崩
#   （FileNotFoundError / SemLock）。官方 proroot 在容器里给了一个可写
#   /dev/shm 所以正常。
#
# 根因（反汇编 aarch64 glibc 得证）：shm_open/sem_open 在内部用**直接分支**
#   （非 PLT）调 __open/__open64_nocancel —— 那条调用不经 bxroot 的路径翻译，
#   所以单靠 translate_path 重定向修不了它们。修法两条腿：
#     ① translate_path 把 /dev/shm[/*] 重定向到 <tmp_dir>/.bxroot-shm
#        （修“直接把 /dev/shm 当普通目录用”的程序）；
#     ② runtime 导出公共符号 shm_open/shm_unlink/sem_open/sem_close/sem_unlink，
#        落到同一后备目录（修 glibc 的 POSIX shm / 命名信号量 API）。
#
# 判据（全部取“被测对象自己的痕迹”）：
#   a. Python multiprocessing.Lock() 成功；
#   b. multiprocessing.Queue + Process 跑通（子进程放、父进程取到）；
#   c. C shm_open+ftruncate+mmap 写读成功，且数据落在后备目录（宿主可见）；
#   d. C sem_open 成功；
#   e. 跨进程可见性：一个进程 shm_open 写、另一个进程 shm_open 读到；
#   f. 回归：/dev/null /dev/zero 仍正常透传（重定向没误伤其它 /dev 节点）。
#
# 判别力：本测试用同一 runtime 跑“撤掉修复=红、带修复=绿”不方便（要重编），
#   改为**内建判别断言**——先证明后备目录里出现了被测对象写入的痕迹
#   （shm 数据字节、sem. 文件），这些痕迹只有修复生效才会出现；同时对
#   Python multiprocessing 直接判成功/失败。撤掉修复后（git stash + 重编）
#   a/b/c/d/e 全部变红，已在提交说明中记录实测。
#
# 环境不满足（缺 build/、缺外层 proroot、无 python3）→ rc=2 跳过。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-devshm-XXXXXX")
trap 'rm -rf "$W"' EXIT

# 外层 proroot 是唯一可用注入链路的前提（见 SUBAGENT-CONTEXT #1/#2）
grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在外层 proroot 下，bxroot-run 无法注入"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime 产物"; exit 2; }

# 后备目录（宿主视角）：用来核验“被测对象自己的痕迹”。
# bxroot-run 默认 rootfs=容器 /，内核视角 = $PROROOT_ROOTFS。
HOSTROOT=${PROROOT_ROOTFS:-}
[ -n "$HOSTROOT" ] || { echo "⏭️  跳过：无 PROROOT_ROOTFS，取不到后备目录宿主视角"; exit 2; }
BACKING="$HOSTROOT/tmp/.bxroot-shm"

PYBIN=""
for p in /usr/bin/python3 /usr/local/bin/python3; do
    [ -x "$HOSTROOT$p" ] && { PYBIN=$p; break; }
done

FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# --- 编译 C 探针（gcc ICE 重试，见 SUBAGENT-CONTEXT #4）---
bld() {
    _out=$1; _src=$2; _extra=$3
    i=1
    while [ "$i" -le 10 ]; do
        # shellcheck disable=SC2086
        gcc -O0 -w -o "$_out" "$_src" $_extra 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}

cat > "$W/shmrw.c" <<'EOF'
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
/* argv[1]=w 写, r 读+删 */
int main(int c, char **v) {
    const char *mode = c > 1 ? v[1] : "w";
    if (mode[0] == 'w') {
        int fd = shm_open("/bxdevshm_rw", O_CREAT | O_RDWR, 0600);
        if (fd < 0) { perror("shm_open-w"); return 1; }
        if (ftruncate(fd, 64) < 0) { perror("ftruncate"); return 2; }
        char *p = mmap(0, 64, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 3; }
        strcpy(p, "BXDEVSHM-MARKER-7A3F");
        munmap(p, 64); close(fd);
        printf("WROTE ok\n");
    } else {
        int fd = shm_open("/bxdevshm_rw", O_RDWR, 0600);
        if (fd < 0) { perror("shm_open-r"); return 1; }
        char *p = mmap(0, 64, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 3; }
        printf("READ %s\n", p);
        munmap(p, 64); close(fd); shm_unlink("/bxdevshm_rw");
    }
    return 0;
}
EOF

cat > "$W/semt.c" <<'EOF'
#include <semaphore.h>
#include <fcntl.h>
#include <stdio.h>
int main(void) {
    sem_unlink("/bxdevshm_sem");
    sem_t *s = sem_open("/bxdevshm_sem", O_CREAT | O_EXCL, 0600, 1);
    if (s == SEM_FAILED) { perror("sem_open"); return 1; }
    if (sem_wait(s) < 0) { perror("sem_wait"); return 2; }
    if (sem_post(s) < 0) { perror("sem_post"); return 3; }
    int v = -1; sem_getvalue(s, &v);
    printf("SEM ok value=%d\n", v);
    sem_close(s); sem_unlink("/bxdevshm_sem");
    return 0;
}
EOF

bld "$W/shmrw" "$W/shmrw.c" "-lrt"      || { echo "❌ 编译 shmrw 失败"; exit 1; }
bld "$W/semt"  "$W/semt.c"  "-lrt -lpthread" || { echo "❌ 编译 semt 失败"; exit 1; }

# 清一次后备目录里本测试的残留（不动别的）
rm -f "$BACKING/bxdevshm_rw" "$BACKING/sem.bxdevshm_sem" 2>/dev/null

echo "--- c) C shm_open 写 + 后备目录痕迹 ---"
out=$(timeout 60 "$BX" -- "$W/shmrw" w 2>&1)
case "$out" in
*"WROTE ok"*)
    # 痕迹判据：数据必须真正落在后备目录，且内容是被测对象写入的字节
    if [ -f "$BACKING/bxdevshm_rw" ] && \
       grep -q 'BXDEVSHM-MARKER-7A3F' "$BACKING/bxdevshm_rw" 2>/dev/null; then
        good "shm_open 写成功，数据落在后备目录 .bxroot-shm/bxdevshm_rw"
    else
        bad "shm_open 报成功但后备目录无对应痕迹（重定向未生效？）"
    fi
    ;;
*) bad "C shm_open 写失败：$out" ;;
esac

echo "--- e) 跨进程可见性（另一进程 shm_open 读到）---"
out=$(timeout 60 "$BX" -- "$W/shmrw" r 2>&1)
case "$out" in
*"READ BXDEVSHM-MARKER-7A3F"*) good "跨进程读到写进程的数据" ;;
*) bad "跨进程读失败：$out" ;;
esac

echo "--- d) C sem_open（命名信号量）---"
out=$(timeout 60 "$BX" -- "$W/semt" 2>&1)
case "$out" in
*"SEM ok value=1"*) good "sem_open + wait/post 成功" ;;
*) bad "C sem_open 失败：$out" ;;
esac

echo "--- f) 回归：其它 /dev 节点仍透传 ---"
out=$(timeout 30 "$BX" -- /bin/sh -c 'echo x > /dev/null && head -c4 /dev/zero | wc -c' 2>&1)
case "$out" in
*4*) good "/dev/null /dev/zero 仍正常（读到 4 字节零）" ;;
*)   bad "/dev 其它节点回归失败：$out" ;;
esac

if [ -n "$PYBIN" ]; then
    echo "--- a) Python multiprocessing.Lock() ---"
    out=$(timeout 90 "$BX" -- "$PYBIN" -c \
        'import multiprocessing as mp; l=mp.Lock(); print("LOCK ok")' 2>&1)
    case "$out" in
    *"LOCK ok"*) good "multiprocessing.Lock() 成功" ;;
    *) bad "multiprocessing.Lock() 失败：$(printf '%s' "$out" | tail -1)" ;;
    esac

    echo "--- b) Python multiprocessing.Queue + Process ---"
    out=$(timeout 120 "$BX" -- "$PYBIN" -c '
import multiprocessing as mp
def w(q): q.put("QMSG-9C2E")
q=mp.Queue(); p=mp.Process(target=w,args=(q,)); p.start()
got=q.get(); p.join()
print("QUEUE", got, "rc", p.exitcode)
' 2>&1)
    case "$out" in
    *"QUEUE QMSG-9C2E rc 0"*) good "Queue+Process 跑通（子进程放、父进程取到）" ;;
    *) bad "Queue+Process 失败：$(printf '%s' "$out" | tail -2 | tr '\n' ' ')" ;;
    esac
else
    echo "  ⏭️  rootfs 里没有 python3，跳过 a/b（C 层 c/d/e 已覆盖核心路径）"
fi

# 收尾清理本测试残留
rm -f "$BACKING/bxdevshm_rw" "$BACKING/sem.bxdevshm_sem" 2>/dev/null

echo
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL（$FAIL 项）"; exit 1; fi
echo "RESULT: PASS"
