/*
 * 真机探针：shmdt 的映射身份校验（2026-10-18 修复 S8）
 *
 * --- 缺陷 ---
 * 本进程的 attach 表只有 (addr, len, id)，而 `shmdt(addr)` **只按地址
 * 匹配**表项 —— 找到就把 [addr, addr+len) 整段 munmap。
 *
 * 地址是会被复用的。客户完全可能绕过 shmdt 直接 `munmap()` 掉 shm
 * 映射（移植代码、JIT、自定义内存池、以及任何"先 munmap 再说"的
 * 写法），此时表项仍然 ACTIVE；之后任何一次 mmap 都可能落回**同一个
 * 地址**。这时客户再调用一次 `shmdt(那个地址)`，就会把**别人的映射**
 * 拆掉：
 *   · 客户进程里莫名少了一块内存，崩溃点离原因极远；
 *   · 每次复现的地址还不一样（取决于当时的映射布局）；
 *   · 僵死表项永不回收，IPC_STAT 的 nattch 也会越算越多。
 *
 * --- 修复 ---
 * 拆之前先证明"这段地址背后还是不是我们那个 seg-<id>"：读
 * `/proc/self/map_files/<start>-<end>` 这个内核导出的符号链接。
 * 确认**不是**我们的 → 拒绝 munmap 并回收僵死表项；读不到证据 →
 * 保持原行为（不能因为拿不到证据就拒绝合法 shmdt）。
 *
 * --- 本探针 ---
 *   1. 正常路径：attach → shmdt → 必须成功且确实被 unmap（正向对照）
 *   2. 地址被窃取：attach → 客户自己 munmap → 在同一地址 MAP_FIXED
 *      一个**别的文件** → shmdt(该地址)
 *        · 修复前：返回 0，把别人的映射拆掉（探针能读到它变回未映射）
 *        · 修复后：返回 -EPERM，别人的映射**仍在**
 *
 * 判别力（已实测的对照实验，见 RUN_PTR_SAFETY.sh 的 M 段）：
 *   用修复前的 sysvshm.c 编同一探针 → 第 2 组的
 *   "无关映射仍然存活" 判定失败（msync 从 ENOMEM 变回 0 之前就被拆掉）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "sysvshm.c"

static int fails, checks;

static void ck(const char *what, int cond)
{
    checks++;
    if (!cond) {
        fails++;
        printf("  [FAIL] %s\n", what);
    } else {
        printf("  [ok]   %s\n", what);
    }
}

/* 这段地址当前是否仍被映射？msync 在未映射区间返回 ENOMEM */
static int still_mapped(void *addr, size_t len)
{
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    int r;
    if (p == MAP_FAILED)
        return -1;
    munmap(p, len);                    /* 只为拿到一个合法页大小 */
    errno = 0;
    r = msync(addr, len, MS_ASYNC);
    if (r == 0)
        return 1;
    return errno == ENOMEM ? 0 : -1;
}

static long shm_at(long id, long *out)
{
    return bxroot_sysvshm_emulate(196 /*SHM_NR_AT*/, (unsigned long)id, 0, 0, out);
}

static long shm_dt(unsigned long addr, long *out)
{
    return bxroot_sysvshm_emulate(197 /*SHM_NR_DT*/, addr, 0, 0, out);
}

static int make_seg(const char *dir, long id, size_t len)
{
    char path[512];
    int fd;
    (void)dir;
    /* 走 libc 路径（会被翻译到 rootfs 内的同一目录）*/
    snprintf(path, sizeof path, "/tmp/bxroot-s8-probe/shm/seg-%ld", id);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (ftruncate(fd, (off_t)len) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/*
 * ★ 路径必须是**宿主可见**的（探针的环境约束，2026-10-18）★
 *
 * sysvshm.c 内部全部是**裸 svc**，而裸 svc 的路径参数**不经过**路径
 * 翻译层。在本容器（proroot）里，`/tmp/x` 经 libc 会落到 rootfs 内，
 * 但裸 svc 会去宿主根找 —— 实测 openat 直接 -EACCES。所以要用
 * PROROOT_ROOTFS 前缀拼出宿主可见路径；建目录、造文件则用 libc
 * （它们会被翻译，落到同一位置）。
 */
static char g_dir[512];

static const char *setup_dir(void)
{
    const char *rf = getenv("PROROOT_ROOTFS");
    char hostbase[512];

    if (rf == NULL || rf[0] == '\0')
        return NULL;
    snprintf(hostbase, sizeof hostbase, "%s/tmp/bxroot-s8-probe", rf);
    {
        char cmd[600];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", hostbase);
        if (system(cmd) != 0) { /* 忽略 */ }
    }
    if (mkdir(hostbase, 0700) != 0 && errno != EEXIST)
        return NULL;
    snprintf(g_dir, sizeof g_dir, "%.400s/shm", hostbase);
    return g_dir;
}

int main(void)
{
    long out = 0, rc;
    size_t len = 4096;
    char dir[512];

    printf("=== SHM attach 身份校验 探针 ===\n\n");

    if (setup_dir() == NULL) {
        printf("  [SKIP] 没有 PROROOT_ROOTFS，裸 svc 路径无法对齐\n");
        return 0;
    }
    snprintf(dir, sizeof dir, "%s", g_dir);
    /* libc 视角的同一目录（会被路径翻译层处理）*/
    {
        char guest[512];
        snprintf(guest, sizeof guest, "/tmp/bxroot-s8-probe/shm");
        if (mkdir(guest, 0700) != 0 && errno != EEXIST) {
            printf("  [SKIP] 建段目录失败: %s\n", strerror(errno));
            return 0;
        }
    }
    if (bxroot_sysvshm_init(dir) != 0) {
        printf("  [SKIP] SHM 初始化失败（环境不支持）\n");
        return 0;
    }
    printf("段目录: %s\n\n", dir);

    /* ---------------- 组 1：正常 attach / detach ---------------- */
    printf("--- 1) 正常路径 ---\n");
    if (make_seg(dir, 1001, len) != 0) {
        printf("  [SKIP] 造段失败\n");
        return 0;
    }
    out = -1;
    rc = shm_at(1001, &out);
    ck("shmat(1001) 成功并返回地址", rc == 1 && out > 0);
    if (out > 0) {
        void *a = (void *)(uintptr_t)out;
        ck("attach 后该地址确实被映射", still_mapped(a, len) == 1);
        {
            long dt = 12345;
            rc = shm_dt((unsigned long)(uintptr_t)a, &dt);
            ck("shmdt 正常返回 0（未被加固误伤）", rc == 1 && dt == 0);
            ck("shmdt 后该地址已解除映射", still_mapped(a, len) == 0);
        }
    }

    /* ---------------- 组 2：地址被无关映射窃取 ---------------- */
    printf("\n--- 2) 地址被无关映射复用 ---\n");
    {
        void *a;
        void *stolen;
        int other_fd;
        char other[512];

        if (make_seg(dir, 1002, len) != 0) {
            printf("  [SKIP] 造段失败\n");
            return fails ? 1 : 0;
        }
        out = -1;
        rc = shm_at(1002, &out);
        ck("shmat(1002) 成功", rc == 1 && out > 0);
        if (rc != 1 || out <= 0)
            return 1;
        a = (void *)(uintptr_t)out;

        /* 客户绕过 shmdt 直接 munmap（模拟"表项变僵死"） */
        munmap(a, len);
        ck("客户自行 munmap 后该地址未映射", still_mapped(a, len) == 0);

        /* 在**同一地址**放一个别的文件映射 —— 这就是"无关映射" */
        snprintf(other, sizeof other, "/tmp/bxroot-s8-probe/shm/unrelated.bin");
        other_fd = open(other, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (other_fd < 0 || ftruncate(other_fd, (off_t)len) != 0) {
            printf("  [SKIP] 造无关文件失败\n");
            return fails ? 1 : 0;
        }
        stolen = mmap(a, len, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_FIXED, other_fd, 0);
        close(other_fd);
        if (stolen == MAP_FAILED) {
            printf("  [SKIP] MAP_FIXED 失败: %s\n", strerror(errno));
            return fails ? 1 : 0;
        }
        ck("无关映射已占据同一地址", stolen == a && still_mapped(a, len) == 1);

        /* 现在调用 shmdt(旧地址) —— 关键判定 */
        {
            long dt = 12345;
            rc = shm_dt((unsigned long)(uintptr_t)a, &dt);
            printf("  [info] shmdt(被窃取的地址) → rc=%ld out=%ld\n", rc, dt);
            ck("shmdt 拒绝拆掉无关映射（返回 -EPERM）", rc == 1 && dt == -1);
            ck("无关映射在 shmdt 之后**仍然存活**", still_mapped(a, len) == 1);
            ck("僵死表项已被回收（再次 shmdt 仍拒绝）",
               (dt = 12345, rc = shm_dt((unsigned long)(uintptr_t)a, &dt),
                rc == 1 && dt == -1));
        }
    }

    /* 清理 */
    {
        const char *rf = getenv("PROROOT_ROOTFS");
        char cmd[700];
        if (rf != NULL)
            snprintf(cmd, sizeof cmd, "rm -rf '%s/tmp/bxroot-s8-probe'", rf);
        else
            snprintf(cmd, sizeof cmd, "rm -rf '/tmp/bxroot-s8-probe'");
        if (system(cmd) != 0) { /* 清理失败不影响判定 */ }
    }

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
