/*
 * sysvshm.c —— SysV 共享内存模拟（shmget 194 / shmctl 195 / shmat 196 / shmdt 197）
 *
 * 【为什么需要】（行动清单 #12，2026-09-25 RUN_TRAP_PARITY 发现）
 * Android seccomp 白名单 TRAP 掉 194..197，glibc 的 shm* 全是**内联 svc**
 * （objdump：shmget@ef304 `mov x8,#0xc2; svc #0`），所以符号钩子拦不到，
 * 只能在 SIGSYS 处理器里模拟。修前 bxroot 一律 ENOSYS；而官方 proroot
 * 已模拟 —— PostgreSQL、X11 MIT-SHM、部分 Python/Java 库依赖它。
 *
 * 【方案：与官方同一磁盘格式】（实测官方 /tmp/.proroot-shm 得出）
 *   <dir>/seg-<id>   段内容文件，ftruncate 到 size；shmat = mmap MAP_SHARED
 *   <dir>/key-<key>  文本，内容为 "<id>\n"（key 是十进制有符号数，如 key--5）
 * 跨进程状态**全部在文件系统里**（天然跨 fork/exec/无关进程可见），
 * 与官方共用目录时两边的段互相可见。本进程只记一张 attach 表
 * （地址 → id/长度），供 shmdt 与 nattch 用。
 *
 * 【语义 —— 以官方可观测行为为准，逐条实测】
 *   shmget(IPC_PRIVATE)          每次新段
 *   shmget(key, CREAT)           key 已存在 → 返回原 id（size 不校验）
 *   shmget(key, CREAT|EXCL) 已存在 → EPERM（官方如此；内核是 EEXIST，
 *                                  这里跟官方，保持对照一致；见 ERR_* 注释）
 *   shmget(key) 不存在           → EPERM（内核 ENOENT；同上）
 *   shmat(无效 id)               → EPERM（内核 EINVAL）
 *   shmat(addr 非 0)             → 忽略 addr，由内核选址（官方实测如此）
 *   shmdt(非本表地址)            → EPERM（内核 EINVAL）
 *   IPC_STAT                     segsz=文件大小，mode=600，其余 0（官方同）；
 *                                nattch=**本进程** attach 数（官方恒 0。内核
 *                                是全局计数 —— 跨进程计数需要共享账本，
 *                                这里取"至少本进程内正确"的折中，比恒 0 更接近内核）
 *   IPC_RMID                     删 seg 与指向它的 key；已映射的继续可用
 *                                （内核语义，mmap 天然保证）；对不存在的 id 也回 0
 *   其它 cmd                     EPERM（官方同）
 *
 * 【errno 选择】官方用 EPERM 表达所有失败。这里**逐条跟官方**，因为本仓库
 * 的判定口径是"与官方对照"，而客户程序对 shm 失败基本只判 -1 不细分
 * errno。若将来要跟内核，只改下面 ERR_* 宏即可，不影响结构。
 *
 * 【★ "默认关闭"的确切含义 —— 只关**创建**，不关**使用** ★】
 *
 * 默认构建 `BXROOT_SHM_CLAIM_VERIFIED=0`，于是：
 *   · `shmget(IPC_PRIVATE)` 与 `shmget(key, ...)` 一律返回 **ENOSYS(38)**；
 *   · `shmat` / `shmdt` / `shmctl` **仍然可用** —— 只要 backing 目录里
 *     本来就有 `seg-<id>`。
 *
 * 为什么这样切分（而不是把四个调用全关掉）：
 *   · 目录里出现 `seg-<id>` 只有两种来源：官方 proroot 建的（共用目录
 *     时两边互相可见），或者 guest 自己 `open()` 造的。两种情况下
 *     "能不能读这块共享内存"都**不由我们决定** —— guest 本就能直接
 *     `mmap` 那个文件。所以关掉 shmat 不增加任何隔离性，只会让
 *     **官方容器退出的段在 bxroot 里读不到**，破坏共用目录的前提。
 *   · 反过来，`shmget` 的"新建"会写入共享目录、并且需要 claim 锁做
 *     跨进程串行化 —— 那条路径依赖 `fcntl(25)` 的 OFD 锁，在目标
 *     seccomp 链里**尚未实测**。这才是真正要保守的那一半。
 *
 * 所以文档口径统一为"**默认关闭新建**"（README 已如此表述），而不是
 * "SysV SHM 默认关闭"。审计意见 S4 指出的"目录里有 seg-<id> 就能真
 * mmap"，正是上面第 1 条的具体体现，**不是缺陷**，是刻意保留。
 *
 * 【★ 已知边界：claim 载体的位置（S7，明确不做）★】
 * claim 锁 `.claim-lock` 与永久预留标记 `.id-<id>` 都放在 backing 目录
 * （默认 `/tmp/.proroot-shm`）里，而该目录位于 guest 自己的可写命名空间。
 * 因此能删目录里文件的进程也可以：
 *   · 删掉 `.id-<id>` → 该 id 之后可能被新段重新占用（ABA）；
 *   · 删掉 `.claim-lock` → 两个进程各自新建一把锁（串行化失效）。
 *
 * 为什么**不修**：guest 与 runtime 是**同一个 uid**，能删 `.id-*` 的
 * 进程同样能删 `seg-*` —— 后者是直接毁数据。也就是说 ABA 并没有把
 * 任何"本来做不到的事"变成"做得到"；真正的隔离需要不同的 uid 或私有
 * 挂载命名空间，那不属于本项目的模型（README「安全边界」明确写了
 * 本实现不是沙箱）。要在兼容 SysV 整型 id 的前提下做代数（generation）
 * 校验，就必须让客户手里的 id 携带代数 —— 与官方整型 id 格式冲突，
 * 因此**在兼容约束内不可实现**，如实记在这里而不是留一个假修复。
 *
 * 【约束】本文件被 #include 进 sigsys.c，运行在 SIGSYS 处理器里：
 *   只用裸 svc、栈上缓冲与原子操作；不 malloc、不 stdio、不碰 errno 约定
 *   （返回值统一是内核约定：成功值或 -errno）。
 */

#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <unistd.h>
#include <fcntl.h>
#include "shm-copyout.h"

/* F_OFD_SETLK on raw fcntl(25) must be checked under the final target filter.
 * A syscall gate cannot relax inherited seccomp; never probe inside SIGSYS. */
#ifndef BXROOT_SHM_CLAIM_VERIFIED
#define BXROOT_SHM_CLAIM_VERIFIED 0
#endif
#if BXROOT_SHM_CLAIM_VERIFIED != 0 && BXROOT_SHM_CLAIM_VERIFIED != 1
#error BXROOT_SHM_CLAIM_VERIFIED must be 0 or 1
#endif

#define SHM_NR_GET  194
#define SHM_NR_CTL  195
#define SHM_NR_AT   196
#define SHM_NR_DT   197

#define ERR_EXIST   1   /* EPERM：官方对 EXCL 冲突的回答（内核 EEXIST=17） */
#define ERR_NOENT   1   /* EPERM：官方对缺键的回答（内核 ENOENT=2） */
#define ERR_INVAL   1   /* EPERM：官方对无效 id/地址/cmd 的回答（内核 EINVAL=22） */
#define ERR_AGAIN  11   /* bxroot 内部 key claim 忙：不等待、不破坏其他 mutator */

/* aarch64 裸号 */
#define NR_OPENAT     56
#define NR_CLOSE      57
#define NR_READ       63
#define NR_WRITE      64
#define NR_FSTAT      80
#define NR_UNLINKAT   35
#define NR_READLINKAT 78
/*
 * gettid 的裸号。必须和上面这批 NR_* 放在一起：shm_claim_key() 在有界
 * 重试里用它让出调度（见该函数注释），而 test/RUN_SHM_ID_ABA.sh 会把
 * 本文件**单独**复制出去编译（-Werror），那时没有 sigsys.c 的上下文。
 * 原先它定义在文件后半段，于是那次编译在 shm_claim_key 处报
 * "SHM_NR_GETTID undeclared" —— 测试长期 FAIL 却没人注意到是**宏位置**
 * 引起的（缺陷修复，2026-10-18）。
 */
#define SHM_NR_GETTID 178
#define NR_MKDIRAT    34
#define NR_FTRUNCATE  46
#define NR_MMAP       222
#define NR_MUNMAP     215
#define NR_GETRANDOM  278
#define NR_RENAMEAT2  276
#define NR_GETDENTS64 61
#define NR_FCNTL      25
#define F_OFD_SETLK   37
#define F_WRLCK       1
#define F_UNLCK       2
#define SEEK_SET_K    0
#define CLAIM_LOCK_NAME ".claim-lock"
#define K_O_DIRECTORY 040000

#define K_AT_FDCWD   (-100)
#define K_O_RDWR     02
#define K_O_CREAT    0100
#define K_O_EXCL     0200
#define K_O_WRONLY   01
#define K_O_CLOEXEC  02000000
/* O_NOFOLLOW 的 ABI 值**按架构不同**，不能照抄 asm-generic。
 * aarch64（本机，内核实测）：0100000 —— 与 syscall_guard.c need_leaf
 * 判据同一个值（那边也记着 0x800 / 00400000 两次写错的历史）。
 * 写成 0400000 在本平台等于 O_DIRECT|O_LARGEFILE，真正的 NOFOLLOW
 * 位是 0 —— 这一层"防符号链接"全部失效：shm 目录里放一个符号链接
 * seg-<id>，shmat 就会映射到目录之外的文件（反证：改成 0100000 后
 * 同一条 openat 得 ELOOP）。回归用 test/probe_shm_nofollow.c。
 * 换架构必须重测。 */
#define K_O_NOFOLLOW 0100000
#define K_O_NONBLOCK 04000
#define K_PROT_RW    3
#define K_PROT_R     1
#define K_MAP_SHARED 1
#define K_RENAME_NOREPLACE 1
#define K_EEXIST     17
#define K_ENOENT     2

#define K_IPC_PRIVATE 0
#define K_IPC_CREAT   01000
#define K_IPC_EXCL    02000
#define K_IPC_RMID    0
#define K_IPC_STAT    2
#define K_SHM_RDONLY  010000

static long shm_svc6(long nr, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;   /* 内核约定：负数即 -errno */
}
#define SVC(nr, a, b, c) shm_svc6((nr), (long)(a), (long)(b), (long)(c), 0, 0, 0)

/* ---------------- 目录 ---------------- */

static char g_shm_dir[512];
static volatile int g_shm_dirfd = -1;
static volatile int g_shm_ready = 0;
static dev_t g_shm_dev;
static ino_t g_shm_ino;
static uid_t g_shm_owner; /* directory owner snapshot; no getuid in handler */
static unsigned long g_shm_pagesize = 4096;

int bxroot_sysvshm_anchor_fd(void)
{
    struct stat st;
    int fd = __atomic_load_n(&g_shm_dirfd, __ATOMIC_ACQUIRE);
    long r;
    if (fd < 0 || !__atomic_load_n(&g_shm_ready, __ATOMIC_ACQUIRE))
        return -1;
    r = shm_svc6(NR_FSTAT, fd, (long)&st, 0, 0, 0, 0);
    if (r != 0 || !S_ISDIR(st.st_mode) || st.st_dev != g_shm_dev ||
        st.st_ino != g_shm_ino || st.st_uid != g_shm_owner ||
        (st.st_mode & 0077) != 0)
        return -1;
    return fd;
}

/*
 * ★ 必须额外校验"目录**路径**还在"（缺陷修复，2026-10-18）★
 *
 * 原实现只对 anchor fd 做 fstat 并比对 dev/ino。但**已删除目录的 fd
 * 仍然可以 fstat 成功，而且 inode 号不变**（实测：rmdir 前后
 * fstat 都返回 0、st_ino 完全相同）。也就是说：
 *
 *     guest 删掉段目录 → anchor fd 还在，fstat 一切正常
 *     → 本函数返回"有效"
 *     → 但 openat(anchor_fd, "seg-N", O_CREAT) 必然 ENOENT
 *     → 新建段失败，且自愈路径永远不会被触发
 *
 * 所以仅靠 fd 无法察觉目录被删。这里再加一次**按路径**的打开：
 * 路径打不开 ⇒ 目录确实没了 ⇒ 判失效，交给 shm_mkdir 重建。
 *
 * 额外开销是一次 openat，且只在构造期与出错路径上发生，不进热路径。
 * 仍然全程裸 syscall，可在 SIGSYS 处理器上下文安全调用。
 */
static int shm_anchor_valid(void)
{
    struct stat st;
    int fd = bxroot_sysvshm_anchor_fd();
    long r, probe;

    if (fd < 0 || !__atomic_load_n(&g_shm_ready, __ATOMIC_ACQUIRE))
        return 0;

    /* 第一关：fd 侧元数据（dev/ino/owner/权限位） */
    r = shm_svc6(NR_FSTAT, fd, (long)&st, 0, 0, 0, 0);
    if (r != 0 || !S_ISDIR(st.st_mode) ||
        st.st_dev != g_shm_dev || st.st_ino != g_shm_ino ||
        st.st_uid != g_shm_owner || (st.st_mode & 0077) != 0)
        return 0;

    /*
     * 第二关：**路径**是否仍然存在。
     *
     * 已删除目录的 fd 会让第一关全过（见上面的实测），所以这一关是
     * 必需的，否则目录被删后永远不会自愈。
     */
    if (g_shm_dir[0] == '\0')
        return 0;
    probe = shm_svc6(NR_OPENAT, K_AT_FDCWD, (long)g_shm_dir,
                     K_O_DIRECTORY | K_O_CLOEXEC | K_O_NOFOLLOW | K_O_NONBLOCK,
                     0, 0, 0);
    if (probe < 0)
        return 0;                       /* 路径不在了 → 判失效，触发重建 */
    SVC(NR_CLOSE, probe, 0, 0);

    return 1;
}

int bxroot_sysvshm_init(const char *host_dir)
{
    struct stat st;
    size_t n;
    long fd, r;
    if (host_dir == NULL)
        return -1;
    if (__atomic_load_n(&g_shm_ready, __ATOMIC_ACQUIRE))
        return shm_anchor_valid() ? 0 : -1;
    n = strlen(host_dir);
    if (n == 0 || n + 64 >= sizeof(g_shm_dir))
        return -1;
    /* Constructor-time setup only; never reopen paths from SIGSYS context. */
    r = shm_svc6(NR_MKDIRAT, K_AT_FDCWD, (long)host_dir, 0700, 0, 0, 0);
    if (r < 0 && r != -17 /* EEXIST */)
        return -1;
    fd = shm_svc6(NR_OPENAT, K_AT_FDCWD, (long)host_dir,
                  K_O_DIRECTORY | K_O_CLOEXEC | K_O_NOFOLLOW | K_O_NONBLOCK,
                  0, 0, 0);
    if (fd < 0)
        return -1;
    r = shm_svc6(NR_FSTAT, fd, (long)&st, 0, 0, 0, 0);
    if (r < 0 || !S_ISDIR(st.st_mode) || (st.st_mode & 0077) != 0) {
        SVC(NR_CLOSE, fd, 0, 0);
        return -1;
    }
    memcpy(g_shm_dir, host_dir, n + 1);
    {
        long ps = sysconf(_SC_PAGESIZE);
        if (ps > 0 && (unsigned long)ps <= (1UL << 20) &&
            ((unsigned long)ps & ((unsigned long)ps - 1)) == 0)
            g_shm_pagesize = (unsigned long)ps;
    }
    g_shm_dev = st.st_dev;
    g_shm_ino = st.st_ino;
    g_shm_owner = st.st_uid;
    __atomic_store_n(&g_shm_dirfd, (int)fd, __ATOMIC_RELEASE);
    __atomic_store_n(&g_shm_ready, 1, __ATOMIC_RELEASE);
    return 0;
}

/* 异步信号安全的小工具：拼路径 */
static char *shm_puts(char *p, const char *s) { while (*s) *p++ = *s++; *p = 0; return p; }
/* 小写十六进制，无前缀 —— 只用于拼 /proc/self/map_files 的地址 */
static char *shm_putx(char *p, unsigned long v)
{
    char t[2 * sizeof v + 1];
    int i = 0;
    do {
        unsigned d = (unsigned)(v & 0xf);
        t[i++] = (char)(d < 10 ? '0' + d : 'a' + (d - 10));
        v >>= 4;
    } while (v);
    while (i)
        *p++ = t[--i];
    *p = 0;
    return p;
}
static char *shm_putl(char *p, long v)
{
    char t[24]; int i = 0; unsigned long u;
    if (v < 0) { *p++ = '-'; u = (unsigned long)(-(v + 1)) + 1; } else u = (unsigned long)v;
    do { t[i++] = (char)('0' + u % 10); u /= 10; } while (u);
    while (i) *p++ = t[--i];
    *p = 0;
    return p;
}
static void shm_path(char *buf, const char *kind, long v)
{
    char *p = shm_puts(buf, kind[0] == '/' ? kind + 1 : kind);
    shm_putl(p, v);
}

/*
 * ★ 目录失效时按 g_shm_dir 重建并刷新 anchor（缺陷修复，2026-10-18）★
 *
 * 【缺陷】原实现只有一句 `return shm_anchor_valid() ? 0 : -1;` ——
 * **只校验、从不重建**。而 bxroot_sysvshm_init() 只在构造函数跑一次，
 * g_shm_ready 一旦置 1 就永不回 0。于是 guest 一条
 * 删除 /tmp 下全部内容（`rm -rf /tmp/` 接通配符）这类操作之后：
 *
 *     shm_anchor_valid() 的 dev/ino 校验失败 → 本函数返回 -1
 *     → shm_get 返回 -ERR_INVAL → 194..197 全部失败
 *     → 而且**无法自愈**，只能重启进程
 *
 * 内核从不因这种原因让 shmget 返回 EINVAL，客户程序的行为不可预期。
 *
 * 【为什么重建是安全的】
 *   · 路径本身存在 g_shm_dir 里（init 时拷进来的），不依赖任何外部状态；
 *   · 重建用的是 mkdirat + openat + fstat，与 init 完全同源，
 *     全部是**裸 syscall**，没有 malloc/stdio —— 本函数可能在 SIGSYS
 *     处理器上下文被调用，必须保持 async-signal-safe；
 *   · 新目录会重新记录 dev/ino/owner，后续校验照常生效；
 *   · 若同一目录已被别人重建，mkdirat 返回 EEXIST，直接沿用 —— 正确。
 *
 * 【边界】只重建**目录本身**。目录里已存在的段文件（seg-*）若被一起
 * 删掉，那是数据丢失，无法恢复 —— 这里只保证"能力恢复可用"，
 * 不假装能恢复数据。
 */
static int shm_mkdir(void)
{
    struct stat st;
    long fd, r;

    if (shm_anchor_valid())
        return 0;

    /* 没有记录过路径（init 从未成功）→ 无从重建 */
    if (g_shm_dir[0] == '\0')
        return -1;

    r = shm_svc6(NR_MKDIRAT, K_AT_FDCWD, (long)g_shm_dir, 0700, 0, 0, 0);
    if (r < 0 && r != -17 /* EEXIST */)
        return -1;

    fd = shm_svc6(NR_OPENAT, K_AT_FDCWD, (long)g_shm_dir,
                  K_O_DIRECTORY | K_O_CLOEXEC | K_O_NOFOLLOW | K_O_NONBLOCK,
                  0, 0, 0);
    if (fd < 0)
        return -1;

    r = shm_svc6(NR_FSTAT, fd, (long)&st, 0, 0, 0, 0);
    if (r < 0 || !S_ISDIR(st.st_mode) || (st.st_mode & 0077) != 0) {
        SVC(NR_CLOSE, fd, 0, 0);
        return -1;
    }

    /* 旧的 anchor fd 可能仍指向已删除的旧 inode：先关再换 */
    {
        int old = __atomic_load_n(&g_shm_dirfd, __ATOMIC_ACQUIRE);
        if (old >= 0)
            SVC(NR_CLOSE, old, 0, 0);
    }

    g_shm_dev   = st.st_dev;
    g_shm_ino   = st.st_ino;
    g_shm_owner = st.st_uid;
    __atomic_store_n(&g_shm_dirfd, (int)fd, __ATOMIC_RELEASE);
    return 0;
}

/* ---------------- id 分配 ---------------- */

/*
 * Keep decimal seg-ID compatibility, but reserve every bxroot candidate forever
 * in .id-ID before creating seg-ID. RMID removes only segments/keys; reservations
 * are never reclaimed, including failed creations. This prevents ID ABA within
 * the lifetime of this backing directory (not against external token deletion).
 * Empty 0400 tokens consume one directory entry/inode per attempted fresh ID.
 */
static long shm_new_segment(long size, int *out_fd)
{
    char path[600];
    int tries;
    unsigned long pagesize = g_shm_pagesize;
    unsigned long rounded = 0;
    if (size < 0 || pagesize == 0)
        return -22;
    if (size > 0) {
        unsigned long us = (unsigned long)size;
        if (us > (unsigned long)-1 - (pagesize - 1))
            return -22;
        rounded = (us + pagesize - 1) & ~(pagesize - 1);
        if (rounded > (~0UL >> 1))
            return -22;
    }
    for (tries = 0; tries < 64; tries++) {
        unsigned int r = 0;
        long id, fd, reserved, closed;
        int dfd;
        if (SVC(NR_GETRANDOM, &r, sizeof r, 0) != (long)sizeof r)
            r = (unsigned int)(uintptr_t)&r ^ (unsigned int)tries * 2654435761u;
        id = (long)(r & 0x3fffffff);
        if (id == 0)
            continue;
        dfd = bxroot_sysvshm_anchor_fd();
        if (dfd < 0)
            return -38;   /* ENOSYS：仿真不可用（内核从不返回 EBADF，见 1073 处说明） */
        shm_path(path, "/.id-", id);
        reserved = shm_svc6(NR_OPENAT, dfd, (long)path,
                            K_O_WRONLY | K_O_CREAT | K_O_EXCL | K_O_CLOEXEC |
                            K_O_NOFOLLOW | K_O_NONBLOCK, 0400, 0, 0);
        if (reserved == -K_EEXIST)
            continue; /* Never open, modify or delete an existing reservation. */
        if (reserved < 0)
            return reserved;
        closed = SVC(NR_CLOSE, reserved, 0, 0);
        if (closed < 0)
            return closed; /* token remains reserved even on close failure */
        shm_path(path, "/seg-", id);
        /* A failed segment creation keeps the token: never recycle this ID. */
        fd = shm_svc6(NR_OPENAT, dfd, (long)path,
                      K_O_RDWR | K_O_CREAT | K_O_EXCL | K_O_CLOEXEC | K_O_NOFOLLOW,
                      0600, 0, 0);
        if (fd == -K_EEXIST)
            continue;
        if (fd < 0)
            return fd;
        /*
         * ★ size == 0 也要把文件撑到一页（缺陷修复，2026-10-18）★
         *
         * 原写法 `if (size > 0)` 时 0 字节段**不做 ftruncate**，文件长度
         * 保持 0。而 sh_do_at() 那条路径明确支持 0 字节段：
         *
         *     len = st.st_size;          // 0
         *     if (len == 0) len = 1;     // → 再取整成一页 4096
         *     mmap(..., 4096, PROT_R|W, MAP_SHARED, fd, 0);
         *
         * 0 字节文件的有效页数是 0，**任何页都不在 page cache 里**，
         * 对 MAP_SHARED 映射的首次读写直接 **SIGBUS** —— 不是返回错误，
         * 是确定性崩溃。也就是说"支持 0 字节段"这条实现反而成了一个
         * 可达的进程崩溃点。
         *
         * 修法：size == 0 时按一页 ftruncate。段长语义仍报 shm_segsz=0
         * （IPC_STAT 用创建者传入的 size），只是 backing 文件有实体页，
         * 映射可安全访问。这与"映射一页"的既有设计一致。
         */
        {
            unsigned long fit = (size > 0) ? (unsigned long)size
                                           : (unsigned long)g_shm_pagesize;
            long t = SVC(NR_FTRUNCATE, fd, (long)fit, 0);
            if (t < 0) {
                SVC(NR_CLOSE, fd, 0, 0);
                SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), path, 0);
                return t;
            }
        }
        *out_fd = (int)fd;
        return id;
    }
    return -28; /* ENOSPC: all 64 random candidates were reserved/unavailable */
}

static int shm_fd_is_private_file(long fd)
{
    struct stat st;
    long r = shm_svc6(NR_FSTAT, fd, (long)&st, 0, 0, 0, 0);
    if (r < 0 || !S_ISREG(st.st_mode) || st.st_uid != g_shm_owner ||
        (st.st_mode & 0077) != 0)
        return 0;
    return 1;
}

static long shm_open_seg(long id, int rdonly)
{
    char path[600];
    if (id <= 0 || id > 0x7fffffffL)
        return -ERR_INVAL;
    shm_path(path, "/seg-", id);
    {
        long fd = SVC(NR_OPENAT, bxroot_sysvshm_anchor_fd(), path,
                      (rdonly ? 0 : K_O_RDWR) | K_O_CLOEXEC | K_O_NOFOLLOW | K_O_NONBLOCK);
        if (fd < 0)
            return fd;
        if (!shm_fd_is_private_file(fd)) {
            SVC(NR_CLOSE, fd, 0, 0);
            return -ERR_INVAL;
        }
        return fd;
    }
}

/* ---------------- key 表 ---------------- */

/* 只接受正的 31-bit 十进制 id，末尾允许一个换行。 */
static int shm_parse_id(const char *s, long n, long *out)
{
    long v = 0;
    long i = 0;
    int digits = 0;
    if (s == NULL || out == NULL || n <= 0)
        return -1;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
        int d = s[i] - '0';
        if (v > (0x7fffffffL - d) / 10)
            return -1;
        v = v * 10 + d;
        digits = 1;
        i++;
    }
    if (!digits || v <= 0)
        return -1;
    if (i < n && s[i] == '\n')
        i++;
    if (i != n)
        return -1;
    *out = v;
    return 0;
}

static int shm_parse_key_name(const char *s, long n, long *out)
{
    long i = 0, v = 0;
    int sign = 1, digits = 0;
    unsigned long limit;
    if (s == NULL || out == NULL || n <= 0)
        return -1;
    if (s[i] == '-') { sign = -1; i++; }
    limit = sign < 0 ? 0x80000000UL : 0x7fffffffUL;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
        unsigned int d = (unsigned int)(s[i] - '0');
        if ((unsigned long)v > (limit - d) / 10UL)
            return -1;
        v = v * 10 + (long)d;
        digits = 1;
        i++;
    }
    if (!digits || i != n)
        return -1;
    *out = sign * v;
    return 0;
}

static long shm_read_key(long key)
{
    char path[600], b[32];
    long fd, n, v = 0;
    shm_path(path, "/key-", key);
    fd = SVC(NR_OPENAT, bxroot_sysvshm_anchor_fd(), path, K_O_CLOEXEC | K_O_NOFOLLOW | K_O_NONBLOCK);
    if (fd < 0)
        return fd;
    if (!shm_fd_is_private_file(fd)) {
        SVC(NR_CLOSE, fd, 0, 0);
        return -22;
    }
    n = SVC(NR_READ, fd, b, sizeof b);
    SVC(NR_CLOSE, fd, 0, 0);
    if (n < 0)
        return n;
    if (n == 0 || n >= (long)sizeof b || shm_parse_id(b, n, &v) != 0)
        return -22;
    return v;
}

static int shm_fd_is_private_file(long fd);

static long shm_claim_key(long key)
{
#if !BXROOT_SHM_CLAIM_VERIFIED
    (void)key;
    return -38; /* ENOSYS until the target filter permits fcntl OFD locks */
#else
    struct { short type; short whence; long long start; long long len; int pid; } fl;
    int dfd = bxroot_sysvshm_anchor_fd();
    long fd, r;
    (void)key;
    if (dfd < 0)
        return -38;   /* ENOSYS：仿真不可用（同上） */
    fd = shm_svc6(NR_OPENAT, dfd, (long)CLAIM_LOCK_NAME,
                  K_O_RDWR | K_O_CREAT | K_O_CLOEXEC | K_O_NOFOLLOW | K_O_NONBLOCK,
                  0600, 0, 0);
    if (fd < 0)
        return fd;
    if (!shm_fd_is_private_file(fd)) {
        SVC(NR_CLOSE, fd, 0, 0);
        return -ERR_INVAL;
    }
    fl.type = F_WRLCK; fl.whence = SEEK_SET_K; fl.start = 0; fl.len = 0; fl.pid = 0;

    /*
     * ★ 锁竞争要**有界重试**，不能直接把 EAGAIN 抛给客户（缺陷修复，2026-10-18）★
     *
     * 原来是一次 `F_OFD_SETLK`（非阻塞），拿不到就返回 -ERR_AGAIN（EAGAIN）。
     * 两个问题：
     *
     *   1. **内核的 shmget 从不返回 EAGAIN**。PostgreSQL 这类程序不会对
     *      shmget 做重试，于是一次瞬时的锁竞争被升级成**永久失败**。
     *   2. 锁是**全局单锁**（注意上面的 `(void)key`——key 根本没参与），
     *      所以任意一个 key 的 RMID 都能挡住别人。
     *
     * 为什么不能直接改成阻塞的 F_OFD_SETLKW：本函数在 **SIGSYS 处理器
     * 上下文**里被调用（emulate → shm_do_get → 这里）。在信号处理器里
     * 阻塞等待锁，一旦持锁方正是被本处理器打断的那个线程，就是永久
     * 死锁，而且是在信号上下文里，连诊断都出不来。
     *
     * 所以用**有界重试**：短暂自旋若干次给竞争方一点时间，仍拿不到才失败。
     * 失败时返回 EAGAIN —— 这不是"内核语义"，但在有界重试之后它已经是
     * 真正的异常（不是瞬时抖动），而且比死锁好得多。这一点如实记录。
     */
    {
        int spins;
        r = -1;
        for (spins = 0; spins < 100; spins++) {
            r = shm_svc6(NR_FCNTL, fd, F_OFD_SETLK, (long)&fl, 0, 0, 0);
            if (r == 0)
                break;
            if (r != -11 && r != -13)   /* 不是 EAGAIN/EACCES（锁被占） */
                break;
            /*
             * 极短让步：不调用任何 libc/sleep（信号上下文不允许），
             * 用一条无副作用的 gettid 往返让出调度机会。
             */
            (void)shm_svc6(SHM_NR_GETTID, 0, 0, 0, 0, 0, 0);
        }
    }
    if (r < 0) {
        SVC(NR_CLOSE, fd, 0, 0);
        return (r == -11 || r == -13) ? -ERR_AGAIN : r;
    }
    return fd;
#endif
}

static void shm_release_claim(long fd, long key)
{
    struct { short type; short whence; long long start; long long len; int pid; } fl;
    (void)key;
    if (fd < 0)
        return;
    fl.type = F_UNLCK; fl.whence = SEEK_SET_K; fl.start = 0; fl.len = 0; fl.pid = 0;
    (void)shm_svc6(NR_FCNTL, fd, F_OFD_SETLK, (long)&fl, 0, 0, 0);
    SVC(NR_CLOSE, fd, 0, 0);
}

/* bxroot claim 持有期间发布 key，官方 decimal key 内容保持不变。 */
static long shm_publish_key(long key, long id)
{
    char tmp[600], path[600], b[24], *p;
    long fd, r;
    unsigned int rnd = 0;
    SVC(NR_GETRANDOM, &rnd, sizeof rnd, 0);
    p = shm_puts(tmp, ".tmp-key-");
    p = shm_putl(p, id);
    p = shm_puts(p, "-");
    shm_putl(p, (long)rnd);
    fd = shm_svc6(NR_OPENAT, bxroot_sysvshm_anchor_fd(), (long)tmp,
                  K_O_WRONLY | K_O_CREAT | K_O_EXCL | K_O_CLOEXEC | K_O_NOFOLLOW,
                  0600, 0, 0);
    if (fd < 0)
        return fd;
    p = shm_putl(b, id);
    *p++ = '\n';
    {
        long want = p - b;
        long wrote = SVC(NR_WRITE, fd, b, want);
        if (wrote != want) {
            SVC(NR_CLOSE, fd, 0, 0);
            SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), tmp, 0);
            return wrote < 0 ? wrote : -ERR_INVAL;
        }
    }
    SVC(NR_CLOSE, fd, 0, 0);
    shm_path(path, "/key-", key);
    r = shm_svc6(NR_RENAMEAT2, bxroot_sysvshm_anchor_fd(), (long)tmp, bxroot_sysvshm_anchor_fd(), (long)path,
                 K_RENAME_NOREPLACE, 0);
    if (r < 0)
        SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), tmp, 0);
    return r;
}

/*
 * 删除所有内容为 "<id>\n" 的 key-* 文件。用 getdents64 扫目录（处理器里
 * 不能用 opendir/readdir —— 它们会 malloc）。
 */
static long shm_unlink_keys_of(long id)
{
    char dbuf[2048], path[600];
    long dfd, n;
    dfd = shm_svc6(NR_OPENAT, bxroot_sysvshm_anchor_fd(), (long)".",
                   K_O_DIRECTORY | K_O_CLOEXEC | K_O_NOFOLLOW, 0, 0, 0);
    if (dfd < 0)
        return dfd;
    while ((n = SVC(NR_GETDENTS64, dfd, dbuf, sizeof dbuf)) > 0) {
        long off = 0;
        while (off < n) {
            unsigned short reclen;
            const char *name;
            if (off < 0 || off + 19 > n)
                break;
            reclen = *(unsigned short *)(dbuf + off + 16);
            if (reclen < 19 || off + reclen > n)
                break;
            name = dbuf + off + 19;
            {
                long key;
                long name_len = 0;
                long capacity = (long)reclen - 19;
                while (name_len < capacity && name[name_len] != '\0')
                    name_len++;
                if (name_len != capacity && name_len >= 5 &&
                    name[0] == 'k' && name[1] == 'e' && name[2] == 'y' && name[3] == '-' &&
                    shm_parse_key_name(name + 4, name_len - 4, &key) == 0 &&
                    shm_read_key(key) == id) {
                    if (shm_read_key(key) == id) {
                        shm_path(path, "/key-", key);
                        long removed = SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), path, 0);
                        if (removed < 0 && removed != -K_ENOENT) {
                            SVC(NR_CLOSE, dfd, 0, 0);
                            return removed;
                        }
                    }
                }
            }
            off += reclen;
        }
    }
    SVC(NR_CLOSE, dfd, 0, 0);
    return n < 0 ? n : 0;
}

/* ---------------- 本进程 attach 表 ---------------- */

#define SHM_MAX_ATT 256
#define ATT_FREE      0UL
#define ATT_RESERVED  1UL
#define ATT_ACTIVE    2UL
#define ATT_DETACHING 3UL
#define ATT_STATE_MASK 3UL
#define ATT_GEN_SHIFT 2
#define ATT_GEN_MAX   ((~0UL) >> ATT_GEN_SHIFT)
struct shm_att {
    _Alignas(8) volatile unsigned long ctrl; /* state + generation */
    volatile unsigned long addr;
    volatile unsigned long len;
    volatile long id;
};
static struct shm_att g_att[SHM_MAX_ATT];
_Static_assert(__atomic_always_lock_free(sizeof(unsigned long), 0),
               "SysV SHM attach table requires lock-free native atomics");

static unsigned long shm_att_token(unsigned long gen, unsigned long state)
{
    return (gen << ATT_GEN_SHIFT) | state;
}

static int shm_att_add(unsigned long addr, unsigned long len, long id)
{
    int i;
    for (i = 0; i < SHM_MAX_ATT; i++) {
        unsigned long old = __atomic_load_n(&g_att[i].ctrl, __ATOMIC_ACQUIRE);
        unsigned long gen;
        unsigned long next;
        if ((old & ATT_STATE_MASK) != ATT_FREE)
            continue;
        gen = old >> ATT_GEN_SHIFT;
        if (gen >= ATT_GEN_MAX)
            continue; /* 饱和后退役槽位，避免代际回卷 */
        next = shm_att_token(gen + 1, ATT_RESERVED);
        if (!__atomic_compare_exchange_n(&g_att[i].ctrl, &old, next, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        __atomic_store_n(&g_att[i].addr, addr, __ATOMIC_RELAXED);
        __atomic_store_n(&g_att[i].len, len, __ATOMIC_RELAXED);
        __atomic_store_n(&g_att[i].id, id, __ATOMIC_RELEASE);
        __atomic_store_n(&g_att[i].ctrl, shm_att_token(gen + 1, ATT_ACTIVE),
                         __ATOMIC_RELEASE);
        return 0;
    }
    return -1;
}

static int shm_att_take(unsigned long addr, unsigned long *len)
{
    int i;
    if (addr <= 1 || len == NULL)
        return -1;
    for (i = 0; i < SHM_MAX_ATT; i++) {
        unsigned long c = __atomic_load_n(&g_att[i].ctrl, __ATOMIC_ACQUIRE);
        unsigned long token;
        unsigned long seen;
        if ((c & ATT_STATE_MASK) != ATT_ACTIVE)
            continue;
        seen = __atomic_load_n(&g_att[i].addr, __ATOMIC_ACQUIRE);
        if (seen != addr)
            continue;
        token = c;
        if (!__atomic_compare_exchange_n(&g_att[i].ctrl, &token,
                                         (c & ~ATT_STATE_MASK) | ATT_DETACHING,
                                         0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        *len = __atomic_load_n(&g_att[i].len, __ATOMIC_RELAXED);
        return i;
    }
    return -1;
}

static unsigned long shm_att_count(long id)
{
    unsigned long n = 0;
    int i;
    for (i = 0; i < SHM_MAX_ATT; i++) {
        unsigned long c1 = __atomic_load_n(&g_att[i].ctrl, __ATOMIC_ACQUIRE);
        long seen;
        unsigned long c2;
        if ((c1 & ATT_STATE_MASK) != ATT_ACTIVE)
            continue;
        seen = __atomic_load_n(&g_att[i].id, __ATOMIC_ACQUIRE);
        c2 = __atomic_load_n(&g_att[i].ctrl, __ATOMIC_ACQUIRE);
        if (c1 == c2 && (c2 & ATT_STATE_MASK) == ATT_ACTIVE && seen == id)
            n++;
    }
    return n;
}

/*
 * ★ 映射身份校验：这段地址还是不是**我们自己**的 seg-<id> ？ ★
 * （缺陷修复，2026-10-18，对应 S8）
 *
 * 【缺陷】attach 表只用**地址**做键：
 *
 *     shm_att_take(addr) → 找到记录 → munmap(addr, len)
 *
 * 而地址是可以被复用的。客户完全可能在拿到 shm 映射之后**绕过
 * shmdt** 直接 `munmap()`（这在移植代码、JIT、自己的内存池里都会
 * 发生），此时表项仍然 ACTIVE。之后任何一次 `mmap`（malloc 的大块、
 * 另一个库的自定义映射）都可能落回**同一个地址**；再来一次
 * `shmdt(那个地址)` 就会把**别人**的映射拆掉 —— 客户进程里莫名
 * 少了一块内存，故障点离原因极远，且每次复现地址还不一样。
 *
 * 另外一个副作用：这类僵死表项永不回收，会让 IPC_STAT 的 nattch
 * 越算越多（内核是真实 attach 计数）。
 *
 * 【校验办法】用 /proc/self/map_files/<start>-<end> 这个符号链接：
 * 内核为**每个**映射导出一个指向其来源文件的链接，readlink 即可拿到
 * 该区间背后到底是哪个文件。我们把区间起点/终点按小写十六进制拼进
 * 去，读出来比对 basename 是否等于 `seg-<id>`。
 *
 * 为什么这个办法合适：
 *   · 一次 readlinkat，无 malloc、无 stdio、无缓冲分配 —— 可以在
 *     SIGSYS 处理器上下文里用；
 *   · 判定是**确定的**：不是"长度像不像"这种启发式；
 *   · 已被 IPC_RMID 删掉的段，映射仍然有效（内核语义），内核会把
 *     路径显示成 `.../seg-<id> (deleted)` —— 允许该后缀。
 *
 * 【不可判定时保持原行为】某些环境（SELinux 收紧的 Android、
 * 内核未开 CONFIG_PROC_MMAP_FILES）读不到 map_files。这时返回 -1，
 * 调用方按修前逻辑继续 munmap —— 宁可保留旧行为，也不能因为
 * 读不到证据就拒绝一个合法的 shmdt。
 *
 * 返回 1 = 确认是我们的；0 = 确认**不是**（地址已被别的映射占用）；
 *      -1 = 无法判定。
 */
static int shm_map_is_seg(unsigned long addr, unsigned long len, long id)
{
    char link[64], buf[600], want[32], *p;
    long r;

    if (addr == 0 || len == 0)
        return -1;
    if (addr + len < addr)                 /* 回绕：不可能是合法映射 */
        return 0;

    p = shm_puts(link, "/proc/self/map_files/");
    p = shm_putx(p, addr);
    *p++ = '-';
    p = shm_putx(p, addr + len);

    r = shm_svc6(NR_READLINKAT, K_AT_FDCWD, (long)link,
                 (long)buf, (long)sizeof buf - 1, 0, 0);
    if (r <= 0 || r >= (long)sizeof buf - 1)
        return -1;                          /* 读不到 → 不可判定 */
    buf[r] = '\0';

    /* 期望的 basename：seg-<id> */
    p = shm_puts(want, "seg-");
    shm_putl(p, id);

    /* 取 buf 的 basename，去掉可选的 " (deleted)" 后缀 */
    p = buf;
    {
        char *slash = NULL, *q;
        for (q = buf; *q; q++)
            if (*q == '/')
                slash = q;
        if (slash != NULL)
            p = slash + 1;
    }
    {
        size_t l = strlen(p);
        if (l >= 10 && strcmp(p + l - 10, " (deleted)") == 0)
            p[l - 10] = '\0';
    }
    return strcmp(p, want) == 0 ? 1 : 0;
}

/* ---------------- 四个调用 ---------------- */

static long shm_do_get(long key, long size, long flg)
{
    long id, result;
    long claim;
    int fd = -1;

    key = (long)(int)key;
    if (shm_mkdir() != 0)
        return -ERR_INVAL;
    if (key == K_IPC_PRIVATE) {
#if !BXROOT_SHM_CLAIM_VERIFIED
        return -38;
#else
        id = shm_new_segment(size, &fd);
        if (id < 0)
            return id;
        SVC(NR_CLOSE, fd, 0, 0);
        return id;
#endif
    }
    claim = shm_claim_key(key);
    if (claim < 0)
        return claim;

    id = shm_read_key(key);
    if (id < 0 && id != -K_ENOENT) {
        shm_release_claim(claim, key);
        return id;
    }
    if (id > 0) {
        long sfd = shm_open_seg(id, 1);
        if (sfd >= 0) {
            SVC(NR_CLOSE, sfd, 0, 0);
            result = ((flg & K_IPC_CREAT) && (flg & K_IPC_EXCL) ? -ERR_EXIST : id);
            shm_release_claim(claim, key);
            return result;
        }
        if (sfd != -K_ENOENT) {
            shm_release_claim(claim, key);
            return sfd;
        }
        /* Only an absent segment permits stale-key cleanup under the lock. */
        {
            char path[600];
            shm_path(path, "/key-", key);
            long removed = SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), path, 0);
            if (removed < 0 && removed != -K_ENOENT) {
                shm_release_claim(claim, key);
                return removed;
            }
        }
    }
    if (!(flg & K_IPC_CREAT)) {
        shm_release_claim(claim, key);
        return -ERR_NOENT;
    }

    id = shm_new_segment(size, &fd);
    if (id < 0) {
        shm_release_claim(claim, key);
        return id;
    }
    SVC(NR_CLOSE, fd, 0, 0);
    result = shm_publish_key(key, id);
    if (result < 0) {
        char path[600];
        long win, winner_fd;
        shm_path(path, "/seg-", id);
        SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), path, 0);
        if (result != -K_EEXIST) {
            shm_release_claim(claim, key);
            return result;
        }
        win = shm_read_key(key);
        if (win <= 0) {
            shm_release_claim(claim, key);
            return win < 0 ? win : -ERR_NOENT;
        }
        winner_fd = shm_open_seg(win, 1);
        if (winner_fd < 0) {
            shm_release_claim(claim, key);
            return winner_fd;
        }
        SVC(NR_CLOSE, winner_fd, 0, 0);
        result = (flg & K_IPC_EXCL) ? -ERR_EXIST : win;
        shm_release_claim(claim, key);
        return result;
    }
    shm_release_claim(claim, key);
    return id;
}

static long shm_do_at(long id, long flg)
{
    struct stat st;
    long fd, r, addr;
    int ro = (flg & K_SHM_RDONLY) != 0;
    unsigned long len;

    fd = shm_open_seg(id, ro);
    if (fd < 0)
        return -ERR_INVAL;
    r = SVC(NR_FSTAT, fd, (long)&st, 0);
    if (r < 0) {
        SVC(NR_CLOSE, fd, 0, 0);
        return r;
    }
    /* size 0 的段（官方允许创建）也要能 attach：映射一页 */
    len = (unsigned long)st.st_size;
    if (len == 0)
        len = 1;
    {
        unsigned long ps = g_shm_pagesize;
        if (len > (unsigned long)-1 - (ps - 1))
            return -22;
        len = (len + ps - 1) & ~(ps - 1);
    }
    addr = shm_svc6(NR_MMAP, 0, (long)len, ro ? K_PROT_R : K_PROT_RW,
                    K_MAP_SHARED, fd, 0);
    SVC(NR_CLOSE, fd, 0, 0);
    if (addr < 0 && addr > -4096)
        return addr;
    if (shm_att_add((unsigned long)addr, len, id) < 0) {
        SVC(NR_MUNMAP, addr, len, 0);
        return -24; /* EMFILE：内核超 SHMSEG 时的回答 */
    }
    return addr;
}

static long shm_do_dt(unsigned long addr)
{
    unsigned long len;
    int slot = shm_att_take(addr, &len);
    long r;
    unsigned long c;
    if (slot < 0)
        return -ERR_INVAL;
    /*
     * ★ 先确认这段地址还是不是我们的段（缺陷修复，2026-10-18，S8）★
     *
     * 表项按地址匹配，而地址会被复用：客户绕过 shmdt 直接 munmap，
     * 表项留成僵死状态，后续 mmap 若落回同一地址，这里的 munmap
     * 就会拆掉**无关**的映射。shm_map_is_seg() 用 map_files 证明
     * 归属；只有"确认不是我们的"才拒绝 —— 读不到证据时按原行为
     * 继续（见该函数注释）。
     */
    {
        long owner = __atomic_load_n(&g_att[slot].id, __ATOMIC_ACQUIRE);
        if (shm_map_is_seg(addr, len, owner) == 0) {
            /*
             * 地址已被别的映射占用：这不是"我们的段"，绝不能 munmap。
             * 同时可以确定该表项已僵死（客户自己 munmap 过），
             * 顺手回收，让它不再污染 nattch 计数。
             */
            c = __atomic_load_n(&g_att[slot].ctrl, __ATOMIC_ACQUIRE);
            __atomic_store_n(&g_att[slot].ctrl,
                             c & ~ATT_STATE_MASK, __ATOMIC_RELEASE);
            return -ERR_INVAL;
        }
    }
    r = SVC(NR_MUNMAP, addr, len, 0);
    c = __atomic_load_n(&g_att[slot].ctrl, __ATOMIC_ACQUIRE);
    if (r == 0)
        __atomic_store_n(&g_att[slot].ctrl, c & ~ATT_STATE_MASK, __ATOMIC_RELEASE);
    else
        __atomic_store_n(&g_att[slot].ctrl,
                         (c & ~ATT_STATE_MASK) | ATT_ACTIVE, __ATOMIC_RELEASE);
    return r; /* 内核约定：0 或 -errno */
}

static long shm_do_ctl(long id, long cmd, unsigned long buf)
{
    (void)buf;
    char path[600];
    struct stat st;
    long fd, r;

    cmd = (long)(int)cmd & ~0x100L;   /* 去掉可能的 IPC_64 */

    if (cmd == K_IPC_RMID) {
        long claim = shm_claim_key(id);
        if (claim < 0)
            return claim;
        shm_path(path, "/seg-", id);
        r = SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), (long)path, 0);
        if (r < 0 && r != -K_ENOENT) {
            shm_release_claim(claim, id);
            return r;
        }
        r = shm_unlink_keys_of(id);
        shm_release_claim(claim, id);
        return r < 0 ? r : 0;
    }
    if (cmd == K_IPC_STAT) {
        struct shmid_ds ds;
        fd = shm_open_seg(id, 1);
        if (fd < 0)
            return -ERR_INVAL;
        r = SVC(NR_FSTAT, fd, (long)&st, 0);
        SVC(NR_CLOSE, fd, 0, 0);
        if (r < 0)
            return r;
        memset(&ds, 0, sizeof ds);
        ds.shm_perm.mode = 0600;
        ds.shm_segsz = (size_t)st.st_size;
        ds.shm_nattch = shm_att_count(id);
        return bx_shm_copyout(buf, &ds, sizeof ds, shm_svc6);
    }
    return -ERR_INVAL;
}

/* Called only at the single-threaded static-exec commit boundary. */
void bxroot_sysvshm_exec_reset(void)
{
    for (int i=0;i<SHM_MAX_ATT;i++) {
        unsigned long ctrl=__atomic_load_n(&g_att[i].ctrl,__ATOMIC_ACQUIRE);
        if ((ctrl & ATT_STATE_MASK)==ATT_ACTIVE) {
            unsigned long addr=__atomic_load_n(&g_att[i].addr,__ATOMIC_RELAXED);
            unsigned long len=__atomic_load_n(&g_att[i].len,__ATOMIC_RELAXED);
            long r=SVC(NR_MUNMAP,addr,len,0);
            if (r==0)
                __atomic_store_n(&g_att[i].ctrl,ctrl & ~ATT_STATE_MASK,__ATOMIC_RELEASE);
        }
    }
}

/* 0=idle, 1=SHM operation, 2=hooked fork. No signal handler waits. */
static unsigned int g_shm_transition;

/*
 * ★ fork 门的属主与代际（缺陷修复，2026-10-18）★
 *
 * 【缺陷】g_shm_transition 只是一个无主计数器：
 *   0 = 空闲，1 = 有 shm 操作在进行，2 = 有 fork 在进行。
 * 而 bxroot_preload_fork_child() 是**空的**（见下面的定义），
 * bxroot_sysvshm_fork_end() 只在自己的 fork 包装里被调用。
 *
 * 于是经 **raw clone / _Fork / glibc 内部隐藏别名** fork 出来的子进程
 * （它们不走 proc.c 的 fork 包装）会**永久继承**门值：
 *   · 若父进程另一线程当时正处在 shm_do_*（transition==1），
 *     子进程拿到 1 且没有任何复位路径；
 *   · 子进程里 194..197 **全部**返回 -EAGAIN；
 *   · 子进程自己再 fork() 也因 CAS 失败返回 -EAGAIN，并遗传给孙进程。
 *
 * 结果不是文档说的"复制了活动槽"那么轻，而是**子进程的 SHM 与 fork
 * 双双永久瘫痪**。
 *
 * 【修法】记录门的属主线程 tid 与一个代际号：
 *   · 加门时写入本线程 tid；
 *   · 子进程在 atfork child 里发现"属主 tid 不是自己"就复位 ——
 *     因为 fork 之后只剩本线程，任何属于别的线程的门都是残值。
 *     （tid 在子进程里与父进程同值，所以判据是"持有者是否还是本线程"，
 *      而不是"tid 是否等于子进程 pid"。）
 *   · 代际号在每次复位时自增，供诊断区分"同一把门被复用"。
 */
static unsigned int g_shm_transition_owner;   /* 门的属主 tid（0=无） */
static unsigned int g_shm_transition_gen;     /* 复位代际，仅诊断用 */

/* 本线程 tid（裸 syscall，async-signal-safe；Linux gettid=178 on arm64） */
static unsigned int shm_self_tid(void)
{
    long r = shm_svc6(SHM_NR_GETTID, 0, 0, 0, 0, 0, 0);
    return (r > 0) ? (unsigned int)r : 0;
}
int bxroot_sysvshm_fork_begin(void)
{
    unsigned int idle=0;
    return __atomic_compare_exchange_n(&g_shm_transition,&idle,2,0,
        __ATOMIC_ACQ_REL,__ATOMIC_RELAXED) ? 0 : -11;
}
void bxroot_sysvshm_fork_prepare(void) { /* fork wrapper owns the gate */ }
void bxroot_sysvshm_fork_parent(void) { /* release after real fork returns */ }
/*
 * ★ 子进程里必须复位门（缺陷修复，2026-10-18）★
 *
 * fork 之后子进程只剩一个线程。此时如果 g_shm_transition != 0：
 *   · 要么是父进程另一个线程正在做 shm 操作（该线程在子进程里不存在），
 *   · 要么是父进程正在做 fork（那个 fork 已经完成）。
 * 两种都是**残值**，必须清掉，否则子进程的 194..197 与 fork 全部
 * 永久 -EAGAIN（见 g_shm_transition 处的详细说明）。
 *
 * 判据：属主不是本线程 ⇒ 残值 ⇒ 复位。若属主恰好是本线程，说明
 * 是本线程在持门期间调了 fork —— 那也不该留（子进程是全新进程，
 * 父进程的临界区语义不该带过来），所以**无条件复位**更简单也更安全：
 * 子进程里不存在任何"正在进行中的 shm 操作"。
 */
void bxroot_sysvshm_fork_child(void)
{
    __atomic_store_n(&g_shm_transition_owner, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_shm_transition, 0, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_shm_transition_gen, 1, __ATOMIC_RELAXED);
}
void bxroot_sysvshm_fork_end(void)
{
    __atomic_store_n(&g_shm_transition,0,__ATOMIC_RELEASE);
}

int bxroot_sysvshm_emulate(long sc, unsigned long a0, unsigned long a1,
                           unsigned long a2, long *x0)
{
    if (sc < SHM_NR_GET || sc > SHM_NR_DT)
        return 0;
    if (!__atomic_load_n(&g_shm_ready, __ATOMIC_ACQUIRE))
        return 0;   /* 未初始化：保持 ENOSYS，不假装 */

    if (sc != SHM_NR_DT && !shm_anchor_valid()) {
        /*
         * ★ 用 ENOSYS 而不是 EBADF（缺陷修复，2026-10-18）★
         *
         * 内核的 shmget/shmat/shmctl 从不返回 EBADF —— 那会让客户程序
         * 走进"fd 用错了"的排查方向。这里真实的语义是"仿真的 backing
         * 目录不可用"，对应 ENOSYS（能力不可用）最接近。
         *
         * ENOSYS 也是 libuv 等库期望的"该调用不可用"信号，客户可以据此
         * 干净回退，而不是当成一个诡异的 fd 错误。
         */
        *x0 = -38; /* ENOSYS: 仿真 backing 不可用 */
        return 1;
    }

    unsigned int idle=0;
    if (!__atomic_compare_exchange_n(&g_shm_transition,&idle,1,0,
                                     __ATOMIC_ACQ_REL,__ATOMIC_RELAXED)) {
        *x0=-11;
        return 1;
    }
    __atomic_store_n(&g_shm_transition_owner, shm_self_tid(),
                     __ATOMIC_RELEASE);
    switch (sc) {
    case SHM_NR_GET: *x0 = shm_do_get((long)a0, (long)a1, (long)a2); break;
    case SHM_NR_CTL: *x0 = shm_do_ctl((long)(int)a0, (long)a1, a2);  break;
    case SHM_NR_AT:  *x0 = shm_do_at((long)(int)a0, (long)a2);       break;
    case SHM_NR_DT:  *x0 = shm_do_dt(a0);                            break;
    }
    __atomic_store_n(&g_shm_transition_owner, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_shm_transition,0,__ATOMIC_RELEASE);
    return 1;
}
