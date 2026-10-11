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
#define K_O_NOFOLLOW 0400000
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

static int shm_anchor_valid(void)
{
    struct stat st;
    int fd = bxroot_sysvshm_anchor_fd();
    long r;
    if (fd < 0 || !__atomic_load_n(&g_shm_ready, __ATOMIC_ACQUIRE))
        return 0;
    r = shm_svc6(NR_FSTAT, fd, (long)&st, 0, 0, 0, 0);
    return r == 0 && S_ISDIR(st.st_mode) &&
           st.st_dev == g_shm_dev && st.st_ino == g_shm_ino &&
           st.st_uid == g_shm_owner && (st.st_mode & 0077) == 0;
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

static int shm_mkdir(void)
{
    return shm_anchor_valid() ? 0 : -1;
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
            return -9;
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
        if (size > 0) {
            long t = SVC(NR_FTRUNCATE, fd, size, 0);
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
        return -9; /* EBADF */
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
    r = shm_svc6(NR_FCNTL, fd, F_OFD_SETLK, (long)&fl, 0, 0, 0);
    if (r < 0) {
        SVC(NR_CLOSE, fd, 0, 0);
        return r == -11 || r == -13 ? -ERR_AGAIN : r;
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
int bxroot_sysvshm_fork_begin(void)
{
    unsigned int idle=0;
    return __atomic_compare_exchange_n(&g_shm_transition,&idle,2,0,
        __ATOMIC_ACQ_REL,__ATOMIC_RELAXED) ? 0 : -11;
}
void bxroot_sysvshm_fork_prepare(void) { /* fork wrapper owns the gate */ }
void bxroot_sysvshm_fork_parent(void) { /* release after real fork returns */ }
void bxroot_sysvshm_fork_child(void) { /* release after real fork returns */ }
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
        *x0 = -9; /* EBADF: never reopen an invalid anchor in handler context */
        return 1;
    }

    unsigned int idle=0;
    if (!__atomic_compare_exchange_n(&g_shm_transition,&idle,1,0,
                                     __ATOMIC_ACQ_REL,__ATOMIC_RELAXED)) {
        *x0=-11;
        return 1;
    }
    switch (sc) {
    case SHM_NR_GET: *x0 = shm_do_get((long)a0, (long)a1, (long)a2); break;
    case SHM_NR_CTL: *x0 = shm_do_ctl((long)(int)a0, (long)a1, a2);  break;
    case SHM_NR_AT:  *x0 = shm_do_at((long)(int)a0, (long)a2);       break;
    case SHM_NR_DT:  *x0 = shm_do_dt(a0);                            break;
    }
    __atomic_store_n(&g_shm_transition,0,__ATOMIC_RELEASE);
    return 1;
}
