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

#define SHM_NR_GET  194
#define SHM_NR_CTL  195
#define SHM_NR_AT   196
#define SHM_NR_DT   197

#define ERR_EXIST   1   /* EPERM：官方对 EXCL 冲突的回答（内核 EEXIST=17） */
#define ERR_NOENT   1   /* EPERM：官方对缺键的回答（内核 ENOENT=2） */
#define ERR_INVAL   1   /* EPERM：官方对无效 id/地址/cmd 的回答（内核 EINVAL=22） */

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
#define K_O_DIRECTORY 040000

#define K_AT_FDCWD   (-100)
#define K_O_RDWR     02
#define K_O_CREAT    0100
#define K_O_EXCL     0200
#define K_O_WRONLY   01
#define K_O_CLOEXEC  02000000
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
static volatile int g_shm_ready = 0;

int bxroot_sysvshm_init(const char *host_dir)
{
    size_t n;
    if (host_dir == NULL)
        return -1;
    n = strlen(host_dir);
    /* 给 "/seg-<20位>" / "/key-<-20位>" / ".tmp-<16>" 留足余量 */
    if (n == 0 || n + 64 >= sizeof(g_shm_dir))
        return -1;
    memcpy(g_shm_dir, host_dir, n + 1);
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
    char *p = shm_puts(buf, g_shm_dir);
    p = shm_puts(p, kind);
    shm_putl(p, v);
}

static void shm_mkdir(void)
{
    /* 0700：与官方一致；已存在返回 -EEXIST，忽略 */
    shm_svc6(NR_MKDIRAT, K_AT_FDCWD, (long)g_shm_dir, 0700, 0, 0, 0);
}

/* ---------------- id 分配 ---------------- */

/*
 * id 必须**跨进程唯一**且非负 int。官方的 id 形如 5121281（递增）。
 * 这里：getrandom 取 30 位随机数作候选，用 O_CREAT|O_EXCL 抢占 seg 文件
 * —— 文件系统本身就是跨进程的原子分配器，撞了就换一个。
 */
static long shm_new_segment(long size, int *out_fd)
{
    char path[600];
    int tries;
    for (tries = 0; tries < 64; tries++) {
        unsigned int r = 0;
        long id, fd;
        if (SVC(NR_GETRANDOM, &r, sizeof r, 0) != (long)sizeof r)
            r = (unsigned int)(uintptr_t)&r ^ (unsigned int)tries * 2654435761u;
        id = (long)(r & 0x3fffffff);
        if (id == 0)
            continue;
        shm_path(path, "/seg-", id);
        /* openat(dfd, path, flags, mode)：mode 在 a3，必须显式给 0600 */
        fd = shm_svc6(NR_OPENAT, K_AT_FDCWD, (long)path,
                      K_O_RDWR | K_O_CREAT | K_O_EXCL | K_O_CLOEXEC, 0600, 0, 0);
        if (fd == -K_EEXIST)
            continue;
        if (fd < 0)
            return fd;
        if (size > 0) {
            long t = SVC(NR_FTRUNCATE, fd, size, 0);
            if (t < 0) {
                SVC(NR_CLOSE, fd, 0, 0);
                SVC(NR_UNLINKAT, K_AT_FDCWD, path, 0);
                return t;
            }
        }
        *out_fd = (int)fd;
        return id;
    }
    return -ERR_INVAL;
}

static long shm_open_seg(long id, int rdonly)
{
    char path[600];
    if (id <= 0 || id > 0x7fffffffL)
        return -ERR_INVAL;
    shm_path(path, "/seg-", id);
    return SVC(NR_OPENAT, K_AT_FDCWD, path,
               (rdonly ? 0 : K_O_RDWR) | K_O_CLOEXEC);
}

/* ---------------- key 表 ---------------- */

static long shm_read_key(long key)
{
    char path[600], b[32];
    long fd, n, v = 0;
    int i, any = 0;
    shm_path(path, "/key-", key);
    fd = SVC(NR_OPENAT, K_AT_FDCWD, path, K_O_CLOEXEC);
    if (fd < 0)
        return fd;
    n = SVC(NR_READ, fd, b, sizeof b - 1);
    SVC(NR_CLOSE, fd, 0, 0);
    if (n <= 0)
        return -ERR_NOENT;
    for (i = 0; i < n && b[i] >= '0' && b[i] <= '9'; i++) {
        v = v * 10 + (b[i] - '0');
        any = 1;
    }
    return any ? v : -ERR_NOENT;
}

/*
 * 原子发布 key → id：先写临时文件，再 renameat2(NOREPLACE)。
 * 两个进程同时 CREAT 同一 key 时只有一个 rename 成功，输家读回赢家的 id。
 */
static long shm_publish_key(long key, long id)
{
    char tmp[600], path[600], b[24], *p;
    long fd, r;
    unsigned int rnd = 0;
    SVC(NR_GETRANDOM, &rnd, sizeof rnd, 0);
    p = shm_puts(tmp, g_shm_dir);
    p = shm_puts(p, "/.tmp-key-");
    p = shm_putl(p, id);
    p = shm_puts(p, "-");
    shm_putl(p, (long)rnd);
    fd = shm_svc6(NR_OPENAT, K_AT_FDCWD, (long)tmp,
                  K_O_WRONLY | K_O_CREAT | K_O_EXCL | K_O_CLOEXEC, 0600, 0, 0);
    if (fd < 0)
        return fd;
    p = shm_putl(b, id);
    *p++ = '\n';
    SVC(NR_WRITE, fd, b, p - b);
    SVC(NR_CLOSE, fd, 0, 0);
    shm_path(path, "/key-", key);
    r = shm_svc6(NR_RENAMEAT2, K_AT_FDCWD, (long)tmp, K_AT_FDCWD, (long)path,
                 K_RENAME_NOREPLACE, 0);
    if (r < 0)
        SVC(NR_UNLINKAT, K_AT_FDCWD, tmp, 0);
    return r;
}

/*
 * 删除所有内容为 "<id>\n" 的 key-* 文件。用 getdents64 扫目录（处理器里
 * 不能用 opendir/readdir —— 它们会 malloc）。
 */
static void shm_unlink_keys_of(long id)
{
    char dbuf[2048], path[600];
    long dfd, n;
    dfd = shm_svc6(NR_OPENAT, K_AT_FDCWD, (long)g_shm_dir,
                   K_O_DIRECTORY | K_O_CLOEXEC, 0, 0, 0);
    if (dfd < 0)
        return;
    while ((n = SVC(NR_GETDENTS64, dfd, dbuf, sizeof dbuf)) > 0) {
        long off = 0;
        while (off < n) {
            /* linux_dirent64: ino(8) off(8) reclen(2) type(1) name[] */
            unsigned short reclen = *(unsigned short *)(dbuf + off + 16);
            const char *name = dbuf + off + 19;
            if (name[0] == 'k' && name[1] == 'e' && name[2] == 'y' && name[3] == '-') {
                long key = 0, sign = 1;
                const char *q = name + 4;
                int ok = 0;
                if (*q == '-') { sign = -1; q++; }
                while (*q >= '0' && *q <= '9') { key = key * 10 + (*q - '0'); q++; ok = 1; }
                if (ok && *q == 0 && shm_read_key(sign * key) == id) {
                    shm_path(path, "/key-", sign * key);
                    SVC(NR_UNLINKAT, K_AT_FDCWD, path, 0);
                }
            }
            if (reclen == 0)
                break;
            off += reclen;
        }
    }
    SVC(NR_CLOSE, dfd, 0, 0);
}

/* ---------------- 本进程 attach 表 ---------------- */

#define SHM_MAX_ATT 256
struct shm_att {
    volatile unsigned long addr;   /* 0 = 空槽；写入用 CAS 抢占 */
    unsigned long len;
    long id;
};
static struct shm_att g_att[SHM_MAX_ATT];

static int shm_att_add(unsigned long addr, unsigned long len, long id)
{
    int i;
    for (i = 0; i < SHM_MAX_ATT; i++) {
        unsigned long z = 0;
        if (__atomic_compare_exchange_n(&g_att[i].addr, &z, 1UL, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            g_att[i].len = len;
            g_att[i].id = id;
            __atomic_store_n(&g_att[i].addr, addr, __ATOMIC_RELEASE);
            return 0;
        }
    }
    return -1;
}

static int shm_att_take(unsigned long addr, unsigned long *len)
{
    int i;
    if (addr <= 1)
        return -1;
    for (i = 0; i < SHM_MAX_ATT; i++) {
        unsigned long a = addr;
        if (__atomic_load_n(&g_att[i].addr, __ATOMIC_ACQUIRE) != addr)
            continue;
        *len = g_att[i].len;
        if (__atomic_compare_exchange_n(&g_att[i].addr, &a, 0UL, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return 0;
    }
    return -1;
}

static unsigned long shm_att_count(long id)
{
    unsigned long n = 0;
    int i;
    for (i = 0; i < SHM_MAX_ATT; i++) {
        unsigned long a = __atomic_load_n(&g_att[i].addr, __ATOMIC_ACQUIRE);
        if (a > 1 && g_att[i].id == id)
            n++;
    }
    return n;
}

/* ---------------- 四个调用 ---------------- */

static long shm_do_get(long key, long size, long flg)
{
    long id;
    int fd = -1;

    key = (long)(int)key;   /* key_t 是 int；glibc 已 sxtw，这里再保险 */
    shm_mkdir();

    if (key == K_IPC_PRIVATE) {
        id = shm_new_segment(size, &fd);
        if (id < 0)
            return id;
        SVC(NR_CLOSE, fd, 0, 0);
        return id;
    }

    id = shm_read_key(key);
    if (id > 0) {
        /* 键指向的段可能已被别的进程 RMID —— 那就当作不存在 */
        long sfd = shm_open_seg(id, 1);
        if (sfd >= 0) {
            SVC(NR_CLOSE, sfd, 0, 0);
            if ((flg & K_IPC_CREAT) && (flg & K_IPC_EXCL))
                return -ERR_EXIST;
            return id;
        }
        {
            char path[600];
            shm_path(path, "/key-", key);
            SVC(NR_UNLINKAT, K_AT_FDCWD, path, 0);
        }
    }
    if (!(flg & K_IPC_CREAT))
        return -ERR_NOENT;

    id = shm_new_segment(size, &fd);
    if (id < 0)
        return id;
    SVC(NR_CLOSE, fd, 0, 0);
    if (shm_publish_key(key, id) < 0) {
        /* 输了竞争：丢掉自己的段，用赢家的 */
        char path[600];
        long win;
        shm_path(path, "/seg-", id);
        SVC(NR_UNLINKAT, K_AT_FDCWD, path, 0);
        win = shm_read_key(key);
        if (win <= 0)
            return -ERR_NOENT;
        if (flg & K_IPC_EXCL)
            return -ERR_EXIST;
        return win;
    }
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
    r = SVC(NR_FSTAT, fd, &st, 0);
    if (r < 0) {
        SVC(NR_CLOSE, fd, 0, 0);
        return r;
    }
    /* size 0 的段（官方允许创建）也要能 attach：映射一页 */
    len = (unsigned long)st.st_size;
    if (len == 0)
        len = 1;
    len = (len + 4095UL) & ~4095UL;
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
    if (shm_att_take(addr, &len) < 0)
        return -ERR_INVAL;
    SVC(NR_MUNMAP, addr, len, 0);
    return 0;
}

static long shm_do_ctl(long id, long cmd, unsigned long buf)
{
    char path[600];
    struct stat st;
    long fd, r;

    cmd = (long)(int)cmd & ~0x100L;   /* 去掉可能的 IPC_64 */

    if (cmd == K_IPC_RMID) {
        shm_path(path, "/seg-", id);
        SVC(NR_UNLINKAT, K_AT_FDCWD, path, 0);
        /*
         * ★ 指向该 id 的 key 文件必须一起删 ★
         * 首版只删 seg、指望"下次 shmget 发现段不存在再清理"。bxroot 自己
         * 确实会清理，但**官方不会**：它读到残留 key 就直接返回那个已删的
         * id，随后 shmat 失败（2026-09-25 互通实测：bxroot RMID 后，官方
         * 进程 shmget(key) 拿到旧 id、attach fail）。共用目录就得守对方的约定。
         */
        shm_unlink_keys_of(id);
        return 0;   /* 官方：对不存在的 id 也回 0 */
    }
    if (cmd == K_IPC_STAT) {
        struct shmid_ds *ds = (struct shmid_ds *)buf;
        fd = shm_open_seg(id, 1);
        if (fd < 0)
            return -ERR_INVAL;
        r = SVC(NR_FSTAT, fd, &st, 0);
        SVC(NR_CLOSE, fd, 0, 0);
        if (r < 0)
            return r;
        if (ds == NULL)
            return -14; /* EFAULT */
        memset(ds, 0, sizeof *ds);
        ds->shm_perm.mode = 0600;
        ds->shm_segsz = (size_t)st.st_size;
        ds->shm_nattch = shm_att_count(id);
        return 0;
    }
    return -ERR_INVAL;
}

int bxroot_sysvshm_emulate(long sc, unsigned long a0, unsigned long a1,
                           unsigned long a2, long *x0)
{
    if (sc < SHM_NR_GET || sc > SHM_NR_DT)
        return 0;
    if (!__atomic_load_n(&g_shm_ready, __ATOMIC_ACQUIRE))
        return 0;   /* 未初始化：保持 ENOSYS，不假装 */

    switch (sc) {
    case SHM_NR_GET: *x0 = shm_do_get((long)a0, (long)a1, (long)a2); break;
    case SHM_NR_CTL: *x0 = shm_do_ctl((long)(int)a0, (long)a1, a2);  break;
    case SHM_NR_AT:  *x0 = shm_do_at((long)(int)a0, (long)a2);       break;
    case SHM_NR_DT:  *x0 = shm_do_dt(a0);                            break;
    }
    return 1;
}
