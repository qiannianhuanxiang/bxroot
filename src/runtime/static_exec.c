/*
 * static_exec.c —— 进程内装载并执行「无 PT_INTERP」的静态 ELF
 *
 * ====================================================================
 * 为什么需要（2026-10-05 真机 + 容器复现）
 * ====================================================================
 *
 * 冷安装 libc-bin 的 postinst 跑 /sbin/ldconfig.real（static-PIE）。旧路径是
 * `execve(PROROOT_STUB_LOADER, …)`：
 *
 *   1. execve 之后 bxroot runtime（LD_PRELOAD）整个消失；静态程序自己也读不到
 *      LD_PRELOAD，没有任何钩子；
 *   2. 官方 stub-loader 自带的 syscall 翻译只覆盖 openat/stat 一类，对
 *      **绝对路径的 renameat / linkat / unlinkat / mkdirat / symlinkat /
 *      fchmodat / faccessat / truncate 不翻译**（本机用官方 stub-loader 单独
 *      跑探针复现：openat 落进 rootfs，renameat 落到宿主 /etc）；
 *   3. 官方 runtime 靠父进程 ptrace 补这些洞，bxroot 不 ptrace。
 *
 *   现场：ldconfig 先把 /etc/ld.so.cache~ 写进 rootfs（openat 已翻译），再
 *   rename 到宿主 /etc/ld.so.cache → Android 只读 /etc → EROFS。
 *   见设备日志 "Renaming of /etc/ld.so.cache~ to /etc/ld.so.cache failed:
 *   Read-only file system"。STUB_ROOTFS 变体的修法已被该日志证伪。
 *
 * ====================================================================
 * 做法
 * ====================================================================
 *
 * 不经内核 execve：本进程自己 mmap 目标 ELF、搭栈、跳进入口（同 src/ldr/ulx.c）。
 * 进程还是同一个进程，runtime 还映射在里面。再把目标代码段里**路径类**
 * `mov x8,#NR ; … ; svc #0` 站点改写成 `b <veneer>`：
 *
 *     站点:    b   veneer_i                （原 svc #0）
 *     veneer_i: ldr x16, =<站点+4>          （返回地址）
 *               ldr x17, =px_static_tramp
 *               br  x17
 *     px_static_tramp（runtime 内）:
 *               存 x1..x17、q0..q7、x29/x30、静态程序的 TPIDR_EL0
 *               TPIDR_EL0 ← 动态 libc 的 TLS（exec 前记下）
 *               px_static_dispatch(a0..a5, nr)   —— 翻译路径，发真 svc
 *               TPIDR_EL0 ← 静态程序的 TLS；还原寄存器；br x16（回站点+4）
 *
 * 为什么是 B 不是 BL：glibc 的 syscall 包装常是 `svc #0 ; ret` 的叶子函数，
 * BL 会覆盖 x30，ret 就回不去了。veneer 用 x16/x17（AAPCS 的 IP0/IP1，
 * 编译器不会跨 svc 让它们保活；内核虽保留但 glibc 内联 svc 不依赖它们）。
 *
 * 为什么要换 TLS：静态 glibc 的 __libc_setup_tls 会把 TPIDR_EL0 指向自己的
 * TCB；而 runtime 的 errno / __thread / 栈保护 canary 都按动态 libc 的 TLS
 * 布局取址。不换回去，runtime 代码会读写静态程序 TCB 的错位置。
 *
 * ====================================================================
 * 边界（如实）
 * ====================================================================
 *   - 只补 `mov x8/w8,#立即数` 近距离跟 `svc` 的站点。syscall 号来自寄存器的
 *     通用 syscall() 包装补不到。
 *   - 不拦 execve/execveat（静态程序再 exec 别的程序时内核看到的仍是 guest
 *     路径）。ldconfig 不 exec。
 *   - 多线程进程拒绝（真 execve 会杀其它线程，我们做不到）→ 调用方回退 stub。
 *   - TLS 切换只对单线程静态程序成立（动态 TLS 取 exec 线程的）。
 *   - ET_EXEC 的固定地址与 runtime/堆冲突时 MAP_FIXED_NOREPLACE 失败 → 回退。
 *   - SIGSYS 用 early handler（不碰 TLS，被 TRAP 的调用回 -ENOSYS），
 *     不再是 runtime 的完整处理器 —— 静态 glibc 在 __libc_setup_tls 前后
 *     TPIDR_EL0 指向不同 TCB，runtime 的处理器会动 errno，不安全。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "static_exec.h"

#define SX_MAX_PHDR    64
#define SX_STACK_SIZE  (8UL << 20)
#define SX_SCAN_WINDOW 12
#define SX_VENEER_SIZE 32
#define SX_SVC_INSN    0xd4000001u
#define SX_PATHBUF     (PATH_MAX * 2)

/* 翻译桥：与 livepatch.c 同一套 weak 约定（单测里无 preload.c → NULL → 原样发 svc） */
__attribute__((weak))
int bxroot_translate_path(const char *path, char *out, size_t out_size);
__attribute__((weak))
int bxroot_resolve_abs_symlink(const char *translated, char *out, size_t out_size);
__attribute__((weak))
void bxroot_log(const char *fmt, ...);

/* 动态 libc 的 TPIDR_EL0（exec 前记下）。汇编跳板用 adrp 直接引用。 */
unsigned long px_static_dyn_tls __attribute__((visibility("hidden")));

/* ------------------------------------------------------------------ */
/* 裸系统调用                                                          */
/* ------------------------------------------------------------------ */

static long sx_sc6(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;

    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;
}

#define SC(nr, a, b, c, d) sx_sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)

/* ------------------------------------------------------------------ */
/* 路径类系统调用表（aarch64 号）                                       */
/* ------------------------------------------------------------------ */

/*
 * bit i 置位 = a<i> 是路径指针。a0/a2 为 dirfd 的位置绝不置位
 * （把 AT_FDCWD=-100 当指针解引用会整进程崩，见 syscall_guard.c 的教训）。
 */
static unsigned sx_path_mask(long nr)
{
    switch (nr) {
    case 33:  return 1u << 1;              /* mknodat(dfd, path, …)        */
    case 34:  return 1u << 1;              /* mkdirat                      */
    case 35:  return 1u << 1;              /* unlinkat                     */
    case 36:  return 1u << 2;              /* symlinkat(target, dfd, link) */
    case 37:  return (1u << 1) | (1u << 3);/* linkat                       */
    case 38:  return (1u << 1) | (1u << 3);/* renameat                     */
    case 43:  return 1u << 0;              /* statfs                       */
    case 45:  return 1u << 0;              /* truncate                     */
    case 48:  return 1u << 1;              /* faccessat                    */
    case 49:  return 1u << 0;              /* chdir                        */
    case 53:  return 1u << 1;              /* fchmodat                     */
    case 54:  return 1u << 1;              /* fchownat                     */
    case 56:  return 1u << 1;              /* openat                       */
    case 78:  return 1u << 1;              /* readlinkat                   */
    case 79:  return 1u << 1;              /* newfstatat                   */
    case 88:  return 1u << 1;              /* utimensat                    */
    case 276: return (1u << 1) | (1u << 3);/* renameat2                    */
    case 291: return 1u << 1;              /* statx                        */
    case 439: return 1u << 1;              /* faccessat2                   */
    case 5: case 6: case 8: case 9: case 11: case 12: case 14: case 15:
              return 1u << 0;              /* *xattr(path, …)              */
    default:  return 0;
    }
}

/*
 * 由汇编跳板调用（此时 TPIDR_EL0 已切回动态 libc 的 TLS）。
 * 返回内核原始约定（负 errno = 错误）。
 */
__attribute__((visibility("hidden")))
long px_static_dispatch(long a0, long a1, long a2, long a3, long a4, long a5,
                        long nr)
{
    unsigned mask = sx_path_mask(nr);
    long a[6];
    char buf[2][SX_PATHBUF];
    int i, used = 0;

    if (mask == 0 || bxroot_translate_path == NULL)
        return sx_sc6(nr, a0, a1, a2, a3, a4, a5);

    a[0] = a0; a[1] = a1; a[2] = a2; a[3] = a3; a[4] = a4; a[5] = a5;
    for (i = 0; i < 4; i++) {
        const char *p;

        if (!(mask & (1u << i)))
            continue;
        p = (const char *)(uintptr_t)a[i];
        if (p == NULL || p[0] != '/' || used >= 2)
            continue;               /* NULL / 相对路径：内核按 dirfd、cwd 解析 */
        if (bxroot_translate_path(p, buf[used], sizeof(buf[used])) > 0)
            a[i] = (long)(uintptr_t)buf[used++];
    }

    {
        long r = sx_sc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);

        /* openat：与 livepatch 的 relay 同一条「绝对符号链接重试」腿 */
        if (nr == 56 && r == -ENOENT && bxroot_resolve_abs_symlink != NULL &&
            (mask & (1u << 1)) && a[1] != a1) {
            static char sbuf[SX_PATHBUF];

            if (bxroot_resolve_abs_symlink((const char *)(uintptr_t)a[1],
                                           sbuf, sizeof(sbuf)))
                return sx_sc6(nr, -100, (long)(uintptr_t)sbuf, a[2], a[3], 0, 0);
        }
        return r;
    }
}

/*
 * 汇编跳板。入口约定：x16 = 返回地址（站点+4），x17 = 本跳板地址（已被 veneer 用掉）。
 * 栈帧 304 字节：
 *   [0]   x29,x30    [16] x1..x17 (17 个 → 到 152)   [152] 静态 TPIDR
 *   [160] q0..q7 (128 字节 → 288)                     [288..304) 对齐
 */
extern void px_static_tramp(void);
__asm__(
    ".text\n"
    ".globl px_static_tramp\n"
    ".hidden px_static_tramp\n"
    ".type  px_static_tramp,%function\n"
    "px_static_tramp:\n"
    "    sub  sp, sp, #304\n"
    "    stp  x29, x30, [sp, #0]\n"
    "    mov  x29, sp\n"
    "    stp  x1,  x2,  [sp, #16]\n"
    "    stp  x3,  x4,  [sp, #32]\n"
    "    stp  x5,  x6,  [sp, #48]\n"
    "    stp  x7,  x8,  [sp, #64]\n"
    "    stp  x9,  x10, [sp, #80]\n"
    "    stp  x11, x12, [sp, #96]\n"
    "    stp  x13, x14, [sp, #112]\n"
    "    stp  x15, x16, [sp, #128]\n"
    "    str  x17,      [sp, #144]\n"
    "    stp  q0,  q1,  [sp, #160]\n"
    "    stp  q2,  q3,  [sp, #192]\n"
    "    stp  q4,  q5,  [sp, #224]\n"
    "    stp  q6,  q7,  [sp, #256]\n"
    "    mrs  x9, tpidr_el0\n"
    "    str  x9, [sp, #152]\n"
    "    adrp x10, px_static_dyn_tls\n"
    "    ldr  x10, [x10, :lo12:px_static_dyn_tls]\n"
    "    msr  tpidr_el0, x10\n"
    "    mov  x6, x8\n"                       /* 第 7 参 = syscall 号；x0..x5 原样 */
    "    bl   px_static_dispatch\n"
    "    ldr  x9, [sp, #152]\n"
    "    msr  tpidr_el0, x9\n"
    "    ldp  q0,  q1,  [sp, #160]\n"
    "    ldp  q2,  q3,  [sp, #192]\n"
    "    ldp  q4,  q5,  [sp, #224]\n"
    "    ldp  q6,  q7,  [sp, #256]\n"
    "    ldp  x1,  x2,  [sp, #16]\n"
    "    ldp  x3,  x4,  [sp, #32]\n"
    "    ldp  x5,  x6,  [sp, #48]\n"
    "    ldp  x7,  x8,  [sp, #64]\n"
    "    ldp  x9,  x10, [sp, #80]\n"
    "    ldp  x11, x12, [sp, #96]\n"
    "    ldp  x13, x14, [sp, #112]\n"
    "    ldr  x15,      [sp, #128]\n"
    "    ldr  x16,      [sp, #136]\n"         /* 返回地址 */
    "    ldr  x17,      [sp, #144]\n"
    "    ldp  x29, x30, [sp, #0]\n"
    "    add  sp, sp, #304\n"
    "    br   x16\n"                          /* x0 = 结果，回站点下一条 */
    ".size px_static_tramp, .-px_static_tramp\n"
);

/* ------------------------------------------------------------------ */
/* ELF 装载                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned long base;
    unsigned long entry;
    unsigned long phdr;
    unsigned phnum;
    unsigned long lo, hi;           /* 装载范围（已加 base） */
    Elf64_Phdr ph[SX_MAX_PHDR];
    unsigned nph;
    unsigned long veneer_pool;      /* 预留的 veneer 区（紧邻镜像） */
    size_t veneer_cap;
} sx_image;

static int sx_load(const char *path, sx_image *img, size_t veneer_bytes)
{
    Elf64_Ehdr eh;
    unsigned long lo = ~0UL, hi = 0, align = 4096;
    unsigned long ps = 4096;
    long fd;
    unsigned i;
    char *res;
    size_t vz = (veneer_bytes + ps - 1) & ~(ps - 1);

    memset(img, 0, sizeof(*img));
    fd = SC(SYS_openat, -100, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) { errno = (int)-fd; return -1; }
    if (sx_sc6(SYS_pread64, fd, (long)&eh, sizeof eh, 0, 0, 0) != (long)sizeof eh ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_machine != EM_AARCH64 || (eh.e_type != ET_DYN && eh.e_type != ET_EXEC) ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 || eh.e_phnum > SX_MAX_PHDR ||
        sx_sc6(SYS_pread64, fd, (long)img->ph, sizeof(Elf64_Phdr) * eh.e_phnum,
               (long)eh.e_phoff, 0, 0) != (long)(sizeof(Elf64_Phdr) * eh.e_phnum)) {
        SC(SYS_close, fd, 0, 0, 0);
        errno = ENOEXEC;
        return -1;
    }
    img->nph = eh.e_phnum;
    for (i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr *p = &img->ph[i];

        if (p->p_type == PT_INTERP) {
            SC(SYS_close, fd, 0, 0, 0);
            errno = ENOEXEC;
            return -1;
        }
        if (p->p_type != PT_LOAD)
            continue;
        if (p->p_align > align)
            align = p->p_align;
        if ((p->p_vaddr & ~(ps - 1)) < lo)
            lo = p->p_vaddr & ~(ps - 1);
        if (p->p_vaddr + p->p_memsz > hi)
            hi = p->p_vaddr + p->p_memsz;
    }
    if (hi <= lo) {
        SC(SYS_close, fd, 0, 0, 0);
        errno = ENOEXEC;
        return -1;
    }
    hi = (hi + ps - 1) & ~(ps - 1);

    /* 镜像 + 紧随其后的 veneer 区一起保留，保证 B 可达（±128MB） */
    if (eh.e_type == ET_EXEC) {
        res = (char *)sx_sc6(SYS_mmap, (long)lo, (long)(hi - lo + vz), PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                             -1, 0);
        if ((unsigned long)res >= (unsigned long)-4095L) {
            SC(SYS_close, fd, 0, 0, 0);
            errno = (int)-(long)res;
            return -1;
        }
        img->base = 0;
    } else {
        res = (char *)sx_sc6(SYS_mmap, 0, (long)(hi - lo + vz + align), PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ((unsigned long)res >= (unsigned long)-4095L) {
            SC(SYS_close, fd, 0, 0, 0);
            errno = (int)-(long)res;
            return -1;
        }
        img->base = (((unsigned long)res + align - 1) & ~(align - 1)) - lo;
    }
    img->lo = img->base + lo;
    img->hi = img->base + hi;
    img->veneer_pool = img->hi;
    img->veneer_cap = vz;

    for (i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr *p = &img->ph[i];
        unsigned long va, off, a, d, fe, fpe, me;
        int prot;

        if (p->p_type != PT_LOAD)
            continue;
        va = p->p_vaddr;
        off = p->p_offset;
        a = va & ~(ps - 1);
        d = va - a;
        prot = ((p->p_flags & PF_R) ? PROT_READ : 0) |
               ((p->p_flags & PF_W) ? PROT_WRITE : 0) |
               ((p->p_flags & PF_X) ? PROT_EXEC : 0);
        if (p->p_filesz > 0) {
            long m = sx_sc6(SYS_mmap, (long)(img->base + a), (long)(p->p_filesz + d),
                            prot, MAP_PRIVATE | MAP_FIXED, fd, (long)(off - d));
            if ((unsigned long)m >= (unsigned long)-4095L) {
                SC(SYS_close, fd, 0, 0, 0);
                errno = (int)-m;
                return -1;
            }
        }
        fe = va + p->p_filesz;
        fpe = (fe + ps - 1) & ~(ps - 1);
        me = va + p->p_memsz;
        if (p->p_memsz > p->p_filesz) {
            if (p->p_filesz > 0 && fpe > fe) {
                if (!(prot & PROT_WRITE))
                    SC(SYS_mprotect, img->base + (fe & ~(ps - 1)), ps, prot | PROT_WRITE, 0);
                memset((void *)(img->base + fe), 0, fpe - fe);
                if (!(prot & PROT_WRITE))
                    SC(SYS_mprotect, img->base + (fe & ~(ps - 1)), ps, prot, 0);
            }
            if (me > fpe) {
                unsigned long s = p->p_filesz > 0 ? fpe : a;
                long m = sx_sc6(SYS_mmap, (long)(img->base + s), (long)(me - s), prot,
                                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
                if ((unsigned long)m >= (unsigned long)-4095L) {
                    SC(SYS_close, fd, 0, 0, 0);
                    errno = (int)-m;
                    return -1;
                }
            }
        }
        if (eh.e_phoff >= off && eh.e_phoff + sizeof(Elf64_Phdr) * eh.e_phnum <= off + p->p_filesz)
            img->phdr = img->base + va + (eh.e_phoff - off);
    }
    SC(SYS_close, fd, 0, 0, 0);
    img->entry = img->base + eh.e_entry;
    img->phnum = eh.e_phnum;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 站点扫描与改写                                                       */
/* ------------------------------------------------------------------ */

static int sx_is_barrier(uint32_t ins)
{
    if ((ins & 0xff80001fu) == 0xf2800008u) return 1;   /* movk x8 */
    if ((ins & 0xff80001fu) == 0x72800008u) return 1;   /* movk w8 */
    if ((ins >> 26) == 0x05u || (ins >> 26) == 0x25u) return 1;   /* B / BL */
    if ((ins >> 24) == 0x54u) return 1;                 /* B.cond */
    if ((ins & 0x7e000000u) == 0x34000000u) return 1;   /* CBZ/CBNZ */
    if ((ins & 0x7e000000u) == 0x36000000u) return 1;   /* TBZ/TBNZ */
    if ((ins & 0xfe000000u) == 0xd6000000u) return 1;   /* BR/BLR/RET */
    return 0;
}

/* movz x8/w8, #imm16（hw=0）→ 返回 imm16，否则 -1 */
static long sx_movz_x8(uint32_t ins)
{
    if ((ins & 0xffe0001fu) == 0xd2800008u || (ins & 0xffe0001fu) == 0x52800008u)
        return (long)((ins >> 5) & 0xffffu);
    return -1;
}

/*
 * 扫描 [lo,hi)。pool 为 NULL 时只计数；否则写 veneer 并改写站点。
 * 返回站点数。
 */
static size_t sx_scan(uint32_t *code, size_t n, uint32_t *pool, size_t pool_cap_bytes)
{
    long nr = -1;
    unsigned since = 0;
    size_t j, total = 0;

    for (j = 0; j < n; j++) {
        uint32_t ins = code[j];
        long m;

        if (ins == SX_SVC_INSN) {
            if (nr >= 0 && sx_path_mask(nr) != 0) {
                if (pool != NULL) {
                    uint32_t *v = pool + total * (SX_VENEER_SIZE / 4);
                    long off;

                    if ((total + 1) * SX_VENEER_SIZE > pool_cap_bytes)
                        return total;           /* 容量不足：fail-open，不再补 */
                    off = (long)((intptr_t)v - (intptr_t)&code[j]);
                    if (off >= (1L << 27) || off < -(1L << 27)) {
                        nr = -1;
                        continue;               /* 够不着：跳过该点 */
                    }
                    v[0] = 0x58000090u;         /* ldr x16, #16 */
                    v[1] = 0x580000b1u;         /* ldr x17, #20 */
                    v[2] = 0xd61f0220u;         /* br  x17 */
                    v[3] = 0xd503201fu;         /* nop */
                    *(uint64_t *)(void *)&v[4] = (uint64_t)(uintptr_t)&code[j + 1];
                    *(uint64_t *)(void *)&v[6] = (uint64_t)(uintptr_t)&px_static_tramp;
                    code[j] = 0x14000000u | ((uint32_t)(off >> 2) & 0x03ffffffu);  /* b v */
                }
                total++;
            }
            nr = -1;
            continue;
        }
        m = sx_movz_x8(ins);
        if (m >= 0) {
            nr = m;
            since = 0;
            continue;
        }
        if (nr >= 0 && (sx_is_barrier(ins) || ++since > SX_SCAN_WINDOW))
            nr = -1;
    }
    return total;
}

static size_t sx_count_sites(const sx_image *img)
{
    size_t total = 0;
    unsigned i;

    for (i = 0; i < img->nph; i++) {
        const Elf64_Phdr *p = &img->ph[i];

        if (p->p_type != PT_LOAD || !(p->p_flags & PF_X))
            continue;
        total += sx_scan((uint32_t *)(img->base + p->p_vaddr), p->p_filesz / 4, NULL, 0);
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* early SIGSYS 处理器（不碰 TLS，与 ldr/early_sigsys.h 同）              */
/* ------------------------------------------------------------------ */

static void sx_early_sigsys(int s, void *si, void *uc)
{
    (void)s;
    if (si == NULL || ((int *)si)[2] != 1)      /* 只处理 seccomp 产生的 */
        return;
    ((unsigned long *)((char *)uc + 184))[0] = (unsigned long)-38;   /* -ENOSYS */
}

struct sx_ksigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

/* 线程数：读 /proc/self/status 的 Threads: 行。读不到按「多线程」处理。 */
static int sx_thread_count(void)
{
    char buf[4096];
    long fd = SC(SYS_openat, -100, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
    long n;
    char *p;

    if (fd < 0)
        return 99;
    n = SC(SYS_read, fd, buf, sizeof(buf) - 1, 0);
    SC(SYS_close, fd, 0, 0, 0);
    if (n <= 0)
        return 99;
    buf[n] = '\0';
    p = strstr(buf, "Threads:");
    return p ? atoi(p + 8) : 99;
}

/* 模拟 execve 对进程状态的重置：信号处理、CLOEXEC 描述符 */
static void sx_reset_process_state(void)
{
    struct sx_ksigaction sa;
    unsigned long unblock = 1UL << (31 - 1);
    int sig, fd;

    for (sig = 1; sig <= 64; sig++) {
        struct sx_ksigaction old;

        if (sig == 9 || sig == 19 || sig == 31)
            continue;
        memset(&old, 0, sizeof old);
        if (SC(SYS_rt_sigaction, sig, 0, &old, 8) != 0)
            continue;
        if (old.handler > 1UL) {                /* 自定义处理器 → 默认（SIG_IGN 保留） */
            memset(&sa, 0, sizeof sa);
            SC(SYS_rt_sigaction, sig, &sa, 0, 8);
        }
    }
    memset(&sa, 0, sizeof sa);
    sa.handler = (unsigned long)(void *)&sx_early_sigsys;
    sa.flags = 4 /* SA_SIGINFO */;
    SC(SYS_rt_sigaction, 31, &sa, 0, 8);
    SC(SYS_rt_sigprocmask, 1 /* SIG_UNBLOCK */, &unblock, 0, 8);

    for (fd = 3; fd < 1024; fd++) {
        long fl = SC(SYS_fcntl, fd, F_GETFD, 0, 0);
        if (fl >= 0 && (fl & FD_CLOEXEC))
            SC(SYS_close, fd, 0, 0, 0);
    }
}

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

int px_static_exec(const char *host, char *const argv[], char *const envp[])
{
    sx_image *img;
    size_t sites, nargc = 0, nenv = 0, i;
    unsigned long av[64], *sp, *w;
    int na = 0, nav;
    char *stk, *top, *rnd, *execfn;
    char **sa, **se;
    unsigned long tls;
    const char *v = getenv("BXROOT_VERBOSE");
    int verbose = (v != NULL && v[0] != '\0' && v[0] != '0');

    if (host == NULL || argv == NULL || argv[0] == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (getenv("BXROOT_NO_STATIC_EXEC") != NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (sx_thread_count() != 1) {
        errno = EBUSY;              /* 多线程：真 execve 会杀其它线程，我们做不到 */
        return -1;
    }

    img = (sx_image *)malloc(sizeof(*img));
    if (img == NULL)
        return -1;

    /* 先按最大站点数估个 veneer 区：第一遍装载后才知道，所以保守取 4096 个 */
    if (sx_load(host, img, 4096 * SX_VENEER_SIZE) != 0) {
        int e = errno;
        free(img);
        errno = e;
        return -1;
    }

    sites = sx_count_sites(img);
    if (sites * SX_VENEER_SIZE > img->veneer_cap) {
        /* 站点超过预留：不半补（半补 = 一部分路径仍泄漏到宿主），整体放弃 */
        free(img);
        errno = ENOEXEC;
        return -1;
    }

    /* veneer 区：先 RW 写入，再 RX */
    if (sites > 0) {
        long m = sx_sc6(SYS_mprotect, (long)img->veneer_pool, (long)img->veneer_cap,
                        PROT_READ | PROT_WRITE, 0, 0, 0);
        unsigned k;
        size_t placed = 0;

        if (m != 0) { free(img); errno = (int)-m; return -1; }
        for (k = 0; k < img->nph; k++) {
            const Elf64_Phdr *p = &img->ph[k];
            unsigned long seg, len;
            int prot;
            size_t got;

            if (p->p_type != PT_LOAD || !(p->p_flags & PF_X))
                continue;
            seg = (img->base + p->p_vaddr) & ~4095UL;
            len = (((img->base + p->p_vaddr + p->p_memsz) + 4095UL) & ~4095UL) - seg;
            prot = PROT_READ | PROT_EXEC;
            if (p->p_flags & PF_W)
                prot |= PROT_WRITE;
            SC(SYS_mprotect, seg, len, PROT_READ | PROT_WRITE | PROT_EXEC, 0);
            got = sx_scan((uint32_t *)(img->base + p->p_vaddr), p->p_filesz / 4,
                          (uint32_t *)(img->veneer_pool + placed * SX_VENEER_SIZE),
                          img->veneer_cap - placed * SX_VENEER_SIZE);
            placed += got;
            SC(SYS_mprotect, seg, len, prot, 0);
            __builtin___clear_cache((char *)seg, (char *)(seg + len));
        }
        SC(SYS_mprotect, img->veneer_pool, img->veneer_cap, PROT_READ | PROT_EXEC, 0);
        __builtin___clear_cache((char *)img->veneer_pool,
                                (char *)(img->veneer_pool + img->veneer_cap));
        if (verbose && bxroot_log != NULL)
            bxroot_log("static_exec: %s 补丁 %zu 个路径 svc 站点", host, placed);
    }

    /* 新栈 */
    stk = (char *)sx_sc6(SYS_mmap, 0, (long)SX_STACK_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if ((unsigned long)stk >= (unsigned long)-4095L) {
        free(img);
        errno = ENOMEM;
        return -1;
    }
    top = stk + SX_STACK_SIZE;

    while (argv[nargc] != NULL) nargc++;
    if (envp != NULL)
        while (envp[nenv] != NULL) nenv++;
    sa = (char **)calloc(nargc + 1, sizeof(char *));
    se = (char **)calloc(nenv + 1, sizeof(char *));
    if (sa == NULL || se == NULL) {
        free(img);
        errno = ENOMEM;
        return -1;
    }
#define SX_PUSH(dst, s) do { size_t _l = strlen(s) + 1; top -= _l; memcpy(top, (s), _l); (dst) = top; } while (0)
    for (i = nargc; i-- > 0;)
        SX_PUSH(sa[i], argv[i]);
    for (i = nenv; i-- > 0;)
        SX_PUSH(se[i], envp[i]);
    SX_PUSH(execfn, host);
    top = (char *)((unsigned long)top & ~15UL) - 16;
    rnd = top;
    memcpy(rnd, (void *)getauxval(AT_RANDOM), 16);

#define SX_AUX(k, val) do { av[na++] = (unsigned long)(k); av[na++] = (unsigned long)(val); } while (0)
    if (getauxval(AT_SYSINFO_EHDR))
        SX_AUX(AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR));
    SX_AUX(AT_HWCAP, getauxval(AT_HWCAP));
    SX_AUX(AT_HWCAP2, getauxval(AT_HWCAP2));
    SX_AUX(AT_PAGESZ, getauxval(AT_PAGESZ));
    SX_AUX(AT_CLKTCK, getauxval(AT_CLKTCK));
    SX_AUX(AT_PHDR, img->phdr);
    SX_AUX(AT_PHENT, sizeof(Elf64_Phdr));
    SX_AUX(AT_PHNUM, img->phnum);
    SX_AUX(AT_BASE, 0);
    SX_AUX(AT_FLAGS, 0);
    SX_AUX(AT_ENTRY, img->entry);
    SX_AUX(AT_UID, getuid());
    SX_AUX(AT_EUID, geteuid());
    SX_AUX(AT_GID, getgid());
    SX_AUX(AT_EGID, getegid());
    SX_AUX(AT_SECURE, 0);
    SX_AUX(AT_RANDOM, rnd);
    SX_AUX(AT_EXECFN, execfn);
    SX_AUX(AT_NULL, 0);
    nav = na;

    sp = (unsigned long *)(((unsigned long)top -
                            (nargc + 1 + nenv + 1 + 1) * 8 - (size_t)nav * 8) & ~15UL);
    w = sp;
    *w++ = (unsigned long)nargc;
    for (i = 0; i < nargc; i++) *w++ = (unsigned long)sa[i];
    *w++ = 0;
    for (i = 0; i < nenv; i++) *w++ = (unsigned long)se[i];
    *w++ = 0;
    memcpy(w, av, (size_t)nav * 8);

    sx_reset_process_state();

    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls));
    px_static_dyn_tls = tls;

    if (verbose && bxroot_log != NULL)
        bxroot_log("static_exec: 即将跳转 entry=%lx sp=%lx tls=%lx", img->entry,
                   (unsigned long)sp, tls);
    {
        /*
         * ★ 操作数必须钉死在固定寄存器 ★ 若让编译器自选，entry 可能落进 x0，
         * 而 `mov x0,#0` 在 `br` 之前 → 跳到地址 0（实测 pc=0）。
         */
        register unsigned long e __asm__("x9") = img->entry;
        register unsigned long s __asm__("x10") = (unsigned long)sp;

        __asm__ volatile("mov sp, x10\n"
                         "mov x0, #0\n"      /* rtld_fini = NULL */
                         "br  x9\n"
                         :: "r"(e), "r"(s) : "memory");
    }
    __builtin_unreachable();
}
