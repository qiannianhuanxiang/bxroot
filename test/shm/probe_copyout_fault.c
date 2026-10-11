#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../src/runtime/shm-copyout.h"

/* Deliberately bypass libc syscall interposition on the target architecture. */
static long raw6(long nr, long a, long b, long c, long d, long e, long f)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    return x0;
#else
    long r = syscall(nr, a, b, c, d, e, f);
    return r < 0 ? -errno : r;
#endif
}

struct result { int stage; int id; long value; int valid; };
static int transfer(int fd, void *p, size_t n, int writing)
{
    unsigned char *b = p;
    while (n) {
        ssize_t r = writing ? write(fd, b, n) : read(fd, b, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        b += r; n -= (size_t)r;
    }
    return 0;
}
static int reap(pid_t pid, int *status)
{
    pid_t r;
    do { r = waitpid(pid, status, 0); } while (r < 0 && errno == EINTR);
    return r == pid ? 0 : -1;
}

static const char *names[] = {"normal", "NULL", "invalid", "readonly", "PROT_NONE", "cross-PROT_NONE", "cross-readonly", "unmapped", "overflow"};
static void child_case(int out, int which, int ipc, int safe)
{
    struct shmid_ds source, normal;
    struct result r = {0, -1, 0, 0};
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *region;
    void *dst = &normal;
    struct iovec local, remote;
    int id = -1;
    if (page <= 0 || (size_t)page < sizeof source) _exit(3);
    region = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) _exit(3);
    memset(&source, 0, sizeof source);
    source.shm_segsz = 4096;
    source.shm_perm.mode = 0600;
    memset(&normal, 0xaa, sizeof normal);
    switch (which) {
    case 1: dst = NULL; break;
    case 2: dst = (void *)(uintptr_t)1; break;
    case 3: dst = region; if (mprotect(region, (size_t)page, PROT_READ)) _exit(3); break;
    case 4: dst = region; if (mprotect(region, (size_t)page, PROT_NONE)) _exit(3); break;
    case 5: case 6:
        dst = region + page - sizeof source / 2;
        if (mprotect(region + page, (size_t)page, which == 5 ? PROT_NONE : PROT_READ)) _exit(3);
        break;
    case 7: dst = region; if (munmap(region, (size_t)page)) _exit(3); break;
    case 8: dst = (void *)(UINTPTR_MAX - sizeof source / 2); break;
    default: break;
    }
    if (ipc) {
        /* Creation and the potentially crashing IPC_STAT both live in this child.
         * Publish the owned id before the fault so the parent can arrange RMID. */
        long created = raw6(SYS_shmget, IPC_PRIVATE, 4096, IPC_CREAT | 0600, 0, 0, 0);
        r.stage = 1; r.value = created;
        if (created < 0) { transfer(out, &r, sizeof r, 1); _exit(0); }
        id = (int)created; r.id = id;
        if (transfer(out, &r, sizeof r, 1)) _exit(3);
        r.value = raw6(SYS_shmctl, id, IPC_STAT, (long)dst, 0, 0, 0);
    } else if (safe) {
        r.value = bx_shm_copyout((unsigned long)dst, &source, sizeof source, raw6);
    } else {
        local.iov_base = &source; local.iov_len = sizeof source;
        remote.iov_base = dst; remote.iov_len = sizeof source;
        r.value = raw6(SYS_process_vm_writev, raw6(SYS_getpid, 0, 0, 0, 0, 0, 0), (long)&local, 1, (long)&remote, 1, 0);
    }
    r.stage = 2;
    r.valid = which != 0 || (ipc ? normal.shm_segsz == 4096 : memcmp(&normal, &source, sizeof normal) == 0);
    if (transfer(out, &r, sizeof r, 1)) _exit(3);
    _exit(0);
}

static int cleanup_id(int id)
{
    int status;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) _exit(raw6(SYS_shmctl, id, IPC_RMID, 0, 0, 0, 0) == 0 ? 0 : 1);
    return reap(pid, &status) == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    int ipc = argc == 2 && strcmp(argv[1], "--ipc-stat") == 0;
    int safe = argc == 2 && strcmp(argv[1], "--safe-copyout") == 0;
    int failed = 0, unavailable = 0;
    size_t i;
    if (argc != 1 && !ipc && !safe) { fprintf(stderr, "usage: %s [--ipc-stat|--safe-copyout]\n", argv[0]); return 1; }
#if !defined(__aarch64__)
    puts("SKIP: target must be Android/Linux AArch64 (syscall 271)"); return 2;
#else
    _Static_assert(SYS_process_vm_writev == 271, "wrong AArch64 syscall number");
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        int p[2], status, got = 0, owned_id = -1;
        struct result r = {0, -1, 0, 0}, event;
        pid_t pid;
        if (pipe(p)) return 1;
        pid = fork();
        if (pid < 0) { close(p[0]); close(p[1]); return 1; }
        if (!pid) { close(p[0]); child_case(p[1], (int)i, ipc, safe); }
        close(p[1]);
        while (transfer(p[0], &event, sizeof event, 0) == 0) {
            if (event.stage == 1 && event.id >= 0) owned_id = event.id;
            r = event; got = 1;
        }
        close(p[0]);
        if (reap(pid, &status)) return 1;
        if (owned_id >= 0 && cleanup_id(owned_id)) {
            printf("FAIL cleanup id=%d\n", owned_id); failed++;
        }
        if ((WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) ||
            (WIFEXITED(status) && WEXITSTATUS(status) == 159)) {
            printf("CASE %s SIGSYS shell_status=159 stage=%d\n", names[i], got ? r.stage : 0);
            if (!ipc || owned_id < 0) unavailable++; else failed++;
            continue;
        }
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("CASE %s SIGNAL=%d shell_status=%d\n", names[i], sig, 128 + sig);
            failed++;
            continue;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) || !got) { printf("CASE %s FAIL child/report\n", names[i]); failed++; continue; }
        if (safe && !BXROOT_SHM_COPYOUT_VERIFIED) {
            long expected = (i == 1 || i == 8) ? -EFAULT : -ENOSYS;
            int valid = r.stage == 2 && r.value == expected;
            printf("CASE %s %s raw=%ld expected=%ld\n", names[i], valid ? "GATED" : "FAIL", r.value, expected);
            if (!valid) failed++;
            continue;
        }
        if (r.value == -ENOSYS || r.value == -EPERM) {
            printf("CASE %s %s raw=%ld stage=%d\n", names[i], r.value == -ENOSYS ? "ENOSYS" : "EPERM", r.value, r.stage);
            unavailable++; continue;
        }
        if (r.stage != 2) { printf("CASE %s FAIL setup raw=%ld\n", names[i], r.value); failed++; continue; }
        if (i == 0) {
            long expected = (ipc || safe) ? 0 : (long)sizeof(struct shmid_ds);
            if (r.value != expected || !r.valid) failed++;
            printf("CASE %s %s raw=%ld expected=%ld fields=%d\n", names[i], r.value == expected && r.valid ? "SUCCESS" : "FAIL", r.value, expected, r.valid);
        } else {
            /* process_vm_writev may partially copy the writable first page. */
            int valid = r.value == -EFAULT || (!ipc && !safe && r.value > 0 && r.value < (long)sizeof(struct shmid_ds));
            printf("CASE %s %s raw=%ld\n", names[i], valid ? (r.value > 0 ? "SHORT_COPY_EFAULT_REQUIRED" : "EFAULT") : "FAIL", r.value);
            if (!valid) failed++;
        }
    }
    printf("RESULT mode=%s failed=%d unavailable=%d\n", ipc ? "IPC_STAT" : "process_vm_writev", failed, unavailable);
    if (failed) return 1;
    if (unavailable) return 2;
    puts("FAULT_PROBE_DONE");
    return 0;
}
