/* Native v3 device probe, run through the guest loader. SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
static long raw(long nr, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    return x0;
}
int main(int argc, char **argv)
{
    const char *p = getenv("BXROOT_SESSION_FD");
    int fd = p && *p ? atoi(p) : -1;
    if (argc > 1 && !strcmp(argv[1], "fd")) {
        long flags = raw(SYS_fcntl, fd, F_GETFL, 0, 0, 0, 0);
        long seals = raw(SYS_fcntl, fd, F_GET_SEALS, 0, 0, 0, 0);
        long write_rc = raw(SYS_write, fd, (long)"x", 1, 0, 0, 0);
        printf("FLAGS=%ld SEALS=%ld WRITE=%ld GUEST_UID=%ld REAL_UID=%ld\n", flags, seals, write_rc,
               (long)getuid(), raw(SYS_getuid, 0, 0, 0, 0, 0, 0));
        return flags >= 0 && (flags & O_ACCMODE) == O_RDONLY && seals == 15 && write_rc == -EBADF ? 0 : 1;
    }
    fprintf(stderr, "unknown probe mode\n");
    return 2;
}
