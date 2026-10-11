#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include "../../src/runtime/shm-copyout.h"
static int calls;
static long pid_result = 123, copy_result;
static long mock_raw(long nr, long a, long b, long c, long d, long e, long f)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    calls++;
    return nr == 172 ? pid_result : copy_result;
}
int main(void)
{
    struct shmid_ds source, target;
    long r;
    memset(&source, 0, sizeof source);
    memset(&target, 0xaa, sizeof target);
    calls = 0;
    if (bx_shm_copyout(0, &source, sizeof source, mock_raw) != -14 || calls)
        return 1;
    if (bx_shm_copyout(UINTPTR_MAX - 1, &source, sizeof source, mock_raw) != -14 || calls)
        return 1;
#if BXROOT_SHM_COPYOUT_VERIFIED
    copy_result = sizeof source;
    r = bx_shm_copyout((unsigned long)&target, &source, sizeof source, mock_raw);
    if (r != 0 || calls != 2) return 1;
    copy_result = sizeof source / 2;
    if (bx_shm_copyout((unsigned long)&target, &source, sizeof source, mock_raw) != -14) return 1;
    copy_result = -1;
    if (bx_shm_copyout((unsigned long)&target, &source, sizeof source, mock_raw) != -1) return 1;
    copy_result = -38;
    if (bx_shm_copyout((unsigned long)&target, &source, sizeof source, mock_raw) != -38) return 1;
    pid_result = -1;
    if (bx_shm_copyout((unsigned long)&target, &source, sizeof source, mock_raw) != -1) return 1;
#else
    r = bx_shm_copyout((unsigned long)&target, &source, sizeof source, mock_raw);
    if (r != -38 || calls) return 1;
#endif
    /* A mock copy never writes target: catches accidental userspace fallback. */
    for (size_t i = 0; i < sizeof target; i++)
        if (((unsigned char *)&target)[i] != 0xaa) return 1;
    puts("COPYOUT_UNIT_DONE");
    return 0;
}
