#ifndef BXROOT_SHM_COPYOUT_H
#define BXROOT_SHM_COPYOUT_H
#include <stdint.h>
#include <sys/uio.h>

/* Enable only when the complete inherited filter chain permits raw AArch64
 * getpid(172) and process_vm_writev(271), including handler context.
 * SIGSYS replay cannot relax an inherited filter. No environment override. */
#ifndef BXROOT_SHM_COPYOUT_VERIFIED
#define BXROOT_SHM_COPYOUT_VERIFIED 0
#endif
#if BXROOT_SHM_COPYOUT_VERIFIED != 0 && BXROOT_SHM_COPYOUT_VERIFIED != 1
#error BXROOT_SHM_COPYOUT_VERIFIED must be 0 or 1
#endif

typedef long (*bx_shm_raw6_fn)(long, long, long, long, long, long, long);
static inline __attribute__((unused)) long bx_shm_copyout(unsigned long dst, const void *src, size_t len,
                           bx_shm_raw6_fn raw)
{
    if (dst == 0 || len > UINTPTR_MAX - (uintptr_t)dst)
        return -14; /* EFAULT; never dereference dst in userspace */
#if BXROOT_SHM_COPYOUT_VERIFIED
    struct iovec local = { (void *)src, len };
    struct iovec remote = { (void *)(uintptr_t)dst, len };
    long pid = raw(172, 0, 0, 0, 0, 0, 0);
    long r;
    if (pid < 0)
        return pid;
    r = raw(271, pid, (long)&local, 1, (long)&remote, 1, 0);
    if (r < 0)
        return r;
    /* A short copy may modify the writable prefix; it is not atomic. */
    return r == (long)len ? 0 : -14;
#else
    (void)src;
    (void)raw;
    return -38; /* ENOSYS: unavailable copy-out, no unsafe fallback */
#endif
}
#endif
