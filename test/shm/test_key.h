#ifndef BX_TEST_SHM_KEY_H
#define BX_TEST_SHM_KEY_H
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <time.h>
/* Explicit nonzero decimal keys only; never fall back to a shared fixed key. */
static int test_shm_key(const char *text, key_t *out)
{
    char *end;
    long value;
    if (!text || !*text) return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || *end || value < INT_MIN || value > INT_MAX || value == IPC_PRIVATE)
        return -1;
    *out = (key_t)value;
    return 0;
}
/* Only the test caller retries the nonwaiting runtime claim. No handler waits. */
static inline int test_shmget_retry(key_t key, size_t size, int flags)
{
    struct timespec delay = {0, 1000000};
    int id;
    for (int attempt = 0; attempt < 100; attempt++) {
        id = shmget(key, size, flags);
        if (id >= 0 || errno != EAGAIN) return id;
        nanosleep(&delay, NULL);
    }
    return -1;
}
static inline int test_shmctl_retry(int id, int cmd, struct shmid_ds *buf)
{
    struct timespec delay = {0, 1000000};
    for (int attempt = 0; attempt < 100; attempt++) {
        int rc = shmctl(id, cmd, buf);
        if (rc == 0 || errno != EAGAIN) return rc;
        nanosleep(&delay, NULL);
    }
    return -1;
}
#endif
