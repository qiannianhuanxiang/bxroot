#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    errno = 0;
    int fd = shm_open("/../../tmp/bxroot_audit_escape", O_CREAT | O_RDWR, 0600);
    if (fd >= 0) {
        close(fd);
        fprintf(stderr, "shm_open accepted a path traversal name\n");
        return 1;
    }
    if (errno != EINVAL) {
        fprintf(stderr, "shm_open traversal errno=%d, expected EINVAL\n", errno);
        return 1;
    }

    errno = 0;
    if (shm_unlink("/../victim") != -1 || errno != EINVAL) {
        fprintf(stderr, "shm_unlink traversal was not rejected (errno=%d)\n", errno);
        return 1;
    }

    errno = 0;
    sem_t *sem = sem_open("/../victim", 0);
    if (sem != SEM_FAILED || errno != EINVAL) {
        if (sem != SEM_FAILED) sem_close(sem);
        fprintf(stderr, "sem_open traversal was not rejected (errno=%d)\n", errno);
        return 1;
    }

    errno = 0;
    if (sem_unlink("/../victim") != -1 || errno != EINVAL) {
        fprintf(stderr, "sem_unlink traversal was not rejected (errno=%d)\n", errno);
        return 1;
    }
    puts("SHM_NAMES_REJECTED_OK");
    return 0;
}
