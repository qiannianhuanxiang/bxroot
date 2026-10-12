#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../src/runtime/sysvshm.c"
#include "../bx_tmpdir.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s line=%d errno=%d\n", #x, __LINE__, errno); return 1; } } while (0)
int main(int argc, char **argv)
{
    char path[PATH_MAX], moved[PATH_MAX + 16];
    if (bx_tmppath(path, sizeof path, "bxroot-anchor-XXXXXX")) return 1;
    int anchor, fd, status;
    long result;
    pid_t child;
    struct stat st;
    if (argc == 3 && strcmp(argv[1], "exec-check") == 0) {
        int inherited = atoi(argv[2]);
        return fcntl(inherited, F_GETFD) == -1 && errno == EBADF ? 0 : 1;
    }
    CHECK(mkdtemp(path) != NULL);
    CHECK(bxroot_sysvshm_init(path) == 0);
    anchor = bxroot_sysvshm_anchor_fd();
    CHECK(anchor >= 0 && shm_anchor_valid());
    CHECK(fcntl(anchor, F_GETFD) & FD_CLOEXEC);
    snprintf(moved, sizeof moved, "%s-old", path);
    CHECK(rename(path, moved) == 0);
    CHECK(mkdir(path, 0700) == 0);
    CHECK(shm_anchor_valid());
    fd = openat(anchor, "seg-77", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0); close(fd);
    CHECK(fstatat(anchor, "seg-77", &st, 0) == 0);
    fd = (int)shm_open_seg(77, 1);
    CHECK(fd >= 0); close(fd);
    child = fork(); CHECK(child >= 0);
    if (child == 0) _exit(shm_anchor_valid() ? 0 : 1);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    child = fork(); CHECK(child >= 0);
    if (child == 0) {
        char number[32]; snprintf(number, sizeof number, "%d", anchor);
        execl("/proc/self/exe", argv[0], "exec-check", number, (char *)NULL);
        _exit(99);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(unlinkat(anchor, "seg-77", 0) == 0);
    CHECK(close(anchor) == 0);
    CHECK(!shm_anchor_valid());
    fd = open(path, O_DIRECTORY | O_RDONLY);
    CHECK(fd >= 0);
    if (fd != anchor) { CHECK(dup2(fd, anchor) == anchor); close(fd); }
    CHECK(!shm_anchor_valid());
    CHECK(bxroot_sysvshm_emulate(SHM_NR_GET, 0, 4096, 0600, &result) == 1 && result == -9);
    close(anchor);
    CHECK(rmdir(path) == 0 && rmdir(moved) == 0);
    puts("ANCHOR_LIFECYCLE_PASS");
    return 0;
}
