#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat fdst, got;
    int fd = open("/etc", O_PATH | O_DIRECTORY);
    if (fd < 0 || fstat(fd, &fdst) != 0) {
        perror("open/fstat /etc");
        return 2;
    }
    errno = 0;
    if (fstatat(fd, "", &got, AT_EMPTY_PATH) != 0 || got.st_dev != fdst.st_dev || got.st_ino != fdst.st_ino) {
        fprintf(stderr, "AT_EMPTY_PATH did not stat fd object: rc/error mismatch (errno=%d)\n", errno);
        close(fd);
        return 1;
    }
    errno = 0;
    if (fstatat(fd, "", &got, 0) != -1 || errno != ENOENT) {
        fprintf(stderr, "empty fstatat without AT_EMPTY_PATH should be ENOENT (errno=%d)\n", errno);
        close(fd);
        return 1;
    }
    errno = 0;
    if (stat("", &got) != -1 || errno != ENOENT) {
        fprintf(stderr, "empty stat should be ENOENT (errno=%d)\n", errno);
        close(fd);
        return 1;
    }
    errno = 0;
    if (openat(fd, "", O_RDONLY) != -1 || errno != ENOENT) {
        fprintf(stderr, "openat with empty path should be ENOENT (errno=%d)\n", errno);
        close(fd);
        return 1;
    }
    close(fd);
    puts("EMPTY_PATH_SEMANTICS_OK");
    return 0;
}
