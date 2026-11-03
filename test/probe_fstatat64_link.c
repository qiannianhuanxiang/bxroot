#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat64 expected, got;
    if (stat64("/etc/hostname", &expected) != 0) {
        perror("stat64 guest target");
        return 2;
    }
    if (fstatat64(AT_FDCWD, "/tmp/lnk/hostname", &got, 0) != 0) {
        perror("fstatat64 through absolute symlink");
        return 1;
    }
    if (got.st_dev != expected.st_dev || got.st_ino != expected.st_ino) {
        fprintf(stderr, "fstatat64 returned a different target: got dev=%llu ino=%llu expected dev=%llu ino=%llu\n",
                (unsigned long long)got.st_dev, (unsigned long long)got.st_ino,
                (unsigned long long)expected.st_dev, (unsigned long long)expected.st_ino);
        return 1;
    }
    puts("FSTATAT64_GUEST_LINK_OK");
    return 0;
}
