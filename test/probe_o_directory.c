#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat expected, opened;
    int fd;

    if (stat("/etc", &expected) != 0) {
        perror("stat /etc");
        return 2;
    }
    fd = open("/tmp/lnk", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("open O_DIRECTORY symlink");
        return 3;
    }
    if (fstat(fd, &opened) != 0) {
        perror("fstat opened directory");
        close(fd);
        return 4;
    }
    close(fd);
    if (expected.st_dev != opened.st_dev || expected.st_ino != opened.st_ino) {
        fprintf(stderr, "O_DIRECTORY followed a link outside guest root: expected dev=%llu ino=%llu, got dev=%llu ino=%llu\n",
                (unsigned long long)expected.st_dev,
                (unsigned long long)expected.st_ino,
                (unsigned long long)opened.st_dev,
                (unsigned long long)opened.st_ino);
        return 1;
    }
    puts("O_DIRECTORY_SYMLINK_GUEST_OK");
    return 0;
}
