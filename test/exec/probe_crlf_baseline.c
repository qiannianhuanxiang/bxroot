#define _GNU_SOURCE
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    char *args[] = {argv[1], NULL};
    /* Statically linked by the runner, so libc exec symbol interposition cannot
     * alter the script before this native syscall baseline. */
    syscall(SYS_execve, argv[1], args, environ);
    return errno == ENOENT || errno == ENOEXEC || errno == EACCES ? 126 : 1;
}
