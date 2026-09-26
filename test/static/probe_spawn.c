/* posix_spawn(argv[1]) 并把子进程的 stdout 原样透出，打印退出码（RUN_STATIC_ELF.sh D 组）。
 * 故意带 file_actions + attr：make 等真实调用方总是带 attr，走的是同一条路径。 */
#include <stdio.h>
#include <spawn.h>
#include <signal.h>
#include <sys/wait.h>
extern char **environ;
int main(int argc, char **argv)
{
    pid_t p;
    int st = -1, r;
    char *a[] = { argv[1], NULL };
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    sigset_t m;
    if (argc < 2) return 2;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, 1, 1);
    posix_spawnattr_init(&at);
    sigemptyset(&m);
    posix_spawnattr_setsigmask(&at, &m);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK);
    fflush(stdout);
    r = posix_spawn(&p, argv[1], &fa, &at, a, environ);
    if (r == 0) waitpid(p, &st, 0);
    printf("spawn r=%d status=%d\n", r, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return 0;
}
