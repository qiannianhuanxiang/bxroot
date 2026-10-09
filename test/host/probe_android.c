/* Real Android guest/host process probe. SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;

static int spawn_case(int search)
{
    int p[2], status, rc; pid_t pid;
    posix_spawn_file_actions_t fa; posix_spawnattr_t attr;
    char buf[4096]; ssize_t n;
    char *args[] = {"custom-host-argv0", "-c", "printf 'SPAWN:%s:%s' \"$0\" \"$FOO\"; exit 23", NULL};
    char *env[] = {"FOO=retained", "LD_PRELOAD=/guest/invalid.so", "BXROOT_SECRET=drop", NULL};
    if (pipe(p)) return 90;
    posix_spawn_file_actions_init(&fa); posix_spawnattr_init(&attr);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    rc = search ? posix_spawnp(&pid, "sh", &fa, &attr, args, env)
                : posix_spawn(&pid, "/system/bin/sh", &fa, &attr, args, env);
    close(p[1]); posix_spawn_file_actions_destroy(&fa); posix_spawnattr_destroy(&attr);
    if (rc) { printf("spawn_error=%d\n", rc); close(p[0]); return 91; }
    n = read(p[0], buf, sizeof(buf) - 1); close(p[0]);
    if (n < 0) return 92;
    buf[n] = 0; waitpid(pid, &status, 0);
    printf("%s STATUS=%d\n", buf, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return WIFEXITED(status) && WEXITSTATUS(status) == 23 &&
           !strcmp(buf, "SPAWN:custom-host-argv0:retained") ? 0 : 93;
}
int main(int argc, char **argv, char **initial_env)
{
    char *host[] = {"custom-host-argv0", "-c", "printf 'EXEC:%s:%s' \"$0\" \"$FOO\"; exit 17", NULL};
    char *env[] = {"FOO=retained", "LD_PRELOAD=/guest/invalid.so", "LD_LIBRARY_PATH=/guest/lib", "BXROOT_TEST=drop", NULL};
    const char *mode = argc > 1 ? argv[1] : "";
    if (!strcmp(mode, "exec")) execve("/system/bin/sh", host, env);
    else if (!strcmp(mode, "execvp")) { setenv("FOO", "retained", 1); execvp("getprop", (char *[]) {"getprop", "ro.product.model", NULL}); }
    else if (!strcmp(mode, "execvpe")) execvpe("getprop", (char *[]) {"getprop", "ro.product.model", NULL}, env);
    else if (!strcmp(mode, "spawn")) return spawn_case(0);
    else if (!strcmp(mode, "spawnp")) {
        int st, rc; pid_t p;
        rc = posix_spawnp(&p, "getprop", NULL, NULL, (char *[]) {"getprop", "ro.product.model", NULL}, env);
        if (rc) return rc;
        waitpid(p, &st, 0);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 94;
    }
    else if (!strcmp(mode, "syscall")) syscall(SYS_execve, "/proc/self/root/system/bin/sh", host, env, 0, 0, 0);
    else if (!strcmp(mode, "execveat")) execveat(AT_FDCWD, "/system/bin/sh", host, env, 0);
    else if (!strcmp(mode, "fexecve")) { int fd = open("/system/bin/sh", O_RDONLY); if (fd < 0) return 95; fexecve(fd, host, env); }
    else if (!strcmp(mode, "system")) { int st = system("getprop ro.product.model"); return WIFEXITED(st) ? WEXITSTATUS(st) : 96; }
    else if (!strcmp(mode, "popen")) {
        char b[128]; FILE *f = popen("getprop ro.product.model", "r"); int st;
        if (!f) return 97;
        if (!fgets(b, sizeof(b), f)) { pclose(f); return 98; }
        st = pclose(f); printf("POPEN:%s", b); return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
    }
    else if (!strcmp(mode, "script-exec")) execve("/tmp/bx-native-script", (char *[]) {"script", "arg-value", NULL}, env);
    else if (!strcmp(mode, "script-spawn")) {
        int st, rc; pid_t pid;
        rc = posix_spawn(&pid, "/tmp/bx-native-script", NULL, NULL, (char *[]) {"script", "arg-value", NULL}, env);
        if (rc) return rc;
        waitpid(pid, &st, 0);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
    }
    else if (!strcmp(mode, "script-denied")) {
        execve("/tmp/bx-native-denied", (char *[]) {"denied", NULL}, env);
        printf("SCRIPT_ERRNO=%d\n", errno);
        return errno == EACCES ? 0 : 1;
    }
    else if (!strcmp(mode, "guest-clean-env")) {
        char *clean[] = {"FOO=retained", NULL};
        execve("/bin/bash", (char *[]) {"bash", "-c", "echo CLEAN_PATH=$PATH AUTO=$BXROOT_AUTO_HOST; grep bxroot-native-v2 /proc/$$/maps; getprop ro.product.model", NULL}, clean);
    }
    else if (!strcmp(mode, "path")) {
        size_t i;
        for (i = 0; initial_env[i]; i++)
            if (!strncmp(initial_env[i], "PATH=", 5)) printf("INITIAL:%s\n", initial_env[i]);
        printf("PATH:%s\nAUTO:%s\n", getenv("PATH"), getenv("BXROOT_AUTO_HOST"));
        setenv("PATH", "/usr/bin:/bin:/system/bin", 1);
        printf("UPDATED:%s\n", getenv("PATH"));
        return 0;
    }
    else return 100;
    perror(mode); return errno == ENOENT ? 127 : 126;
}
