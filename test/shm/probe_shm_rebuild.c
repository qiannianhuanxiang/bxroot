#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "test_key.h"

struct reply { int id; int rc; };
static int io(int fd, void *buf, size_t n, int wr)
{
    char *p = buf;
    while (n) {
        ssize_t r = wr ? write(fd, p, n) : read(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}
static int live(int id)
{
    void *p;
    if (id < 0) return 0;
    p = shmat(id, NULL, SHM_RDONLY);
    if (p == (void *)-1)
        return errno == EINVAL || errno == EIDRM || errno == ENOENT || errno == EPERM ? 0 : -1;
    if (shmdt(p)) return -1;
    return 1;
}
static int remove_ids(int *ids, int n)
{
    int failed = 0;
    for (int i = 0; i < n; i++) {
        int duplicate = 0;
        for (int j = 0; j < i; j++) if (ids[j] == ids[i]) duplicate = 1;
        if (ids[i] >= 0 && !duplicate && shmctl(ids[i], IPC_RMID, NULL) &&
            errno != EINVAL && errno != EIDRM) failed = 1;
    }
    return failed ? -1 : 0;
}
int main(int argc, char **argv)
{
    key_t key;
    if (argc != 2 || test_shm_key(argv[1], &key)) return 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    for (int round = 0; round < 100; round++) {
        int ids[4] = {-1,-1,-1,-1}, gates[2], reports[2];
        pid_t kids[3]; int count = 0, ok = 1;
        char *mapping;
        ids[0] = shmget(key, 4096, IPC_CREAT | IPC_EXCL | 0600);
        if (ids[0] < 0) { perror("claim"); return 1; }
        mapping = shmat(ids[0], NULL, 0);
        if (mapping == (void *)-1) { remove_ids(ids, 1); return 1; }
        mapping[0] = 'S';
        if (pipe(gates) || pipe(reports)) { shmdt(mapping); remove_ids(ids, 1); return 1; }
        for (int worker = 0; worker < 3; worker++) {
            pid_t pid = fork();
            if (pid < 0) { ok = 0; break; }
            if (!pid) {
                char go; struct reply r = {-1, -1};
                close(gates[1]); close(reports[0]);
                if (io(gates[0], &go, 1, 0)) _exit(1);
                if (worker == 0) r.rc = shmctl(ids[0], IPC_RMID, NULL);
                else { r.id = test_shmget_retry(key, 4096, IPC_CREAT | 0600); r.rc = r.id >= 0 ? 0 : -1; }
                if (io(reports[1], &r, sizeof r, 1)) _exit(1);
                _exit(r.rc ? 1 : 0);
            }
            kids[count++] = pid;
        }
        close(gates[0]); close(reports[1]);
        for (int i = 0; i < count; i++) { char go = 'g'; if (io(gates[1], &go, 1, 1)) ok = 0; }
        close(gates[1]);
        for (int i = 0; i < count; i++) {
            struct reply r = {-1,-1};
            if (io(reports[0], &r, sizeof r, 0)) ok = 0;
            ids[i+1] = r.id;
            if (r.rc) ok = 0;
        }
        close(reports[0]);
        for (int i = 0; i < count; i++) {
            int status; pid_t waited;
            do { waited = waitpid(kids[i], &status, 0); } while (waited < 0 && errno == EINTR);
            if (waited != kids[i] || !WIFEXITED(status) || WEXITSTATUS(status)) ok = 0;
        }
        /* After concurrent operations quiesce, each still-live returned ID must
         * remain indexed. IDs removed before return are permitted here. */
        int indexed = shmget(key, 0, 0600);
        for (int i = 1; i < 4; i++) {
            int active = live(ids[i]);
            if (active < 0 || (active && ids[i] != ids[0] && indexed != ids[i])) ok = 0;
        }
        if (mapping[0] != 'S') ok = 0; /* RMID must not invalidate existing mapping. */
        if (shmdt(mapping)) ok = 0;
        if (remove_ids(ids, 4)) ok = 0;
        if (!ok || count != 3) { fprintf(stderr, "FAIL rebuild round=%d indexed=%d\n", round, indexed); return 1; }
        /* If both creators observed the old ID, no new ID need exist. */
        int fresh = shmget(key, 4096, IPC_CREAT | IPC_EXCL | 0600);
        if (fresh < 0) { perror("recreate after RMID"); return 1; }
        if (shmctl(fresh, IPC_RMID, NULL)) return 1;
    }
    puts("RMID_REBUILD_DONE rounds=100");
    return 0;
}
