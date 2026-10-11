#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "test_key.h"

#define NP 16
#define NT 8
#define LOOPS 200

static int write_full(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t n)
{
    char *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static void *thr(void *arg)
{
    int id = *(int *)arg;
    int i;
    for (i = 0; i < LOOPS; i++) {
        char *p = shmat(id, NULL, 0);
        if (p == (void *)-1) return (void *)1;
        __atomic_fetch_add((int *)p, 1, __ATOMIC_SEQ_CST);
        if (shmdt(p) != 0) return (void *)1;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    key_t key;
    if (argc != 2 || test_shm_key(argv[1], &key)) {
        fprintf(stderr, "usage: %s KEY\n", argv[0]); return 1;
    }
    int barrier[2], results[2], seed, id, *cnt = (void *)-1;
    pid_t kids[NP];
    int ids[NP], i, ok = 1, child_count = 0;
    pthread_t threads[NT];
    int started = 0;
    long bad = 0;
    struct shmid_ds ds = {0};

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    for (i = 0; i < NP; i++) ids[i] = -1;
    seed = shmget(key, 4096, 0600 | IPC_CREAT | IPC_EXCL);
    if (seed < 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "race key collision\n");
            return 1;
        }
        perror("seed shmget");
        return 1;
    }
    if (shmctl(seed, IPC_RMID, NULL) != 0) { perror("seed RMID"); return 1; }
    if (pipe(barrier) != 0 || pipe(results) != 0) { perror("pipe"); return 1; }
    for (i = 0; i < NP; i++) {
        kids[i] = fork();
        if (kids[i] < 0) { perror("fork"); ok = 0; break; }
        child_count++;
        if (kids[i] == 0) {
            char token;
            int child_id;
            close(barrier[1]);
            close(results[0]);
            if (read_full(barrier[0], &token, 1) != 0) _exit(2);
            child_id = test_shmget_retry(key, 4096, 0600 | IPC_CREAT);
            if (write_full(results[1], &child_id, sizeof child_id) != 0) _exit(2);
            _exit(child_id < 0 ? 1 : 0);
        }
    }
    close(barrier[0]);
    close(results[1]);
    for (i = 0; i < child_count; i++) {
        char token = 'g';
        if (write_full(barrier[1], &token, 1) != 0) ok = 0;
    }
    close(barrier[1]);
    for (i = 0; i < child_count; i++) {
        if (read_full(results[0], &ids[i], sizeof ids[i]) != 0) ok = 0;
    }
    close(results[0]);
    for (i = 0; i < child_count; i++) {
        int status;
        pid_t waited;
        do { waited = waitpid(kids[i], &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited != kids[i] || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            ok = 0;
    }
    if (!ok) {
        for (i = 0; i < child_count; i++) if (ids[i] >= 0) shmctl(ids[i], IPC_RMID, NULL);
        fprintf(stderr, "child phase failed\n"); return 1;
    }
    id = ids[0];
    if (id < 0) ok = 0;
    for (i = 1; i < NP; i++) if (ids[i] != id) ok = 0;
    for (i = 0; i < NP; i++) printf("%d\n", ids[i]);
    if (!ok) {
        for (i = 0; i < NP; i++) if (ids[i] >= 0) shmctl(ids[i], IPC_RMID, NULL);
        fprintf(stderr, "ids are not identical\n"); return 1;
    }

    cnt = shmat(id, NULL, 0);
    if (cnt == (void *)-1) { perror("counter attach"); shmctl(id, IPC_RMID, NULL); return 1; }
    *cnt = 0;
    for (i = 0; i < NT; i++) {
        if (pthread_create(&threads[i], NULL, thr, &id) != 0) { ok = 0; break; }
        started++;
    }
    for (i = 0; i < started; i++) {
        void *ret = NULL;
        if (pthread_join(threads[i], &ret) != 0 || ret != NULL) bad++;
    }
    if (started != NT) ok = 0;
    printf("counter=%d (expect %d) bad=%ld\n", *cnt, NT * LOOPS, bad);
    if (*cnt != NT * LOOPS || bad != 0) ok = 0;
    if (shmctl(id, IPC_STAT, &ds) != 0) ok = 0;
    printf("nattch after threads=%lu (expect 1)\n", (unsigned long)ds.shm_nattch);
    if ((unsigned long)ds.shm_nattch != 1) ok = 0;
    if (shmdt(cnt) != 0) ok = 0;
    if (shmctl(id, IPC_RMID, NULL) != 0) ok = 0;
    if (!ok) return 1;
    puts("RACE_DONE");
    return 0;
}
