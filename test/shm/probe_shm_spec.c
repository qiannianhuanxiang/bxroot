#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include "test_key.h"

#define MAX_OWNED 32
#define MAX_MAPS 8
static int owned[MAX_OWNED];
static size_t owned_n;
static void *maps[MAX_MAPS];
static size_t maps_n;
static int cleaned;
static int cleanup_failed;

static void own_id(int id)
{
    size_t i;
    if (id < 0) return;
    for (i = 0; i < owned_n; i++) if (owned[i] == id) return;
    if (owned_n < MAX_OWNED) owned[owned_n++] = id;
}

static void own_map(void *p)
{
    if (p != NULL && p != (void *)-1 && maps_n < MAX_MAPS) maps[maps_n++] = p;
}

static void cleanup(void)
{
    size_t i;
    if (cleaned) return;
    cleaned = 1;
    for (i = maps_n; i > 0; i--) {
        if (maps[i - 1] != NULL && maps[i - 1] != (void *)-1)
            if (shmdt(maps[i - 1])) cleanup_failed = 1;
    }
    for (i = 0; i < owned_n; i++)
        if (owned[i] >= 0 && shmctl(owned[i], IPC_RMID, NULL)) cleanup_failed = 1;
}

#define EVAL(expr) do { errno = 0; long _r = (long)(expr); \
    printf("%-44s = %ld errno=%d\n", #expr, _r, errno); } while (0)
#define REQUIRE(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s errno=%d\n", msg, errno); return 1; } } while (0)

int main(int argc, char **argv)
{
    int a, b, key_id, neg_id, c, k, status, extra;
    key_t key, missing, negative;
    pid_t child;
    if (argc != 4 || test_shm_key(argv[1], &key) || test_shm_key(argv[2], &missing) ||
        test_shm_key(argv[3], &negative) || key <= 0 || missing <= 0 || negative >= 0 || key == missing) {
        fprintf(stderr, "usage: %s KEY MISSING_KEY NEGATIVE_KEY\n", argv[0]); return 1;
    }
    char *p, *q, *r;
    struct shmid_ds ds;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (atexit(cleanup) != 0) {
        fprintf(stderr, "FAIL: cannot register cleanup\n");
        return 1;
    }
    a = shmget(IPC_PRIVATE, 5000, 0600 | IPC_CREAT); REQUIRE(a >= 0, "private shmget"); own_id(a); printf("private id=%d\n", a);
    b = shmget(IPC_PRIVATE, 5000, 0600); REQUIRE(b >= 0 && b != a, "private2 shmget"); own_id(b); printf("private2 id=%d (distinct=%d)\n", b, a != b);
    extra = shmget(IPC_PRIVATE, 0, 0600); own_id(extra);
    printf("private-zero result=%s\n", extra >= 0 ? "created" : "rejected");
    key_id = shmget(key, 100, 0600 | IPC_CREAT | IPC_EXCL);
    REQUIRE(key_id >= 0, "key create"); own_id(key_id);
    printf("keyed id=%d\n", key_id);
    EVAL(shmget(key, 0, 0600 | IPC_CREAT));
    EVAL(shmget(key, 100, 0600 | IPC_CREAT));
    EVAL(shmget(key, 100, 0600 | IPC_CREAT | IPC_EXCL));
    EVAL(shmget(key, 99999, 0600));
    EVAL(shmget(missing, 100, 0600));
    neg_id = shmget(negative, 100, 0600 | IPC_CREAT | IPC_EXCL);
    REQUIRE(neg_id >= 0, "negative key create"); own_id(neg_id); printf("negative key id=%d\n", neg_id);
    EVAL(shmat(-1, 0, 0));
    p = shmat(a, (void *)0x1234, 0);
    printf("requested-address result=%s\n", p != (void *)-1 ? "accepted" : "rejected");
    if (p != (void *)-1) {
        own_map(p); REQUIRE(shmdt(p) == 0, "requested detach"); maps[maps_n - 1] = NULL;
    }
    p = shmat(a, NULL, 0); REQUIRE(p != (void *)-1, "normal attach"); own_map(p);
    printf("normal attach ok=%d\n", p != (void *)-1);
    memset(p, 'x', 5000);
    q = shmat(a, 0, SHM_RDONLY); REQUIRE(q != (void *)-1, "second attach"); own_map(q);
    printf("second attach distinct=%d sees=%c\n", q != p, q[0]);
    memset(&ds, 0xAB, sizeof ds); REQUIRE(shmctl(a, IPC_STAT, &ds) == 0, "IPC_STAT");
    printf(" segsz=%zu nattch=%lu mode=%o key=%d uid=%d gid=%d cuid=%d cgid=%d cpid=%d lpid=%d atime=%ld ctime=%ld\n", (size_t)ds.shm_segsz, (unsigned long)ds.shm_nattch, ds.shm_perm.mode, ds.shm_perm.__key, ds.shm_perm.uid, ds.shm_perm.gid, ds.shm_perm.cuid, ds.shm_perm.cgid, ds.shm_cpid, ds.shm_lpid, (long)ds.shm_atime, (long)ds.shm_ctime);
    printf("mapped data intact=%d\n", p[4999] == 'x');
    REQUIRE(shmctl(a, IPC_RMID, NULL) == 0, "IPC_RMID a");
    for (size_t i = 0; i < owned_n; i++) if (owned[i] == a) owned[i] = -1;
    REQUIRE(p[1] == 'x' && q[1] == 'x', "RMID mapping retained");
    printf("after RMID still mapped: %c\n", p[1]);
    extra = shmget(IPC_PRIVATE, 100, 0); own_id(extra);
    printf("private-small result=%s\n", extra >= 0 ? "created" : "rejected");
    REQUIRE(shmdt(p) == 0, "detach p"); maps[maps_n - 2] = NULL;
    EVAL(shmdt(p));
    EVAL(shmdt((void *)0x1000));
    EVAL(shmctl(-1, IPC_STAT, &ds));
    EVAL(shmctl(b, IPC_SET, &ds));
    EVAL(shmctl(b, SHM_LOCK, 0));
    EVAL(shmctl(b, IPC_INFO, (struct shmid_ds *)&ds));
    EVAL(shmctl(b, SHM_STAT, &ds));
    EVAL(shmctl(b, 12345, &ds));
    REQUIRE(shmctl(b, IPC_RMID, NULL) == 0, "RMID b");
    for (size_t i = 0; i < owned_n; i++) if (owned[i] == b) owned[i] = -1;
    EVAL(shmctl(b, IPC_RMID, NULL));
    k = shmget(key, 100, 0600); REQUIRE(k == key_id, "key remains owned"); REQUIRE(shmctl(k, IPC_RMID, NULL) == 0, "RMID keyed segment");
    for (size_t i = 0; i < owned_n; i++) if (owned[i] == k) owned[i] = -1;
    EVAL(shmget(key, 100, 0600));
    c = shmget(IPC_PRIVATE, 4096, 0600 | IPC_CREAT); REQUIRE(c >= 0, "fork segment"); own_id(c);
    r = shmat(c, 0, 0); REQUIRE(r != (void *)-1, "fork attach"); own_map(r); r[0] = 'P';
    child = fork(); REQUIRE(child >= 0, "fork");
    if (child == 0) { r[0] = 'C'; _exit(0); }
    pid_t waited; do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    REQUIRE(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "fork wait");
    REQUIRE(r[0] == 'C', "fork shared mapping content");
    printf("fork-inherit shared: %c\n", r[0]);
    REQUIRE(shmdt(r) == 0, "detach r"); maps[maps_n - 1] = NULL;
    /* Huge allocations are not needed to verify cleanup and can consume quota. */
    cleanup();
    REQUIRE(!cleanup_failed, "cleanup");
    puts("SPEC_DONE");
    return 0;
}
