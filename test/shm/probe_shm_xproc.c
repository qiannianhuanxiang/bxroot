#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "test_key.h"

int main(int argc, char **argv)
{
    key_t key;
    int id;
    char *p;
    const char *action;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && strcmp(argv[1], "rm-id") == 0) {
        char *end; long value;
        errno = 0; value = strtol(argv[2], &end, 10);
        if (errno || !*argv[2] || *end || value < 0 || value > INT_MAX) return 1;
        if (shmctl((int)value, IPC_RMID, NULL)) { perror("rm-id"); return 1; }
        printf("rm id=%ld rc=0\n", value); return 0;
    }
    if (argc < 3 || argc > 4 || test_shm_key(argv[2], &key)) {
        fprintf(stderr, "usage: %s put|get|rm|expect-absent KEY [VALUE]\n", argv[0]);
        return 1;
    }
    action = argv[1];
    if (strcmp(action, "put") == 0) {
        size_t len;
        if (argc != 4 || (len = strlen(argv[3])) >= 4096) return 1;
        id = shmget(key, 4096, 0600 | IPC_CREAT | IPC_EXCL);
        if (id < 0) { perror("put shmget"); return 1; }
        p = shmat(id, NULL, 0);
        if (p == (void *)-1) { perror("put shmat"); shmctl(id, IPC_RMID, NULL); return 1; }
        memcpy(p, argv[3], len + 1);
        if (shmdt(p)) { perror("put shmdt"); shmctl(id, IPC_RMID, NULL); return 1; }
        printf("put id=%d '%s'\n", id, argv[3]);
        return 0;
    }
    if (argc != 3) return 1;
    id = shmget(key, 0, 0600);
    if (strcmp(action, "expect-absent") == 0) {
        if (id < 0 && (errno == ENOENT || errno == EPERM)) { puts("ABSENT"); return 0; }
        fprintf(stderr, "FAIL: key is present or lookup failed errno=%d\n", errno);
        return 1;
    }
    if (id < 0) { perror("lookup"); return 1; }
    if (strcmp(action, "get") == 0) {
        p = shmat(id, NULL, SHM_RDONLY);
        if (p == (void *)-1) { perror("get shmat"); return 1; }
        /* Created only by this probe with a 4096-byte segment. */
        printf("get id=%d '%.*s'\n", id, 4095, p);
        if (shmdt(p)) { perror("get shmdt"); return 1; }
        return 0;
    }
    if (strcmp(action, "rm") == 0) {
        if (shmctl(id, IPC_RMID, NULL)) { perror("rm"); return 1; }
        printf("rm id=%d rc=0\n", id);
        return 0;
    }
    return 1;
}
