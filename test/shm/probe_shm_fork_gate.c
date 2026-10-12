#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t gate_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
static int gate_phase;
static int gate_release;
static int gate_armed=1;
static void test_shm_window(int phase)
{
    if (!__atomic_exchange_n(&gate_armed,0,__ATOMIC_ACQ_REL)) return;
    pthread_mutex_lock(&gate_mu);
    gate_phase = phase;
    pthread_cond_broadcast(&gate_cv);
    while (gate_release != phase)
        pthread_cond_wait(&gate_cv, &gate_mu);
    pthread_mutex_unlock(&gate_mu);
}
static void wait_window(int phase)
{
    pthread_mutex_lock(&gate_mu);
    while (gate_phase != phase)
        pthread_cond_wait(&gate_cv, &gate_mu);
    pthread_mutex_unlock(&gate_mu);
}
static void release_window(int phase)
{
    pthread_mutex_lock(&gate_mu);
    gate_release = phase;
    pthread_cond_broadcast(&gate_cv);
    pthread_mutex_unlock(&gate_mu);
}
#define FAIL(stage) do { fprintf(stderr,"FAIL:%s errno=%d\n",stage,errno); return 1; } while (0)
#include "sysvshm_gate_impl.c"
#include "../bx_tmpdir.h"

struct worker_arg { long id; unsigned long addr; long result; int op; long syscall_return; };
static void *worker(void *vp)
{
    struct worker_arg *a = vp;
    if (a->op == 1)
        a->result = bxroot_sysvshm_emulate(SHM_NR_AT, (unsigned long)a->id, 0, 0, (long *)&a->addr);
    else
        a->result = bxroot_sysvshm_emulate(SHM_NR_DT, a->addr, 0, 0, &a->syscall_return);
    return NULL;
}
static int make_seg(int anchor, long id)
{
    char name[64]; struct stat st; int fd;
    snprintf(name, sizeof name, "seg-%ld", id);
    fd = openat(anchor, name, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC, 0600);
    if (fd < 0 || ftruncate(fd, 4096) != 0) return -1;
    if (fstat(fd, &st) != 0 || st.st_size != 4096) return -1;
    close(fd); return 0;
}
int main(void)
{
    char dir[PATH_MAX]; if (bx_tmppath(dir, sizeof dir, "bxroot-shm-fork-gate-XXXXXX")) return 1;
    pthread_t th; struct worker_arg a = {77, 0, -1, 1, -1};
    long x0 = 0; int anchor, st; pid_t child; unsigned long addr;
    if (!mkdtemp(dir) || bxroot_sysvshm_init(dir) != 0) FAIL("init");
    anchor = bxroot_sysvshm_anchor_fd();
    if (anchor < 0 || make_seg(anchor, 77) != 0) FAIL("segment");
    if (pthread_create(&th, NULL, worker, &a) != 0) FAIL("thread mmap");
    wait_window(1);
    if (bxroot_sysvshm_fork_begin() != -EAGAIN) FAIL("mmap gate");
    release_window(1);
    if (pthread_join(th, NULL) != 0 || a.result != 1 || a.addr <= 4096) FAIL("mmap worker");
    addr = a.addr;

    a.op = 2; a.result = -1; a.addr = addr; gate_phase = gate_release = 0;
    __atomic_store_n(&gate_armed,1,__ATOMIC_RELEASE);
    if (pthread_create(&th, NULL, worker, &a) != 0) FAIL("thread dt");
    wait_window(2);
    if (bxroot_sysvshm_fork_begin() != -EAGAIN) FAIL("dt gate");
    release_window(2);
    if (pthread_join(th, NULL) != 0 || a.result != 1 || a.syscall_return != 0) FAIL("dt worker");
    a.addr=0; a.result=-1; a.op=1;
    if (bxroot_sysvshm_emulate(SHM_NR_AT,77,0,0,(long *)&a.addr)!=1 || a.addr<=4096) FAIL("post-window attach");
    addr=a.addr;

    if (bxroot_sysvshm_fork_begin() != 0) FAIL("fork begin");
    child = fork();
    bxroot_sysvshm_fork_end();
    if (child < 0) FAIL("fork");
    if (child == 0) {
        long r = -1;
        bxroot_sysvshm_fork_end();
        if (bxroot_sysvshm_emulate(SHM_NR_DT, addr, 0, 0, &r) != 1 || r != 0) {
            fprintf(stderr,"child dt result=%ld\n",r); _exit(1);
        }
        bxroot_sysvshm_fork_end(); _exit(0);
    }
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st) != 0) FAIL("child detach");
    if (bxroot_sysvshm_emulate(SHM_NR_DT, addr, 0, 0, &x0) != 1) FAIL("parent detach");
    {
        char name[64]; snprintf(name, sizeof name, "seg-%ld", 77L);
        unlinkat(anchor, name, 0); close(anchor); rmdir(dir);
    }
    puts("SHM_FORK_GATE_PASS"); return 0;
}
