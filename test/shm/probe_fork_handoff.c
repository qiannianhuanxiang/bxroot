#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../src/runtime/shm-fork.h"
#include "../bx_tmpdir.h"

static int claim_fd=-1, child_seen, parent_seen, prepare_seen;
static void prepare(void) { prepare_seen++; /* no wait, no unlock */ }
static void parent(void) { parent_seen++; }
static void child(void) { child_seen++; if(claim_fd>=0){ close(claim_fd); claim_fd=-1; } }
static int lock_fd(int fd) {
    struct flock l={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0};
    return fcntl(fd,F_OFD_SETLK,&l);
}
int main(void) {
    char path[PATH_MAX]; if(bx_tmppath(path,sizeof path,"bxroot-fork-handoff-XXXXXX"))return 1;
    int a=mkstemp(path), b, st; pid_t p;
    if(a<0)return 1;
    if(lock_fd(a)!=0)return 1;
    b=open(path,O_RDWR|O_CLOEXEC); if(b<0)return 1;
    if(pthread_atfork(prepare,parent,child)!=0)return 1;
    claim_fd=a;
    p=fork(); if(p<0)return 1;
    if(p==0){
        struct flock l={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0};
        int r=fcntl(b,F_OFD_SETLK,&l);
        _exit(child_seen==1 && r==-1 && (errno==EAGAIN||errno==EACCES) ? 0:1);
    }
    if(waitpid(p,&st,0)!=p||!WIFEXITED(st)||WEXITSTATUS(st)!=0)return 1;
    if(prepare_seen!=1||parent_seen!=1||child_seen!=0)return 1;
    close(a); unlink(path);
    puts("FORK_HANDOFF_ORDER_PASS"); return 0;
}
