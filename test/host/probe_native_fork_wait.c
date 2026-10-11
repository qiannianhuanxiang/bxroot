#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include "proc.h"
#pragma weak px_runtime_ledger
#pragma weak px_ledger_get
extern px_ledger *px_runtime_ledger(void);
extern int px_ledger_get(const px_ledger *, pid_t, px_entry_kind, px_procinfo *);
extern int bxroot_sysvshm_fork_begin(void) __attribute__((weak));
extern void bxroot_sysvshm_fork_end(void) __attribute__((weak));
int main(void) {
    if (!px_runtime_ledger || !px_ledger_get) {puts("NO_RUNTIME_LEDGER");return 2;}
    px_ledger *ledger=px_runtime_ledger();
    if(!ledger) {puts("NO_INITIALIZED_LEDGER");return 1;}
    if (!bxroot_sysvshm_fork_begin || !bxroot_sysvshm_fork_end) return 1;
    if (bxroot_sysvshm_fork_begin()!=0) return 1;
    errno=0;
    pid_t rejected=fork();
    int rejected_errno=errno;
    if(rejected==0)_exit(99);
    bxroot_sysvshm_fork_end();
    if(rejected>0){int st;waitpid(rejected,&st,0);return 1;}
    if(rejected!=-1 || rejected_errno!=EAGAIN)return 1;
    puts("AUTO_FORK_BUSY_GATE_EAGAIN");
    pid_t child=fork();
    if(child<0){perror("fork");return 1;}
    if(child==0){
        int ready=bxroot_sysvshm_fork_begin();
        if(ready==0)bxroot_sysvshm_fork_end();
        _exit(ready==0?73:74);
    }
    if(bxroot_sysvshm_fork_begin()!=0)return 1;
    bxroot_sysvshm_fork_end();
    px_procinfo before={0},after={0};
    int found=px_ledger_get(ledger,child,PX_ENTRY_PID,&before);
    int status=0; pid_t waited;
    do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    int reaped=px_ledger_get(ledger,child,PX_ENTRY_PID,&after);
    printf("AUTO_FORK registered=%d live=%d tag=%u\n",found==PX_OK,found==PX_OK&&before.life==PX_LIVE,before.tag);
    printf("AUTO_WAIT waited=%d status=%d reaped=%d\n",waited==child,WIFEXITED(status)?WEXITSTATUS(status):-1,reaped==PX_OK&&after.life==PX_REAPED);
    if(found!=PX_OK||before.life!=PX_LIVE||before.tag!=PX_TAG_FORK||waited!=child||!WIFEXITED(status)||WEXITSTATUS(status)!=73||reaped!=PX_OK||after.life!=PX_REAPED)return 1;
    puts("NATIVE_CHAIN_FORK_WAIT_PASS");return 0;
}
