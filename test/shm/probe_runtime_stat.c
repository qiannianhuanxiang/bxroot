#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../src/runtime/sysvshm.c"
#include "../bx_tmpdir.h"

static int one(int which, long id)
{
    long page=sysconf(_SC_PAGESIZE);
    struct shmid_ds normal;
    unsigned char *p=mmap(NULL,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    void *dst=&normal;
    if(p==MAP_FAILED)return 1;
    memset(&normal,0xa5,sizeof normal);
    switch(which){
    case 1:dst=NULL;break;
    case 2:dst=(void *)1;break;
    case 3:dst=p;if(mprotect(p,(size_t)page,PROT_READ))return 1;break;
    case 4:dst=p;if(mprotect(p,(size_t)page,PROT_NONE))return 1;break;
    case 5:dst=p+page-sizeof normal/2;if(mprotect(p+page,(size_t)page,PROT_NONE))return 1;break;
    case 6:dst=p;if(munmap(p,(size_t)page))return 1;break;
    case 7:dst=(void *)(UINTPTR_MAX-sizeof normal/2);break;
    }
    /* Exercise the actual runtime operation, not just the copyout helper. */
    long r=shm_do_ctl(id,K_IPC_STAT,(unsigned long)dst);
    long expected;
#if BXROOT_SHM_COPYOUT_VERIFIED
    expected=which==0?0:-EFAULT;
#else
    expected=(which==1||which==7)?-EFAULT:-ENOSYS;
#endif
    int ok=r==expected;
    if(which==0){
#if BXROOT_SHM_COPYOUT_VERIFIED
        ok=ok&&normal.shm_segsz==4096&&normal.shm_perm.mode==0600;
#else
        unsigned char before[sizeof normal];memset(before,0xa5,sizeof before);
        ok=ok&&memcmp(&normal,before,sizeof normal)==0;
#endif
    }
    printf("RUNTIME_STAT case=%d result=%ld expected=%ld ok=%d\n",which,r,expected,ok);
    fflush(stdout);
    return ok?0:1;
}
int main(void)
{
    char dir[PATH_MAX]; if(bx_tmppath(dir,sizeof dir,"bxroot-runtime-stat-XXXXXX"))return 1;
    if(!mkdtemp(dir)||bxroot_sysvshm_init(dir))return 1;
    /* Fixture setup is deliberately separate from shmget/RMID capability. */
    const long id=77;
    int anchor=bxroot_sysvshm_anchor_fd();
    int fixture=openat(anchor,"seg-77",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
    if(fixture<0 || ftruncate(fixture,4096)!=0) return 1;
    if(close(fixture)!=0) return 1;
    int failed=0;
    for(int i=0;i<8;i++){
        fflush(NULL);pid_t child=fork();
        if(child<0){failed=1;break;}
        if(child==0)_exit(one(i,id));
        int st;pid_t w;do{w=waitpid(child,&st,0);}while(w<0&&errno==EINTR);
        if(w!=child||!WIFEXITED(st)||WEXITSTATUS(st)!=0)failed=1;
    }
    /* Clean only the private segment we created; no lock protocol required. */
    char name[64];snprintf(name,sizeof name,"seg-%ld",id);
    anchor=bxroot_sysvshm_anchor_fd();
    if(unlinkat(anchor,name,0)||close(anchor)||rmdir(dir))failed=1;
    if(!failed)puts("RUNTIME_IPC_STAT_PASS");
    return failed?1:0;
}
