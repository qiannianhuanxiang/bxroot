#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
#include <dirent.h>
#include "../../src/runtime/static_exec.c"
#include "../../src/runtime/sysvshm.c"
_Static_assert(offsetof(ucontext_t,uc_mcontext.regs)==184,"AArch64 signal register ABI changed");
static long raw(long nr,long a,long b,long c){return shm_svc6(nr,a,b,c,0,0,0);}
static int frame_check(void) {
 siginfo_t info={0};ucontext_t uc={0};info.si_code=1;
 uc.uc_mcontext.regs[8]=194;uc.uc_mcontext.regs[0]=0;uc.uc_mcontext.regs[1]=4096;uc.uc_mcontext.regs[2]=0600;
 uc.uc_mcontext.regs[3]=0x12345;printf("FRAME ready=%d code=%d nr=%lu offset=%zu\n",g_shm_ready,info.si_code,(unsigned long)uc.uc_mcontext.regs[8],offsetof(ucontext_t,uc_mcontext.regs));sx_early_sigsys(SIGSYS,&info,&uc);
 long id=(long)uc.uc_mcontext.regs[0];
#if !BXROOT_SHM_CLAIM_VERIFIED
 if(id!=-38)return 1;
 puts("STATIC_SHM_FRAME_GATE_CLOSED_PASS");return 0;
#else
 if(id<=0||uc.uc_mcontext.regs[3]!=0x12345)return 1;
#endif
 struct shmid_ds ds;uc.uc_mcontext.regs[8]=195;uc.uc_mcontext.regs[0]=id;uc.uc_mcontext.regs[1]=2;uc.uc_mcontext.regs[2]=(unsigned long)&ds;
 sx_early_sigsys(SIGSYS,&info,&uc);
#if BXROOT_SHM_COPYOUT_VERIFIED
 if((long)uc.uc_mcontext.regs[0]!=0||ds.shm_segsz!=4096)return 1;
#else
 if((long)uc.uc_mcontext.regs[0]!=-38)return 1;
#endif
 char name[64];snprintf(name,sizeof name,"seg-%ld",id);if(unlinkat(bxroot_sysvshm_anchor_fd(),name,0))return 1;
 uc.uc_mcontext.regs[8]=99;uc.uc_mcontext.regs[0]=0x123;sx_early_sigsys(SIGSYS,&info,&uc);if((long)uc.uc_mcontext.regs[0]!=-38)return 1;
 info.si_code=SI_USER;uc.uc_mcontext.regs[0]=0x456;sx_early_sigsys(SIGSYS,&info,&uc);if(uc.uc_mcontext.regs[0]!=0x456)return 1;
 puts("STATIC_SHM_FRAME_PASS");return 0;
}
static int fork_window_check(void) {
#if BXROOT_SHM_CLAIM_VERIFIED
 long id=shm_do_get(0,4096,0600);if(id<0)return 1;
 long addr=shm_do_at(id,0);if(addr<0&&addr>-4096)return 1;
 int slot=-1;for(int i=0;i<SHM_MAX_ATT;i++)if(g_att[i].addr==(unsigned long)addr){slot=i;break;}
 if(slot<0)return 1;
 unsigned long active=g_att[slot].ctrl;
 for(unsigned long state=ATT_RESERVED;state<=ATT_DETACHING;state+=2){
  g_att[slot].ctrl=(active&~ATT_STATE_MASK)|state;pid_t child=fork();if(child<0)return 1;
  if(child==0){long r=shm_do_dt((unsigned long)addr);_exit(r==-ERR_INVAL?0:1);}
  int st;if(waitpid(child,&st,0)!=child||!WIFEXITED(st)||WEXITSTATUS(st))return 1;
 }
 g_att[slot].ctrl=active;
 if(shm_do_dt((unsigned long)addr)||shm_do_ctl(id,K_IPC_RMID,0))return 1;
 puts("ATTACH_FORK_TRANSITION_BOUNDARY_CONFIRMED");
#endif
 return 0;
}
static char fixture_dir[]="/tmp/bxroot-static-syscall-XXXXXX";
static int fixture_created;
static int cleanup_fixture(void) {
 if(!fixture_created)return 0;
 int anchor=bxroot_sysvshm_anchor_fd(),failed=0;
 if(anchor<0)return 1;
 int scan=openat(anchor,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 if(scan<0)return 1;
 DIR *listing=fdopendir(scan);
 if(!listing){close(scan);return 1;}
 struct dirent *e;
 errno=0;
 while((e=readdir(listing))!=NULL){
  if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
  if(unlinkat(anchor,e->d_name,0))failed=1;
  errno=0;
 }
 if(errno)failed=1;
 if(closedir(listing)||close(anchor))failed=1;
 if(rmdir(fixture_dir))failed=1;
 return failed;
}
static int run(void){
 long id=-1,r; struct shmid_ds ds;
 if(!mkdtemp(fixture_dir))return 1;
 fixture_created=1;
 if(bxroot_sysvshm_init(fixture_dir))return 1;
 if(frame_check()||fork_window_check())return 1;
 if(!sx_wants_site(194)||!sx_wants_site(197)||sx_wants_site(198))return 1;
 /* Actual static-exec reset must install early handler and retain anchor. */
 sx_reset_process_state();
 struct sock_filter f[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,194,0,2),BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K,197,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRAP),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
 struct sock_fprog p={sizeof f/sizeof f[0],f};
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p)){perror("filter");return 2;}
 id=raw(194,0,4096,0600);
 if(id<0){printf("TRAP_UNREACHED create=%ld; outer filter/ptracer prevents SHM trap dispatch\n",id);return 2;}
 r=raw(195,id,2,(long)&ds);
#if BXROOT_SHM_COPYOUT_VERIFIED
 if(r||ds.shm_segsz!=4096)return 1;
#else
 if(r!=-ENOSYS)return 1;
#endif
 long addr=raw(196,id,0,0);if(addr<0&&addr>-4096)return 1;
 ((char *)addr)[0]='S';if(raw(197,addr,0,0))return 1;
 r=raw(195,id,0,0);
#if BXROOT_SHM_CLAIM_VERIFIED
 if(r)return 1;
#else
 if(r!=-ENOSYS)return 1;
 char name[64];snprintf(name,sizeof name,"seg-%ld",id);if(unlinkat(bxroot_sysvshm_anchor_fd(),name,0))return 1;
#endif
 puts("STATIC_SHM_SYSCALL_PASS");return 0;
}
int main(void){pid_t p=fork();int st;if(p<0)return 1;if(!p){int rc=run();if(cleanup_fixture()){fprintf(stderr,"FAIL static SHM fixture cleanup\n");rc=1;}fflush(NULL);_exit(rc);}if(waitpid(p,&st,0)!=p||!WIFEXITED(st))return 1;return WEXITSTATUS(st);}
