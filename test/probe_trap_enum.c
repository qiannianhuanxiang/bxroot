/*
 * probe_trap_enum.c —— seccomp TRAP 全号枚举探针（RUN_TRAP_PARITY.sh 用）
 *
 * 对 [lo, hi] 每个号 fork 一个子进程，用无害参数（fd=-1、空指针）发一次
 * 裸 svc，打印 "nr 状态 x0"。
 *   无 NOH 环境变量：装一个只记录"是否收到 SIGSYS"的处理器 → 得到 TRAP 集合
 *   NOH=1         ：不装处理器 → 看当前 runtime 的 SIGSYS 层给出的返回值
 * 跳过表里是会伤害父进程、会挂起、或无意义的号（exit/kill/clone/sleep/…）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
/* 每个号 fork 一个子进程，装 SIGSYS 处理器（写 x0 = -ENOSYS 并记录），
 * 用无害参数（fd=-1、空指针）发一次裸 svc。输出: nr trapped ret */
static volatile int hit;
static void h(int s, siginfo_t *si, void *uc){ (void)s;(void)si;(void)uc; hit=1; }
static long raw(long nr){
  register long x8 __asm__("x8")=nr; register long x0 __asm__("x0")=-1;
  register long x1 __asm__("x1")=0, x2 __asm__("x2")=0, x3 __asm__("x3")=0, x4 __asm__("x4")=0, x5 __asm__("x5")=0;
  __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory");
  return x0; }
int main(int argc,char**argv){
  int lo=atoi(argv[1]), hi=atoi(argv[2]);
  /* 跳过会伤害父进程或挂住的号 */
  static const int skip[]={93,94,/*exit*/ 129,130,131,/*kill tkill tgkill*/ 220,435,/*clone*/ 101,115,/*nanosleep clock_nanosleep*/ 98,/*futex*/ 
    142,/*reboot*/ 139,/*rt_sigreturn*/ 72,73,22,/*pselect ppoll epoll_pwait*/ 241,/*perf*/ 260,/*wait4*/ 95,/*waitid*/ 81,/*sync*/ 267,/*syncfs*/ 215,/*munmap*/ 226,/*mprotect*/ 216,/*mremap*/ 233,/*madvise*/ 280,/*bpf*/ 441,/*epoll_pwait2*/ 449, -1};
  for(int nr=lo; nr<=hi; nr++){
    int sk=0; for(int i=0;skip[i]!=-1;i++) if(skip[i]==nr) sk=1;
    if(sk){ printf("%d skip\n",nr); continue; }
    pid_t p=fork();
    if(p==0){ struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO; if(!getenv("NOH")) sigaction(SIGSYS,&sa,0);
      alarm(2); long r=raw(nr); printf("%d %s %ld\n",nr,hit?"TRAP":"ok",r); fflush(stdout); _exit(0); }
    int st; waitpid(p,&st,0);
    if(!WIFEXITED(st)) printf("%d died sig=%d\n",nr,WIFSIGNALED(st)?WTERMSIG(st):-1);
    fflush(stdout);
  }
  return 0; }
