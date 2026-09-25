/* koxs <mode> <pidfile>：fork 2 个子进程（第 2 个再 fork 一个孙进程，且孙进程
 * setsid 脱离），把**全部 3 个 pid** 写进 pidfile，然后按 mode 退出。 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
int main(int c,char**v){ int fd=open(v[2],O_WRONLY|O_CREAT|O_TRUNC|O_APPEND,0600); if(fd<0) return 9;
 for(int i=0;i<2;i++){ pid_t p=fork(); if(p==0){ if(i==1){ pid_t g=fork(); if(g==0){ setsid(); dprintf(fd,"%d\n",getpid()); for(;;) pause(); } } for(;;) pause(); } dprintf(fd,"%d\n",p);} usleep(300000);
 if(!strcmp(v[1],"exit")) exit(7);
 if(!strcmp(v[1],"_exit")) _exit(7);
 if(!strcmp(v[1],"exit_group")) syscall(SYS_exit_group,7);
 if(!strcmp(v[1],"segv")) *(volatile int*)0=1;
 if(!strcmp(v[1],"kill9")) kill(getpid(),SIGKILL);
 if(!strcmp(v[1],"abort")) abort();
 return 3; }
