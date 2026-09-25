#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
static volatile int n_term=0, n_int=0;
static void h(int s){ if(s==SIGTERM) n_term++; else n_int++; }
int main(int c,char**v){ setvbuf(stdout,0,_IONBF,0); signal(SIGTERM,h); signal(SIGINT,h);
 printf("guest pid=%d ppid=%d\n",getpid(),getppid());
 for(int i=0;i<30 && !(n_term&&n_int);i++) usleep(100000);
 printf("TERM=%d INT=%d\n",n_term,n_int); return n_term*10+n_int; }
