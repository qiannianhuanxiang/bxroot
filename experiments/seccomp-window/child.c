#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
int main(int argc,char**argv){
  pid_t c=fork();
  if(c==0){ execv(argv[1],argv+1); fprintf(stderr,"execv failed: %s\n",strerror(errno)); _exit(127);}
  int st; waitpid(c,&st,0);
  printf("rc=%d sig=%d\n",WIFEXITED(st)?WEXITSTATUS(st):-1,WIFSIGNALED(st)?WTERMSIG(st):0);
}
