/*
 * probe_execveat.c —— execve/execveat/fexecve 各形态（RUN_EXEC_DIAG.sh 用）
 * 每项在子进程里 exec /usr/bin/echo hi，经管道收输出；成功打 OK out=…，
 * 失败打 FAIL errno=…。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
extern char**environ;
#define T(name, call) do{ int pp[2]; pipe(pp); if(fork()==0){ close(pp[0]); dup2(pp[1],1); errno=0; call; dprintf(2,"%-44s FAIL errno=%d %s\n",name,errno,strerror(errno)); _exit(99);} close(pp[1]); char b[256]={0}; int n=read(pp[0],b,255); close(pp[0]); int st; wait(&st); if(WIFEXITED(st)&&WEXITSTATUS(st)==0) printf("%-44s OK out=%.*s",name,n>0?n:0,b); }while(0)
int main(void){ setvbuf(stdout,0,_IONBF,0); char *a[]={"echo","hi",0}; char *s[]={"s.sh",0};
 int fd=open("/usr/bin/echo",O_RDONLY|O_CLOEXEC); int dfd=open("/usr/bin",O_RDONLY|O_DIRECTORY);
 FILE*f=fopen("/tmp/xs.sh","w"); fprintf(f,"#!/bin/sh\necho script:$0\n"); fclose(f); chmod("/tmp/xs.sh",0755); int sfd=open("/tmp/xs.sh",O_RDONLY);
 symlink("/usr/bin/echo","/tmp/xlnk");
 T("execve(/usr/bin/echo)", execve("/usr/bin/echo",a,environ));
 T("execveat(AT_FDCWD,/usr/bin/echo,0)", execveat(AT_FDCWD,"/usr/bin/echo",a,environ,0));
 T("execveat(dirfd(/usr/bin),\"echo\",0)", execveat(dfd,"echo",a,environ,0));
 T("execveat(fd,\"\",AT_EMPTY_PATH)", execveat(fd,"",a,environ,AT_EMPTY_PATH));
 T("fexecve(fd)", fexecve(fd,a,environ));
 T("fexecve(script fd)", fexecve(sfd,s,environ));
 T("execveat(link,NOFOLLOW) 期望ELOOP", execveat(AT_FDCWD,"/tmp/xlnk",a,environ,AT_SYMLINK_NOFOLLOW));
 T("execveat(AT_FDCWD,\"/nonexist\",0) 期望ENOENT", execveat(AT_FDCWD,"/nonexist",a,environ,0));
 T("fexecve(-1) 期望EBADF", fexecve(-1,a,environ));
 unlink("/tmp/xs.sh"); unlink("/tmp/xlnk"); return 0; }
