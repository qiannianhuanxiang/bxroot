#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/wait.h>
#define E(x) do{ errno=0; long _r=(long)(x); printf("%-44s = %ld errno=%d\n", #x, _r, errno);}while(0)
int main(void){ setvbuf(stdout,0,_IONBF,0);
 int a=shmget(IPC_PRIVATE,5000,0600|IPC_CREAT); printf("private id=%d\n",a);
 int b=shmget(IPC_PRIVATE,5000,0600); printf("private2 id=%d (distinct=%d)\n",b,a!=b);
 E(shmget(IPC_PRIVATE,0,0600));
 E(shmget(0x55,0,0600|IPC_CREAT));
 E(shmget(0x55,100,0600|IPC_CREAT));
 E(shmget(0x55,100,0600|IPC_CREAT|IPC_EXCL));
 E(shmget(0x55,99999,0600));
 E(shmget(0x56,100,0600));
 E(shmget(-5,100,0600|IPC_CREAT));
 E(shmat(999999,0,0));
 E(shmat(a,(void*)0x1234,0));
 char *p=shmat(a,0,0); printf("shmat page-aligned=%d\n",((long)p&4095)==0);
 struct shmid_ds ds; memset(&ds,0xAB,sizeof ds); E(shmctl(a,IPC_STAT,&ds));
 printf(" segsz=%zu nattch=%lu mode=%o key=%d uid=%d gid=%d cuid=%d cgid=%d cpid=%d lpid=%d atime=%ld ctime=%ld\n",(size_t)ds.shm_segsz,(unsigned long)ds.shm_nattch,ds.shm_perm.mode,ds.shm_perm.__key,ds.shm_perm.uid,ds.shm_perm.gid,ds.shm_perm.cuid,ds.shm_perm.cgid,ds.shm_cpid,ds.shm_lpid,(long)ds.shm_atime,(long)ds.shm_ctime);
 memset(p,'x',5000); printf("write beyond size to page end ok\n"); p[8191]=1;
 char *q=shmat(a,0,SHM_RDONLY); printf("second attach distinct=%d sees=%c\n",q!=p,q[0]);
 E(shmctl(a,IPC_RMID,0));
 printf("after RMID still mapped: %c\n",p[1]);
 E(shmget(IPC_PRIVATE,100,0));
 E(shmdt(p)); E(shmdt(p)); E(shmdt((void*)0x1000));
 E(shmctl(999999,IPC_STAT,&ds));
 E(shmctl(b,IPC_SET,&ds));
 E(shmctl(b,SHM_LOCK,0));
 E(shmctl(b,IPC_INFO,(void*)&ds));
 E(shmctl(b,SHM_STAT,&ds));
 E(shmctl(b,12345,&ds));
 E(shmctl(b,IPC_RMID,0));
 E(shmctl(b,IPC_RMID,0));
 E(shmctl(0x55,IPC_RMID,0));
 int k=shmget(0x55,100,0600); E(shmctl(k,IPC_RMID,0));
 E(shmget(0x55,100,0600));
 /* fork 继承 */
 int c=shmget(IPC_PRIVATE,4096,0600); char *r=shmat(c,0,0); r[0]='P';
 if(fork()==0){ r[0]='C'; _exit(0);} wait(0); printf("fork-inherit shared: %c\n",r[0]);
 shmdt(r); shmctl(c,IPC_RMID,0);
 E(shmget(IPC_PRIVATE,(size_t)1<<40,0600));
 return 0; }
