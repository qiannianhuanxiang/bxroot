#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/shm.h>
#include <sys/wait.h>
#define NP 16
static void *thr(void *a){ int id=*(int*)a; for(int i=0;i<200;i++){ char*p=shmat(id,0,0); if(p==(void*)-1){ printf("thr attach fail errno=%d\n",errno); return (void*)1;} __atomic_fetch_add((int*)p,1,__ATOMIC_SEQ_CST); if(shmdt(p)){ printf("thr dt fail\n"); return (void*)1;} } return 0; }
int main(void){ setvbuf(stdout,0,_IONBF,0); key_t k=0x7ace; int pfd[2]; pipe(pfd);
 shmctl(shmget(k,0,0600),IPC_RMID,0);
 for(int i=0;i<NP;i++) if(fork()==0){ char c; read(pfd[0],&c,1); int id=shmget(k,4096,0600|IPC_CREAT); write(1,"",0); printf("%d\n",id); _exit(0);}
 close(pfd[0]); for(int i=0;i<NP;i++) write(pfd[1],"g",1); for(int i=0;i<NP;i++) wait(0);
 int id=shmget(k,4096,0600); int *cnt=shmat(id,0,0); *cnt=0;
 pthread_t t[8]; for(int i=0;i<8;i++) pthread_create(&t[i],0,thr,&id); long bad=0; for(int i=0;i<8;i++){ void*r; pthread_join(t[i],&r); bad+=(long)r; }
 printf("counter=%d (expect 1600) bad=%ld\n",*cnt,bad);
 struct shmid_ds ds; shmctl(id,IPC_STAT,&ds); printf("nattch after threads=%lu (expect 1)\n",(unsigned long)ds.shm_nattch);
 shmdt(cnt); shmctl(id,IPC_RMID,0); return 0; }
