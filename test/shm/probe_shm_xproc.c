#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/shm.h>
int main(int argc,char**argv){ setvbuf(stdout,0,_IONBF,0); key_t k=0x6b0b;
 if(!strcmp(argv[1],"put")){ int id=shmget(k,4096,0600|IPC_CREAT); char*p=shmat(id,0,0); if(p==(void*)-1){printf("put fail errno=%d\n",errno);return 1;} strcpy(p,argv[2]); printf("put id=%d '%s'\n",id,p); return 0; }
 if(!strcmp(argv[1],"get")){ int id=shmget(k,0,0600); if(id<0){printf("get: no key errno=%d\n",errno);return 1;} char*p=shmat(id,0,SHM_RDONLY); printf("get id=%d '%s'\n",id,p==(void*)-1?"(attach fail)":p); return 0; }
 if(!strcmp(argv[1],"rm")){ int id=shmget(k,0,0600); printf("rm id=%d rc=%d\n",id,shmctl(id,IPC_RMID,0)); return 0; }
 return 2; }
