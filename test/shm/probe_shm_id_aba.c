#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static unsigned int candidates[2];
static int calls, transition;
static long fixed_random(void *buf, size_t len) {
    if (len != sizeof(unsigned int)) return -22;
    unsigned int r = candidates[(transition && calls > 0) ? 1 : 0];
    memcpy(buf, &r, len); calls++; return (long)len;
}
/* Runner changes only the allocator's getrandom expression in a private copy. */
#include "sysvshm-id-test.c"
#include "../bx_tmpdir.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line=%d %s\n",__LINE__,#x); return 1; } } while (0)
static void sequence(unsigned int first, unsigned int second, int change) {
    candidates[0]=first;candidates[1]=second;transition=change;calls=0;
}
static long allocate(void) { int fd=-1; long id=shm_new_segment(4096,&fd); if(fd>=0)CHECK(close(fd)==0); return id; }
int main(void) {
    char dir[PATH_MAX], path[PATH_MAX+32]; if(bx_tmppath(dir,sizeof dir,"bxroot-id-aba-XXXXXX"))return 1;
    struct stat st;
    CHECK(mkdtemp(dir));CHECK(bxroot_sysvshm_init(dir)==0);
    int anchor=bxroot_sysvshm_anchor_fd();CHECK(anchor>=0);
    sequence(77,0,0);CHECK(allocate()==77);CHECK(calls==1);
    CHECK(fstatat(anchor,".id-77",&st,AT_SYMLINK_NOFOLLOW)==0);
    CHECK(S_ISREG(st.st_mode)&&st.st_size==0&&(st.st_mode&0777)==0400);
    CHECK(shm_do_ctl(77,K_IPC_RMID,0)==0);
    CHECK(fstatat(anchor,".id-77",&st,0)==0);
    sequence(77,0,0);CHECK(allocate()==-28);CHECK(calls==64);
    sequence(77,78,1);CHECK(allocate()==78);CHECK(calls==2);
    CHECK(shm_do_ctl(77,K_IPC_RMID,0)==0);
    int fd=(int)shm_open_seg(78,1);CHECK(fd>=0);CHECK(close(fd)==0);
    CHECK(shm_do_ctl(78,K_IPC_RMID,0)==0);
    /* Existing legacy segment must remain untouched; reserve candidate and skip. */
    fd=openat(anchor,"seg-79",O_CREAT|O_EXCL|O_RDWR,0600);CHECK(fd>=0);CHECK(write(fd,"old",3)==3);CHECK(close(fd)==0);
    sequence(79,80,1);CHECK(allocate()==80);CHECK(calls==2);
    CHECK(fstatat(anchor,"seg-79",&st,0)==0&&st.st_size==3);
    CHECK(fstatat(anchor,".id-79",&st,0)==0);
    CHECK(shm_do_ctl(79,K_IPC_RMID,0)==0);CHECK(shm_do_ctl(80,K_IPC_RMID,0)==0);
    sequence(79,0,0);CHECK(allocate()==-28&&calls==64);
    /* A foreign reservation's contents are not read, changed, or removed. */
    fd=openat(anchor,".id-81",O_CREAT|O_EXCL|O_RDWR,0600);CHECK(fd>=0);CHECK(write(fd,"foreign",7)==7);CHECK(close(fd)==0);
    sequence(81,82,1);CHECK(allocate()==82);CHECK(shm_do_ctl(82,K_IPC_RMID,0)==0);
    fd=openat(anchor,".id-81",O_RDONLY);CHECK(fd>=0);char b[8]={0};CHECK(read(fd,b,7)==7&&!strcmp(b,"foreign"));CHECK(close(fd)==0);
    /* Remove only this fixture's known tokens after the lifetime assertions. */
    for(int id=77;id<=82;id++){snprintf(path,sizeof path,".id-%d",id);CHECK(unlinkat(anchor,path,0)==0);}
    CHECK(unlinkat(anchor,CLAIM_LOCK_NAME,0)==0);CHECK(close(anchor)==0);CHECK(rmdir(dir)==0);
    puts("SHM_ID_ABA_PASS");return 0;
}
