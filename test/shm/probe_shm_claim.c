#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include "../../src/runtime/sysvshm.c"
static int test_anchor = -1;
static char test_dir[128];
static void cleanup_fixture(void) {
    char buf[2048];
    long dfd, n;
    if (test_anchor < 0) return;
    dfd=shm_svc6(NR_OPENAT,test_anchor,(long)".",K_O_DIRECTORY|K_O_CLOEXEC|K_O_NOFOLLOW,0,0,0);
    if(dfd>=0) {
        while((n=SVC(NR_GETDENTS64,dfd,buf,sizeof buf))>0) {
            long off=0;
            while(off+19<=n) {
                unsigned short len=*(unsigned short *)(buf+off+16);
                if(len<19 || off+len>n) break;
                const char *name=buf+off+19;
                if(name[0] && !(name[0]=='.' && (name[1]=='\0' || (name[1]=='.' && name[2]=='\0')))) {
                    if(SVC(NR_UNLINKAT,test_anchor,(long)name,AT_REMOVEDIR)<0)
                        SVC(NR_UNLINKAT,test_anchor,(long)name,0);
                }
                off+=len;
            }
        }
        SVC(NR_CLOSE,dfd,0,0);
    }
    SVC(NR_CLOSE,test_anchor,0,0); test_anchor=-1;
    if(test_dir[0]) rmdir(test_dir);
}
#if BXROOT_SHM_CLAIM_VERIFIED
static int check(int ok, const char *s) { if (!ok) fprintf(stderr,"FAIL %s errno=%d\n",s,errno); return ok ? 0 : 1; }
#endif
int main(void) {
    char d[]="/tmp/bxclaim-XXXXXX";
#if !BXROOT_SHM_CLAIM_VERIFIED
    if(!mkdtemp(d) || bxroot_sysvshm_init(d)!=0) return 1;
    snprintf(test_dir,sizeof test_dir,"%s",d); test_anchor=bxroot_sysvshm_anchor_fd();
    if(test_anchor<0 || atexit(cleanup_fixture)!=0) return 1;
    long got=shm_do_get(12345,4096,K_IPC_CREAT);
    if(got!=-38) { fprintf(stderr,"FAIL gate expected ENOSYS got=%ld\n",got); return 1; }
    got=shm_do_get(K_IPC_PRIVATE,4096,K_IPC_CREAT);
    if(got!=-38) { fprintf(stderr,"FAIL private must be gated got=%ld\n",got); return 1; }
    DIR *listing=fdopendir(openat(test_anchor,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC));
    if(!listing) return 1;
    struct dirent *entry;
    while((entry=readdir(listing))!=NULL) {
        if(strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) {
            fprintf(stderr,"FAIL disabled gate created %s\n",entry->d_name);
            closedir(listing);return 1;
        }
    }
    if(closedir(listing)) return 1;
    puts("SHM_CLAIM_GATE_CLOSED_PASS"); return 0;
#else
    long id, again, r; int p[2], st; pid_t c;
    if(!mkdtemp(d) || bxroot_sysvshm_init(d)!=0) return 1;
    snprintf(test_dir,sizeof test_dir,"%s",d); test_anchor=bxroot_sysvshm_anchor_fd();
    if(test_anchor<0 || atexit(cleanup_fixture)!=0) return 1;
    if (shm_parse_key_name("-2147483648", 11, &id) != 0 || id != (-2147483648L)) {
        fprintf(stderr, "FAIL INT_MIN key parse\n"); return 1;
    }
    long min_id=shm_do_get(-2147483648L,4096,K_IPC_CREAT|K_IPC_EXCL);
    if(check(min_id>0,"INT_MIN create")) return 1;
    if(check(shm_do_ctl(min_id,K_IPC_RMID,0)==0,"INT_MIN RMID")) return 1;
    struct stat min_st;
    errno=0;
    if(check(fstatat(test_anchor,"key--2147483648",&min_st,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT,"INT_MIN key removed")) return 1;
    if (shm_do_get(12340, -1, K_IPC_CREAT) != -22) {
        fprintf(stderr, "FAIL negative size\n"); return 1;
    }
    {
        int fd = -1; unsigned long old_pagesize = g_shm_pagesize;
        long rounded_id;
        g_shm_pagesize = 16384;
        rounded_id = shm_new_segment(4097, &fd);
        if (rounded_id <= 0 || fd < 0) { fprintf(stderr, "FAIL 16K allocation\n"); return 1; }
        struct stat rounded_st;
        if (shm_svc6(NR_FSTAT, fd, (long)&rounded_st, 0, 0, 0, 0) < 0 || rounded_st.st_size != 4097) {
            fprintf(stderr, "FAIL exact segment size=%ld\n", (long)rounded_st.st_size); return 1;
        }
        long mapped=shm_do_at(rounded_id,0);
        if(mapped<0 && mapped>-4096) return 1;
        unsigned long mapping_len=0;
        int slot=shm_att_take((unsigned long)mapped,&mapping_len);
        if(slot<0 || mapping_len!=16384) {fprintf(stderr,"FAIL 16K mapping length=%lu\n",mapping_len);return 1;}
        if(SVC(NR_MUNMAP,mapped,mapping_len,0)<0)return 1;
        __atomic_store_n(&g_att[slot].ctrl,g_att[slot].ctrl & ~ATT_STATE_MASK,__ATOMIC_RELEASE);
        SVC(NR_CLOSE, fd, 0, 0);
        char rounded_path[64]; shm_path(rounded_path, "/seg-", rounded_id);
        SVC(NR_UNLINKAT, bxroot_sysvshm_anchor_fd(), rounded_path, 0);
        g_shm_pagesize = old_pagesize;
    }
    {
        long owner = shm_claim_key(0); int child, status;
        if (owner < 0) { fprintf(stderr, "FAIL inherited lock setup\n"); return 1; }
        child = fork();
        if (child < 0) return 1;
        if (child == 0) { shm_release_claim(owner, 0); _exit(0); }
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 1;
        owner = shm_claim_key(0);
        if (owner < 0) { fprintf(stderr, "FAIL inherited child release\n"); return 1; }
        shm_release_claim(owner, 0);
    }
    id=shm_do_get(12345,4096,K_IPC_CREAT|K_IPC_EXCL); if(check(id>0,"create")) return 1;
    again=shm_do_get(12345,4096,K_IPC_CREAT); if(check(again==id,"reuse")) return 1;
    if(pipe(p)) return 1;
    c=fork(); if(c<0)return 1;
    if(c==0){ long lock=shm_claim_key(0); char x='L'; close(p[0]); if(lock<0)_exit(2); if(write(p[1],&x,1)!=1)_exit(4); pause(); _exit(3); }
    close(p[1]); { char x; if(read(p[0],&x,1)!=1)return 1; }
    r=shm_do_get(12346,4096,K_IPC_CREAT);
    if(check(r==-ERR_AGAIN,"concurrent creator is nonwaiting"))return 1;
    r=shm_do_ctl(id,K_IPC_RMID,0);
    if(check(r==-ERR_AGAIN,"concurrent RMID is nonwaiting"))return 1;
    r=shm_open_seg(id,1); if(check(r>=0,"busy RMID leaves segment intact"))return 1; SVC(NR_CLOSE,r,0,0);
    kill(c,SIGKILL); if(waitpid(c,&st,0)!=c || !WIFSIGNALED(st))return 1;
    r=shm_claim_key(0); if(check(r>=0,"sigkill releases lock"))return 1; shm_release_claim(r,0);
    r=shm_do_get(12346,4096,K_IPC_CREAT|K_IPC_EXCL);
    if(check(r>0,"retry after owner crash"))return 1;
    long second=r;
    if(check(mkdirat(bxroot_sysvshm_anchor_fd(),"key-12347",0700)==0,"prepare publish fault"))return 1;
    r=shm_do_get(12347,4096,K_IPC_CREAT|K_IPC_EXCL);
    if(check(r==-22,"bad key record rejected"))return 1;
    { long lock=shm_claim_key(12347); if(check(lock>=0,"publish error released lock"))return 1; shm_release_claim(lock,12347); }
    r=shm_do_ctl(id,K_IPC_RMID,0); if(check(r==0,"rmid original"))return 1;
    r=shm_do_ctl(second,K_IPC_RMID,0); if(check(r==0,"rmid recreated"))return 1;
    if(shm_read_key(12345)>0 || shm_read_key(12346)>0)return 1;
    SVC(NR_UNLINKAT,bxroot_sysvshm_anchor_fd(),"key-12347",AT_REMOVEDIR);
    int anchor = bxroot_sysvshm_anchor_fd();
    if(check(mkdirat(anchor,"seg-77",0700)==0,"prepare nonregular segment"))return 1;
    if(check(shm_publish_key(12348,77)==0,"prepare key to abnormal segment"))return 1;
    r=shm_do_get(12348,4096,K_IPC_CREAT);
    if(check(r<0 && shm_read_key(12348)==77,"abnormal segment error preserves key"))return 1;
    SVC(NR_UNLINKAT,anchor,"seg-77",AT_REMOVEDIR); SVC(NR_UNLINKAT,anchor,"key-12348",0);
    if(check(mkdirat(anchor,"seg-88",0700)==0,"prepare undeletable segment type"))return 1;
    r=shm_do_ctl(88,K_IPC_RMID,0);
    if(check(r<0,"RMID delete failure is not success"))return 1;
    { long lock=shm_claim_key(0); if(check(lock>=0,"RMID failure releases lock"))return 1; shm_release_claim(lock,0); }
    SVC(NR_UNLINKAT,anchor,"seg-88",AT_REMOVEDIR);
    puts("SHM_CLAIM_PASS"); return 0;
#endif
}
