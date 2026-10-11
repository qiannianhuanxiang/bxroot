#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "l2s-runtime.h"
/* Private fixture reproducing the exact A1 prerequisite: l2s clients and
 * intermediate files must remain observable as symlinks to injected FS ops. */
static int ls(const char *p, struct stat *s) { return lstat(p,s); }
static int sl(const char *a,const char *b) { return symlink(a,b); }
static int rn(const char *a,const char *b) { return rename(a,b); }
static int un(const char *p) { return unlink(p); }
static ssize_t rl(const char *p,char *b,size_t n) { return readlink(p,b,n); }
static int ac(const char *p,int m) { return access(p,m); }
static int rd(const char *p,char *b,size_t n,size_t *len) {
    int f=open(p,O_RDONLY); ssize_t r; if(f<0)return -errno;
    r=read(f,b,n-1); close(f); if(r<0)return -errno; b[r]=0; *len=(size_t)r; return 0;
}
static int wr(const char *p,const char *b,size_t n) {
    int f=open(p,O_WRONLY|O_CREAT|O_TRUNC,0600); ssize_t r;
    if(f<0)return -errno;
    r=write(f,b,n); close(f); return r==(ssize_t)n?0:-EIO;
}
int main(void) {
    char dir[]="/tmp/bxroot-l2s-baseline-XXXXXX",a[512],b[512],mid[4096],end[4096];
    struct stat st={0};
    l2s_rt_ops ops={ls,sl,rn,un,rl,ac,rd,wr};
    l2s_config cfg=L2S_CONFIG_DEFAULT;
    int r,lr,result;
    if(!mkdtemp(dir)){perror("mkdtemp");return 1;}
    snprintf(a,sizeof a,"%s/a.txt",dir); snprintf(b,sizeof b,"%s/b.txt",dir);
    cfg.l2s_dir=NULL; cfg.scheme=L2S_SCHEME_PROOT;
    l2s_rt_init(&ops,&cfg);
    if(wr(a,"fixture",7)){rmdir(dir);return 1;}
    r=l2s_rt_link(a,b); errno=0; lr=lstat(a,&st);
    printf("link=%d client_lstat=%d errno=%d mode=%o symlink=%d\n",r,lr,errno,(unsigned)st.st_mode,S_ISLNK(st.st_mode));
    result=r==0 && (lr!=0 || !S_ISLNK(st.st_mode)) ? 3 : r==0?0:1;
    puts(result==3?"L2S_INJECTED_FS_PREREQUISITE_NOT_NATIVE":result==0?"L2S_INJECTED_FS_PREREQUISITE_OK":"BASELINE_SETUP_FAIL");
    /* Explicit exact private filenames only; no recursive deletion. */
    if(l2s_make_paths_ex(&cfg,a,1,2,NULL,mid,end)==L2S_OK){
        char count[4200]; snprintf(count,sizeof count,"%s.cnt",end); unlink(count);
        unlink(a); unlink(b); unlink(mid); unlink(end);
    }
    unlink(a);unlink(b);rmdir(dir);
    return result;
}
