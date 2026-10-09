/* V3 session wire/fd/path integration regression. SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "session.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef ENOTUNIQ
#define ENOTUNIQ 76
#endif
static unsigned checks, failures, skipped;
static int outer_proc_dup;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++; fprintf(stderr,"FAIL: "); fprintf(stderr,__VA_ARGS__); fprintf(stderr," [errno=%d]\n",errno); } } while (0)
#define SKIP(...) do { skipped++; fprintf(stderr,"SKIP: "); fprintf(stderr,__VA_ARGS__); fputc('\n',stderr); } while (0)
static long diagnostic_raw(long nr,long a,long b,long c,long d,long e,long f)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8")=nr;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    if(x0<0 && x0>=-4095){errno=(int)-x0;return -1;}return x0;
#else
    return syscall(nr,a,b,c,d,e,f);
#endif
}
static void independent_proc_diagnostic(void)
{
    int fd=(int)diagnostic_raw(SYS_memfd_create,(long)"independent-proc-open",3,0,0,0,0);
    CHECK(fd>=0,"independent raw memfd diagnostic created");
    if(fd<0)return;
    CHECK(diagnostic_raw(SYS_write,fd,(long)"fixture",7,0,0,0)==7,"independent raw memfd written");
    CHECK(diagnostic_raw(SYS_fcntl,fd,F_ADD_SEALS,15,0,0,0)==0,"independent raw memfd sealed");
    char p[96];
    snprintf(p,sizeof(p),"/proc/%ld/fd/%d",diagnostic_raw(SYS_getpid,0,0,0,0,0,0),fd);
    int ro=(int)diagnostic_raw(SYS_openat,AT_FDCWD,(long)p,O_RDONLY,0,0,0);
    CHECK(ro>=0,"independent raw proc O_RDONLY open");
    if(ro>=0){
        long flags=diagnostic_raw(SYS_fcntl,ro,F_GETFL,0,0,0,0);
        long seals=diagnostic_raw(SYS_fcntl,ro,F_GET_SEALS,0,0,0,0);
        errno=0;long w=diagnostic_raw(SYS_write,ro,(long)"x",1,0,0,0);int we=errno;
        CHECK((seals&15)==15,"independent readonly reopen retains immutable seals");
        outer_proc_dup=(flags&O_ACCMODE)==O_RDWR && (seals&15)==15 && w<0 && we==EPERM;
        CHECK(((flags&O_ACCMODE)==O_RDONLY && w<0 && we==EBADF) || outer_proc_dup,"independent raw proc reopen classified flags=%ld seals=%ld write=%ld errno=%d",flags,seals,w,we);
        fprintf(stderr,"DIAG: independent raw proc O_RDONLY open flags=%ld seals=%ld write_errno=%d outer_proc_dup=%d\n",flags,seals,we,outer_proc_dup);
        diagnostic_raw(SYS_close,ro,0,0,0,0,0);
    }
    diagnostic_raw(SYS_close,fd,0,0,0,0,0);
}
static char fixture[BX_SESSION_PATH];
static void path(char *out, size_t cap, const char *suffix)
{
    int n=snprintf(out,cap,"%s/%s",fixture,suffix);
    if(n<0 || (size_t)n>=cap) { fprintf(stderr,"fixture path too long\n"); exit(2); }
}
static void directory(const char *suffix)
{
    char p[BX_SESSION_PATH]; path(p,sizeof(p),suffix);
    if(mkdir(p,0700)<0 && errno!=EEXIST) {perror(p);exit(2);}
}
static void file(const char *suffix)
{
    char p[BX_SESSION_PATH];int fd;path(p,sizeof(p),suffix);
    fd=open(p,O_WRONLY|O_CREAT|O_TRUNC,0600);
    if(fd<0 || write(fd,"session-fixture\n",16)!=16) {perror("fixture");exit(2);}
    close(fd);
}
static void link_at(const char *suffix,const char *target)
{
    char p[BX_SESSION_PATH];path(p,sizeof(p),suffix);
    if(symlink(target,p)<0){perror("symlink");exit(2);}
}
static void basic(bx_session *s)
{
    char p[BX_SESSION_PATH];bx_session_init(s);path(p,sizeof(p),"root");
    CHECK(bx_session_set(s,"BXROOT_ROOTFS",p)==0,"rootfs set");
    CHECK(bx_session_set(s,"GUEST_PATH","/usr/bin:/bin")==0,"guest PATH set");
    CHECK(bx_session_set(s,"GUEST_HOME","/root")==0,"guest HOME set");
    CHECK(bx_session_set(s,"GUEST_TMPDIR","/tmp")==0,"guest TMPDIR set");
}
static void expect_host(const bx_session *s,const char *g,const char *cwd,const char *suffix)
{
    char got[BX_SESSION_PATH],want[BX_SESSION_PATH];path(want,sizeof(want),suffix);
    int rc=bx_session_to_host(s,g,cwd,got,sizeof(got));
    CHECK(rc==0 && !strcmp(got,want),"to-host %s (%s): rc=%d got=%s want=%s",g,cwd?cwd:"NULL",rc,rc?"<error>":got,want);
}
static void expect_guest(const bx_session *s,const char *suffix,const char *want)
{
    char h[BX_SESSION_PATH],got[BX_SESSION_PATH];path(h,sizeof(h),suffix);
    int rc=bx_session_to_guest(s,h,got,sizeof(got));
    CHECK(rc==0 && !strcmp(got,want),"to-guest %s: rc=%d got=%s want=%s",suffix,rc,rc?"<error>":got,want);
}
static void test_mapping(void)
{
    bx_session s;char host[BX_SESSION_PATH],got[BX_SESSION_PATH];basic(&s);
    expect_host(&s,"/",NULL,"root");
    expect_host(&s,"/usr/bin/test",NULL,"root/usr/bin/test");
    expect_host(&s,"./test","/usr/bin","root/usr/bin/test");
    expect_host(&s,"../bin/test","/usr/share","root/usr/bin/test");
    expect_host(&s,"../../../../usr/bin/test","/root","root/usr/bin/test");
    expect_host(&s,"//usr///bin/./test",NULL,"root/usr/bin/test");
    expect_host(&s,"/bin/test",NULL,"root/usr/bin/test");
    expect_host(&s,"/bin/../share/new-output",NULL,"root/usr/share/new-output");
    expect_host(&s,"/absolute-link",NULL,"root/usr/bin/test");
    expect_host(&s,"/relative-link",NULL,"root/usr/bin/test");
    expect_host(&s,"/space 目录/new file",NULL,"root/space 目录/new file");
    errno=0;CHECK(bx_session_to_host(&s,"/tmp/new/directory/file",NULL,got,sizeof(got))<0 && errno==ENOENT,"missing output ancestor rejected");
    errno=0;CHECK(bx_session_to_host(&s,"/usr/bin/test/../next",NULL,got,sizeof(got))<0 && errno==ENOTDIR,"regular file before dotdot is not directory");
    errno=0;CHECK(bx_session_to_host(&s,"/usr/bin/test/",NULL,got,sizeof(got))<0 && errno==ENOTDIR,"regular file with trailing slash ENOTDIR");
    errno=0;CHECK(bx_session_to_host(&s,"/tmp/missing-leaf/",NULL,got,sizeof(got))<0 && errno==ENOENT,"missing leaf with trailing slash ENOENT");
    errno=0;CHECK(bx_session_to_host(&s,"/loop-a",NULL,got,sizeof(got))<0 && errno==ELOOP,"guest symlink cycle ELOOP");
    errno=0;CHECK(bx_session_to_host(&s,"",NULL,got,sizeof(got))<0 && errno==ENOENT,"empty path ENOENT");
    errno=0;CHECK(bx_session_to_host(&s,"relative",NULL,got,sizeof(got))<0,"relative path needs cwd");
    errno=0;CHECK(bx_session_to_host(&s,"/",NULL,got,1)<0 && errno==ENAMETOOLONG,"short host output fails");
    errno=0;CHECK(bx_session_to_host(&s,"/",NULL,NULL,0)<0 && errno==ENAMETOOLONG,"zero host output fails without write");
    CHECK(bx_session_to_host(&s,"/proc/self/fd/123",NULL,got,sizeof(got))==0 && !strcmp(got,"/proc/self/fd/123"),"proc magic handle preserved");
    expect_guest(&s,"root/usr/bin/test","/usr/bin/test");
    expect_guest(&s,"root/tmp/new-output","/tmp/new-output");
    path(host,sizeof(host),"shared");CHECK(bx_session_add_bind(&s,host,"/workspace",1)==0,"readonly bind set");
    expect_host(&s,"/workspace/project/file",NULL,"shared/project/file");
    expect_host(&s,"../project/file","/workspace/other","shared/project/file");
    expect_guest(&s,"shared/project/file","/workspace/project/file");
    CHECK(s.binds[0].ro==1,"readonly flag remains explicit");
    path(host,sizeof(host),"nested");CHECK(bx_session_add_bind(&s,host,"/workspace/cache",0)==0,"nested bind set");
    expect_host(&s,"/workspace/cache/output",NULL,"nested/output");
    expect_guest(&s,"nested/output","/workspace/cache/output");
    /* The parent-bind backing path is shadowed and has no forward-valid alias. */
    path(host,sizeof(host),"shared/cache/output");errno=0;
    CHECK(bx_session_to_guest(&s,host,got,sizeof(got))<0 && errno==ENOENT,"shadowed parent-bind backing path rejected");
    path(host,sizeof(host),"root/workspace/project/file");errno=0;
    CHECK(bx_session_to_guest(&s,host,got,sizeof(got))<0 && errno==ENOENT,"bind-shadowed rootfs path rejected");
    path(host,sizeof(host),"shared");CHECK(bx_session_add_bind(&s,host,"/second-view",0)==0,"duplicate host bind set");
    path(host,sizeof(host),"shared/project/file");errno=0;
    CHECK(bx_session_to_guest(&s,host,got,sizeof(got))<0 && errno==ENOTUNIQ,"ambiguous host backing path ENOTUNIQ");
    expect_host(&s,"/second-view/project/file",NULL,"shared/project/file");
    /* Explicit bind takes priority over /dev passthrough. */
    path(host,sizeof(host),"nested");CHECK(bx_session_add_bind(&s,host,"/dev/test-v3",0)==0,"special-tree bind set");
    expect_host(&s,"/dev/test-v3/output",NULL,"nested/output");
    CHECK(bx_session_to_host(&s,"/sys/kernel",NULL,got,sizeof(got))==0 && !strcmp(got,"/sys/kernel"),"unbound sys passthrough");
    CHECK(bx_session_to_host(&s,"/dev/null",NULL,got,sizeof(got))==0 && !strcmp(got,"/dev/null"),"unbound dev passthrough");
    /* Runtime's target '/' bind matches the root itself, not all descendants. */
    bx_session_dispose(&s);basic(&s);path(host,sizeof(host),"shared");
    CHECK(bx_session_add_bind(&s,host,"/",0)==0,"root bind set");
    expect_host(&s,"/",NULL,"shared");
    expect_host(&s,"/project/file",NULL,"root/project/file");
    path(host,sizeof(host),"shared/project/file");errno=0;
    CHECK(bx_session_to_guest(&s,host,got,sizeof(got))<0 && errno==ENOENT,"root bind does not imply descendant aliases");
    bx_session_dispose(&s);
    /* Bind source is a physical host path. Do not collapse symlink/.. lexically. */
    basic(&s);path(host,sizeof(host),"root/host-jump/../output");
    CHECK(bx_session_add_bind(&s,host,"/physical",0)==0,"physical source bind set");
    expect_host(&s,"/physical/file",NULL,"root/host-jump/../output/file");
    CHECK(!strcmp(s.binds[0].host,host),"physical source retained before host lookup");
    expect_guest(&s,"nested/output/file","/physical/file");
    bx_session_dispose(&s);
    /* A source symlink denotes a host directory, not a guest absolute link. */
    basic(&s);path(host,sizeof(host),"host-directory-alias");
    CHECK(bx_session_add_bind(&s,host,"/physicalalias",0)==0,"direct source symlink bind set");
    expect_host(&s,"/physicalalias",NULL,"host-directory-alias");
    expect_host(&s,"/physicalalias/file",NULL,"host-directory-alias/file");
    CHECK(!strcmp(s.binds[0].host,host),"direct source symlink stored unchanged");
    expect_guest(&s,"nested/output","/physicalalias");
    expect_guest(&s,"nested/output/file","/physicalalias/file");
    expect_guest(&s,"host-directory-alias/file","/physicalalias/file");
    bx_session_dispose(&s);
    /* Sixteen explicit binds leave implicit shm mapping available independently. */
    basic(&s);
    for(size_t bi=0;bi<BX_SESSION_MAX_BINDS;bi++){
        char source[BX_SESSION_PATH],target[64];path(source,sizeof(source),"nested");
        snprintf(target,sizeof(target),"/many%zu",bi);
        CHECK(bx_session_add_bind(&s,source,target,(unsigned)(bi%2))==0,"full bind vector %zu",bi);
    }
    path(host,sizeof(host),"shm");CHECK(bx_session_set(&s,"_SHM_HOST",host)==0,"implicit shm backing field");
    CHECK(bx_session_set(&s,"_SHM_GUEST","/dev/shm")==0,"implicit shm guest field");
    CHECK(s.nb==BX_SESSION_MAX_BINDS,"implicit shm does not consume bind slot");
    expect_host(&s,"/dev/shm/output",NULL,"shm/output");
    expect_guest(&s,"shm/output","/dev/shm/output");
    bx_session_dispose(&s);
    basic(&s);path(host,sizeof(host),"shared");CHECK(bx_session_add_bind(&s,host,"/dev/shm",0)==0,"explicit shm bind set");
    path(host,sizeof(host),"shm");CHECK(bx_session_set(&s,"_SHM_HOST",host)==0,"unused implicit shm field");
    CHECK(bx_session_set(&s,"_SHM_GUEST","/dev/shm")==0,"unused implicit shm guest field");
    expect_host(&s,"/dev/shm/output",NULL,"shared/output");
    bx_session_dispose(&s);
}
static void test_api(void)
{
    bx_session s;char key[40],host[BX_SESSION_PATH];size_t i;basic(&s);
    CHECK(bx_session_set(&s,"EMPTY","")==0,"empty value accepted");
    CHECK(!strcmp(bx_session_get(&s,"EMPTY"),""),"empty value read");
    CHECK(bx_session_set(&s,"EMPTY","replaced")==0,"existing value replaced");
    CHECK(s.nkv==5 && !strcmp(bx_session_get(&s,"EMPTY"),"replaced"),"replacement doesn't grow key count");
    CHECK(bx_session_get(&s,"MISSING")==NULL,"missing value NULL");
    errno=0;CHECK(bx_session_set(&s,"INVALID=NAME","x")<0 && errno==EINVAL,"invalid key rejected");
    errno=0;CHECK(bx_session_set(&s,"","x")<0 && errno==EINVAL,"empty key rejected");
    errno=0;CHECK(bx_session_add_bind(&s,"relative","/a",0)<0 && errno==EINVAL,"relative bind source rejected");
    errno=0;CHECK(bx_session_add_bind(&s,"/a","relative",0)<0 && errno==EINVAL,"relative bind target rejected");
    errno=0;CHECK(bx_session_add_bind(&s,"/a","/a",2)<0 && errno==EINVAL,"invalid bind flag rejected");
    path(host,sizeof(host),"shared/../nested//");CHECK(bx_session_add_bind(&s,host,"/a/../b//",1)==0,"bind paths normalized");
    path(host,sizeof(host),"shared/../nested");CHECK(!strcmp(s.binds[0].host,host) && !strcmp(s.binds[0].guest,"/a/../b"),"bind physical syntax retained with trailing slashes trimmed");
    for(i=s.nkv;i<BX_SESSION_MAX_KV;i++){snprintf(key,sizeof(key),"KEY%zu",i);CHECK(bx_session_set(&s,key,"v")==0,"key %zu set",i);}
    errno=0;CHECK(bx_session_set(&s,"ONE_TOO_MANY","v")<0 && errno==E2BIG,"key count bound checked");
    CHECK(bx_session_set(&s,"EMPTY","still-replaceable")==0,"existing key replaceable at max count");
    char *big=malloc(131073);
    if(!big){perror("large value");exit(2);}
    memset(big,'v',131072);big[131072]=0;
    errno=0;CHECK(bx_session_set(&s,"EMPTY",big)<0 && errno==EINVAL,"oversized value rejected");
    big[131071]=0;
    CHECK(bx_session_set(&s,"EMPTY",big)==0,"largest supported value accepted");
    for(i=5;i<22;i++){snprintf(key,sizeof(key),"KEY%zu",i);CHECK(bx_session_set(&s,key,big)==0,"large key %zu replaced",i);}
    errno=0;CHECK(bx_session_create_fd(&s)<0 && errno==E2BIG,"total encoding budget enforced");
    free(big);
    for(i=s.nb;i<BX_SESSION_MAX_BINDS;i++){snprintf(key,sizeof(key),"/bind%zu",i);CHECK(bx_session_add_bind(&s,"/host",key,0)==0,"bind %zu set",i);}
    errno=0;CHECK(bx_session_add_bind(&s,"/host","/overflow",0)<0 && errno==E2BIG,"bind count bound checked");
    bx_session_dispose(&s);CHECK(!s.nkv && !s.nb,"dispose clears counts");
    CHECK(bx_session_fd_number("3")==3,"fd decimal accepted");
    CHECK(bx_session_fd_number("0009")==9,"fd leading zero accepted");
    CHECK(bx_session_fd_number("2147483647")==2147483647,"fd maximum representable accepted");
    const char *bad[]={NULL,"","-1","2","0","3x"," 3","+3","2147483648","999999999999999999999999"};
    for(i=0;i<sizeof(bad)/sizeof(bad[0]);i++){errno=0;CHECK(bx_session_fd_number(bad[i])<0 && errno==EINVAL,"invalid fd %s rejected",bad[i]?bad[i]:"NULL");}
}
static int raw_blob(const unsigned char *data,size_t n)
{
    int fd=(int)syscall(SYS_memfd_create,"bx-session-bad",0);
    if(fd<0 || write(fd,data,n)!=(ssize_t)n){perror("memfd blob");exit(2);}return fd;
}
static uint32_t get32(const unsigned char *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void put32(unsigned char *p,uint32_t v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);}
static void bad_blob(const unsigned char *data,size_t n,const char *name)
{
    bx_session s;int fd=raw_blob(data,n);bx_session_init(&s);errno=0;
    CHECK(bx_session_read(fd,&s)<0 && errno==EPROTO,"malformed %s rejected",name);
    CHECK(s.nkv==0 && s.nb==0,"malformed %s leaves destination empty",name);
    bx_session_dispose(&s);close(fd);
}
static void test_wire_fd(void)
{
    bx_session s,t;char h[BX_SESSION_PATH];int fd;basic(&s);path(h,sizeof(h),"shared");
    CHECK(bx_session_add_bind(&s,h,"/workspace",1)==0,"wire bind set");
    CHECK(bx_session_set(&s,"UNICODE","space 目录 😀")==0,"wire unicode set");
    fd=bx_session_create_fd(&s);CHECK(fd>=3,"session fd >= 3");
    if(fd<3){bx_session_dispose(&s);return;}
    long fdflags=bx_session_raw(SYS_fcntl,fd,F_GETFL,0,0,0,0);
    long seals=bx_session_raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0);
    errno=0;long written=bx_session_raw(SYS_write,fd,(long)"x",1,0,0,0);int write_errno=errno;
    const char *allow=getenv("BX_SESSION_ALLOW_OUTER_PROC_DUP");
    int skip_mode=allow && !strcmp(allow,"1") && outer_proc_dup &&
        (fdflags&O_ACCMODE)==O_RDWR && (seals&15)==15 && written<0 && write_errno==EPERM;
    if(skip_mode)SKIP("session O_RDONLY mode: independent raw proc-open also duplicates O_RDWR sealed fd");
    else CHECK((fdflags&O_ACCMODE)==O_RDONLY,"session fd is read-only (flags=%ld)",fdflags);
    CHECK(!(bx_session_raw(SYS_fcntl,fd,F_GETFD,0,0,0,0)&FD_CLOEXEC),"session fd inherits across exec");
    CHECK((seals&15)==15,"session fd is immutable");
    if(skip_mode)SKIP("read-only write EBADF: independent raw proc-open returns sealed handle with EPERM");
    else CHECK(written<0 && write_errno==EBADF,"read-only session cannot be written write=%ld errno=%d",written,write_errno);
    CHECK(lseek(fd,7,SEEK_SET)==7,"set shared fd offset");
    bx_session_init(&t);CHECK(bx_session_read(fd,&t)==0,"wire round trip");
    CHECK(lseek(fd,0,SEEK_CUR)==7,"session pread leaves fd offset");
    CHECK(t.nkv==s.nkv && t.nb==1 && t.binds[0].ro==1,"round trip counts and readonly");
    CHECK(!strcmp(bx_session_get(&t,"UNICODE"),"space 目录 😀"),"round trip unicode");
    CHECK(!strcmp(t.binds[0].host,s.binds[0].host) && !strcmp(t.binds[0].guest,"/workspace"),"round trip bind paths");
    int pipes[2];CHECK(pipe(pipes)==0,"concurrent test pipe");
    pid_t pid=fork();CHECK(pid>=0,"concurrent session fork");
    if(pid==0){
        close(pipes[0]);
        bx_session child;bx_session_init(&child);
        int ok=bx_session_read(fd,&child)==0 && child.nb==1 && !strcmp(bx_session_get(&child,"UNICODE"),"space 目录 😀");
        bx_session_dispose(&child);
        char c=ok?'Y':'N';
        if(write(pipes[1],&c,1)!=1) _exit(2);
        _exit(ok?0:1);
    }
    if(pid>0){close(pipes[1]);char c=0;CHECK(read(pipes[0],&c,1)==1 && c=='Y',"child reads same immutable fd");int st;CHECK(waitpid(pid,&st,0)==pid && WIFEXITED(st) && !WEXITSTATUS(st),"child reader exit");close(pipes[0]);}
    bx_session_dispose(&t);
    unsigned char head[24];CHECK(pread(fd,head,sizeof(head),0)==24,"read wire header");
    size_t len=get32(head+12);unsigned char *b=malloc(len),*m=malloc(len);
    if(!b || !m || pread(fd,b,len,0)!=(ssize_t)len){perror("wire capture");exit(2);}
    bad_blob(b,23,"short header");bad_blob(b,len-1,"truncated payload");
    memcpy(m,b,len);m[0]='!';bad_blob(m,len,"magic");
    memcpy(m,b,len);put32(m+8,2);bad_blob(m,len,"version");
    memcpy(m,b,len);put32(m+12,23);bad_blob(m,len,"small total size");
    memcpy(m,b,len);put32(m+12,BX_SESSION_MAX_BYTES+1);bad_blob(m,len,"large total size");
    memcpy(m,b,len);put32(m+16,BX_SESSION_MAX_KV+1);bad_blob(m,len,"key count overflow");
    memcpy(m,b,len);put32(m+20,BX_SESSION_MAX_BINDS+1);bad_blob(m,len,"bind count overflow");
    memcpy(m,b,len);put32(m+24,9);bad_blob(m,len,"unknown record kind");
    memcpy(m,b,len);put32(m+28,1);bad_blob(m,len,"key flags");
    memcpy(m,b,len);put32(m+32,0);bad_blob(m,len,"empty string length");
    memcpy(m,b,len);put32(m+36,0xffffffff);bad_blob(m,len,"string length overflow");
    memcpy(m,b,len);uint32_t la=get32(m+32);m[40+la-1]='x';bad_blob(m,len,"missing key terminator");
    memcpy(m,b,len);m[41]=0;bad_blob(m,len,"embedded key NUL");
    memcpy(m,b,len);m[40]='=';bad_blob(m,len,"invalid key name");
    memcpy(m,b,len);m[40+la]='x';bad_blob(m,len,"rootfs relative");
    /* Mutating a good source must not alter a previously decoded session. */
    bx_session_init(&t);CHECK(bx_session_read(fd,&t)==0,"decode before mutation test");
    CHECK(bx_session_set(&s,"UNICODE","new value")==0,"mutate source after snapshot");
    CHECK(!strcmp(bx_session_get(&t,"UNICODE"),"space 目录 😀"),"decoded snapshot independent");
    bx_session_dispose(&t);free(m);free(b);close(fd);bx_session_dispose(&s);
    /* Two sessions never share configuration even if readers use the same fd offset. */
    bx_session a,c;basic(&a);basic(&c);CHECK(bx_session_set(&a,"MARKER","one")==0,"session one marker");CHECK(bx_session_set(&c,"MARKER","two")==0,"session two marker");
    int af=bx_session_create_fd(&a),cf=bx_session_create_fd(&c);CHECK(af>=3 && cf>=3 && af!=cf,"separate sessions separate fds");
    if(af>=3 && cf>=3){bx_session_init(&t);CHECK(bx_session_read(cf,&t)==0 && !strcmp(bx_session_get(&t,"MARKER"),"two"),"session two contents");bx_session_dispose(&t);bx_session_init(&t);CHECK(bx_session_read(af,&t)==0 && !strcmp(bx_session_get(&t,"MARKER"),"one"),"session one contents");bx_session_dispose(&t);}
    if(af>=0) close(af);
    if(cf>=0) close(cf);
    bx_session_dispose(&a);
    bx_session_dispose(&c);
}
int main(int argc,char **argv)
{
    if(argc!=2 || strlen(argv[1])>=sizeof(fixture)){fprintf(stderr,"usage: test_session FIXTURE\n");return 2;}
    strcpy(fixture,argv[1]);
    directory("root");directory("root/usr");directory("root/usr/bin");directory("root/usr/share");directory("root/tmp");directory("root/root");directory("root/space 目录");directory("root/project");
    directory("shared");directory("shared/project");directory("shared/other");directory("shared/cache");directory("nested");directory("nested/deep");directory("nested/output");directory("shm");
    file("root/usr/bin/test");file("shared/project/file");file("nested/output/file");
    char jump[BX_SESSION_PATH];path(jump,sizeof(jump),"nested/deep");link_at("root/host-jump",jump);
    path(jump,sizeof(jump),"nested/output");link_at("host-directory-alias",jump);
    link_at("root/bin","usr/bin");link_at("root/absolute-link","/usr/bin/test");link_at("root/relative-link","usr/bin/test");link_at("root/loop-a","loop-b");link_at("root/loop-b","loop-a");
    independent_proc_diagnostic();test_mapping();test_api();test_wire_fd();
    printf("RESULT: %s session checks=%u passed=%u failures=%u skipped=%u\n",failures?"FAIL":"PASS",checks,checks-failures,failures,skipped);
    return failures?1:0;
}
