/* Native host -> original guest entry, static executable. SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "session.h"
#include "host-world.h"
#ifndef BX_ENTER_NATIVE
#include "../ldr/early_sigsys.h"
#endif
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
extern char **environ;
static int fail(const char *what)
{ int e=errno; fprintf(stderr,"bx-enter: %s: %s\n",what,strerror(e));return e==ENOENT ? 127 : 126; }
static const char *val(const bx_session *s,const char *name,const char *fallback)
{ const char *p=bx_session_get(s,name);return p ? p : fallback; }
static int env_set(const char *name,const char *value)
{ return value ? setenv(name,value,1) : 0; }
static int guest_env(const bx_session *s,int fd,const char *cwd,const char *exe,const char *comm)
{
    size_t i,n=0;char **clean;char num[32],libs[BX_SESSION_PATH*3];char *binds;size_t bytes=1,pos=0;
    while(environ && environ[n])n++;
    clean=calloc(n+1,sizeof(char*));if(!clean)return -1;
    for(i=0,n=0;environ && environ[i];i++)if(bxhc_keep_env(environ[i]))clean[n++]=environ[i];
    environ=clean;
    for(i=0;i<s->nkv;i++)if(s->kv[i].name[0]!='_' && strcmp(s->kv[i].name,"BXROOT_SESSION_FD"))
        if(env_set(s->kv[i].name,s->kv[i].value))return -1;
    for(i=0;i<s->nb;i++)bytes+=strlen(s->binds[i].host)+strlen(s->binds[i].guest)+6;
    binds=calloc(1,bytes);if(!binds)return -1;
    for(i=0;i<s->nb;i++) {
        if(strchr(s->binds[i].host,';') || strchr(s->binds[i].host,':') || strchr(s->binds[i].guest,';') || strchr(s->binds[i].guest,':')) {free(binds);errno=ENOTSUP;return -1;}
        pos+=(size_t)snprintf(binds+pos,bytes-pos,"%s%s:%s%s",i ? ";" : "",s->binds[i].host,s->binds[i].guest,s->binds[i].ro ? ":ro" : "");
    }
    i=(size_t)env_set("BXROOT_BINDS",binds);free(binds);if(i)return -1;
    snprintf(num,sizeof(num),"%d",fd);
    if(!bx_session_get(s,"_LIBRARY_PATH")) {
        const char *root=val(s,"BXROOT_ROOTFS","");
        if(snprintf(libs,sizeof(libs),"%s/usr/lib/aarch64-linux-gnu:%s/lib/aarch64-linux-gnu:%s/lib:%s/usr/lib",root,root,root,root)>=(int)sizeof(libs)) {errno=ENAMETOOLONG;return -1;}
    }
    return env_set("BXROOT_SESSION_FD",num) || env_set("PATH",val(s,"_GUEST_PATH",BX_HOST_GUEST_DEFAULT_PATH)) ||
        env_set("HOME",val(s,"_GUEST_HOME","/root")) || env_set("TMPDIR",val(s,"_GUEST_TMPDIR","/tmp")) ||
        env_set("PWD",cwd) || env_set("BXROOT_WORKDIR",cwd) || env_set("BXROOT_WORKDIR_DONE","1") ||
        env_set("BXROOT_GUEST_EXE",exe) || env_set("BXROOT_ORIG_COMM",comm) ||
        env_set("LD_LIBRARY_PATH",val(s,"_LIBRARY_PATH",libs)) || env_set("LD_PRELOAD",val(s,"_RUNTIME",NULL)) ||
        env_set("BXROOT_LD_PRELOAD",val(s,"_RUNTIME",NULL)) || env_set("PROROOT_LIB_PATH",val(s,"_RUNTIME",NULL));
}
static int executable(const bx_session *s,const char *name,const char *cwd,char *guest,char *host)
{
    const char *p=val(s,"_GUEST_PATH","/usr/local/bin:/usr/bin:/bin");int denied=0;
    if(strchr(name,'/')) {
        if(name[0]=='/') { if(strlen(name)>=BX_SESSION_PATH) {errno=ENAMETOOLONG;return -1;}strcpy(guest,name); }
        else if(snprintf(guest,BX_SESSION_PATH,"%s/%s",cwd,name)>=BX_SESSION_PATH) {errno=ENAMETOOLONG;return -1;}
        return bx_session_to_host(s,guest,cwd,host,BX_SESSION_PATH) ||
               bx_session_raw(SYS_faccessat,AT_FDCWD,(long)host,X_OK,0,0,0)<0 ? -1 : 0;
    }
    do {
        const char *end=strchr(p,':');size_t len=end ? (size_t)(end-p) : strlen(p);char dir[BX_SESSION_PATH];
        if(len>=sizeof(dir)) {errno=ENAMETOOLONG;return -1;}memcpy(dir,p,len);dir[len]=0;
        if(snprintf(guest,BX_SESSION_PATH,"%s/%s",len ? dir : cwd,name)<BX_SESSION_PATH &&
            bx_session_to_host(s,guest,cwd,host,BX_SESSION_PATH)==0 &&
            bx_session_raw(SYS_faccessat,AT_FDCWD,(long)host,X_OK,0,0,0)==0)return 0;
        if(errno==EACCES)denied=1;
        if(!end)break;
        p=end+1;
    }while(1);
    errno=denied ? EACCES : ENOENT;return -1;
}
static long entry_pread(int fd, void *buf, size_t n, uint64_t off)
{ return bx_session_raw(SYS_pread64, fd, (long)buf, (long)n, (long)off, 0, 0); }
int main(int argc,char **argv)
{
    const char *fdtext=getenv("BXROOT_SESSION_FD"),*cwd_opt=NULL,*argv0=NULL,*convert=NULL;int direction=0,i=1,fd,depth=0;
    bx_session s;char cwd[BX_SESSION_PATH],actual[BX_SESSION_PATH],host[BX_SESSION_PATH],guest[BX_SESSION_PATH],original[BX_SESSION_PATH];
    char **args,**chain;size_t ac,n,j;const char *tramp,*linker,*runtime;
    for(;i<argc;i++) {
        if(!strcmp(argv[i],"--")) {i++;break;}
        if(!strcmp(argv[i],"--help")) {puts("usage: bx-enter [--session-fd N] [--cwd GUEST] [--argv0 NAME] -- PROGRAM [ARGS...]\n       bx-enter [--session-fd N] [--cwd GUEST] --to-host PATH\n       bx-enter [--session-fd N] --to-guest PATH");return 0;}
        if((!strcmp(argv[i],"--session-fd") || !strcmp(argv[i],"--cwd") || !strcmp(argv[i],"--argv0") || !strcmp(argv[i],"--to-host") || !strcmp(argv[i],"--to-guest")) && i+1<argc) {
            const char *option=argv[i++];
            if(!strcmp(option,"--session-fd"))fdtext=argv[i];else if(!strcmp(option,"--cwd"))cwd_opt=argv[i];
            else if(!strcmp(option,"--argv0"))argv0=argv[i];else {direction=!strcmp(option,"--to-host") ? 1 : -1;convert=argv[i];}
            continue;
        }
        if(argv[i][0]=='-') {errno=EINVAL;return fail("unknown option or missing value");}break;
    }
    bx_session_init(&s);fd=bx_session_fd_number(fdtext);
    if(fd<0 || bx_session_read(fd,&s))return fail("session unavailable");
    if(bx_session_raw(SYS_fcntl,fd,F_GETFD,0,0,0,0)<0 ||
       bx_session_raw(SYS_fcntl,fd,F_SETFD,0,0,0,0)<0)return fail("session fd");
    if(bx_session_raw(SYS_getcwd,(long)actual,sizeof(actual),0,0,0,0)<0 && !cwd_opt &&
       !(direction && convert && convert[0]=='/'))return fail("current directory unavailable; use --cwd");
    if(cwd_opt) {
        if(cwd_opt[0]!='/') {errno=EINVAL;return fail("--cwd must be a guest absolute path");}
        if(strlen(cwd_opt)>=sizeof(cwd)) {errno=ENAMETOOLONG;return fail("cwd");}strcpy(cwd,cwd_opt);
    }else if(direction==1 && convert && convert[0]=='/')strcpy(cwd,"/");
    else if(direction>=0 && bx_session_to_guest(&s,actual,cwd,sizeof(cwd)))return fail("cwd mapping unavailable or ambiguous; use --cwd");
    if(direction) {
        if(i!=argc || !convert) {errno=EINVAL;return fail("conversion arguments");}
        if((direction>0 ? bx_session_to_host(&s,convert,cwd,host,sizeof(host)) : bx_session_to_guest(&s,convert,host,sizeof(host))))return fail("path conversion");
        puts(host);bx_session_dispose(&s);return 0;
    }
    if(i>=argc) {errno=EINVAL;return fail("missing guest program");}
    if(executable(&s,argv[i],cwd,guest,host))return fail("guest executable");
    strcpy(original,guest);ac=(size_t)(argc-i);args=calloc(ac+1,sizeof(char*));if(!args)return fail("argv allocation");
    for(j=0;j<ac;j++)args[j]=argv[i+(int)j];
    if(argv0)args[0]=(char*)argv0;
    /* Linux shebang rewrite, with guest script paths visible to the interpreter. */
    for(;;) {
        char line[256],*p,*end,*arg;long readn,ef;
        ef=bx_session_raw(SYS_openat,AT_FDCWD,(long)host,O_RDONLY|O_CLOEXEC,0,0,0);if(ef<0)return fail("open guest executable");
        readn=bx_session_raw(SYS_pread64,ef,(long)line,sizeof(line)-1,0,0,0);bx_session_raw(SYS_close,ef,0,0,0,0,0);
        if(readn<0)return fail("read guest executable");
        line[readn]=0;
        if(readn>=4 && !memcmp(line,ELFMAG,4)) {
            /* Native ELF belongs to v2's host entry, not guest reentry. */
            ef=bx_session_raw(SYS_openat,AT_FDCWD,(long)host,O_RDONLY|O_CLOEXEC,0,0,0);
            if(ef<0)return fail("ELF inspection");
            if(!bxhc_guest_elf((int)ef,entry_pread)) {
                bx_session_raw(SYS_close,ef,0,0,0,0,0);errno=ENOEXEC;return fail("guest dynamic AArch64 glibc ELF required");
            }
            bx_session_raw(SYS_close,ef,0,0,0,0,0);
            break;
        }
        if(readn<3 || line[0]!='#' || line[1]!='!') {errno=ENOEXEC;return fail("guest ELF or shebang required");}
        if(++depth>4) {errno=ELOOP;return fail("nested shebang");}
        end=strchr(line,'\n');if(!end && readn==(long)sizeof(line)-1) {errno=ENOEXEC;return fail("truncated shebang");}
        if(end)*end=0;
        p=line+2;while(*p==' ' || *p=='\t')p++;
        arg=p;while(*arg && *arg!=' ' && *arg!='\t')arg++;
        if(*arg) { *arg++=0;while(*arg==' ' || *arg=='\t')arg++;end=arg+strlen(arg);while(end>arg && (end[-1]==' ' || end[-1]=='\t'))*--end=0;}
        if(*p!='/') {errno=ENOEXEC;return fail("absolute shebang interpreter required");}
        chain=calloc(ac+4,sizeof(char*));if(!chain)return fail("script argv");n=0;chain[n]=strdup(p);
        if(!chain[n++])return fail("script argv allocation");
        if(*arg){chain[n]=strdup(arg);if(!chain[n++])return fail("script argument allocation");}
        chain[n]=strdup(guest);if(!chain[n++])return fail("script path allocation");
        for(j=1;j<ac;j++)chain[n++]=args[j];
        free(args);args=chain;ac=n;
        if(executable(&s,p,cwd,guest,host))return fail("script interpreter");
    }
    tramp=bx_session_get(&s,"_TRAMP");linker=bx_session_get(&s,"_LINKER");runtime=bx_session_get(&s,"_RUNTIME");
    if(!tramp || !linker || !runtime) {errno=ENOTSUP;return fail("session loader chain missing");}
    if(bx_session_to_host(&s,cwd,"/",actual,sizeof(actual)) || bx_session_raw(SYS_chdir,(long)actual,0,0,0,0,0)<0)return fail("guest cwd");
    if(guest_env(&s,fd,cwd,guest,original))return fail("guest environment");
    chain=calloc(ac+8,sizeof(char*));if(!chain)return fail("loader argv");n=0;
    chain[n++]=(char*)tramp;chain[n++]=(char*)linker;chain[n++]=(char*)"--argv0";chain[n++]=args[0];
    chain[n++]=(char*)"--preload";chain[n++]=(char*)runtime;chain[n++]=host;
    for(j=1;j<ac;j++)chain[n++]=args[j];
    bx_session_raw(SYS_execve,(long)tramp,(long)chain,(long)environ,0,0,0);
    return fail("guest loader exec");
}
