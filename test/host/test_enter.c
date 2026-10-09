/* V3 bx-enter integration: real helper, mapped ELF/script, captured loader exec. */
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
#include <signal.h>
#include <unistd.h>
#ifdef TRAMP_ONLY
#include "../../src/ldr/early_sigsys.h"
static void field(const char *kind,const char *key,const char *value)
{
    printf("%s:%s:",kind,key);
    if(value) for(const unsigned char *p=(const unsigned char *)value;*p;p++)printf("%02x",*p);
    else printf("<unset>");
    putchar('\n');
}
int main(int argc,char **argv)
{
    char cwd[BX_SESSION_PATH],key[32],input[256];
    for(int i=0;i<argc;i++){snprintf(key,sizeof(key),"%d",i);field("ARG",key,argv[i]);}
    static const char *const names[]={"FOO","KEEP_EMPTY","PAYLOAD","PATH","HOME","TMPDIR","PWD","LD_PRELOAD","LD_LIBRARY_PATH","BXROOT_ROOTFS","BXROOT_BINDS","BXROOT_FAKEROOT","BXROOT_FAKE_UID","BXROOT_REENTRY","BXROOT_SESSION_FD","BXROOT_ENTER","BXROOT_WORKDIR","BXROOT_WORKDIR_DONE","BXROOT_GUEST_EXE","BXROOT_ORIG_COMM","BXROOT_LEAK","PROOT_LEAK","PROROOT_LEAK","BXROOT_AUTO_HOST"};
    for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++)field("ENV",names[i],getenv(names[i]));
    if(!getcwd(cwd,sizeof(cwd))){perror("tramp cwd");return 90;}
    field("CWD","actual",cwd);
    ssize_t n=read(0,input,sizeof(input)-1);
    if(n<0){perror("tramp input");return 91;}input[n]=0;field("STDIN","text",input);
    char extra;field("STDIN","eof",read(0,&extra,1)==0?"1":"0");
    const char *fdtext=getenv("BXROOT_SESSION_FD");
    int fd=fdtext?atoi(fdtext):-1;char header[24];
    int alive=fd>=3 && pread(fd,header,sizeof(header),0)==24 && !memcmp(header,"BXSESS3\0",8);
    field("SESSION","live",alive?"1":"0");
    if(!alive) return 92;
    fprintf(stderr,"TRAMP_STDERR\n");
    field("ENV","BULK_299",getenv("BULK_299"));
    const char *sig=getenv("RETURN_SIGNAL");
    if(sig && raise(atoi(sig))!=0) return 93;
    const char *rc=getenv("RETURN_RC");return rc?atoi(rc):0;
}
#else
static unsigned checks,failures;
#define CHECK(c, ...) do { checks++; if(!(c)){failures++;fprintf(stderr,"FAIL: ");fprintf(stderr,__VA_ARGS__);fprintf(stderr," [errno=%d]\n",errno);} } while(0)
static char fixture[BX_SESSION_PATH],helper[BX_SESSION_PATH],tramp[BX_SESSION_PATH],root[BX_SESSION_PATH],shared[BX_SESSION_PATH];
static void makepath(char *out,size_t cap,const char *suffix)
{
    int n=snprintf(out,cap,"%s/%s",fixture,suffix);if(n<0 || (size_t)n>=cap){fprintf(stderr,"fixture overflow\n");exit(2);}
}
static void mkdir_at(const char *suffix)
{
    char p[BX_SESSION_PATH];makepath(p,sizeof(p),suffix);if(mkdir(p,0700)<0 && errno!=EEXIST){perror("mkdir");exit(2);}
}
static void blob_at(const char *suffix,const void *data,size_t n,mode_t mode)
{
    char p[BX_SESSION_PATH];makepath(p,sizeof(p),suffix);int fd=open(p,O_WRONLY|O_CREAT|O_TRUNC,mode);
    if(fd<0){perror("fixture open");exit(2);}const unsigned char *b=data;
    while(n){ssize_t w=write(fd,b,n);if(w<0){if(errno==EINTR)continue;perror("fixture write");exit(2);}b+=w;n-=(size_t)w;}
    if(fchmod(fd,mode)<0){perror("fixture chmod");exit(2);}close(fd);
}
static void copy_self(const char *suffix)
{
    char p[BX_SESSION_PATH],data[65536];makepath(p,sizeof(p),suffix);
    int in=open("/proc/self/exe",O_RDONLY),out=open(p,O_WRONLY|O_CREAT|O_TRUNC,0700);
    if(in<0 || out<0){perror("copy fixture");exit(2);}ssize_t n;
    while((n=read(in,data,sizeof(data)))>0){size_t pos=0;while(pos<(size_t)n){ssize_t w=write(out,data+pos,(size_t)n-pos);if(w<=0){perror("copy write");exit(2);}pos+=(size_t)w;}}
    if(n<0 || fchmod(out,0700)<0){perror("copy end");exit(2);}close(in);close(out);
}
static void setkv(bx_session *s,const char *name,const char *value)
{if(bx_session_set(s,name,value)){perror(name);exit(2);}}
static void base(bx_session *s)
{
    bx_session_init(s);setkv(s,"BXROOT_ROOTFS",root);setkv(s,"_TRAMP",tramp);
    setkv(s,"_LINKER","/loader/linker.so");setkv(s,"_RUNTIME","/loader/runtime.so");
    setkv(s,"_LIBRARY_PATH","/guest/lib:/guest/usr/lib");setkv(s,"_GUEST_PATH","/usr/bin:/bin");
    setkv(s,"_GUEST_HOME","/guest-home");setkv(s,"_GUEST_TMPDIR","/guest-tmp");
    setkv(s,"BXROOT_FAKEROOT","1");setkv(s,"BXROOT_FAKE_UID","1234");setkv(s,"BXROOT_AUTO_HOST","1");
    setkv(s,"BXROOT_REENTRY","1");setkv(s,"BXROOT_ENTER",helper);
    if(bx_session_add_bind(s,shared,"/workspace",1)){perror("bind");exit(2);}
}
struct result{int rc;char text[32768];};
static struct result run(const bx_session *s,const char *cwd,char *const command[],int fdmode)
{
    struct result r={-999,{0}};int fd=bx_session_create_fd(s),in[2],out[2];
    if(fd<0 || pipe(in) || pipe(out)){perror("run setup");exit(2);}pid_t pid=fork();
    if(pid<0){perror("fork");exit(2);}if(!pid){
        close(in[1]);close(out[0]);
        if(dup2(in[0],0)<0 || dup2(out[1],1)<0 || dup2(out[1],2)<0 || chdir(cwd)<0)_exit(89);
        close(in[0]);close(out[1]);
        if(clearenv())_exit(88);
        setenv("FOO","host-updated",1);setenv("KEEP_EMPTY","",1);setenv("PAYLOAD","{\"path\":\"/leave/as/is\",\"url\":\"https://example.test/a\"}",1);
        setenv("PATH","/host/bin",1);setenv("HOME","/host-home",1);setenv("TMPDIR","/host-tmp",1);
        char preload[BX_SESSION_PATH];
        if(strlen(helper)>=sizeof(preload))_exit(85);
        strcpy(preload,helper);char *preloadslash=strrchr(preload,'/');
        if(!preloadslash || (size_t)(preloadslash-preload)+sizeof("/host-preload.so")>sizeof(preload))_exit(85);
        strcpy(preloadslash,"/host-preload.so");
        setenv("LD_PRELOAD",preload,1);setenv("LD_LIBRARY_PATH","/host/wrong-libs",1);
        setenv("BXROOT_LEAK","bad",1);setenv("PROOT_LEAK","bad",1);setenv("PROROOT_LEAK","bad",1);
        setenv("RETURN_RC","17",1);
        char bulkkey[32];
        for(int bi=0;bi<300;bi++){snprintf(bulkkey,sizeof(bulkkey),"BULK_%d",bi);if(setenv(bulkkey,"bulk-value",1))_exit(86);}
        char fdbuf[32];snprintf(fdbuf,sizeof(fdbuf),"%d",fd);
        if(fdmode!=1)setenv("BXROOT_SESSION_FD",fdmode==3?"999999":fdbuf,1);
        if(fdmode==2)close(fd);
        if(fdmode==4)fcntl(fd,F_SETFD,FD_CLOEXEC);
        char *call[128];size_t ci=0;
        for(;command[ci] && ci<127;ci++)call[ci]=!strcmp(command[ci],"@FD@")?fdbuf:command[ci];
        call[ci]=NULL;
        execv(helper,call);perror("helper exec");_exit(87);
    }
    close(in[0]);close(out[1]);close(fd);
    static const char input[]="hello-through-entry\n";
    if(write(in[1],input,sizeof(input)-1)!=(ssize_t)sizeof(input)-1){perror("stdin write");exit(2);}close(in[1]);
    size_t pos=0;ssize_t n;while((n=read(out[0],r.text+pos,sizeof(r.text)-1-pos))>0){pos+=(size_t)n;if(pos>=sizeof(r.text)-1)break;}r.text[pos]=0;close(out[0]);
    int st;if(waitpid(pid,&st,0)!=pid){perror("waitpid");exit(2);}r.rc=WIFEXITED(st)?WEXITSTATUS(st):-WTERMSIG(st);return r;
}
static void hasfield(const struct result *r,const char *kind,const char *key,const char *value)
{
    char want[16384];size_t pos=(size_t)snprintf(want,sizeof(want),"%s:%s:",kind,key);
    if(value)for(const unsigned char *p=(const unsigned char*)value;*p && pos+3<sizeof(want);p++)pos+=(size_t)snprintf(want+pos,sizeof(want)-pos,"%02x",*p);
    else pos+=(size_t)snprintf(want+pos,sizeof(want)-pos,"<unset>");
    snprintf(want+pos,sizeof(want)-pos,"\n");CHECK(strstr(r->text,want)!=NULL,"field %s:%s expected=%s output=%s",kind,key,value?value:"<unset>",r->text);
}
static void executable_case(void)
{
    bx_session s;base(&s);char *cmd[]={helper,"--argv0","custom argv0","--","/usr/bin/probe","space arg","https://example.test/a",NULL};
    struct result r=run(&s,root,cmd,0);CHECK(r.rc==17,"ELF helper returns target status rc=%d output=%s",r.rc,r.text);
    hasfield(&r,"ARG","0",tramp);hasfield(&r,"ARG","1","/loader/linker.so");hasfield(&r,"ARG","2","--argv0");hasfield(&r,"ARG","3","custom argv0");hasfield(&r,"ARG","4","--preload");hasfield(&r,"ARG","5","/loader/runtime.so");
    char expected[BX_SESSION_PATH];makepath(expected,sizeof(expected),"root/usr/bin/probe");hasfield(&r,"ARG","6",expected);hasfield(&r,"ARG","7","space arg");hasfield(&r,"ARG","8","https://example.test/a");
    hasfield(&r,"ENV","FOO","host-updated");hasfield(&r,"ENV","KEEP_EMPTY","");hasfield(&r,"ENV","PAYLOAD","{\"path\":\"/leave/as/is\",\"url\":\"https://example.test/a\"}");
    hasfield(&r,"ENV","PATH","/usr/bin:/bin");hasfield(&r,"ENV","HOME","/guest-home");hasfield(&r,"ENV","TMPDIR","/guest-tmp");hasfield(&r,"ENV","PWD","/");
    hasfield(&r,"ENV","LD_PRELOAD","/loader/runtime.so");hasfield(&r,"ENV","LD_LIBRARY_PATH","/guest/lib:/guest/usr/lib");hasfield(&r,"ENV","BXROOT_ROOTFS",root);hasfield(&r,"ENV","BXROOT_FAKEROOT","1");hasfield(&r,"ENV","BXROOT_FAKE_UID","1234");hasfield(&r,"ENV","BXROOT_REENTRY","1");hasfield(&r,"ENV","BXROOT_ENTER",helper);hasfield(&r,"ENV","BXROOT_AUTO_HOST","1");
    hasfield(&r,"ENV","BXROOT_WORKDIR","/");hasfield(&r,"ENV","BXROOT_WORKDIR_DONE","1");hasfield(&r,"ENV","BXROOT_GUEST_EXE","/usr/bin/probe");
    hasfield(&r,"ENV","BXROOT_LEAK",NULL);hasfield(&r,"ENV","PROOT_LEAK",NULL);hasfield(&r,"ENV","PROROOT_LEAK",NULL);
    char binds[BX_SESSION_PATH+40];snprintf(binds,sizeof(binds),"%s:/workspace:ro",shared);hasfield(&r,"ENV","BXROOT_BINDS",binds);
    hasfield(&r,"CWD","actual",root);hasfield(&r,"STDIN","text","hello-through-entry\n");hasfield(&r,"STDIN","eof","1");hasfield(&r,"SESSION","live","1");CHECK(strstr(r.text,"TRAMP_STDERR")!=NULL,"stderr inherited");
    char *explicitfd[]={helper,"--session-fd","@FD@","--","/usr/bin/probe",NULL};
    r=run(&s,root,explicitfd,1);CHECK(r.rc==17,"explicit session fd works without locator env rc=%d output=%s",r.rc,r.text);hasfield(&r,"SESSION","live","1");
    char *bincommand[]={helper,"--","/bin/probe",NULL};r=run(&s,root,bincommand,0);CHECK(r.rc==17,"guest bin symlink rc=%d output=%s",r.rc,r.text);hasfield(&r,"ARG","6",expected);hasfield(&r,"ENV","BXROOT_GUEST_EXE","/bin/probe");
    /* host chdir determines guest cwd; no startup cwd override. */
    char cwd[BX_SESSION_PATH];makepath(cwd,sizeof(cwd),"shared/project");char *namecmd[]={helper,"--","probe",NULL};r=run(&s,cwd,namecmd,0);CHECK(r.rc==17,"PATH search rc=%d output=%s",r.rc,r.text);hasfield(&r,"ENV","PWD","/workspace/project");hasfield(&r,"CWD","actual",cwd);hasfield(&r,"ARG","3","probe");
    char *cwdcmd[]={helper,"--cwd","/workspace/project","--","/usr/bin/probe",NULL};r=run(&s,fixture,cwdcmd,0);CHECK(r.rc==17,"explicit cwd works outside mapped tree rc=%d output=%s",r.rc,r.text);hasfield(&r,"ENV","PWD","/workspace/project");hasfield(&r,"CWD","actual",cwd);
    char *relcmd[]={helper,"--","./probe",NULL};r=run(&s,cwd,relcmd,0);CHECK(r.rc==17,"relative executable works rc=%d output=%s",r.rc,r.text);makepath(expected,sizeof(expected),"shared/project/probe");hasfield(&r,"ARG","6",expected);
    setkv(&s,"_GUEST_PATH","");r=run(&s,cwd,namecmd,0);CHECK(r.rc==17,"empty guest PATH searches cwd rc=%d output=%s",r.rc,r.text);hasfield(&r,"ARG","6",expected);hasfield(&r,"ENV","PATH","");
    setkv(&s,"_GUEST_PATH",".");r=run(&s,cwd,namecmd,0);CHECK(r.rc==17,"relative guest PATH searches cwd rc=%d output=%s",r.rc,r.text);hasfield(&r,"ARG","6",expected);
    hasfield(&r,"ENV","BULK_299","bulk-value");
    char *emptyargv[]={helper,"--argv0","","--","/usr/bin/probe","",NULL};
    r=run(&s,root,emptyargv,0);CHECK(r.rc==17,"empty argv0 and argument accepted rc=%d",r.rc);hasfield(&r,"ARG","3","");hasfield(&r,"ARG","7","");
    setkv(&s,"RETURN_SIGNAL","15");r=run(&s,root,emptyargv,0);CHECK(r.rc==-SIGTERM,"signal exit preserves SIGTERM rc=%d output=%s",r.rc,r.text);
    bx_session_dispose(&s);
}
static void script_case(void)
{
    bx_session s;base(&s);char *cmd[]={helper,"--","/scripts/one","user-arg",NULL};struct result r=run(&s,root,cmd,0);
    CHECK(r.rc==17,"shebang rc=%d output=%s",r.rc,r.text);hasfield(&r,"ARG","3","/usr/bin/probe");hasfield(&r,"ARG","7","one optional arg");hasfield(&r,"ARG","8","/scripts/one");hasfield(&r,"ARG","9","user-arg");hasfield(&r,"ENV","BXROOT_GUEST_EXE","/usr/bin/probe");
    char *nested[]={helper,"--","/scripts/two","arg2",NULL};r=run(&s,root,nested,0);CHECK(r.rc==17,"nested shebang rc=%d output=%s",r.rc,r.text);hasfield(&r,"ARG","7","one optional arg");hasfield(&r,"ARG","8","/scripts/one");hasfield(&r,"ARG","9","outer optional arg");hasfield(&r,"ARG","10","/scripts/two");hasfield(&r,"ARG","11","arg2");
    bx_session_dispose(&s);
}
static void failures_case(void)
{
    bx_session s;base(&s);char *good[]={helper,"--","/usr/bin/probe",NULL};struct result r;
    for(int mode=1;mode<=4;mode++){r=run(&s,root,good,mode);CHECK(r.rc==126 && strstr(r.text,"session unavailable"),"missing/closed/invalid/cloexec fd mode=%d rc=%d output=%s",mode,r.rc,r.text);}
    char *help[]={helper,"--help",NULL};r=run(&s,fixture,help,1);CHECK(r.rc==0 && strstr(r.text,"usage:"),"help works without session");
    char *unknown[]={helper,"--not-an-option",NULL};r=run(&s,root,unknown,0);CHECK(r.rc==126 && strstr(r.text,"unknown option"),"unknown option rejected");
    char *missingvalue[]={helper,"--session-fd",NULL};r=run(&s,root,missingvalue,0);CHECK(r.rc==126 && strstr(r.text,"missing value"),"missing option value rejected");
    char *missingprogram[]={helper,"--",NULL};r=run(&s,root,missingprogram,0);CHECK(r.rc==126 && strstr(r.text,"missing guest program"),"missing guest program rejected");
    char *badcwd[]={helper,"--cwd","relative","--","/usr/bin/probe",NULL};r=run(&s,root,badcwd,0);CHECK(r.rc==126 && strstr(r.text,"--cwd"),"relative --cwd rejected rc=%d",r.rc);
    char *outside[]={helper,"--","/usr/bin/probe",NULL};r=run(&s,fixture,outside,0);CHECK(r.rc==127 && strstr(r.text,"cwd mapping"),"unmapped cwd rejected rc=%d output=%s",r.rc,r.text);
    const struct {const char *name;int rc;} cases[]={
        {"/missing-command",127},{"/usr/bin/not-executable",126},{"/usr/bin/wrong-arch",126},{"/usr/bin/truncated-elf",126},
        {"/usr/bin/native-elf",126},{"/usr/bin/static-elf",126},{"/usr/bin/big-endian",126},{"/usr/bin/duplicate-interp",126},{"/usr/bin/interp-unterminated",126},{"/usr/bin/unknown-interp",126},{"/usr/bin/phdr-overflow",126},{"/scripts/plain-text",126},{"/scripts/relative-interp",126},{"/scripts/script-loop",126},
        {"/scripts/missing-interp",127},{"/scripts/long-shebang",126},{"/scripts/no-exec",126}
    };
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++){char *cmd[]={helper,"--",(char*)cases[i].name,NULL};r=run(&s,root,cmd,0);CHECK(r.rc==cases[i].rc && !strstr(r.text,"ARG:"),"reject %s rc=%d expected=%d output=%s",cases[i].name,r.rc,cases[i].rc,r.text);}
    if(bx_session_add_bind(&s,shared,"/alias",0)){perror("ambiguous bind");exit(2);}char cwd[BX_SESSION_PATH];makepath(cwd,sizeof(cwd),"shared/project");r=run(&s,cwd,good,0);CHECK(r.rc==126 && strstr(r.text,"ambiguous"),"ambiguous cwd rejected rc=%d output=%s",r.rc,r.text);
    char *explicit[]={helper,"--cwd","/workspace/project","--","/usr/bin/probe",NULL};r=run(&s,cwd,explicit,0);CHECK(r.rc==17,"explicit cwd resolves ambiguous bind rc=%d output=%s",r.rc,r.text);
    bx_session_dispose(&s);
}
static void conversion_case(void)
{
    bx_session s;base(&s);char *tohost[]={helper,"--to-host","/workspace/new file",NULL};struct result r=run(&s,root,tohost,0);char expected[BX_SESSION_PATH+16];snprintf(expected,sizeof(expected),"%s/new file\n",shared);CHECK(r.rc==0 && !strcmp(r.text,expected),"to-host new output path rc=%d got=%s want=%s",r.rc,r.text,expected);
    r=run(&s,fixture,tohost,0);CHECK(r.rc==0 && !strcmp(r.text,expected),"absolute to-host works from unmapped cwd rc=%d output=%s",r.rc,r.text);
    char *relative[]={helper,"--to-host","relative",NULL};r=run(&s,fixture,relative,0);CHECK(r.rc==127 && strstr(r.text,"cwd mapping"),"relative to-host needs mapped cwd rc=%d output=%s",r.rc,r.text);
    char target[BX_SESSION_PATH];makepath(target,sizeof(target),"shared/new file");char *toguest[]={helper,"--to-guest",target,NULL};r=run(&s,fixture,toguest,0);CHECK(r.rc==0 && !strcmp(r.text,"/workspace/new file\n"),"to-guest works from unmapped cwd rc=%d output=%s",r.rc,r.text);
    char *extra[]={helper,"--to-host","/usr/bin/probe","unexpected",NULL};r=run(&s,root,extra,0);CHECK(r.rc==126 && strstr(r.text,"conversion arguments"),"conversion extra args rejected");
    bx_session_dispose(&s);
}
static void elf_bytes(unsigned char *b,unsigned machine,const char *interp)
{
    memset(b,0,512);memcpy(b,"\177ELF",4);b[4]=2;b[5]=1;b[6]=1;b[16]=3;b[18]=(unsigned char)machine;b[19]=(unsigned char)(machine>>8);b[24]=0x40;b[32]=64;b[52]=64;b[54]=56;b[56]=1;
    b[64]=3;b[72]=128;size_t n=strlen(interp)+1;b[96]=(unsigned char)n;memcpy(b+128,interp,n);
}
int main(int argc,char **argv)
{
    if(argc!=4 || strlen(argv[1])>=sizeof(fixture) || strlen(argv[2])>=sizeof(helper) || strlen(argv[3])>=sizeof(tramp)){fprintf(stderr,"usage: test_enter FIXTURE HELPER TRAMP\n");return 2;}
    strcpy(fixture,argv[1]);strcpy(helper,argv[2]);strcpy(tramp,argv[3]);makepath(root,sizeof(root),"root");makepath(shared,sizeof(shared),"shared");
    mkdir_at("root");mkdir_at("root/usr");mkdir_at("root/usr/bin");mkdir_at("root/scripts");mkdir_at("shared");mkdir_at("shared/project");copy_self("root/usr/bin/probe");copy_self("shared/project/probe");
    static const char one[]="#!/usr/bin/probe one optional arg\n",two[]="#!/scripts/one outer optional arg\n",relative[]="#!relative\n",plain[]="plain text\n",loop[]="#!/scripts/script-loop\n",missing[]="#!/no-such-interpreter\n";
    blob_at("root/scripts/one",one,sizeof(one)-1,0700);blob_at("root/scripts/two",two,sizeof(two)-1,0700);blob_at("root/scripts/relative-interp",relative,sizeof(relative)-1,0700);blob_at("root/scripts/plain-text",plain,sizeof(plain)-1,0700);blob_at("root/scripts/script-loop",loop,sizeof(loop)-1,0700);blob_at("root/scripts/missing-interp",missing,sizeof(missing)-1,0700);blob_at("root/scripts/no-exec",one,sizeof(one)-1,0600);
    char longline[400];memset(longline,'x',sizeof(longline));longline[0]='#';longline[1]='!';longline[2]='/';longline[sizeof(longline)-1]='\n';blob_at("root/scripts/long-shebang",longline,sizeof(longline),0700);
    unsigned char elf[512];elf_bytes(elf,62,"/lib64/ld-linux-x86-64.so.2");blob_at("root/usr/bin/wrong-arch",elf,sizeof(elf),0700);blob_at("root/usr/bin/truncated-elf","\177ELF",4,0700);elf_bytes(elf,183,"/system/bin/linker64");blob_at("root/usr/bin/native-elf",elf,sizeof(elf),0700);blob_at("root/usr/bin/not-executable",elf,sizeof(elf),0600);
    elf[64]=1;blob_at("root/usr/bin/static-elf",elf,sizeof(elf),0700);
    elf_bytes(elf,183,"/lib/ld-linux-aarch64.so.1");elf[5]=2;blob_at("root/usr/bin/big-endian",elf,sizeof(elf),0700);
    elf_bytes(elf,183,"/lib/ld-linux-aarch64.so.1");elf[56]=2;memcpy(elf+120,elf+64,56);elf[80]=200;elf[128]=200;memcpy(elf+200,"/lib/ld-linux-aarch64.so.1",sizeof("/lib/ld-linux-aarch64.so.1"));blob_at("root/usr/bin/duplicate-interp",elf,sizeof(elf),0700);
    elf_bytes(elf,183,"/lib/ld-linux-aarch64.so.1");elf[128+strlen("/lib/ld-linux-aarch64.so.1")]='x';blob_at("root/usr/bin/interp-unterminated",elf,sizeof(elf),0700);
    elf_bytes(elf,183,"/unknown/ld.so");blob_at("root/usr/bin/unknown-interp",elf,sizeof(elf),0700);
    elf_bytes(elf,183,"/lib/ld-linux-aarch64.so.1");memset(elf+32,255,8);blob_at("root/usr/bin/phdr-overflow",elf,sizeof(elf),0700);
    char binlink[BX_SESSION_PATH];makepath(binlink,sizeof(binlink),"root/bin");
    if(symlink("usr/bin",binlink)<0){perror("bin link");return 2;}
    executable_case();script_case();failures_case();conversion_case();
    printf("RESULT: %s bx-enter checks=%u failures=%u\n",failures?"FAIL":"PASS",checks,failures);return failures?1:0;
}
#endif
