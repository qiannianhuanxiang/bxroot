#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
/* Both implementation files share this translation unit: exercise real getter
 * and real reset, without redefining the C static keyword. */
#include "../../src/runtime/static_exec.c"
#include "../../src/runtime/sysvshm.c"
#include "../bx_tmpdir.h"

static int cloexec_file(void) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    return fd;
}
static int is_open(int fd) { return fcntl(fd, F_GETFD) >= 0; }

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "exec-check") == 0) {
        int fd = atoi(argv[2]);
        return fcntl(fd, F_GETFD) < 0 && errno == EBADF ? 0 : 1;
    }
    char dir[PATH_MAX]; if (bx_tmppath(dir, sizeof dir, "bxroot-static-anchor-XXXXXX")) return 1;
    int anchor;
    int ordinary, reused;
    if (!mkdtemp(dir) || bxroot_sysvshm_init(dir) != 0) { perror("anchor init"); return 1; }
    anchor = bxroot_sysvshm_anchor_fd();
    if (anchor < 0) return 1;
    int mapping_fd=openat(anchor,"seg-77",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(mapping_fd<0 || ftruncate(mapping_fd,4096) || close(mapping_fd)) return 1;
    long old_mapping=shm_do_at(77,0);
    if(old_mapping<0 && old_mapping>-4096) return 1;
    ((char *)old_mapping)[0]='X';
    if(shm_att_count(77)!=1) return 1;
    ordinary = cloexec_file();
    if (ordinary < 0) return 1;
    sx_reset_process_state();
    unsigned char resident=0;
    errno=0;
    if(shm_att_count(77)!=0 || mincore((void *)old_mapping,4096,&resident)!=-1 || errno!=ENOMEM) {
        fprintf(stderr,"FAIL static exec kept old SHM mapping\n");return 1;
    }
    if(unlinkat(anchor,"seg-77",0)) return 1;
    if (!is_open(anchor) || is_open(ordinary)) {
        fprintf(stderr, "FAIL valid anchor preservation ordinary close anchor=%d ordinary=%d\n",
                is_open(anchor), is_open(ordinary));
        return 1;
    }
    pid_t child=fork();
    if(child<0){perror("fork exec check");return 1;}
    if(child==0){char num[24];snprintf(num,sizeof num,"%d",anchor);execl("/proc/self/exe",argv[0],"exec-check",num,(char *)NULL);_exit(99);}
    int status;pid_t waited;do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    if(waited!=child||!WIFEXITED(status)||WEXITSTATUS(status)!=0){fprintf(stderr,"FAIL real exec CLOEXEC anchor\n");return 1;}
    close(anchor);
    reused = cloexec_file();
    if (reused != anchor) {
        fprintf(stderr, "FAIL fd reuse expected=%d got=%d\n", anchor, reused);
        return 1;
    }
    /* getter no longer identifies the closed anchor; reused CLOEXEC fd must close. */
    if (bxroot_sysvshm_anchor_fd() != -1) { fprintf(stderr, "FAIL real getter accepted reused fd\n"); return 1; }
    sx_reset_process_state();
    if (is_open(reused)) {
        fprintf(stderr, "FAIL reused fd survived static reset\n");
        return 1;
    }
    ordinary = cloexec_file();
    if (ordinary < 0) return 1;
    sx_reset_process_state();
    if (is_open(ordinary)) {
        fprintf(stderr, "FAIL invalid getter did not close ordinary fd\n");
        return 1;
    }
    puts("STATIC_SHM_FD_PASS");
    close(anchor);
    if (rmdir(dir) != 0) { perror("rmdir anchor"); return 1; }
    return 0;
}
