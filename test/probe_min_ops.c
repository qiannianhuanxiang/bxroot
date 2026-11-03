#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
int main(void){
    struct stat st;
    char b[256];
    fprintf(stderr,"A stat\n");  if(stat("/etc",&st)) {perror("stat");return 1;}
    fprintf(stderr,"B lstat\n"); if(lstat("/etc",&st)) {perror("lstat");return 1;}
    fprintf(stderr,"C realpath\n"); if(!realpath("/etc",b)) {perror("realpath");return 1;}
    fprintf(stderr,"D access\n"); if(access("/etc",F_OK)) {perror("access");return 1;}
    fprintf(stderr,"E done\n");
    return 0;
}
