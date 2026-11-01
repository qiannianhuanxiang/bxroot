#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
int main(void){
    char b[4096];
    char *r;
    fprintf(stderr,"A\n");
    r = realpath("/etc", b);
    fprintf(stderr,"B r=%p same=%d\n", (void*)r, r==b);
    r = realpath("/etc", NULL);
    fprintf(stderr,"C r=%s\n", r?r:"NULL");
    free(r);
    fprintf(stderr,"D ok\n");
    return 0;
}
