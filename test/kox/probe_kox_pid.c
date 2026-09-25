#include <stdio.h>
#include <unistd.h>
int main(void){ printf("%d %d\n",getpid(),getppid()); return 0;}
