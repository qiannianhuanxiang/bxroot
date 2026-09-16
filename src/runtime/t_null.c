/* T1：空指针解引用 -> SEGV_MAPERR */
#include "crash.h"
int main(void){
    bxroot_crash_install("bxroot");
    volatile int *p = (int *)0;
    *p = 42;
    return 0;
}
