/* T2：写只读代码段 -> SEGV_ACCERR，应走内存窗口分支 */
#include <stdint.h>
#include <string.h>
#include "crash.h"
int main(void){
    bxroot_crash_install("bxroot");
    void (*f)(void) = (void (*)(void))main;
    memcpy((void *)(uintptr_t)f, "X", 1);
    return 0;
}
