/* T3：栈溢出 -> 验证 sigaltstack */
#include "crash.h"
static volatile int depth = 0;
static void recurse(void){
    char pad[4096];
    pad[0] = (char)depth;
    depth++;
    recurse();
    if (pad[0] == 127) depth = 0;
}
int main(void){
    bxroot_crash_install("bxroot");
    recurse();
    return 0;
}
