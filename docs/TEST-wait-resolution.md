# Wait 测试 RTLD_NEXT 假设修正

旧日志的7个失败全部是 late-dlopen stub 计数为0；真实子进程状态、WNOHANG/WUNTRACED/WNOWAIT边界与ledger已经成功。将RTLD_GLOBAL的后加载顺序解释成必然RTLD_NEXT命中并不成立：scope、已加载libc、linker服务及缓存都会影响选择。句柄dlsym直接调用也不等价于LD_PRELOAD PLT注入。

源码归属须区分：src/proc/proc.c提供ledger以及其自己的px_dlsym；当前源码wait导出实现位于src/runtime/preload.c，px_wait_dlsym经bxroot_next_symbol走linker服务或原生dlsym。wait3可回落wait4。当前源码不保证late stub为后端；观察构建产物真实执行成功也不能仅凭计数0认定选用了裸syscall fallback，具体后端需部署链追踪。本任务没有修改runtime。

修正后的两层验证：

- Runtime kernel-ledger：保留原有退出/信号/停止/WNOHANG/WNOWAIT/ECHILD/30轮账本断言，增加AArch64 inline svc wait4确认已回收的正PID再次返回ECHILD，防止只伪造返回值/账本却未等真实kernel。
- Independent stub：通过stub自身句柄直调waitpid/wait4/wait3/waitid；四入口检查真实退出状态及精确调用数1，waitid WNOWAIT后由裸kernel完成回收，再确认ECHILD。stub在AArch64使用inline svc，计数原子访问。late stub计数仅显示观察，不作为backend契约。

父进程隔离运行库构造副作用；所有测试kill检查正PID，只对fork的子进程操作。runner使用私有mktemp fixture、严格-Werror编译、timeout、唯一PASS标记；独立SIGKILL自检必须被父进程归类rc1，崩溃或缺完成标记不允许假PASS。

实际执行 `sh test/RUN_WAIT_TESTS.sh`：15 cases、69 checks、0 failed；stub四入口精确计数通过、runtime late stub仍0但kernel/ledger通过；崩溃自检rc1和wait四符号导出门禁通过。完整日志位于 /root/work/bxroot-wait-repaired.log。

仍不能证明：真实APK/guest LD_PRELOAD下PLT自动插入；真实fork hook自动ledger登记（本测试显式登记）；特定RTLD_NEXT/libc/raw fallback后端选择；跨线程并发解析安全性。需要在真实启动链另做调用者未显式dlsym的PLT注入测试，不能把本项PASS推广到该层。
