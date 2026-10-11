# AArch64 syscall 271 能力与 IPC_STAT fault 测试

本测试同时覆盖 runtime 使用的 `shm-copyout.h` helper。默认构建 `BXROOT_SHM_COPYOUT_VERIFIED=0`：有效地址的模拟 IPC_STAT 返回 ENOSYS，NULL/溢出返回 EFAULT，不执行 syscall 172/271，不直接解引用用户缓冲区。只有完整目标过滤链确认允许这些调用后，才能以 `-DBXROOT_SHM_COPYOUT_VERIFIED=1` 编译 runtime；这不是环境变量开关，也不改变继承的 seccomp 规则。真实目标新增过滤器后须重新验证。

开启后的 runtime 先在栈上构造 `struct shmid_ds`，再用 raw `process_vm_writev` 写回。负 errno 原样返回，短写统一 EFAULT，绝不 fallback 到 memcpy。保留当前 guest/glibc ABI，尚未声称支持 bionic/glibc 跨 ABI 结构转换。默认关闭会影响依赖 IPC_STAT 的 guest 程序，应在发布说明中显式标明。

无需给 sigsys/syscall_guard 增加 replay/ALLOW：inline svc 绕过符号 guard，已继承过滤器不能放宽；TRAP 271 不可重放同一个被禁调用。默认 gate 确保 handler 不发出新 syscall。

## 用法

```sh
sh test/RUN_COPYOUT_FAULT.sh --compile-only
sh test/RUN_COPYOUT_FAULT.sh                 # process_vm_writev raw svc 271
sh test/RUN_COPYOUT_FAULT.sh --ipc-stat      # 对当前继承 runtime 做故障测试
sh test/RUN_COPYOUT_FAULT.sh --gate-disabled # 默认gate: 不发syscall、不写目标
sh test/RUN_COPYOUT_FAULT.sh --safe-copyout  # 测试构建gate=1: 短写->EFAULT
```

交叉编译或将探针放进 APK guest 时，应在工作区先编译，再在**实际目标 guest 进程环境**运行二进制：

```sh
aarch64-linux-gnu-gcc -std=c11 -O1 -Wall -Wextra -Werror \
  -o probe-copyout test/shm/probe_copyout_fault.c
# 在目标 guest 会话运行（路径按实际部署设置）
./probe-copyout
./probe-copyout --ipc-stat
```

编译在非 AArch64 上也需通过，但运行返回 2；AArch64 编译期静态断言 SYS_process_vm_writev 等于271。目标上使用 inline svc，绕过 libc syscall 符号拦截。不得把 Ubuntu/宿主 shell 成功结果当作 APK guest 内能力证明。

## 隔离与判据

每个 case 都 fork 独立子进程，由父进程通过 pipe 收集结构化返回值，waitpid 判断退出或信号，不在主进程安装临时故障 handler。地址矩阵：正常栈缓冲、NULL、地址1、只读页、PROT_NONE、第一页RW/第二页PROT_NONE跨页、第一页RW/第二页只读跨页、munmap后的地址、地址范围溢出。

syscall271模式：正常情况必须返回完整结构体长度且字节相同；非法情况必须返回-EFAULT，跨页允许正的短写，并打印 SHORT_COPY_EFAULT_REQUIRED。将来 runtime 的 copy-out 必须把任何短写转为-EFAULT，不得声称复制原子性。负ENOSYS/EPERM分别记录；SIGSYS或显式159分别报告为能力不可用，不作成功。

IPC_STAT模式：子进程用IPC_PRIVATE创建自己的4096字节段，通过pipe先公布ID，再执行raw shmctl(IPC_STAT)。正常缓冲必须返回0且segsz=4096；非法缓冲必须返回-EFAULT。SIGSEGV、SIGBUS或在已创建段后SIGSYS均是失败。创建阶段ENOSYS/EPERM/SIGSYS属于当前环境能力不可用。父进程知道ID后另fork清理进程执行RMID，即使fault子进程崩溃也尝试回收，清理失败会报FAIL和ID，不删除未知对象。不映射该segment、不使用固定key。

返回码：0全部case通过；1构建/通信/回归/清理失败；2架构不符或内核/过滤能力不可用。runner使用60秒timeout和5秒强杀宽限；timeout、缺少完成标记、其他异常均为失败。不能保证父进程SIGKILL或段创建到pipe登记的窗口中绝无泄漏，遇超时需根据输出ID人工核查。

## 当前验证及限制

本次在当前AArch64工作容器执行raw271：正常复制112字节；NULL/invalid/readonly/PROT_NONE/unmapped/overflow=-14；两个跨页case均短写56字节；全部能力case通过。IPC_STAT模式在该环境的创建阶段返回ENOSYS，退出2，未实际创建SHM段。

该结果未覆盖Android APK最终guest过滤链。不能通过给已继承seccomp追加ALLOW来放宽旧过滤器，也不能仅在syscall_guard新增case保护inline svc。IPC_STAT结构布局测试使用当前编译环境struct shmid_ds；将来实现跨ABI写回前须检查glibc/bionic布局和实际guest ABI。
