# Termux 原生 SSH 能力证据

用户启用Termux sshd并安装本次临时公钥后，127.0.0.1:8022可连接。只读身份检查：UID/GID10399(u0_a399)，SELinux untrusted_app_27，AArch64 Android 6.1.145，TracerPid=0。这是Termux原生进程，不是共存DSHA应用UID，也不代表DSHA最终过滤器。

copyout探针仅操作本进程内存；首次写锁探针曾在Termux home创建并在同一命令中清理临时文件，后续唯一owner强杀探针只使用现有普通文件只读句柄。未上传测试文件或保留设备夹具。

## copyout

bionic process_vm_writev八场景：normal112；NULL/invalid/readonly/PROT_NONE/unmapped/overflow=-EFAULT；cross-PROT_NONE短写56，后端需转换EFAULT。页面大小4096。全部与预期一致。未测试DSHA SIGSYS handler上下文。

## OFD对象差异

Android memfd fd_access_mode=O_RDWR，ctypes原生struct flock长32；F_GETLK/F_SETLK/F_OFD_GETLK/F_OFD_SETLK返回EACCES，F_SETLK64返回EINVAL。不能据此判定整个fcntl不支持。

已有Termux普通文件clang的O_RDONLY独立open句柄上，F_GETLK/F_SETLK/F_OFD_GETLK/F_OFD_SETLK读锁成功。第一个OFD取read lock后第二独立OFD用write query查到F_RDLCK/pid=-1；显式unlock后query为F_UNLCK。TERMUX_REGULAR_OFD_READ_QUERY_PASS。

普通文件写锁、竞争和显式解锁已补测；强杀恢复只读测试见下文，写锁强杀场景仍未取得独立正确实证。

## OFD 写锁补充

Termux home 临时夹具的首次探针验证了普通文件写锁：owner成功、独立句柄竞争EAGAIN、显式UNLCK后可重新取得。该探针随后发现父进程仍持有同一OFD时杀子进程不会释放锁；它错误打印了PASS，不能作为强杀证据，结果已排除。

第二个只读现有普通文件探针让唯一持锁子进程取得OFD读锁，父进程独立句柄查询到F_RDLCK/pid=-1；SIGKILL唯一owner后查询到F_UNLCK，输出`TERMUX_OFD_READ_SOLE_OWNER_KILL_PASS`。这证明Android内核普通文件OFD owner退出释放，但没有证明匿名memfd可用，也没有在Termux home保留测试文件。


Termux clang通过stdin syntax-only与record layout输出bionic shmid64_ds：sizeof112/align8，ipc64_perm48，mode offset20，segsz48，atime56，cpid80，nattch88。

Ubuntu AArch64 glibc独立编译probe：sizeof(shmid_ds)=112，ipc_perm48，mode20，segsz48，atime56，cpid80，nattch88。以上已检查字段的大小/偏移相同。仍不声称全类型/不同Android版本布局通用一致。

## 真实 SIGSYS 上下文能力

不落设备文件的ctypes子进程探针安装SA_SIGINFO处理器，只TRAP getppid(173)，其他调用保留继承策略。8秒alarm兜底。实测si_code=1、保存x8=173、regs起点184；handler写x0=4242，syscall返回4242。handler内getpid成功、process_vm_writev正常复制16字节、已有普通文件OFD读锁/解锁成功，child退出0，TERMUX_SIGNAL_CONTEXT_CAPABILITY_PASS。

该探针仅证明Termux UID下信号帧和调用可达，Python/ctypes回调不是生产异步信号安全实现；没有执行bxroot完整SHM handler，也没有验证DSHA UID最终filter。bionic sigaction sizeof32（flags0/handler8/mask16/restorer24），ucontext.mcontext176、regs184均通过clang stdin layout核对。

## 源码回归 runner（用户在原生 Termux 执行）

用户在原生 Termux 执行 `test/RUN_TERMUX_NATIVE.sh`。祖先链因 `hidepid=invisible` 停在 UID 边界（`ANCESTRY_BOUNDARY pid=1890`），同 UID 链 TracerPid=0。TMPDIR 使用 `$PREFIX/tmp`。

结果目录：`~/bxroot-native-run-0r16TE/bxroot-termux-native/termux-results-ZAuNuO`，`uid=10399`。

| 项 | rc | 标记 |
|---|---|---|
| copyout | 0 | `RUNTIME_IPC_STAT_PASS`（gate 0/1 各 8 地址） |
| claim | 0 | `RESULT: SHM claim PASS` |
| id_aba | 0 | `SHM_ID_ABA_PASS` |
| fork_gate | 0 | `SHM_FORK_GATE_PASS` |
| static_reset | 0 | `STATIC_SHM_FD_PASS` |
| static_trap | 0 | `RESULT: static SHM syscall PASS` |
| l2s_mock | 0 | `RESULT: L2S mock closure PASS`（5/28） |
| l2s_native | 0 | `RESULT: PASS`（18 cases / 153 checks） |
| integration | 1 | `RESULT: FAIL`（7 cases 中 4 失败 / 47 checks 中 4 失败） |

`static_trap` 在原生 Termux 上第一次走到 bxroot SHM SIGSYS：`FRAME ready=1 code=1 nr=194 offset=184`，四组 gate 均 `STATIC_SHM_SYSCALL_PASS`。这替代了外层 PRoot 下的 `TRAP_UNREACHED`。它仍不是 DSHA UID 下的最终过滤器。

`l2s_native` 在真实可写文件系统上 153 项检查通过，替代外层 PRoot 下的原生 l2s FAIL。

`integration` 四项失败都是 `st.st_uid=10399` 期望 `0`。测试把 fakeroot 的 `real_uid` 写死为 2000（旧 shell UID），启发式只在 `st_uid == real_uid` 时改写，Termux 文件属主是 10399，所以不改。l2s 链长断言未失败。已改为 `getuid()`/`getgid()`，待用户再跑一次该测试确认。

## 后续范围

Termux 源码回归覆盖了 SHM copyout/claim/ABA/fork/static trap 与原生 l2s。未解决：共存 APK 的 DSHA UID 过滤链、完整 LD_PRELOAD runtime 加载、官方 proroot 混合并发、高风险 mount/chroot 审计。Android 设备文件写入仍必须使用受保护设备 shell；不能用 SSH/SCP/远程 Python 文件写入绕过设备文件策略。
