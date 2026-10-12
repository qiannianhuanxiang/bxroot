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

## 后续范围

Termux入口解决了可访问原生应用UID和无PRoot追踪的验证条件，未解决DSHA应用UID策略、完整runtime加载或新建普通文件fixture写入路径。Android设备文件写入仍必须使用受保护设备shell；不能用SSH/SCP/远程Python文件写入绕过设备文件策略。
