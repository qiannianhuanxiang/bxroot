# Termux 原生 SSH 能力证据

用户启用Termux sshd并安装本次临时公钥后，127.0.0.1:8022可连接。只读身份检查：UID/GID10399(u0_a399)，SELinux untrusted_app_27，AArch64 Android 6.1.145，TracerPid=0。这是Termux原生进程，不是共存DSHA应用UID，也不代表DSHA最终过滤器。

探针通过SSH标准输入传入Python，只操作本进程匿名内存、memfd或现有普通文件只读fd；未通过SSH写入/上传设备测试文件。

## copyout

bionic process_vm_writev八场景：normal112；NULL/invalid/readonly/PROT_NONE/unmapped/overflow=-EFAULT；cross-PROT_NONE短写56，后端需转换EFAULT。页面大小4096。全部与预期一致。未测试DSHA SIGSYS handler上下文。

## OFD对象差异

Android memfd fd_access_mode=O_RDWR，ctypes原生struct flock长32；F_GETLK/F_SETLK/F_OFD_GETLK/F_OFD_SETLK返回EACCES，F_SETLK64返回EINVAL。不能据此判定整个fcntl不支持。

已有Termux普通文件clang的O_RDONLY独立open句柄上，F_GETLK/F_SETLK/F_OFD_GETLK/F_OFD_SETLK读锁成功。第一个OFD取read lock后第二独立OFD用write query查到F_RDLCK/pid=-1；显式unlock后query为F_UNLCK。TERMUX_REGULAR_OFD_READ_QUERY_PASS。

尚未在本次新建普通文件上验证write-lock、并发EAGAIN、owner SIGKILL释放；这些仍不能称通过。

## 结构ABI

Termux clang通过stdin syntax-only与record layout输出bionic shmid64_ds：sizeof112/align8，ipc64_perm48，mode offset20，segsz48，atime56，cpid80，nattch88。

Ubuntu AArch64 glibc独立编译probe：sizeof(shmid_ds)=112，ipc_perm48，mode20，segsz48，atime56，cpid80，nattch88。以上已检查字段的大小/偏移相同。仍不声称全类型/不同Android版本布局通用一致。

## 后续范围

Termux入口解决了可访问原生应用UID和无PRoot追踪的验证条件，未解决DSHA应用UID策略、完整runtime加载或新建普通文件fixture写入路径。Android设备文件写入仍必须使用受保护设备shell；不能用SSH/SCP/远程Python文件写入绕过设备文件策略。
