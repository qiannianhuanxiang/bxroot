# bxroot 小型底层项目源码对照审计

日期：2026-09-28

## 范围

本次实际获取并检查了以下仓库的源码：

- https://github.com/termux/termux-exec
- https://github.com/dex4er/fakechroot
- https://github.com/termux/libandroid-shmem
- https://github.com/proot-me/proot-rs
- https://github.com/vasi/squashfuse

本地对照对象为 bxroot 当前工作树，最新提交 `6181811 fix: harden native session descriptors`。

## 结论摘要

bxroot 当前的 exec 路径处理已经明显超过 fakechroot 的基础实现：`src/proc/proc.c` 已覆盖 `execve`、`execv`、`execvp`、`execvpe`、`execveat`、`fexecve`，并有 shebang、`AT_EMPTY_PATH`、裸 syscall 和 guest PATH 处理。此处不建议直接移植 fakechroot 的 exec 实现。

最有价值的外部参考是 Termux exec 的测试和 Android 特殊边界，而不是其主体代码。建议优先补：

1. `execve`/`fexecve`/`execveat` 的 Android 系统目录与非 ELF 文件边界回归测试。
2. envp 重写、`LD_PRELOAD` 清理和 reentry 防递归测试。
3. Android SysV SHM / ashmem 兼容测试，尤其是跨 fork/exec 和并发 key 分配。
4. squashfuse 只读 rootfs 的独立可选组件设计，不要并入当前核心 runtime。

本轮没有发现足够确定、低风险且应立即修改的核心缺陷，因此没有改动 bxroot 源码。

## 逐项结果

### 1. termux-exec：高价值参考，适合补测试

源码重点：`ExecIntercept.c`、`ExecVariantsIntercept.c`。

它明确处理了这些边界：

- `fexecve()` 的 `/proc/self/fd/N` 还原。
- 绝对路径先规范化，再做前缀替换。
- 相对路径先按 cwd 绝对化，再规范化，避免 `../` 被提前错误裁剪。
- 系统目录下的可执行文件可能无法读取 ELF 头，因此不能一律 `open + read header`。
- 非 ELF 文件、目录、socket、pipe 的 exec 错误码需要接近 Android 行为。
- 环境中的 `LD_PRELOAD`、`LD_LIBRARY_PATH` 需要按目标是否为系统程序决定是否清理。
- `fexecve` 在旧 Android API 上有特殊 fallback。

bxroot 已具备的对应能力：

- `src/proc/proc.c` 已实现 exec 家族和 shebang 处理。
- `execveat(..., AT_EMPTY_PATH)` 和 `fexecve` 已走统一 trampoline。
- `src/runtime/syscall_guard.c` 已识别裸 `execveat`。
- `src/launcher/launcher.c` 已有 ELF/shebang 诊断。

建议：吸收 Termux 的测试场景，不复制其 glibc/Termux 特定路径代码。重点加入：

- `/system/bin`、`/vendor/bin` 目标不能读头时的行为。
- `fexecve` 指向目录、FIFO、socket、已删除文件和 memfd 的错误码。
- `LD_PRELOAD=` 空值、多个 preload、目标为系统 ELF 和 guest ELF 的差异。
- `execvp` 从 guest PATH 搜索时的相对路径和 `..` 组合。

### 2. fakechroot：接口覆盖清单，不适合直接合并

源码显示其核心是 libc 符号 wrapper 和 `dlsym(RTLD_NEXT)`，覆盖 `openat`、`statx`、`realpath`、`execve`、`execvp` 等。

可借鉴：

- `__openat_2`、`__openat64_2` 等 fortified/glibc 入口容易被漏掉。
- `realpath`、`canonicalize_file_name` 和 `execve` 之间存在递归风险。
- exec 前要重建 envp，并防止旧的 fakechroot 变量重复注入。
- hashbang 解释器需要参与路径转换。

不应直接移植：

- 该项目大量依赖 glibc 内部符号和 glibc ABI。
- Android bionic 的符号导出、FORTIFY 和 linker 行为不同。
- bxroot 已经有自己的裸 syscall、l2s、fakeroot 和 native session 层，直接叠加会产生双重翻译。

建议仅做覆盖审计：核查 Android bionic 中可见的 `__openat_2`、`open64`、`execvpe`、`canonicalize_file_name` 是否需要弱符号或别名测试。

### 3. libandroid-shmem：小而有用，适合兼容性测试

该项目把 SysV SHM API 映射到 ashmem 和 Unix socket，并维护跨进程的 shmid/FD 对应关系。它覆盖 `shmget`、`shmat`、`shmdt`、`shmctl`，并测试了：

- fork 后父子进程共享段。
- `IPC_PRIVATE`。
- key 查找和跨进程发现。
- `IPC_RMID` 延迟删除。
- 指定地址 attach。
- 错误码和死锁场景。

bxroot 已有独立的 `src/runtime/sysvshm.c`，并且通过 SIGSYS 模拟 AArch64 裸 syscall 194..197。这比普通 LD_PRELOAD 方案更适合处理内联 `svc`。

值得吸收的不是 ashmem 后端，而是测试矩阵：

- fork 后 attach/detach。
- exec 后通过共享目录重新发现段。
- 并发 `IPC_CREAT|IPC_EXCL`。
- `IPC_RMID` 后已有映射继续可用。
- `SHM_RDONLY`、指定地址和无效 id。
- 目录权限、临时文件清理和跨进程 key 冲突。

特别注意：bxroot 的 SHM 实现使用文件作为跨进程账本，必须持续检查目录是否位于受保护的 host bind 之外，避免 guest 能通过路径参数影响宿主任意位置。

### 4. proot-rs：行为对照，不建议移植

该仓库的价值是对照 PRoot 的进程/ptrace 状态机，尤其适合发现：

- clone/fork/exec 的继承关系。
- 多线程下 syscall 状态。
- 信号转发和子进程回收。
- exec 失败时的恢复路径。

bxroot 采用 LD_PRELOAD、SIGSYS、裸 syscall 和 native session，架构完全不同。直接引入 Rust 运行时会扩大 Android APK 体积和 ABI 风险，不建议作为当前实现依赖。

建议用途：建立差分测试样本，而不是复制代码。相同 rootfs 和命令分别运行 PRoot、proot-rs、bxroot，比较 cwd、`/proc/self/exe`、signals、exec 退出码和 fd 泄漏。

### 5. squashfuse：rootfs 分发方向，保持独立

squashfuse 的价值在于只读压缩 rootfs、inode 映射、缓存和 FUSE 生命周期处理。它适合未来做：

```text
只读 SquashFS 基础 rootfs + 用户可写工作目录 + bxroot 路径/exec 层
```

但当前不宜并入核心 runtime：

- Android 设备的 FUSE 能力和挂载策略不统一。
- FUSE daemon 生命周期会增加 session fd 和崩溃清理复杂度。
- bxroot 当前路径翻译已经假定明确的 host/guest bind 身份。

建议做成独立的 `bxroot-rootfs` 可选工具，先验证：挂载失败时能否无损回退到目录 rootfs、应用退出时是否可靠卸载、以及只读镜像是否会泄漏 host 绝对路径。

## 风险审计

### 已确认没有重复实现的问题

- exec 家族不是当前明显缺口；`proc.c` 已覆盖多个入口。
- SysV SHM 不是简单的 ENOSYS 空实现；已有 SIGSYS 模拟和持久化目录协议。
- `statx`、`newfstatat`、`readlinkat`、`renameat2` 等裸 syscall 已有专门处理路径。

### 仍需重点验证的风险

1. **系统 ELF 头读取边界**：Android 系统分区中的程序可能可执行但不可读。需要确认 bxroot 不会把“读不到头”错误地变成 guest 路径失败。
2. **环境变量清理**：native reentry 过程中，guest 的 `BXROOT_*`、`LD_PRELOAD`、`LD_LIBRARY_PATH` 和宿主专用变量必须按层次保留或清理，避免递归加载和 host 路径泄漏。
3. **SHM 目录权限**：`_SHM_HOST` 对应目录应始终由 host 创建并限制权限；不能仅信任 guest 传入的路径字符串。
4. **FUSE rootfs 生命周期**：未来引入 squashfuse 时，必须把 mount fd、daemon pid、session fd 绑定到同一生命周期，避免残留挂载和 stale session。
5. **fortify 符号覆盖**：Android/bionic 和不同 NDK 版本下，`openat` 的 fortified 入口可能不同，需通过编译和运行时探针确认，不能只看 glibc 符号表。

## 推荐实施顺序

### P0：只加测试，不改核心语义

- 从 Termux exec 提取 10-15 个 Android exec 边界用例。
- 从 libandroid-shmem 提取跨 fork/exec、并发 key、RMID 和只读 attach 用例。
- 增加 guest/host 环境变量快照，检查 reentry 前后是否有宿主路径泄漏。

### P1：小范围兼容增强

- 对 bionic 可见的 fortified exec/open 入口补弱别名或构建探针。
- 将系统目录 ELF 头读取策略抽成单独测试函数，避免改动现有路径翻译。
- 完善 SHM 临时文件异常退出后的清理和权限检查。

### P2：独立实验组件

- 设计 `bxroot-rootfs`，先支持 squashfuse 只读镜像和目录 rootfs 二选一。
- 不把 FUSE 依赖放入 `libbxroot-runtime.so`，防止普通 APK 安装包和启动路径变重。

## 本轮落地变更

在审计后完成了以下低风险修复：

- launcher 将“存在但解释器缺失”的脚本从 ENOENT 分类为退出码 126；失败分类只做 `stat`，不再读取未知文件，避免 FIFO 阻塞。
- CRLF 测试允许当前执行环境明确接受 CRLF shebang 的结果，同时仍检查输出和退出码。
- SysV SHM 后备目录创建后重新以 `O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK` 打开并检查目录类型和权限。
- SHM segment、key 和临时 key 文件打开增加 `O_NOFOLLOW`，读取路径增加 `O_NONBLOCK`。
- key 发布严格检查写入长度，失败时删除临时文件。
- `RUN_SYSVSHM.sh` 不再把 timeout 或静默失败的空输出判为 PASS。

验证结果：

- `sh test/RUN_EXEC_DIAG.sh`：PASS。
- `sh test/RUN_PROC_FD.sh`：63 passed / 0 failed。
- `sh test/RUN_WARN_GATE.sh -v`：21 个编译单元零告警。
- `BX_SESSION_ALLOW_OUTER_PROC_DUP=1 sh test/RUN_HOST_SESSION.sh`：372/372 PASS，2 个平台行为跳过。
- `sh test/RUN_SYSVSHM.sh`：当前工作环境因没有外层官方 proroot 对照而按约定跳过。

本轮仍未解决、已明确保留为后续任务的 SHM 风险：key 删除/重建 TOCTOU、attach 表 ABA、非法 `IPC_STAT` 输出指针、完整的 IPC_RMID 延迟语义和 orphan 回收。这些需要更大的协议或信号安全设计，不应通过普通信号处理器锁快速修补。

## 下一轮加固结果

继续完成了以下改动：

- SHM key 内容和目录文件名采用有界 31-bit 十进制解析，拒绝溢出、尾随垃圾和截断记录。
- 后备目录检查当前 UID、目录类型和私有权限；segment/key 打开后检查普通文件、owner 和权限。
- attach 表改为 64-bit `state + generation` 控制字：`FREE -> RESERVED -> ACTIVE -> DETACHING`，detach 在 `munmap` 完成前不释放槽位，避免地址 ABA 和旧长度卸载新映射。
- attach 表要求本机 native atomics lock-free，并对 id/addr/len 使用原子访问或控制字发布顺序。
- SHM 语义探针非零或 timeout 现在记为失败，不再降级为环境跳过。

验证结果：

- 编译告警门禁：21 个编译单元零告警。
- exec 诊断回归：PASS。
- proc fd 回归：63/63 PASS。
- shell 语法和 `git diff --check`：通过。

## 探针加固结果

本轮继续完成：

- `probe_shm_xproc.c` 增加参数、长度、attach/detach、RMID 和 absent 结果检查，避免对 `(void *)-1` 解引用。
- `probe_shm_race.c` 改为结构化 pipe 传递子进程 ID，检查 fork、barrier IO、waitpid、线程创建/回收、唯一 ID、计数、nattch 和最终清理，并要求输出 `RACE_DONE`。
- `RUN_SYSVSHM.sh` 对互通阶段的每次调用检查退出码和 payload；并发阶段检查 timeout、完成标记和精确输出。
- 原生 Ubuntu 环境实测 SysV IPC 被 seccomp 禁用（`ENOSYS`），因此只能确认探针在该环境下明确失败，不能把它当作 bxroot runtime 结果。

## IPC_STAT 非法指针结论

## 一次性并行处理结果

> 下文为历史审查快照；最新源码和验证状态以 `TEST-shm-final-closure.md` 为准。后续已接入 copyout gate、OFD claim 和固定目录 fd，生产端到端验证仍未完成。

本轮并行完成三项工作：

- 发布失败处理已收紧：只有 `EEXIST` 走竞争分支；其他错误清理自有 segment 后原样返回；竞争赢家必须重新读取并确认 segment 存在。
- 新增 `RUN_COPYOUT_FAULT.sh` 和 `probe_copyout_fault.c`，独立 fork 测试 AArch64 raw syscall 271 的正常、NULL、无效、只读、PROT_NONE、跨页、unmapped 和溢出地址。
- 固定目录 fd 方案完成生命周期审查，但未直接并入：它必须协调 static exec 的 CLOEXEC 清理、runtime 重初始化、内部 fd 关闭/复用保护，不能只新增一个全局 fd。

当前容器的 raw `process_vm_writev(271)` 探针通过：正常复制 112 字节；非法地址返回 `-EFAULT`；跨页不可写返回 56 字节短写。该结果只代表当前容器过滤链，不能外推 Android APK/guest seccomp 链。`--ipc-stat` 在当前环境因 SysV IPC 创建返回 `ENOSYS`，正确退出 2。

仍未完成且不能伪称已修复：

- `IPC_STAT` runtime 安全 copy-out 尚未接入；直接写用户指针仍有 SIGSEGV 风险。
- key 删除/重建 TOCTOU 尚未解决。普通 quarantine rename + 事后校验存在确定性反例，不能作为条件 CAS。
- 固定目录 fd 尚未接入核心 runtime；父路径替换、static exec 生命周期和内部 fd 复用仍需整体设计。


本轮三个专项审查达成一致：

- `IPC_STAT` 不能在未确认 syscall 271/seccomp 能力前接入 `process_vm_writev`，也不能保留直接指针写作为 fallback。
- key 删除/重建 TOCTOU 需要 quarantine/代际协议；当前实现仍不能宣称完整并发语义。
- 后备目录仍使用绝对字符串路径，`O_NOFOLLOW` 只保护末端对象，不能完全消除父路径组件替换竞态；长期应改为初始化时固定目录 fd。

已落地的低风险修复：

- 删除 `shm_mkdir()` 在 SIGSYS handler 内裸调用 `getuid` 的新增风险。
- `getdents64` 目录项解析增加 `reclen` 和边界检查。
- race 探针记录成功 fork 数量，避免 fork 失败后遍历未初始化 `kids[]`。
- xproc/互通测试使用 runner 生成的独立 key，不再无条件 RMID 固定未知对象。
- 互通测试先清理官方创建的段，再单独验证 bxroot 发布路径。

验证：三个 SHM 探针以 `-Wall -Wextra -Werror` 编译通过；编译告警门禁零告警；exec 和 proc fd 回归通过。当前 `IPC_STAT` 仍不能直接写入任意用户指针：在 SIGSYS handler 内直接 `memset(ds)` 会把无效、只读或跨页地址变成进程 SIGSEGV，而不是 EFAULT。

审查后确认，推荐的 `process_vm_writev` copy-out 方案需要先确认 Android seccomp 允许 AArch64 syscall 271，并同步 syscall guard/能力探测；不能在 handler 内盲调，否则被 TRAP 的嵌套 SIGSYS 可能再次终止进程。本轮没有接入未验证的 fallback，也没有宣称该风险已修复。下一步应先增加设备能力探针和允许/拒绝路径，再实现栈上临时 `shmid_ds` 到用户缓冲区的内核 copy-out。

`probe_shm_spec.c` 现在登记所有成功创建的 segment 和 attach，普通失败路径及 `atexit` 都会 detach 并 RMID 本探针创建的对象。删除了把 key `0x55` 当作 shmid 的调用，改用由本探针取得的 `key_id`；无效 ID 使用 `-1`。1 TiB sparse-segment 探针即使创建成功也会登记并清理，且不映射该段。完成时输出 `SPEC_DONE`，runner 要求两侧都正常退出并出现该标记。

验证：探针以 `-Wall -Wextra -Werror` 编译通过；在当前原生环境执行时明确以 `ENOSYS` 失败（SysV IPC 被环境禁用），因此没有运行会创建实际共享内存对象的路径。launcher 和 proc fd 回归仍通过，编译告警门禁零告警。


## 最终并行收尾

已完成并验证：

- SHM 后备目录固定 anchor fd：初始化阶段创建并校验，handler 使用相对 leaf 操作；扫描使用独立目录 OFD；anchor 失效时 fail-closed；static exec 按经过 fstat 校验的 getter 保留 anchor，避免 fd 数字复用误保留。
- bxroot 内部 keyed mutator 使用非等待 claim 文件协调 `shmget`、stale 清理和 RMID；claim 忙时返回 `EAGAIN`，测试 caller 做有限重试。该协议不约束未采用它的官方 proroot 进程，混合并发仍有边界。
- IPC_STAT 只在栈上构造结果并调用 `shm-copyout.h`；默认 gate 返回 `ENOSYS`，验证过完整过滤链后才允许构建 `BXROOT_SHM_COPYOUT_VERIFIED=1` 使用 raw 172/271。无直接用户指针写回和 memcpy fallback。
- `Makefile` 和告警门禁均包含 `sysvshm.c` / `shm-copyout.h`。

最终验证：22 个编译单元零告警；SHM/copyout/anchor 探针编译通过；copyout gate-disabled 和 safe-copyout 通过；anchor 生命周期通过；exec、proc-fd、session 回归通过；脚本语法和 diff 检查通过。

客观限制：当前原生环境 SysV IPC 创建返回 ENOSYS；Android APK/guest 最终 seccomp 链和 bionic `shmid_ds` ABI 尚未验证；普通 rename/quarantine 之外的官方混合进程不受 bxroot claim 协议约束；static-exec 的同进程并发 close/reuse 仍不是安全沙箱保证。默认构建禁用 IPC_STAT 是有意的兼容性收缩，发布说明必须明确。
