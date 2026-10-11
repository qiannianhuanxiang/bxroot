# Runtime 构建与能力矩阵

## 构建入口

```sh
# 安全默认版：两个 gate 都关闭，输出不与 verified 版重叠
sh BUILD_RUNTIME.sh -O1
# 产物：build/libbxroot-runtime.so
# 元数据：build/BUILD-METADATA

# 仅在目标 APK guest 完整验证后构建
BXROOT_BUILD_PROFILE=verified \
BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 \
BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 \
sh BUILD_RUNTIME.sh -O1
# 产物：build/verified/libbxroot-runtime.so
# 元数据：build/verified/BUILD-METADATA
```

`BUILD_RUNTIME.sh` 默认强制 `copyout=0` 和 `claim=0`。即使调用环境误带 gate 环境变量，默认构建也不会开启它们。`verified` profile 必须同时显式设置两个 gate 为 `1`，否则构建失败。默认 profile 保持历史 `build/libbxroot-runtime.so` 路径；verified 使用独立目录，不会互相覆盖。

## 能力矩阵

| 能力 | 默认版 | verified 版 | 当前证据 | 生产 APK 状态 |
|---|---:|---:|---|---|
| `IPC_STAT` 有效缓冲 copy-out | `ENOSYS` | 可用 | `RUN_RUNTIME_STAT.sh` 两 gate 通过；原生 bridge 后端 STAT 成功 | 未验证完整 guest filter，不能盲开 |
| `IPC_STAT` 非法/只读/跨页地址 | `EFAULT` 或 gate-disabled | `EFAULT` | 8 个隔离地址场景通过 | 需目标 ABI/bionic 复核 |
| keyed SHM claim | `ENOSYS` | OFD nonblocking lock | `RUN_SHM_CLAIM.sh` 创建、竞争、SIGKILL 恢复和错误路径通过 | 需 APK guest 验证 fcntl 25 |
| `shmget(IPC_PRIVATE)` 新建 | `ENOSYS`，不创建 backing | 可用，需可回收 | claim 默认模式拒绝创建 | 不以手工 unlink 代替 API 回收 |
| `IPC_RMID` | `ENOSYS` | OFD 锁内删除 segment 后清 key | 删除失败保留原 key，INT_MIN 清理与错误传播测试 | 官方并发不受此锁约束 |
| static SHM 分发 | gate 约束 | handler/veneer 接入后端 | 四组合寄存器帧通过；真实 SHM TRAP 当前 rc2 | 不是静态 ELF 端到端通过 |
| SHM anchor fd | 启用 | 启用 | `STATIC_SHM_FD_PASS`、`ANCHOR_LIFECYCLE_PASS` | 已源码验证，仍非沙箱 |
| 原生 fork/wait 账本 | 启用 | 启用 | `NATIVE_CHAIN_FORK_WAIT_PASS` | 需最终 APK 入口复核 |

## Gate 开启条件

必须在实际 APK guest 进程中，以 inline syscall 探针确认：

- `getpid(172)` 可用；
- `process_vm_writev(271)` 可用且 handler 上下文不会被 seccomp TRAP；
- `fcntl(25)` 的 `F_OFD_SETLK` 可用；
- bionic 的 `struct shmid_ds` 布局与构建目标一致。

普通宿主、shell、Ubuntu 容器或外层 bridge 的成功结果都不能单独证明 APK guest 条件满足。当前设备 `run-as` 被策略阻止，且 UI 读屏目标不可用，因此 APK guest 矩阵仍是阻塞项。
