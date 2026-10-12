# Runtime 构建发布说明

## 本轮决策

默认发布构建保持两个 gate 关闭：

- `BXROOT_SHM_COPYOUT_VERIFIED=0`
- `BXROOT_SHM_CLAIM_VERIFIED=0`

这是保守兼容策略，不是功能完整策略。默认版不会在未知 Android seccomp 链中盲发 `process_vm_writev(271)` 或 `fcntl(25)`；相应 keyed SHM 和有效 `IPC_STAT` copy-out 会明确返回 `ENOSYS`。依赖这些功能的 guest 程序可能看到能力缺失，发布说明必须明确这一点。

## Verified 构建

只有在实际目标 APK guest 进程内完成能力矩阵后才允许：

```sh
BXROOT_BUILD_PROFILE=verified \
BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 \
BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 \
sh BUILD_RUNTIME.sh -O1
```

Verified 产物位于 `build/verified/`；默认产物仍位于历史兼容路径 `build/libbxroot-runtime.so`，并写入 `build/BUILD-METADATA`。两个 profile 不会互相覆盖。

## 尚未满足的发布条件

当前设备上的 shell 通道可用，但 `run-as` 受设备策略拦截，UI 读屏目标也不可用。因而尚未完成 APK guest 的 syscall/seccomp/bionic ABI 验证，不能把 verified runtime 作为已验证 DSHA APK 发布。

v0.2.3 源码发行使用默认 gate=0。verified runtime 仍不作为默认 APK 部署。本仓库不上传 DSHA APK 或 DSHA 源码。
