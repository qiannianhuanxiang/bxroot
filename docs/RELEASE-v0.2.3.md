# bxroot v0.2.3

源码与运行库发行。不含 DSHA APK、DSHA 源码或设备数据。

## 相对 v0.2.2 的要点

- SysV SHM：默认 gate 关闭；claim 协议、ID ABA、fork 门、static SIGSYS 194–197。
- 静态 ELF 进程内执行 + 官方 `PROROOT_CFG_FD`。
- SIGSYS 影子槽；livepatch 扫 libc 全部 r-x 段并复位保护位。
- native session v3 回入口保持；default / verified 构建隔离。

## 构建

```sh
sh BUILD_RUNTIME.sh -O1
# verified 仅在目标 guest 过滤链已核过时使用
BXROOT_BUILD_PROFILE=verified \
BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 \
BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 \
sh BUILD_RUNTIME.sh -O1
```

默认 so：`build/libbxroot-runtime.so`（`copyout_verified=0` `claim_verified=0`）。
verified so：`build/verified/libbxroot-runtime.so`。

## 验证摘要

| 环境 | 结果 |
|---|---|
| 编译告警门 | 22 单元零告警 |
| 原生 Termux UID 10399 | SHM copyout/claim/ABA/fork/static trap、l2s native 153、integration 47 |
| 共存测试包 guest（仓库外） | reentry=1、TracerPid=0、ldconfig.real、node 24 + 4 worker、exit 7 |

## 边界

- 默认构建会明确拒绝新建 SysV SHM；不要把「SHM 不能建」当成回归失败。
- 官方 proroot 不用 `.claim-lock` / `.id-ID`，混合并发不保证。
- 文件式 RMID 与本进程 `nattch`，不是完整 Linux 延迟删除。
- bxroot 不是 Android root，也不是安全沙箱。
