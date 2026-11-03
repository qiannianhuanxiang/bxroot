# bxroot v0.2.5

源码与运行库发行，不含 DSHA APK、DSHA 源码或设备数据。附件：`bxroot-v0.2.5-android-arm64.tar.gz`（运行库）、`bxroot-v0.2.5-source.tar.gz`（源码，`git archive v0.2.5`）、`SHA256SUMS.txt`。

## 变化

| 项 | 默认 | 说明 |
|---|---|---|
| Termux 路径兼容 | 开 | Termux 前缀 shebang、`$PREFIX/...`、Termux home 在 `translate_path` 里先改写成 Ubuntu 布局（`$PREFIX`→`/usr`，`$PREFIX/{etc,var,tmp}`→`/{etc,var,tmp}`，home→`/root`）。rootfs 在 `com.termux` 下时自动关闭；`BXROOT_NO_TERMUX_COMPAT=1` 关闭 |
| 静态映像 seccomp 兜底层 | 关 | `BXROOT_SECCOMP_FALLBACK=1`：只对映像地址范围内的路径类调用 TRAP，接住改写漏掉的 `svc` |
| 寄存器取号 svc 改写 | 关 | `BXROOT_SVC_ALL=1`：号来自寄存器的 `svc` 站点（如 Go `syscall.Syscall6`）进跳板 |
| 原生调用集成 | — | `bx-host` 间接 `execve`；两个静态执行跳板保存/恢复 x18；session 初始化失败告警并关闭回入口 |
| launcher `-V` | — | `0.2.5` |

## 验证

| 项 | 结果 |
|---|---|
| Termux 映射纯函数 `test/probe_termux_compat.c` | 37 / 37 |
| `test/RUN_TERMUX_COMPAT.sh`（真实 runtime） | 8 / 8 |
| 真机 DSHA build214（vivo V2352A / Android 16） | Termux shebang 脚本输出 `ok`；`cd` Termux home 后 `pwd -P` = `/root` |
| `test/test_seccomp_fallback.c` | A–I 全过（容器 aarch64） |
| `test/test_seccomp_fallback_e2e.c` | 关闭 ENOENT、开启翻译成功 |
| 兜底开销（容器） | 过滤器对非陷阱调用约 0 ns；陷阱固定成本约 1.06 µs |

## 边界

- Termux 兼容只处理路径：不提供 `pkg`，不跑 Termux 的 bionic 二进制，不设 `PREFIX` / `TERMUX_VERSION`，不含 Termux:X11/Boot/Widget。
- seccomp 兜底层**未经真机验证**：继承过滤器的原生子进程、真 Go 二进制未测，所以默认关。
- 其余同 v0.2.4：bxroot 不是安全沙箱；默认构建拒绝新建 SysV SHM。
