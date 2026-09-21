# bxroot 与 DSHA 的边界

> 本文说明 bxroot（本独立项目）与 DSHA（Android 应用）之间的接口边界。
> 用户已明确定调：**bxroot 保持独立通用项目，定制只放在 DSHA 里面。**

## 边界在哪

| | bxroot | DSHA |
|---|---|---|
| 提供什么 | 5 个 .so、`BXROOT_*` 环境变量、`-r/-w/-b/-0` 参数 | 5 个 .so 的打包、一个 Java 适配类 |
| 是否知道对方 | **不知道 DSHA 存在** | 知道 bxroot 的接口约定 |
| 定制内容 | 无 | 仅配置翻译，无 bxroot 内部逻辑 |

## bxroot 对外契约（DSHA 依赖这些，改动需双方同步）

### 命令行（`launcher.c`）

```
libbxroot.so -r <rootfs> [-w <workdir>] [-b <host>:<guest>]... [-0] [--link2symlink] [-v] <guest-exe> [args...]
```

### 环境变量

| 变量 | 谁设置 | 用途 |
|---|---|---|
| `BXROOT_LIB_PATH` | DSHA | 显式指定 runtime .so 路径（优先于自身目录推断） |
| `BXROOT_LINKER_PATH` | DSHA / launcher | linker 路径 |
| `BXROOT_STUB_LOADER` | DSHA / launcher | stub loader 路径 |
| `BXROOT_TMP_DIR` | DSHA | 临时目录。**launcher 只在环境里没有时才填默认值** |
| `BXROOT_L2S_DIR` | DSHA / launcher | l2s 中间层目录，默认 `<rootfs>/.l2s` |
| `BXROOT_ROOTFS` | launcher（由 `-r` 派生） | 运行时读它做路径翻译 |
| `BXROOT_GUEST_EXE` | launcher | guest 可执行路径伪装 |
| `BXROOT_WORKDIR` | launcher（由 `-w` 派生） | 工作目录 |
| `BXROOT_FAKEROOT` | launcher（由 `-0` 派生） | 伪装 uid=0 |
| `BXROOT_LINK2SYMLINK` | launcher（由 `--link2symlink` 派生） | 启用 l2s |
| `BXROOT_BINDS` | launcher | bind 列表（`src:dst;src:dst`） |
| `BXROOT_VERBOSE` | 任一方 | 排障日志（注意 `LOG` 宏还受**编译期**开关约束） |

**约定**：`BXROOT_ROOTFS` / `BXROOT_GUEST_EXE` / `BXROOT_WORKDIR` /
`BXROOT_FAKEROOT` / `BXROOT_LINK2SYMLINK` 一律**由 launcher 从 argv 派生**，
DSHA 侧不要重复设置 —— 两边都设会让"以 argv 为准"这条约定失效，
且顺序不同时行为不可预期。DSHA 只设 `LIB_PATH` / `LINKER_PATH` /
`STUB_LOADER` / `TMP_DIR` / `L2S_DIR`。

## 两个只有 DSHA 场景才暴露的 trap

### 1. app 私有目录禁 `link(2)`（SELinux）

限制来自 **SELinux 而不是文件系统** —— ext4/f2fs 本身支持硬链接。
所以「在可写目录里试 `link()`」这种探针在 app 进程里可能给出与真实
客户进程不同的答案。DSHA 因此**无条件**传 `--link2symlink`。

代价：不开模拟时 pnpm/dpkg/tar 的每次硬链接操作都在失去模拟的情况下
运行，而且**失败是静默的**。

### 2. l2s 链存的是宿主绝对路径

客户进程必须能按**同一路径**访问到 l2s 中间层，否则 dpkg 安装时对
硬链接执行 chown/stat 会报「文件不存在」。因此 `--link2symlink` 必须
配套把该目录 bind 到相同的宿主绝对路径。

bxroot 侧的默认值（`<rootfs>/.l2s`）已与 DSHA 的 `PROOT_L2S_DIR` 对齐，
但 DSHA 仍应显式给出，避免将来默认值变动时静默失配。

## DSHA 侧的第三个 trap（在 DSHA 代码里，不在 bxroot 里）

`WebProcSel.looksLikeWeb()` 排除容器启动器用的是 `contains("proot")`，
而 **`"bxroot"` 不含 `"proot"` 子串**。新增 bxroot 运行时后若不改这个
判据，「停止 Web」会把承载整个环境的启动器杀掉。已修，详见 DSHA 侧
`WebProcSelTest#neverMistakesBxrootLauncherForWeb`。

## 本轮 bxroot 侧的改动（与 DSHA 无关，属独立项目自身）

| 文件 | 改动 |
|---|---|
| `src/runtime/livepatch.c/.h` | **新增**：seccomp 中和（2 个站点） |
| `src/runtime/syscall_guard.c` | **加路径翻译**：node/libuv 用 `syscall(291)` 直发 statx，绕过符号钩子 |
| `src/runtime/sigsys.c/.h` | 新增 SIGSYS 兼容层（`__libc_sigaction` 修正） |
| `src/runtime/preload.c` | l2s stat 契约接线（`bl` 0→10）、livepatch 接线、真 NUL 字节修复 |
| `BUILD_RUNTIME.sh` / `Makefile` | 纳入全部新层 |

产物：`build/libbxroot-runtime.so`，225896 字节，**328 导出符号**。
实测可独立跑通 `dsh --version` → `0.1.5-rc.2`。


## 集成状态（2026-09-21）

**已完成**：DSHA 侧 `feat/bxroot-runtime` 分支（提交 `c083bf4`）已按本文契约
实现第三运行时：

- `runtime/BxrootRuntime.java`：`ContainerRuntime` 第三实现（形态 A launcher 直启）
- `ProotBootstrap.runtime()`：bxroot → proroot → proot 三选一降级链（API 26+）
- `WebProcSel.isBxrootWebPayload`：上述第三个 trap 已修（DSHA 侧
  `WebProcSelTest` 15/15 通过，含 `neverMistakesBxrootLauncherForWeb`）
- jniLibs 五件套全部 16KB 页对齐（LOAD 段 0x4000）
- `THIRD_PARTY_NOTICES.md` MIT 条目 + 产物 sha256
- ConfigStore 三值泛化（旧 prefs 键兼容）、ConfigFragment 三选一 UI

**集成后发现并修复的 bxroot 自身缺陷**（均为 v0.1.2 已含）：

| 缺陷 | 触发 | 修复 |
|---|---|---|
| O_NOFOLLOW 常量按架构不同 | 裸 openat 的 NOFOLLOW 判定 | aarch64 实测 `0100000`，非 asm-generic `00400000` |
| l2s 内部探测被符号层污染 | probe 拿不到磁盘真值 | readlink/lstat ops 改裸 syscall |
| open64 相对路径缺口 | dash 重定向 | 钩子补绝对化 |
| errno 残留 | 成功 open 后 errno=EINVAL | open 家族四处 + raw_syscall6 成功清 errno |

**真机验证待办**：按 [`docs/真机验证清单.md`](真机验证清单.md) A1–E5 逐项验收
（`dsh web` 完整启动、WebProcSel 停止路径、长稳使用）。开发容器内只能验
形态 B（bridge+linker），形态 A（launcher）在真机顶层才有效。
