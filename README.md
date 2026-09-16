# bxroot

开源容器运行时 —— 用 `LD_PRELOAD` 做 Linux 路径翻译，零 `ptrace` 开销。

面向 Android（arm64），但架构本身不依赖 Android：任何能加载 `.so` 的 Linux 都能用。

## 它解决什么问题

Android 的应用沙箱不允许 `chroot`/`mount`，所以想在应用私有目录里跑一个完整的
Ubuntu 用户态（apt / dpkg / Node / pnpm / git），只能靠**用户态路径翻译**：

```
客户程序 open("/etc/passwd")
        ↓  bxroot 在中间改写路径
内核    open("/data/.../ubuntu/etc/passwd")
```

传统方案是 proot —— 它用 `ptrace` 拦截每一个系统调用，开销巨大（一次 `stat`
要进出内核两次）。bxroot 走 `LD_PRELOAD`：在客户进程内直接改写路径参数，
**不产生额外的内核往返**。

## 与其他方案的关系

| | 机制 | 开销 | 说明 |
|---|---|---|---|
| chroot | 内核 | 零 | Android 上不可用（需要特权） |
| proot | `ptrace` | 高 | 成熟稳定，但每个系统调用都要停两次 |
| proroot | `LD_PRELOAD` + 活体补丁 | 低 | **闭源** |
| **bxroot** | `LD_PRELOAD` | 低 | 本项目，开源 |

## 当前状态

**可用**（已在 Android 容器内实测）：

| 能力 | 状态 |
|---|---|
| 路径翻译（含 bind mount、特殊路径透传） | ✅ |
| fakeroot（伪装 uid=0） | ✅ |
| l2s 硬链接模拟（含 `st_nlink` 契约） | ✅ |
| 子进程派生（`fork`/`exec`/`spawn` 全套 + 账本防泄漏） | ✅ |
| seccomp 中和（Android 沙箱禁止的系统调用） | ✅ |
| 运行 `node` + `dsh` | ✅ `dsh --version` → `0.1.5-rc.2` |
| `dsh web` 子命令 | ❌ 段错误，根因已缩小（见下） |

导出符号 **328** 个（对照闭源 proroot 的 258 个）。

## 已知问题

**`dsh web --help` 段错误** —— `--version`/`--help` 正常，`web` 崩。

根因已用逐层二分缩小到确凿范围（详见 `docs/web子命令崩溃分析.md`）：

```
不含 seccomp 中和层              → 正常
含但只拦截、不做路径翻译          → 正常
翻译但不替换参数                 → 正常
替换成【原路径副本】             → 正常   ★
替换成【翻译后的路径】           → 段错误 ★
```

最后两行的唯一差别是**替换进去的字符串内容**。所以崩溃不是层自身的缺陷，
而是**翻译后路径让程序成功 stat 到目标，走进了后续一段会崩的代码**。
欢迎排查。

## 构建

```sh
./BUILD_RUNTIME.sh          # 构建 libbxroot-runtime.so
make                        # 构建全部 5 个组件
make test                   # 跑测试
```

产出 5 个文件（名字沿用原 proroot 的布局，便于替换）：

| 文件 | 作用 |
|---|---|
| `libbxroot.so` | 启动器（静态可执行，伪装成 `.so`） |
| `libbxroot-runtime.so` | 运行时：全部 `LD_PRELOAD` 钩子 |
| `libbxroot-linker.so` | 自研 ELF 加载器 |
| `libbxroot-bridge.so` | 宿主/客户桥接 |
| `libbxroot-stub-loader.so` | 静态程序加载器 |

## 架构

```
libbxroot-bridge.so  libbxroot-linker.so --argv0 node \
    --preload libbxroot-runtime.so <guest-exe> [args...]
```

运行时由这几层组成（各自独立、可单独测试）：

| 层 | 职责 |
|---|---|
| `preload.c` | 主体：路径翻译 + 全部系统调用钩子 |
| `l2s/` | 硬链接模拟（符号链接 + 中间层，含 `st_nlink` 契约） |
| `fakeroot.c` | 伪造 root 身份 |
| `crash.c` | 崩溃现场捕获（bxroot 曾有零诊断能力） |
| `sigsys.c` | SIGSYS 兼容层 |
| `syscall_guard.c` | `syscall()` 接管：seccomp 中和 + **路径翻译**（关键） |
| `livepatch.c` | 最小化运行时指令补丁（seccomp 中和） |

### 一个非显而易见的要点

`syscall_guard.c` 里的**路径翻译**是必需的，不是冗余。

Node 静态链接的 libuv **不经 libc 的 `stat`/`statx` 符号**，而是用
`syscall(291, AT_FDCWD, path, ...)` 直接发起。所以只 hook 符号的话，
Node 的所有文件操作**都会绕过翻译** —— 现象是 C 程序一切正常、
Node 全部 `ENOENT`。

判定证据：开 `BXROOT_SCG=1` 时 Node 的 `statSync` 产生"转发 291"，
却不产生任何 `translate` 日志。

## 环境变量

| 变量 | 说明 |
|---|---|
| `BXROOT_ROOTFS` | 根文件系统路径（由 `-r` 派生） |
| `BXROOT_WORKDIR` | 工作目录（由 `-w` 派生） |
| `BXROOT_FAKEROOT` | 伪装 uid=0（由 `-0` 派生） |
| `BXROOT_LINK2SYMLINK` | 启用 l2s（由 `--link2symlink` 派生） |
| `BXROOT_L2S_DIR` | l2s 中间层目录，默认 `<rootfs>/.l2s` |
| `BXROOT_BINDS` | bind 列表（`src:dst;src:dst`） |
| `BXROOT_LIB_PATH` | 显式指定 runtime `.so` 路径 |
| `BXROOT_TMP_DIR` | 临时目录 |
| `BXROOT_VERBOSE` | 排障日志（注意还受**编译期**开关约束） |
| `BXROOT_SCG` | `syscall` 层追踪 |

## 测试

```sh
sh test/RUN_TESTS.sh            # 主测试套件
sh test/RUN_INTEGRATION.sh      # 层间协同
sh test/RUN_WAIT_TESTS.sh       # wait 家族
sh src/runtime/RUN_CRASH_TESTS.sh
sh test/RUN_E2E.sh --selftest   # 端到端自检
```

全部为纯逻辑测试（不需要 root、不需要真机）。

## 许可

MIT，见 `LICENSE`。

### 与 PRoot 的关系

`src/l2s/` 实现的硬链接模拟遵循 PRoot `link2symlink` 扩展建立的
**磁盘命名约定**（`.l2s.<name><GGGG>[.<NNNN>]`），目的是让两边准备的
rootfs 可以互相读取。

共享的是**格式**，不是实现：

| | 上游 PRoot | bxroot |
|---|---|---|
| 机制 | `ptrace` 拦截 | 纯函数 + 可注入的 FS 操作 |
| 规模 | 1342 行 | 1170 行 |
| 依赖 | `talloc`、PRoot 内部 tracee API | 无（仅 libc） |
| 代码重合 | — | **无共享代码** |

命名约定属于思想/格式，不受版权保护；本项目未复制上游代码。

---

## 开发笔记

以下内容来自实际排查，记录下来避免重复踩坑。

### 路径视角陷阱

proroot/bxroot 环境下，同一份文件有两个名字：

| 操作 | 只认 | 给错的后果 |
|---|---|---|
| `mkdir` / `cp` | 容器视角 `/tmp/x` | 给宿主路径 → **返回 0 却不创建**（静默失败） |
| `--preload` | 宿主视角 `<rootfs>/tmp/x` | 给 `/tmp/x` → 加载失败 |
| shell 的 `test -f` / `ls` | 容器视角 | 看不到宿主路径，报"不存在" |
| `exec` | 宿主视角 | 同样路径却能正常运行 |

### 内核 trap 集合不是一刀切

Android 沙箱的 seccomp 策略逐个列举了 80+ 个系统调用号（`425/426/427` 在内，
`424` 不在）。被禁调用以 `KILL_PROCESS` 处理时**不投递信号**，
所以 `SIGSYS` 处理器救不了 —— 只能从源头不发出去。

### 内联 `svc` 拦不住

`LD_PRELOAD` 只能拦符号。glibc 内部有**内联 `svc`**（不经 PLT、
不经导出符号），这类调用必须靠改写指令（`livepatch.c`）。
判别方法：搜索 `mov w8,#imm` 紧跟 `svc #0` 的字节序列。

### `struct sigaction` 的两种布局

glibc 与内核的 `struct sigaction` **布局不同**：

| 字段 | glibc（152 字节） | 内核 |
|---|---|---|
| handler | 0 | 0 |
| **flags** | **136** | **8** |
| restorer | 144 | 16 |
| mask | 8 | 24 |

直接调 `rt_sigaction` 传 glibc 结构体会返回 `EINVAL`，处理器**静默不生效**。
用 `__libc_sigaction`（`GLIBC_PRIVATE`）做布局转换。

（相反，`sigset_t` 两边都是 128 字节位图，布局一致，裸调用安全。）
