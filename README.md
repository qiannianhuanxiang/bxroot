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

下表全部为**实测**（同一环境、同一 `node`、只替换 `--preload` 指向的 runtime，
与闭源 proroot 逐项对照）：

| 能力 | bxroot | proroot | 备注 |
|---|---|---|---|
| 路径翻译（含 bind mount、特殊路径透传） | ✅ | ✅ | `readdir('/')` 22 项，一致 |
| fakeroot（伪装 uid=0） | ✅ | ✅ | `getuid/getgid` → `0/0` |
| l2s 硬链接模拟（含 `st_nlink` 契约） | ✅ | — | proroot 用私有实现，磁盘格式互通 |
| 子进程派生（`fork`/`spawn`，**单层**） | ✅ | ✅ | `spawnSync("/bin/echo")` → `status=0 out="ok\n"`，**逐字节一致** |
| 子进程派生（**经 shell，多层**） | ❌ | ✅ | `sh -c '/bin/echo'` 报 `CANNOT LINK EXECUTABLE` |
| `execSync`（内部走 shell） | ❌ | ✅ | 与上一条同源 |
| seccomp 中和（Android 沙箱禁止的系统调用） | ✅ | ✅ | |
| `dsh --version` | ✅ | ✅ | `0.1.5-rc.2` |
| `dsh --help` / `web --help` | ✅ | ✅ | rc=0 |
| `dsh web` 真正启动（插件树） | ❌ | ✅ | 5 个插件 `Cannot find package`，根因已定位 |
| 加载 N-API 原生模块 | ⚠️ | ✅ | 模块能加载，但内部 `dlsym` 探测失败 |

导出符号 **338** 个（对照闭源 proroot 的 **259** 个）。

### 那 127 个符号缺口的实际构成

数字看着大，但按性质分类后**真正需要关注的只有 1 项**：

| 类别 | 数量 | 性质 |
|---|---|---|
| DRM / GBM / libseat | 74 | 宿主图形栈（伪造 vGPU、KMS scanout）。不提供虚拟 GPU，不需要 |
| `proroot_*` | 33 | 官方**私有内部 API**，不是公开契约 |
| `link2symlink_*` | 9 | **改名了** —— 就是本项目的 `src/l2s/` |
| `fake_id0_*` | 6 | **改名了** —— 就是本项目的 `src/runtime/fakeroot.c` |
| `dlsym` / `dlerror` / `dladdr` / … | 6 | `dlsym` 有硬约束（见已知问题 3）；其余待补 |
| `audit_*` | 5 | Linux 审计接口，容器场景不用 |

## 已知问题

### 1. 多层子进程派生失败（`sh -c`、`execSync`）

单层 `spawn` 已与官方一致，但子进程**再去 exec** 时失败：

```
$ spawnSync("/bin/sh", ["-c", "/bin/echo direct"])
status=1
stderr: CANNOT LINK EXECUTABLE "/bin/echo": library "libc.so.6" not found:
        needed by .../libbxroot-runtime.so in namespace (default)
```

**这不是一个 bug，是两个叠加**：

1. **SELinux 标签** —— `/data/data` 下 app 私有目录的文件**内核不允许 exec**
   （实测 `uid=0` 也一样），而 `/data/app`、`/system/bin` 可以。
   所以"把 guest 路径翻译成宿主路径再 `execve`"这条路**永远不可能成功**。
   官方的解法是 **trampoline**：`execve(bridge.so, [bridge, linker, exe, ...])`，
   由 bridge 在特权上下文里 mmap + 跳转，而不是让子进程自己 exec。
   本项目的 trampoline 已实现（`px_trampoline_exec`），**顶层生效**。
2. **孙进程没走 trampoline** —— 即 `sh` → `/bin/echo` 这一层仍是裸 `execve`。修复中。

★ 踩过的坑：trampoline 的 `argv[0]` **必须**写成 `/proc/self/root` + bridge 原路径。
bridge 在 `/data/app/...`，该前缀既不在 rootfs 内也不是 bind source，
会被翻译成 `<rootfs>/data/app/...` → 恒 ENOENT。
实测对照：原路径 ❌ / `/proc/self/root` + 原路径 ✅ / `/proc/1/root` ❌ /
`execveat(fd, AT_EMPTY_PATH)` ❌。

### 2. `dsh web` 的 5 个插件 `Cannot find package`

**根因已定位**（详见 `docs/web插件加载失败调查.md`）：

`node-addon-require-builtin` 这个 N-API 模块在 bxroot 下**加载成功但功能失效** ——
它内部用 `dlsym` 找 V8 的 `Isolate::GetCurrent` 之类符号，bxroot 下找不到：

```
bxroot : requireBuiltin("internal/modules/esm/loader")
           → Unsupported/no-context (required V8 current-context symbols were not found)
proroot: → OK
```

传导链：`dlsym` 缺垫片 → V8 探测失败（`try/catch` **静默吞掉**）→
cordis 的 `loader.internal === undefined` → `dsh-app-boot` 走 `super.import()` fallback
→ ESM 解析基准从 **profile 目录**退化成 **cordis-plugin-loader/lib/index.js**
→ 该目录祖先链上找不到 `dsh-*` 包 → 5 个插件全部报错。

**因果已闭合**：在 fallback 会搜的目录放相对符号链接后，`dsh web` **完整启动成功**。
修复中。

★ 官方为此导出**整套 `dl*` 家族**（`dlsym` / `dlerror` / `dladdr` / `dladdr1` /
`dlinfo` / `dl_iterate_phdr` / `dlopen`），bxroot 目前只有 `dlopen`。

### 3. `dlsym` 为什么不能简单转发（一条硬约束）

本项目的 `dlsym` 目前**刻意不导出** —— 因为最自然的写法会自毁：

```c
void *dlsym(void *h, const char *n) {
    static void *(*real)(void*,const char*) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "dlsym");   /* ← 解析自己要调 dlsym */
    ...
}
```

`dlsym(RTLD_NEXT, "dlsym")` 会命中**我们自己**，于是每层吃一个栈帧直到栈耗尽。
有 core dump 实证：崩溃 PC = `.so+0x6c44`（正是 `dlsym` 入口），
主线程 `sp == x29`（栈耗尽）。

**正确做法**是像官方那样自己实现一个（内部走加载器服务或自有符号表视图），
而不是转发给 libc 的同名函数。这也正是上面第 2 条待修的部分。

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

**一个入口跑全部**（推荐）：

```sh
sh test/RUN_ALL.sh          # 10 组测试 + 构建核对
sh test/RUN_ALL.sh --quick  # 跳过重新编译
```

它串起下面这些，逐项汇报，任何一项红则整体退出码非 0：

| 组 | 说明 |
|---|---|
| 编译告警门禁 | 11 个编译单元，**零告警**硬要求（见下方"为什么这条重要"） |
| l2s 运行时 | 硬链接模拟（15 用例） |
| l2s×fakeroot 协同 | 两层在同一进程里的交互（7 用例） |
| fakeroot 纯逻辑 | 身份伪装与记账（22 用例 / 100 断言） |
| 系统调用参数位置 | **两层**：我们的"路径参数表"（主证据）+ 内核 ABI（依据），28 用例 |
| rename/link 双路径 | `renameat`/`renameat2`/`linkat` 的两个路径参数都翻译（54 用例） |
| crash 崩溃处理器 | 子进程崩溃 → 父进程检查输出（12 用例） |
| D4 进程管理 | fork/exec/posix_spawn/kill 账本（117 用例 / 904 断言） |
| wait 家族钩子 | `waitpid`/`wait4`/`wait3`/`waitid`（14 用例） |
| 运行时构建 | 链接 + **导出符号核对**（漏导出 → 构建失败） |

也可以单独跑：

```sh
sh test/RUN_TESTS.sh            # fakeroot 主测试套件
sh test/RUN_INTEGRATION.sh      # 层间协同
sh test/RUN_WAIT_TESTS.sh       # wait 家族
sh src/runtime/RUN_CRASH_TESTS.sh
sh src/proc/RUN_TESTS.sh        # D4 进程管理
sh test/RUN_E2E.sh --selftest   # 端到端自检（需要真机 rootfs）
```

除端到端外全部为纯逻辑测试（不需要 root、不需要真机）。

### 为什么"告警门禁"是硬要求

本项目曾经用 `-w` 编译，把**全部**告警静默掉 —— 结果一处 `fprintf` 少传两个实参
（被调用方从栈上取到垃圾指针，进程 exit 139）在代码里活了很久才被发现。

修法分两步：构建脚本改用精确警告集，并加一道**独立门禁**
（`test/RUN_WARN_GATE.sh`）—— 因为"编译通过"不等于"没有回归"，
新代码带进来的告警必须让回归变红，否则下次还会有人图快用 `-w`。

门禁本身也踩过一次坑并有实测记录：它最初用 `-fsyntax-only`，
只跑前端，**后端告警全部漏报**。同一份 `launcher.c` 在门禁下 0 条、
真实编译 3 条 —— 也就是说"唯一卖点是拦住告警"的门禁自己静默了 3 条。
现在改为 `-c -o /dev/null -O1`，与真实构建的优化级别对齐。

### 已知的环境限制

| 限制 | 影响 |
|---|---|
| 无法用 `LD_PRELOAD` 做端到端注入验证 | 外层容器会吞掉注入。可信手段：纯逻辑单测、编译检查、反汇编、真实 FS 操作、显式 `ld.so --preload` |
| gcc 13.3.0 间歇性 ICE | 随机位置内部编译器错误，重试即可。构建脚本自带 `-O2→-O1→-O0` 回退 |
| ASan 不可用 | 外层容器报 "ASan runtime does not come first"；改用 UBSan |
| `link(2)` 在 app 私有目录被 SELinux 禁止 | 这正是 l2s 存在的理由；测试里相关断言在不可用时降级跳过 |

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
