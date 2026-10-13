# 开发笔记与历史（自 README 迁出）

> 本文件由 README 原样迁出，内容未删减，仅调整标题层级。入口见 [README](../README.md)。

## 性能说法的复核记录


架构上成立：bxroot 在客户进程内直接改写路径参数，**不产生额外的内核往返**；
ptrace 方案（proot）要让每个系统调用停两次。

★ **但本仓库目前没有可信的对比数字**，所以不写具体倍数 ★

原因是一次实测尝试失败了，如实记录在这里，免得后人重复：

```
在本项目所处的容器内测 stat 吞吐（各 3 轮，30000 次）：
  无 runtime       4.67 / 4.69 / 4.69  us/op
  官方 proroot     4.77 / 4.63 / 4.68  us/op
  bxroot           1.78 / 1.68 / 1.60  us/op
```

初看像是"bxroot 快 2.7 倍"，但**这个数字不可信**，两个原因：

1. **对照组没有开 ptrace**。实测 `/proc/self/status` 显示
   `TracerPid: 0` —— 连官方 runtime 都没在用 ptrace 跟踪（官方 linker
   不导出任何 ptrace/waitpid 符号）。既然对照侧没付出 ptrace 的代价，
   这组对比就体现不出架构差异。
2. **"无 runtime"那一列也不是干净基线** —— 它同样跑在 proroot 容器里。

要拿到有意义的数字，需要一个**真正用 ptrace 的对照**（上游 proot）与一个
**不在任何容器内**的裸基线。这两样当前环境都不具备，所以本 README 不给数字。

★ 这条本身也是一次教训 ★ 我第一次跑出"bxroot 快 4.5 倍"时差点写进文档，
复核时发现那一轮的 `stat` **全部失败**（`ok=0 bad=30000`）——
"快"是因为它在快速返回错误。**基准测试必须先断言操作真的成功**，
否则测的是失败路径的速度。


## 非 Android 环境（请先读这段）


架构上不依赖 Android，但**非 Android 环境是次要目标，验证程度明显更低**。
在普通 Linux 上使用前请知道三件事：

1. **需要 `BXROOT_NO_LIVEPATCH=1`**（或确保环境无 seccomp 过滤器）。
   livepatch 层要 `mprotect` libc 代码页，在没有 Android 那套 seccomp
   白名单的环境里**收益为零、风险全担**。
   （2026-09-18 起已加 `PR_GET_SECCOMP` 自动门控 + glibc 版本断言，
   正常情况下不再需要手工设置 —— 但保留这个开关作为兜底。）
2. **降级路径已被真实修复并纳入回归**：无自研 linker 服务时，
   `dlsym` 会转发给 libc 的真身（此前是 `return NULL`，客户程序
   `call NULL` 直接崩）。详见下节"非 Android 环境的修复历史"。
3. **不要用 `LD_PRELOAD` 在 proroot 容器内测试本库** —— 外层 proroot 用
   自研加载器接管了 `execve`，`LD_PRELOAD` 会**静默失效**（连空构造函数
   都不执行），测试会显示假绿。用官方四件套
   （`bridge + linker + --argv0 + --preload`）。详见
   [`docs/调查-LD_PRELOAD在proroot容器内失效.md`](docs/调查-LD_PRELOAD在proroot容器内失效.md)。


## 非 Android 环境的修复历史

v0.1.0 之后，有用户在纯 Linux（Ubuntu 24.04 / aarch64 / 外层 proot 沙箱）
做了源码走读 + 实测，先后报出两批问题。**全部已修复并加了回归**：

### 第一批：加载即崩（P0，降级路径）

| 缺陷 | 现象 | 根因 | 状态 |
|---|---|---|---|
| `ldso_service_*` 强引用 | `LD_PRELOAD` 后 `symbol lookup error`，**一个命令都跑不了** | 4 个符号是普通 `extern`（强引用），纯 glibc 下链接器在符号解析阶段就失败，构造函数跑不到 | ✅ 改 `__attribute__((weak))` |
| `dlsym` 无服务分支 `return NULL` | `bash` 启动即 `SEGV pc=0x0` | 客户程序拿到 NULL 直接调用 | ✅ 改用 `dlvsym` 取真身并转发 |
| livepatch 无门控 | 非 Android 环境改 libc 代码页 → SIGSEGV | 站点表按 Android seccomp 白名单设计，却无条件 `mprotect` | ✅ `PR_GET_SECCOMP` 门控 + `BXROOT_NO_LIVEPATCH=1` |

★ 为什么能活过 v0.1.0 ★ 它们**都在降级路径上**（只有"无 ldso 服务"的
环境才会走到），而此前测试全跑有服务的路径 —— 降级路径**零覆盖**。
现补 `test/RUN_FALLBACK.sh`（`BXROOT_FORCE_NO_LDSO_SERVICE=1` 强制走）。

### 第二批：可用性/正确性缺陷

| 缺陷 | 类别 | 状态 |
|---|---|---|
| `__libc_sigaction` 强引用（GLIBC_PRIVATE） | 非 glibc 环境加载失败（与第一批同类） | ✅ 改弱引用 + 探测降级 |
| `realpath` 返回值不剥宿主前缀 | 客户拿到 `/data/.../rootfs/...`，路径相等性判断错 | ✅ 三钩子接入反向翻译 |
| `-b <单路径>` 被拒 | 上游语义是 `path:path` | ✅ 按上游语义接受 |
| `/proc/self/fd/N` readlink 泄漏宿主路径 | 客户把它喂回 open 会双重翻译/ENOENT | ✅ 反向翻译（socket/pipe 原样放行） |
| 25 个路径型 syscall 未列入参数表 | 裸 `syscall()` 客户（如静态 libuv）绕过翻译 | ✅ 补齐 + 审计器入回归 |
| fakeroot 账本无锁 | **多线程下堆破坏**（`double free`，可复现） | ✅ 自旋锁 + 并发回归 |
| Android 策略中和无开关 | 非 Android 误伤合法调用（io_uring 族恒定 ENOSYS） | ✅ `BXROOT_RAW_SYSCALL=1` |
| crash 处理器抢占客户 handler | node/V8 的自愈逻辑被短路 | ✅ `BXROOT_NO_CRASH=1` / `BXROOT_CRASH_CHAIN=1` |

### 工程可信度（第二批同时补齐）

- **CI**：`.github/workflows/ci.yml`（build / 全量回归 / 告警门禁三 job，
  双架构矩阵，逐步骤超时）
- **审计型测试**：`RUN_SYSCALL_TABLE_AUDIT.sh`（裸 svc 逐号对内核实测，
  主动发现遗漏）与 `RUN_CONCUR.sh`（并发压测）—— 它们不是防回归，
  而是**主动发现问题**，上表两项缺陷正是它们查出来的
- **`.gitignore` 修正**：原先 `src/runtime/t_*` 裸通配会静默吞掉新增的
  `t_*.c` 源码（只该忽略无扩展名的编译产物）


## 开发笔记

以下内容来自实际排查，记录下来避免重复踩坑。完整排查报告见 `docs/`。

### 路径视角陷阱

proroot/bxroot 环境下，同一份文件有两个名字：

| 操作 | 只认 | 给错的后果 |
|---|---|---|
| `mkdir` / `cp` | 容器视角 `/tmp/x` | 给宿主路径 → **返回 0 却不创建**（静默失败） |
| `--preload` | 宿主视角 `<rootfs>/tmp/x` | 给 `/tmp/x` → 加载失败 |
| shell 的 `test -f` / `ls` | 容器视角 | 看不到宿主路径，报"不存在" |
| `exec` | 宿主视角 | 同样路径却能正常运行 |

### 对照实验的两个致命坑

1. **环境变量前缀不同**：官方读 `PROROOT_*`（41 个），bxroot 读
   `BXROOT_*`。传错了**不报错**，只是静默跑另一套配置——
   得出的"官方如何如何"结论完全无效。
2. **容器视角 ≠ 磁盘真相**。判断内核到底建了什么必须用宿主视角
   （`/proc/<pid>/root` 前缀，或直接看 `/data/data/...`）。
   曾把"f2fs 真硬链接"误判为"隐藏了中间文件"，排查两轮才发现。

### 同一功能不同入口覆盖不全（本项目最高频的缺陷模式）

真实程序发起同一功能有多条路径，漏掉任何一条就是"测试绿了但真实场景挂"：

| 功能 | 路径① | 路径② | 路径③ |
|---|---|---|---|
| 身份查询 | libc `getuid` | `syscall(174)` | 内联 svc（拦不住，官方也拦不住）|
| 降权 | `setuid(2)` 符号 | `syscall(143..159)` | 同上 |
| 路径查询 | `stat` | `syscall(79/291)` | libuv 的 `uv__fs_statx` |
| 子进程 | `system`/`popen` | `posix_spawn` | `execvp`/`vfork` |
| 用户查询 | `getpwuid` | `getpwnam(_r)` | `getgrnam(_r)` |
| **目录项流** | `readdir` | `scandir` | 裸 `syscall(61)`（libuv）|

**教训**：修一条路径 ≠ 功能可用。每次"功能已实现"都要问——
其余入口在哪，谁在用它们。

### 入口之间还可能是"内部直调"，PLT 插不进去

上表那三条目录项入口**不是并列的三条**，而是**一条链上互相直调**。
反汇编 libc.so.6（aarch64 / glibc 2.39）实测：

```
readdir  体内:  bcc90: bl bcb80 <getdents64>   ← 本地 bl，不经 PLT
scandir  体内:          bl bcbf0 <readdir>      ← 同样本地 bl
```

于是 hook 上一层**对下一层完全无效**：给 `readdir` 挂钩子后跑 `scandir`，
钩子命中 **0 次**（实测）。三条链必须各自接。

**判别方法**：`objdump -d <lib> | grep -A20 '<函数名>'`，看内部 `bl` 的目标是
`<名字@plt>`（能拦）还是本地地址（拦不住）。**别靠"它应该会调那一层"来推断。**

### 内核 trap 集合不是一刀切

Android 沙箱的 seccomp 策略逐个列举了 80+ 个系统调用号（`425/426/427` 在内，
`424` 不在）。被禁调用以 `KILL_PROCESS` 处理时**不投递信号**，
所以 `SIGSYS` 处理器救不了 —— 只能从源头不发出去。

### 内联 `svc` 拦不住

`LD_PRELOAD` 只能拦符号。glibc 内部有**内联 `svc`**（不经 PLT、
不经导出符号），这类调用必须靠改写指令（`livepatch.c`；早期针对特定 glibc 版本的站点表为 112 处，运行期指令扫描不依赖该表）。
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


## 开发工具：受保护推送


```sh
sh tools/push-verified.sh       # 推送并在推后核对 hash
```

★ **推送必须用这个脚本，不要直接 `git push --force`** ★

`--force` 的语义是"用我这条谱系无条件替换远端"。本项目实际发生过一次
事故：另一个停在旧状态的 clone 一推，就把远端整体换回了前一天的样子，
而**推送输出照样写着 `forced update`、退出码照样是 0**（详见
`docs/事件-远端被旧clone覆盖.md`）。

本脚本把两个必需动作固化下来，堵住这个静默失败：

1. **推之前**：远端 HEAD 必须是本地 HEAD 的祖先。不是 → 远端有本地
   没见过的提交 → 停下并列出那些提交，让人判断。
2. **推之后**：远端 HEAD 必须 == 本地 HEAD。不等 → 推上去的不是本地
   的东西 → 报错退出并给出排查步骤。

已用真实误推场景验证过它确实会拦（另起两个 clone 互相推，再让落后的
那个去推 —— 脚本正确识别并拒绝）。


## 与 PROROOT 对比的测量方法


bxroot 与 PROROOT 的对比必须使用同一设备、同一 rootfs、同一 Node 版本和同样的
bind 参数，并确认没有自动 fallback。推荐至少测：

```sh
/usr/bin/time -f '%e sec' sh -c '
i=0; while [ "$i" -lt 1000 ]; do /bin/true; i=$((i+1)); done'

/usr/bin/time -f '%e sec' sh -c '
i=0; while [ "$i" -lt 300 ]; do node -e "process.stdout.write(\"ok\")"; i=$((i+1)); done'

/usr/bin/time -f '%e sec' pnpm install --ignore-scripts
/usr/bin/time -f '%e sec' git status
```

同时记录软/硬链接、`rename`、`lstat`、`readlink`、`/proc/self/fd`、并发 Node 和
host -> guest 回入的成功率、错误类型、fallback 状态及中位耗时。出现
`automatic proot fallback` 的结果不能作为 bxroot 结果。

