# bxroot

开源容器运行时 —— 用 `LD_PRELOAD` 做 Linux 路径翻译，不引入额外的内核往返。

**主战场是 Android（arm64）**：在应用私有目录里跑完整 Ubuntu 用户态
（apt / dpkg / node / pnpm）。真机容器内已对照官方 proroot 实测。

### 关于"零 ptrace 开销"这个说法

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

### 非 Android 环境（请先读这段）

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
| **bxroot** | `LD_PRELOAD` | 低 | 本项目，开源（MIT） |

## 当前状态

**可用**（已在 Android 真机容器内对照官方 proroot 实测）：

| 能力 | 状态 |
|---|---|
| 路径翻译（含 bind mount、特殊路径透传） | ✅ |
| fakeroot（伪装 uid=0，含身份账本：setter/getter 自洽） | ✅ |
| l2s 硬链接模拟（含 `st_nlink` 契约；`link()` 失败时**自动启用**） | ✅ |
| 子进程派生（`fork`/`vfork`/`exec`/`posix_spawn` 全套 + trampoline + 账本） | ✅ |
| `system()`/`popen()`（子进程带钩子 + 路径翻译） | ✅ |
| seccomp 中和（Android 沙箱禁止的系统调用 + livepatch） | ✅ |
| shebang 脚本直接 exec | ✅ |
| NSS 用户/组查询（getpwnam/getpwnam_r/getgrnam/getgrnam_r 直解回退） | ✅ |
| libaudit 符号（passwd/login/chage 等 20 个程序依赖） | ✅ |
| `dpkg -l` / `dpkg -S` / `dpkg-deb --build` / `dpkg -i`（unpack+configure） | ✅ |
| `dlerror`/`dl_iterate_phdr`/`pthread_create`（栈下限与官方一致） | ✅ |
| `syscall(174..177/148/150/158)` 身份查询（裸 syscall 层） | ✅ |
| 运行 `node` + `dsh` | ✅ `dsh --version` → `0.1.5-rc.2` |

**导出符号 372 个**（对照闭源 proroot 的 259 个）。

## 上游 24 个 issue 回归

将上游 coderredlab/proroot 的全部 issue 转成 **25 个可执行用例**（双基线判定，
bxroot vs proot 对照）：

```
PASS  14    FAIL  0    NOCTL 7    SKIP 4
```

**上游 issue 无一在 bxroot 上重现**（详见 `tests-upstream/ISSUE-TEST-MATRIX.md`）。

★ **别把这一行读成"25 个全过"** ★ 其中 **12 个并非真实通过的验证**：

| 判定 | 数量 | 含义 |
|---|---|---|
| PASS | 14 | 真的在这个环境里验证过 |
| **NOCTL** | **7** | **无对照** —— 官方在同条件下行为相同，无法判定优劣 |
| **SKIP** | **4** | **被跳过** —— 环境不满足（缺依赖/需要真机），**没有跑** |
| FAIL | 0 | — |

所以准确说法是：**"14 项通过，7 项无对照，4 项未测，0 项失败"**。

## 已知限制

详见 [`docs/已知限制与架构能力边界.md`](docs/已知限制与架构能力边界.md)。

| 限制 | 影响 | 说明 |
|---|---|---|
| `make` 配方子进程 | 构建链 | glibc 私有 spawn 路径不经任何导出符号钩子（LD_PRELOAD 架构原理性不可观测；官方 ptrace 架构可见） |
| **绝对目标的符号链接** | 依赖绝对链接的软件 | `open()` 经"目标为绝对路径"的链接会 ENOENT（官方正常）。内核在内部解析链接目标，不经过任何 libc 符号。**l2s 生成的链接不踩此坑**（已实测）。详见 [`docs/缺陷-绝对目标符号链接打不开.md`](docs/缺陷-绝对目标符号链接打不开.md) |
| NSS `getpwnam_r` 内部分派 | `df` 标签 | 已用 /etc/passwd 直解回退修复主流程；仅 `df` 的挂载点标签显示差异（数值正确） |
| `dpkg -i` 的 timestamp | 非致命 | 包内容/状态/配置全正确，仅 mtime 为当前时间（`AT_EMPTY_PATH` 需要 CAP，fakeroot 无真实 CAP） |
| livepatch 站点表版本绑定 | 换 glibc 时 | 站点偏移针对特定 glibc 版本；已加运行期版本断言，不匹配时**打印告警并跳过**（原先会静默失效） |
| `-H`/`-p`/`-q` 等 CLI 选项 | 少数用户 | 官方 proroot 同样未实现；bxroot **明确报错**而非静默忽略 |

## 构建

```sh
./BUILD_RUNTIME.sh          # 构建 libbxroot-runtime.so（自带 ICE 重试）
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
| `libbxroot-stub-loader.so` | 静态二进制的 `PT_INTERP` 修补器（**非独立 ELF 加载器**：为静态二进制补上 PT_INTERP 后 `execve`，交给内核加载；不做 mmap/段加载/跳 `_start`。定位见 `src/stub-loader/stub-loader.c` 注释） |

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
| `fakeroot.c` | 伪造 root 身份（含身份账本：setter 写 / getter 读） |
| `crash.c` | 崩溃现场捕获（寄存器/回溯打印） |
| `sigsys.c` | SIGSYS 兼容层（含信号屏蔽防护） |
| `syscall_guard.c` | `syscall()` 接管：seccomp 中和 + 路径翻译 + 身份改写 |
| `livepatch.c` | 运行时指令补丁（seccomp 中和，112 处） |

### 一个非显而易见的要点

`syscall_guard.c` 里的**路径翻译**是必需的，不是冗余。

Node 静态链接的 libuv **不经 libc 的 `stat`/`statx` 符号**，而是用
`syscall(291, AT_FDCWD, path, ...)` 直接发起。所以只 hook 符号的话，
Node 的所有文件操作**都会绕过翻译** —— 现象是 C 程序一切正常、
Node 全部 `ENOENT`。

## 环境变量

| 变量 | 说明 |
|---|---|
| `BXROOT_ROOTFS` | 根文件系统路径（由 `-r` 派生） |
| `BXROOT_WORKDIR` | 工作目录（由 `-w` 派生） |
| `BXROOT_FAKEROOT` | 伪装 uid=0（由 `-0` 派生） |
| `BXROOT_LINK2SYMLINK` | 启用 l2s（由 `--link2symlink` 派生；`link()` 失败时也会自动启用） |
| `BXROOT_L2S_DIR` | l2s 中间层目录，默认 `<rootfs>/.l2s` |
| `BXROOT_BINDS` | bind 列表（`src:dst;src:dst`） |
| `BXROOT_LIB_PATH` | 显式指定 runtime `.so` 路径 |
| `BXROOT_TMP_DIR` | 临时目录 |
| `BXROOT_VERBOSE` | 排障日志（**部分日志为 debug 构建编译期开关**：release 包中仅 proc 等运行期日志生效，`preload.c` 的 LOG 需 `make debug`/`-DBXROOT_VERBOSE=1` 重编才完整） |
| `BXROOT_SCG` | `syscall` 层追踪 |
| `BXROOT_RAW_SYSCALL` | 置 1 时对「因 Android 策略而中和」的调用（io_uring 家族 425/426/427）**真透传**，不再恒定回 `ENOSYS`，由真实内核/宿主 seccomp 给出答案 —— 适用于非 Android 环境（如通用 seccomp profile 的普通容器）。身份/降权伪装与路径翻译不受影响；`0` 或未设时行为不变 |
| `BXROOT_NO_AUTORUN` | 置 1 跳过 runtime 构造链（源码级单元测试专用，正常使用勿设） |
| `BXROOT_NO_CRASH` | 置 1 不安装崩溃处理器，由客户程序自管 SIGSEGV/SIGBUS |
| `BXROOT_CRASH_CHAIN` | 置 1 打印现场后链式调用更早注册的 handler（默认关，开启会有双方各一段输出） |
| `BXROOT_NO_LIVEPATCH` | 置 1 跳过 libc 站点活体补丁（非 Android 环境兜底；正常有 `PR_GET_SECCOMP` 自动门控） |
| `BXROOT_FORCE_NO_LDSO_SERVICE` | 置 1 强制走"无 ldso 服务"降级分支（**测试专用**：让该分支可在开发环境真实执行） |

> 提示：检测到 `PROROOT_*`（旧名/官方名）环境变量但未设对应 `BXROOT_*` 时，启动会向 stderr 打一行拼写/迁移防呆警告（每进程最多一次）。

### 已知行为边界（如实告知）

- **crash 处理器**：runtime 默认安装 SIGSEGV/SIGBUS 现场打印处理器
  （崩溃时留现场而不是无声退出）。客户在 `main()` 之后注册的 handler
  会覆盖它（后装者胜）。若需完全自管崩溃处理，置 `BXROOT_NO_CRASH=1`；
  若需在打印现场后把控制权交给**更早注册**的 handler（如嵌套容器的
  外层运行时），置 `BXROOT_CRASH_CHAIN=1`（默认关闭 —— 链式会导致
  双方各输出一段现场）。
- **fakeroot 不等于真 root**：uid/gid/chmod 是用户态视图伪装，
  内核真实属主不变。依赖真实 uid 的检测（`make install` 的属主
  断言、部分 npm 安全校验）可能与真 root 有出入 —— 与官方 proot
  同样的边界。
- **架构死绑 aarch64**：syscall 编号表、寄存器上下文均为 arm64
  硬编码。armv7/x86_64 需要独立的参数表工作，当前不支持，也不在
  v0.x 路线图内。

## 测试

```sh
sh test/RUN_ALL.sh --quick      # 主回归（25 项，一键全跑）
```

分项：

```sh
sh test/RUN_TESTS.sh            # 纯逻辑（不需真机）
sh test/RUN_CONCUR.sh           # fakeroot 账本多线程并发（8线程×400键）
sh test/RUN_L2S_E2E.sh          # l2s 端到端（对照官方）
sh test/RUN_ID_SYSCALL.sh       # 身份 syscall（47 用例）
sh test/RUN_DL_TESTS.sh         # dl 家族契约
sh test/RUN_SYSTEM_POPEN.sh     # system/popen 子进程
sh test/RUN_PTHREAD_CREATE.sh   # pthread_create 栈
sh test/RUN_PRIVDROP.sh         # 降权族（真实 chage 验收）
sh test/RUN_SHEBANG.sh          # shebang 直接 exec
sh test/RUN_WARN_GATE.sh        # 编译零告警门禁
sh test/RUN_CLI_COMPAT.sh       # proot CLI 语义（38 项）
sh test/RUN_UPSTREAM_CLI.sh     # 上游选项表全覆盖（35 项）
sh test/RUN_PATH_FORMS.sh       # 路径形态（裸相对名/dirfd+相对/…）
sh test/RUN_SYSCALL_TABLE_AUDIT.sh  # 路径参数表实测审计（裸 svc 逐号对内核）
sh test/RUN_RAW_SYSCALL.sh      # 非 Android 透传开关
sh test/RUN_REALPATH_FIXUP.sh   # realpath 返回值反向翻译
sh test/RUN_D3_FIXUP.sh         # /proc 泄漏反向翻译
sh issue-regression-test.sh     # 上游 24 issue 的 25 用例回归
```

其中两项是「会主动发现问题」的审计型测试，不只是防回归：

- **`RUN_SYSCALL_TABLE_AUDIT.sh`**：用裸 `svc` 对内核逐号实测哪些系统
  调用的哪个参数是路径，再与我们源码里的表比对。2026-09-18 用它发现
  25 个路径型调用（xattr 族 / chdir / truncate / openat2 等）**未列入
  表** —— 走裸 `syscall()` 的程序（如 node 的静态 libuv）对这些调用
  拿不到翻译。补齐后遗漏归零。
- **`RUN_CONCUR.sh`**：并发压测 fakeroot 账本。它曾直接暴露无锁下的
  堆破坏（`double free`），促成加锁修复。

判定口径：所有端到端测试都采用**双基线**——bxroot 与官方 proroot
对照，逐行比对输出，"比官方差"才算 FAIL。

## 开发工具

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
| 依赖 | `talloc`、PRoot 内部 tracee API | 无（仅 libc） |
| 代码重合 | — | **无共享代码** |

命名约定属于思想/格式，不受版权保护；本项目未复制上游代码。

---

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

**教训**：修一条路径 ≠ 功能可用。每次"功能已实现"都要问——
其余入口在哪，谁在用它们。

### 内核 trap 集合不是一刀切

Android 沙箱的 seccomp 策略逐个列举了 80+ 个系统调用号（`425/426/427` 在内，
`424` 不在）。被禁调用以 `KILL_PROCESS` 处理时**不投递信号**，
所以 `SIGSYS` 处理器救不了 —— 只能从源头不发出去。

### 内联 `svc` 拦不住

`LD_PRELOAD` 只能拦符号。glibc 内部有**内联 `svc`**（不经 PLT、
不经导出符号），这类调用必须靠改写指令（`livepatch.c`，实测 112 处）。
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
