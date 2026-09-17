# `system()` / `popen()` 全部失败：LD_PRELOAD 注入的是宿主视角无法解析的路径

> **严重度：最高**（本项目当前最高优先级）。它让容器里任何 exec 出来的
> 子进程都起不来 —— `system()`、`popen()`，以及所有依赖它们的工具链。
>
> **状态：已修复**。修法经 A/B 对照与两组源码级负对照验证。
>
> 缺陷由子代理 d117c724 在调查「高频符号缺口」时**顺带发现**（他本来在
> 查 `pclose`）。我在 `docs/子进程全部失败-LD_PRELOAD注入缺陷.md`（原缺
> 陷文档）的分析基础上重新定位，**发现原文档给出的根因只对了一半**，
> 详见 §三。

---

## 〇、结论摘要（先看这个）

| | 官方 | bxroot（修复前） | bxroot（修复后） |
|---|---|---|---|
| `system()` | `rc=0`，`SYSCALL-OK` | **`rc=256`**，`CANNOT LINK EXECUTABLE` | `rc=0`，`SYSCALL-OK` |
| `popen()` | `rc=0`，`POPEN-OK` | **`rc=256`**，无输出 | `rc=0`，`POPEN-OK` |
| `pclose()` | `rc=0` | **`rc=256`** | `rc=0` |
| 子进程带 runtime | 是 | 否（起不来） | **是**（maps 里可见） |
| 子进程路径翻译 | 生效 | 不适用 | **生效** |

**根因是两条独立的缺陷叠加**（原文档只指出了第二条）：

1. **`environ` 里被写入容器视角的 `LD_PRELOAD`** —— 污染的是**进程级**
   状态，任何不经我们 hook 的宿主 exec 都会继承它并失败。
2. **`system()` / `popen()` 根本没走通「用容器内 shell」这条路** ——
   `system()` 用真实 glibc `posix_spawn` 去 exec `/data/data/...` 下的
   文件（SELinux `app_data_file` 禁止执行，`EACCES`）；`popen()` 压根
   没接管（薄转发给 glibc，用的是**宿主** `/bin/sh`）。

两条都必须修，只修一条**都**过不了完整判据（§五有实测负对照）。

---

## 一、复现

### 1.1 探针

`sysprobe.c`（`system("echo SYSCALL-OK")` + `popen("echo POPEN-OK")`）。
落地在 `/root/lpfix/`（= `<ROOTFS>/root/lpfix/`，容器视角与内核视角同 inode）。

### 1.2 A/B harness 的三个必备条件

不满足其中任何一条，都会得到「两侧都红」或「两侧都绿」的假结果：

1. **两侧各用各的环境变量前缀**：官方只认 `PROROOT_*`，bxroot 只认
   `BXROOT_*`。官方产物里 `strings | grep -c BXROOT` = **0**，传了会被
   **静默忽略**。
2. **探针与 runtime 都必须用内核视角路径**（`<ROOTFS>/root/lpfix/...`）：
   `--preload` 只认内核视角，给容器视角会报
   `deps: failed to preload … proroot-ldso: failure rc=2`。
3. **必须设 `PROROOT_TRAMPOLINE_PATH` / `PROROOT_LINKER_PATH`**，否则
   bridge/linker 三件套不齐，同样 rc=2。

（这三条我都踩过，最终 harness 在 `/root/lpfix/repro.sh`。）

### 1.3 原始对照输出（逐字）

```
########## 修复前（NEG-A3 = 源码级完整回退）##########
CANNOT LINK EXECUTABLE "sh": library "libc.so.6" not found: needed by /data/data/com.dsh.client/files/linux/ubuntu/root/lpfix/stage/libnegA3.so in namespace (default)
CANNOT LINK EXECUTABLE "sh": library "libc.so.6" not found: needed by /data/data/com.dsh.client/files/linux/ubuntu/root/lpfix/stage/libnegA3.so in namespace (default)
system rc=256 errno=13
pclose rc=256

########## 修复后（build/libbxroot-runtime.so）##########
SYSCALL-OK
system rc=0 errno=0
popen got: POPEN-OK
pclose rc=0
```

官方侧（同一条命令、只换 `--preload` 指向的库）：

```
########## 官方 libproroot-runtime.so ##########
SYSCALL-OK
system rc=0 errno=0
popen got: POPEN-OK
pclose rc=0
```

---

## 二、官方做法的调查（**这是修法的依据，不是可选步骤**）

### 2.1 官方**完全不使用 `LD_PRELOAD`**

```
$ strings -a work/parity/off/libproroot-runtime.so | grep -c "LD_PRELOAD"
0
$ strings -a work/parity/off/libproroot-runtime.so | grep -c "BXROOT"
0
$ strings -a work/parity/off/libproroot-bridge.so  | grep -c "LD_PRELOAD"
0
$ strings -a work/parity/off/libproroot-linker.so  | grep -c "LD_PRELOAD"
0
```

（linker 里唯一的 `preload` 命中是它自己的 `--preload` 选项字符串。）

### 2.2 实测：官方子进程的 `LD_PRELOAD` 是**未设置**，但确实带着 runtime

在官方容器里 `system()` 一个 shell，让 shell 打印**它自己**（`$$`）的环境
与 maps：

```
--- shell pid=11849 ---
LD_PRELOAD=[]
LD_LIBRARY_PATH=[/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu:...]
PROROOT_LIB_PATH=[/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64/libproroot-runtime.so]
BXROOT_LD_PRELOAD=[]
--- proroot/bxroot maps of shell ---
7aa418e000-7aa41d1000 r-xp ... /data/app/~~.../lib/arm64/libproroot-runtime.so
7aa41ed000-7aa41ef000 rw-p ... /data/app/~~.../lib/arm64/libproroot-runtime.so
system rc=0
```

### 2.3 官方机制：**argv 重写 + 显式解释器**（子代理逆向确认）

同一条命令的 `/proc/<pid>/cmdline`：

```
/data/app/~~.../lib/arm64/libproroot-bridge.so
/data/app/~~.../lib/arm64/libproroot-linker.so
--argv0 /bin/sh
--preload /data/app/~~.../lib/arm64/libproroot-runtime.so
/data/data/com.dsh.client/files/linux/ubuntu/usr/bin/dash -c ...
```

即：官方把 `execve` 的 **pathname 换成自己的 bridge**，argv 重写成
`[bridge, linker, --argv0 X, --preload runtime, guest路径, 原argv[1..]]`，
由 bridge（静态、无 `.dynamic` 的裸蹦床）mmap 加载 guest，再由 linker
（自研 RTLD）按 `--preload` 把 runtime 装进新进程，最后交控制权给 guest
main。全程**不经内核 `PT_INTERP`、不经任何 `LD_*`**。

反汇编侧证：`execve@@Base`（0x1afec）里 `build child_envp` 段
（debug 串 0x36660 → 引用点 0x1c0ac）构造子进程 envp 时，前缀表是
`LD_LIBRARY_PATH=` / `PATH=` / `PROROOT_ROOTFS=` / `PROROOT_CFG_FD=` /
`PROROOT_ESCAPE_FD=` / `PROROOT_LINKER_PATH=` / `PROROOT_LIB_PATH=` /
`PROROOT_TRAMPOLINE_PATH=` / `PROROOT_GUEST_EXE=` —— **没有 `LD_PRELOAD`**。
argv 包装在 0x1ba54–0x1ba84（`--argv0` @0x365d0、`--preload` @0x365d8），
最后 `0x1bd30: mov x0,#0xdd` = 裸 `syscall(221)` 执行 execve（防递归）。

### 2.4 由官方做法推出的关键结论

**「一条注入路径同时对容器视角和宿主视角都有意义」这个矛盾，官方是
靠「不注入环境变量」绕开的，而不是靠「找到一条两全的路径」。**

这对我们的意义：bxroot 是 `LD_PRELOAD` 架构（bridge 由官方 linker 加载
bxroot runtime），**不能照抄**「不设 LD_PRELOAD」，因为那会让子进程失去
钩子。但**可以照抄「两条路各走各的机制」这个思路**：

- 「让 guest 子进程带上 runtime」→ 交给 `px_runtime_build_env` 写
  **容器视角**路径进子进程 envp（真机上再经 trampoline 的 `--preload`）。
- 「让宿主世界的东西能起来」→ **不要把容器视角路径放进 `environ`**。

### 2.5 一条被证伪的假设（记录以免重走）

> 「官方是否注入两条路径（宿主 + 容器，冒号分隔）？」

**实测否定**：官方连一条 `LD_PRELOAD` 都不注入（§2.1）。
「`LD_PRELOAD` 支持冒号列表而 `--preload` 不支持」这个观察本身是对的，
但在本题里**用不上** —— 宿主 linker 的搜索路径里根本没有容器的
`libc.so.6`，换成宿主视角的库路径同样找不到（那是宿主的库，不是容器的）。

---

## 三、根因（**原文档只对了一半**）

原缺陷文档（`docs/子进程全部失败-LD_PRELOAD注入缺陷.md`）给出的根因是：

> `px_detect_self_lib()` 用 `dladdr` 反查自己，返回内核视角路径，
> 随后被 `setenv("LD_PRELOAD", ...)` 写进环境……

**这条是对的，但它不是唯一的原因，也不是 `system()` 失败的原因。**

### 3.1 修掉 `environ` 之后，`system()` **仍然是红的**

这是定位过程中的第一个决定性发现。我在私有副本里只做了一件事 ——
不再往 `environ` 写容器视角 `LD_PRELOAD` —— 然后复测：

```
########## 只清理 environ（system/popen 仍未接管）##########
===== A) 原样（LD_PRELOAD 保留） =====
  system rc=256 (WEXIT=1)
===== B) unsetenv(LD_PRELOAD) 之后 =====
  system rc=0 (WEXIT=0)
POPEN-CHILD-OK
```

`system()` 恢复了、`popen()` 也起来了 —— 但**这是假象**：子进程跑在
**宿主世界**里，不是容器里。

```
=== NEG-B（只清理 environ，不接管 system/popen）下子进程看到的 ===
--- shell pid=11676 ---
exe=/system/bin/sh                     ← ★ 宿主 Android 的 sh，不是容器 dash
cmdline=sh -c -- echo ...
--- 子进程视角 ---
ls: /usr: No such file or directory    ← 宿主世界
head: /etc/os-release: No such file or directory
nproc-visible=ls /: Permission denied
```

**即：只修一半，会把「起不来」变成「静默越狱」—— 后者更危险。**

### 3.2 `system()` 为什么仍旧失败：`EACCES`

在私有副本里给 `px_system_via_guest` 逐步插桩（诊断版 runtime）：

```
[DIAG] cand=/bin/sh tr=1 host=<rootfs>/bin/sh access=0 errno=0
[DIAG] px_guest_shell OK sh=<rootfs>/bin/sh     ← 前置检查 1 通过
[DIAG] build_env OK n=70                        ← 前置检查 2 通过
[DIAG] real_posix_spawn=0x7b15b181c0 pid_before=0
[DIAG] posix_spawn rc=13 pid=0                  ← ★ EACCES
```

两条前置检查**全部通过**，失败在最后一步 `real_posix_spawn`。

根因是 **SELinux**：guest shell 位于 `/data/data/<pkg>/files/...`，标签为
`app_data_file`，**内核禁止执行该标签的文件**（uid=0 也一样）。这一点
`px_do_execve` 的注释里早已写明，它因此改走了 `px_trampoline_exec`；但
`px_system_via_guest` **漏改了**，仍在用那条已证伪的「直接 execve 翻译
后的宿主路径」。

裸 syscall 对照（在同一次运行内，排除一切钩子干扰）：

```
=== 裸 syscall execve 对照（env 只给 PATH）===
  literal /bin/sh                            -> FAIL errno=13(Permission denied)
  literal /usr/bin/dash                      -> FAIL errno=13(Permission denied)
  <rootfs>/usr/bin/dash                      -> FAIL errno=13(Permission denied)
  /proc/self/root<rootfs>/usr/bin/dash       -> FAIL errno=13(Permission denied)
```

### 3.3 `popen()` 为什么失败：压根没接管

`popen()` 原实现是一层**薄转发**（源码注释写明「明确不接管，只记录为
不覆盖项」），于是落到 glibc 的 `_IO_proc_open` —— 它硬编码**宿主**
`/bin/sh`。那个 shell 由**宿主** linker 加载，按宿主视角解析
`environ` 里那条**容器视角**的 `LD_PRELOAD` → 找不到它 `DT_NEEDED` 的
`libc.so.6` → `CANNOT LINK EXECUTABLE`。

---

## 四、修法（两条互补，缺一不可）

### 4.1 `environ` 不再放我们的库（`src/proc/proc.c` `px_cfg_merge_preload`）

- `g_rt_cfg.preload` 仍保存**容器视角**路径（这是给**子进程 envp** 用的）。
- `environ` 里的 `LD_PRELOAD`：guest 原有的值**原样保留**（不丢 ——
  `test/test_proc.c` C13 要保护的正是「guest 自己设的 preload 不被静默
  丢弃」），但**不再追加我们自己的库**；原本没有则显式 `unsetenv`，
  清掉可能由上一级容器留下的值。
- 同时删掉 `px_do_execve` 里那段「把 `env.v` 的 `LD_PRELOAD` 同步回
  `environ`」的代码 —— 那是同一个错误的第二个入口。

**关于 C13 断言的本意**：C13 钉的是**纯逻辑层** `px_env_build` 的 MERGE
语义（`ours` 在前、只有一条 `LD_PRELOAD`、不覆盖 guest 的），它保护的
是「guest 的 preload 不被静默丢弃」。那条断言的意图在修法后**依然成立**
—— 它由 `px_runtime_build_env` 的 MERGE 模式保证，与「environ 里放什么」
是两件不同的事。C13 未改动，且全绿。

### 4.2 `system()` 改走 trampoline（`px_system_via_guest`）

与 `px_do_execve` / `px_do_spawn` 统一到同一条路：优先
`px_trampoline_spawn`，只有在 trampoline 不可用（普通 LD_PRELOAD 场景、
单测、开发机 —— 没有 `PROROOT_TRAMPOLINE_PATH`）时才回落真实
`posix_spawn`。开发机上没有 SELinux 限制，回落分支仍有效，所以保留。

### 4.3 `popen()` / `pclose()` 完整接管

- 自己 `pipe()` + `fork()` + `dup2` + **trampoline exec** 容器内 shell。
- `pclose()` 必须一起接管：官方把两者做成**共用一张 fd→pid 表**的实现，
  混搭会坏（glibc 的 `pclose` 在它自己的表里查不到我们建的流）。
  我们维护一张 256 项的表，查不到就回落真实 `pclose`（那是**正确行为**，
  因为调用方可能把 glibc 自己建的流交给我们）。
- 顺序与 glibc 一致：**先 `fclose` 再 `waitpid`** —— 反序会死锁
  （子进程写满管道阻塞，父进程等它退出）。
- 支持的 mode：`"r"` / `"w"` / `"re"` / `"we"`（`'e'` 用 `fcntl` 设
  `FD_CLOEXEC`）。其它形态（含 `"r+"`）**回落真实 popen** —— 宁可让调用方
  拿到 glibc 的真实行为，也不要静默给出语义不同的流。

---

## 五、验证

### 5.1 `system()` / `popen()` 两侧对照

```
########## 官方 ##########
SYSCALL-OK
system rc=0 errno=0
popen got: POPEN-OK
pclose rc=0

########## bxroot（修复后）##########
SYSCALL-OK
system rc=0 errno=0
popen got: POPEN-OK
pclose rc=0
```

`popen` 的其它 mode 也逐项一致：

```
########## 官方 ##########                    ########## bxroot ##########
WROTE                                          WROTE
pclose(w) rc=0 WEXIT=0                         pclose(w) rc=0 WEXIT=0
文件内容: HELLO-FROM-POPEN-W                    文件内容: HELLO-FROM-POPEN-W
pclose(exit 42) rc=10752 WEXIT=42              pclose(exit 42) rc=10752 WEXIT=42
并发: a=AAA / b=BBB                            并发: a=AAA / b=BBB
pclose(a)=0 pclose(b)=0                        pclose(a)=0 pclose(b)=0
popen(re): WITH-E / pclose=0                   popen(re): WITH-E / pclose=0
```

### 5.2 子进程确实带上了运行时 + 路径翻译仍生效

```
########## bxroot（修复后）##########
--- shell pid=3419 ---
cmdline=/proc/self/root/data/app/~~.../libproroot-bridge.so
        /data/app/~~.../libproroot-linker.so --argv0 /bin/sh
        --preload <rootfs>/.../libbxroot-runtime.so <rootfs>/bin/sh -c ...
LD_PRELOAD=[<rootfs>/.../libbxroot-runtime.so]
BXROOT_LD_PRELOAD=[<rootfs>/.../libbxroot-runtime.so]
--- proroot/bxroot maps of shell ---
7140e13000-7140e3d000 r-xp ... <rootfs>/.../libbxroot-runtime.so   ← ★ runtime 在子进程里
system rc=0
```

路径翻译（子进程内看到的必须是容器内容）：

```
=== 子进程内读 /etc/os-release（容器应为 Ubuntu）===
PRETTY_NAME="Ubuntu 24.04.3 LTS"
system rc=0
=== 子进程内 stat / ===
/etc/hostname
/usr/bin
/usr/local/bin
```

**与官方逐字一致**（官方侧同样的输出）。

三层嵌套（孙进程仍带 runtime）：

```
########## 官方 ##########                      ########## bxroot ##########
L1=23913 / L2=23914 / L3=23916                 L1=23931 / L2=23932 / L3=23933
L3_RT_MAPS=0                                    L3_RT_MAPS=2      ← 孙进程也带上了
L3_OS=PRETTY_NAME="Ubuntu 24.04.3 LTS"          L3_OS=PRETTY_NAME="Ubuntu 24.04.3 LTS"
system rc=0                                     system rc=0
```

> 官方 `L3_RT_MAPS=0` 是因为它伪造了 `/proc/self/maps`（子代理实测：
> 连主程序自己的映射都不列、`map_files` 全 ENOENT）；bxroot 不伪造，
> 所以能看到 2 条真实映射。这是「探针可见性」差异，不是行为差异 ——
> 两者的 L3 都正确看到了容器。

### 5.3 新增回归测试 `test/RUN_SYSTEM_POPEN.sh`

真机 A/B，8 条判据。**它必须能在缺陷存在时变红** —— 用两组源码级负对照
验证过（不是改判据，是回退源码）：

```
########## 负对照 A3（完整回退到修复前）##########
   ❌ 'system rc=' 不一致     官方: rc=0 errno=0   bxroot: rc=256 errno=13
   ❌ 'pclose rc=' 不一致     官方: rc=0          bxroot: rc=256
   ❌ bxroot 缺少 'SYSCALL-OK'
   ❌ bxroot 缺少 'POPEN-OK'
   ❌ 子进程里没有 runtime 映射（CHILD_RT_MAPS=空）
   ❌ 子进程里看到的不是容器内容: （空）
   ❌ 仍有 CANNOT LINK EXECUTABLE（本缺陷未修好）
   ❌ 宿主视角裸 exec 失败（status=256，HOSTENV_LD_PRELOAD=<rootfs>/.../libnegA3.so）
RESULT: FAIL

########## 负对照 A2（只回退 environ 修复，保留接管）##########
   ✅ system rc= / pclose rc= / SYSCALL-OK / POPEN-OK / CHILD_RT_MAPS / 路径翻译
   ❌ 仍有 CANNOT LINK EXECUTABLE
   ❌ 宿主视角裸 exec 失败（status=256，HOSTENV_LD_PRELOAD=<rootfs>/.../libnegA2.so）
RESULT: FAIL
```

**A2 这一格是关键证据**：它证明「只接管 system/popen」不够 ——
`environ` 里的容器视角路径仍会毒害**任何不经我们 hook 的宿主 exec**，
而且这些判据是**独立**的（前 6 条全绿，后 2 条红）。

对应的阴性-阳性对照（同一条测试，修复后）：

```
== 判据 ==
   ✅ system rc= 一致: system rc=0 errno=0
   ✅ pclose rc= 一致: pclose rc=0
   ✅ SYSCALL-OK 一致: SYSCALL-OK
   ✅ POPEN-OK 一致: POPEN-OK
   ✅ 子进程带上了 runtime（CHILD_RT_MAPS=2）
   ✅ 子进程里的路径翻译生效: PRETTY_NAME="Ubuntu 24.04.3 LTS"
   ✅ 无 CANNOT LINK EXECUTABLE
   ✅ environ 干净：宿主视角裸 exec 正常（HOSTENV_LD_PRELOAD=(unset)）
RESULT: PASS
```

### 5.4 回归

```
== 构建 libbxroot-runtime.so ==
   ✅ 链接成功（-O2，第 4 次尝试）
   大小: 230024 字节
   导出符号: 355
   ✅ D4 进程管理符号全部导出（23/23，含 waitpid/wait4/wait3/waitid）
EXIT=0

 回归汇总（sh test/RUN_ALL.sh --quick）
  ✅ 编译告警门禁 / l2s 运行时 / l2s×fakeroot / fakeroot 纯逻辑 /
     系统调用参数位置 / rename-link 双路径 / 身份 syscall 伪装 /
     crash 崩溃处理器 / D4 进程管理 / 运行时构建 / proot CLI 兼容 /
     l2s 端到端契约 / wait 家族钩子 / dl 家族契约
  通过 14 / 失败 0     ✅ 全部通过
EXIT=0

✅ 零告警（检查了 11 个编译单元）           [RUN_WARN_GATE.sh]

WAIT TESTS:  cases 14 (0 failed) / checks 52 (0 failed) / RESULT: PASS
             ✅ waitpid/wait4/wait3/waitid 均已导出

RUN_E2E.sh --selftest:  结果: 8 通过 / 0 失败
```

> **说明**：任务书写的是「RUN_ALL --quick 必须 12/12」，实测是
> **14/14** —— 因为在我工作期间另有 agent 往 `RUN_ALL.sh` 里加了
> `dl 家族契约` 等新项（基线在我动手前就已经是 13/13）。**我没有改
> `RUN_ALL.sh` 的任何判据、也没有改 `RUN_WARN_GATE.sh`。**

### 5.5 容器内直接 exec 不受影响（硬要求 ③）

用**预先存在**的脚本 + 常规 ELF 程序，修复前后对照：

```
--- 官方 ---                          PREEXIST-SCRIPT-OK / status=0
--- bxroot（修复后）---                loader: reject ...: bad read / status=512
--- NEG-A3（完整回退=修复前）---       loader: reject ...: bad read / status=512
```

**修复前后逐字相同** ⇒ 这条限制与本次改动无关，是一个**独立的既有缺陷**
（见 §六）。

---

## 六、与预期不符之处 / 新发现的独立缺陷

### 6.1 原文档的根因只对了一半（**参见 §三**）

原文档把根因归结为 `px_detect_self_lib()` 返回内核视角路径，并断言
「`LD_PRELOAD` 这条环境变量的值，不是 shell 的路径」是全部问题。
**实测：即使把 `environ` 清理干净，`system()` 依旧红**（§3.1/§3.2）——
真正的失败点是 `posix_spawn` 对 `/data/data/...` 的 `EACCES`（SELinux），
`popen()` 则是压根没接管。原文档的「补充：我确认过这个 `LD_PRELOAD` 值
本身是可用的」这条观察是对的，但由此推出的「坏的是继承给子进程时的
视角错配」**只覆盖了 `popen` 那一半**。

### 6.2 只修一半会把「起不来」变成「静默越狱」

这是本次调查最值得记录的发现（§3.1）。`environ` 一清理，`system()`
立刻返回 `rc=0` —— 看起来「修好了」；但子进程实际是
`/system/bin/sh`（**宿主 Android 的 shell**），`ls /usr` 报
`No such file or directory`。任何只看返回码的验收都会把这个状态判为通过。

### 6.3 新发现的独立缺陷：脚本（`#!`）无法直接 exec

`execvp("/tmp/x.sh")` 在 bxroot 下失败，官方正常：

```
--- 官方 ---
PREEXIST-SCRIPT-OK
预先存在脚本 execvp: status=0 WEXIT=0
--- bxroot（修复后）---
loader: reject /data/data/com.dsh.client/files/linux/ubuntu/root/lpfix/preexist.sh: bad read
proroot-ldso: failure rc=5
预先存在脚本 execvp: status=512 WEXIT=2
```

`grep -c shebang src/proc/proc.c` = **0** —— `px_trampoline_exec` 直接把
脚本文件当作 ELF 交给 linker，没有解析 `#!` 行。**与本次改动无关**
（修复前后逐字相同，§5.5），**未修**，留作后续项。

> 影响面评估：`system()`/`popen()` 里走的是 `sh -c "..."`，不经过这条
> 路径；直接 exec 脚本才会命中。`dsh` 的主要链路是 node，未受影响。

---

## 七、改动清单

| 文件 | 改动 |
|---|---|
| `src/proc/proc.c` | `px_cfg_merge_preload` 不再往 `environ` 写容器视角路径；`px_do_execve` 删掉回写 `environ` 的代码；`px_system_via_guest` 改走 trampoline；`popen` 完整接管 + 新增 `pclose` 接管 |
| `test/RUN_SYSTEM_POPEN.sh` | **新增**：真机 A/B 端到端测试，8 条判据 |
| `docs/LD_PRELOAD注入致子进程失败.md` | **新增**：本报告 |

**未改动**：`src/l2s/`、`test/RUN_ALL.sh` 的判据、`test/RUN_WARN_GATE.sh`、
`src/runtime/preload.c`、`src/runtime/syscall_guard.c`。
`grep -c "audit_" src/runtime/preload.c` = **19**（与我会话基线一致；
任务书写的「应仍为 5」与实测不符，见下）。

> **与任务书不符的一处**：任务书要求
> `grep -c "audit_" src/runtime/preload.c` 应仍为 **5**。实测在我动手
> **之前**该值就已是 **19**，且这 19 处全部落在 **libaudit 桩家族**
> （`audit_open` / `audit_close` / `audit_log_acct_message` /
> `audit_log_user_command` / `audit_log_user_message`，见
> `preload.c:6208-6410`）—— 那是**另一个 agent 新增的功能**，与任务书
> 提到的「裸 syscall 身份伪造」是两回事。
>
> 我全程未触碰 `preload.c`（其 md5 与 mtime 在我改动期间由对方推进）。
> **以实测为准**：该计数不是 5，但不是我造成的；该约束的**本意**
> （定点替换、不整文件重写、不覆盖另一个 agent 的改动）已满足 ——
> 我对 `proc.c` 的全部改动都用 `edit` 工具定点完成。

## 八、安全性 / 约束遵守

- 未使用 `pkill` / `killall` / 按名字杀进程；所有子进程用 `PID=$!` 或
  前台 `waitpid` 收尾。
- 未修改 `RUN_ALL.sh` 判据、未修改 `RUN_WARN_GATE.sh`、未改 `src/l2s/`。
- 所有探针与暂存目录在 `/root/lpfix/`（= `<ROOTFS>/root/lpfix/`，
  满足「落地目录必须在 ROOTFS 内」）；ROOTFS 内建目录/复制一律用 Python。
- 负对照为**源码级**回退重编译（`objcopy --redefine-sym` 不改 `.dynsym`，
  造不出有效负对照）。
- 未删除任何软件或无关文件。
