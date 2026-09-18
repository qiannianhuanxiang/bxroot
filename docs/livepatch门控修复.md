# livepatch 无门控缺陷 —— 修复报告

> **状态**：已修复、已实测、回归已跑。
>
> **性质**：**真实缺陷**（评估报告已确认）。在**没有** Android seccomp 白名单的
> 环境里，`bxroot_livepatch_apply()` 会无条件对 libc 代码页做 `mprotect` +
> 逐字节改写 —— 收益为零，风险全担。
>
> **改动范围**：`src/runtime/livepatch.c`（主体）、`src/runtime/livepatch.h`
> （接口补 3 个访问器）。**未动** `src/runtime/preload.c` 的 `dlsym` /
> `ldso_service_*`（另一位同事在改那部分）。
>
> **原始证据复跑入口**：`sh docs/raw/livepatch门控探针.sh`

---

## 一、缺陷现象与根因

### 1.1 现象

在**普通 Ubuntu / 其它容器**（不带 Android 那套 seccomp 白名单）里跑 bxroot：

- 现象 A：`bxroot_livepatch_apply()` 一点就 **SIGSEGV**，连崩溃现场都来不及
  打印（报告作者的实测）；
- 现象 B：即使没崩，本层做的事也**毫无收益** —— 没有白名单要绕，那些 `svc`
  本来就能正常执行。

### 1.2 根因

`livepatch.c` 的**设计前提**是"宿主 loader 用 seccomp 以 `KILL_PROCESS`
逐个列举禁止了 80+ 个系统调用号，glibc 内部的内联 `svc` 会撞上其中
`set_robust_list(99)` / `rseq(293)` 而**直接杀死进程**（不投递信号，SIGSYS
处理器救不了）"。这个前提在 Android 容器里成立，**在普通 Ubuntu 里不成立**。

而原实现对这个前提**零校验**：

```
grep -cE 'prctl|PR_GET_SECCOMP|BXROOT_NO_LIVEPATCH' src/runtime/livepatch.c
→ 0        （修复前）
```

于是它照常执行：

```c
mprotect((void *)lo, (size_t)(hi - lo), PROT_READ | PROT_WRITE | PROT_EXEC);
...
*p = s->patch;   /* 逐字节改写 libc 代码页 */
```

### 1.3 本容器实测：为什么"没有收益"是可以证明的

判据是内联 `svc` 直发（不经过任何符号层），看是被 **KILL** 还是被**拒绝**：

```
nr=99   set_robust_list（站点 1）          -> -38  (= -ENOSYS，调用被拒绝但进程存活)
nr=293  rseq（站点 2）                     -> -38  (= -ENOSYS，调用被拒绝但进程存活)
nr=425  io_uring_setup（已知被 TRAP 的对照） -> -38  (= -ENOSYS，调用被拒绝但进程存活)
```

`-38` = `ENOSYS`。**进程活着**，只是调用被拒绝 —— 这正是 livepatch 要模拟的
语义。也就是说在本环境里这两个站点**哪怕不补也杀不掉进程**，补丁纯属多余。

对照 `docs/官方seccomp补丁分析.md` §四记录的 Android 侧行为（那套过滤器对
425/426/427 等以 `TRAP`/`KILL` 处理，进程会死于 159），差异一目了然。

> ★ 现象 A（崩溃）在本容器**未能复现**。原因见 §3.4：本容器的 libc 代码页已经
> 被**外层 proroot runtime** 改成了可写（活体内存比对：两个站点都已是
> `0xd2800000`，即外层已替我们打过补丁），写入路径因此是通的。
> 也就是说本容器恰好是"不适用的环境 + 恰好不会崩"的巧合组合 ——
> **不能**用"这里没崩"去否定报告里"受限环境会崩"的结论。

---

## 二、修复方案

### 2.1 三道门，全部前置在**任何**内存操作之前

```
① BXROOT_NO_LIVEPATCH=1        → 硬开关，无条件跳过
② 非 aarch64                   → 站点指令编码不适用，跳过
③ prctl(PR_GET_SECCOMP) != 2   → 没有过滤器，跳过（= 非 Android 环境的正常路径）
④ glibc 版本 != 站点表声明版本 → 偏移不可信，跳过 + **告警**
```

返回 `LP_SKIP_*` 正数常量，**不是失败** —— 调用方本来就把本层当尽力而为的
优化，跳过不该有副作用。

### 2.2 为什么这么选

**（a）门必须在 `mprotect` 之前。** 报告实测的崩溃点正是"把 libc 代码页改成
RWX"这一步。若先改页属性再发现环境不对，可写代码页窗口已经打开了。现在的
顺序是"三道门全过 → 才开始算页范围"，一处内存属性都不碰。这一点用
**数 `mprotect` 次数**做了硬验证（见 §4.1）。

**（b）门 ③ 用 `prctl` 而不是读 `/proc/self/status`。** 本函数在 LD_PRELOAD
构造函数里被调用，可能早于 libc 内部初始化；`prctl` 是一条系统调用，无
内存分配、无 `FILE` 状态，依赖面最小。两者都是 Linux 2.6.39 引入的，语义等价。

**（c）版本断言用严格相等、不用"大于等于"。** 站点偏移是**版本精确绑定**的
（0x855c4 / 0x85850 是 Ubuntu 24.04 glibc 2.39 的），2.40 相对 2.39 的布局没有
任何兼容保证。"≥"会放过一次真实的不匹配。

**（d）门的顺序：seccomp 在版本之前。** 版本告警是给"本来要打补丁、结果打不上"
的场景用的。没有 seccomp 的环境连补丁都不需要，再报一行"站点表过期"只是噪声 ——
而 LD_PRELOAD 构造函数**每个 exec 都跑一次**，噪声会被放大成刷屏。反过来只要
seccomp 在（= 真机场景），版本不符就一定会报出来，**不会静默**。

**（e）`BXROOT_NO_LIVEPATCH` 用 `BXROOT_` 前缀、`atoi() != 0` 语义。** 与项目既有
的 `BXROOT_FAKEROOT` / `BXROOT_VERBOSE` 一致。用 `=0`（而不是"删掉变量"）来表达
"不关"，是为了让上层脚本能**覆盖**父进程环境里的 `=1` —— 删不掉，只能改值。

### 2.3 顺带修正的两个小问题

| 问题 | 修复前 | 修复后 |
|---|---|---|
| `bxroot_livepatch_apply()` 的返回值语义 | `hits == 0` 时返回 `-5`，但 `g_applied` 被无条件置 1 → 对外报 `applied=1` 的**假象** | `g_applied` 只在 `hits > 0` 时置位，与 `hits` 同源 |
| `skip_reason` 的残留 | （新访问器，无此问题） | 无条件记录**包括** `LP_SKIP_NONE`，避免"第二次调用的不跳过"读回上一次的跳过原因 |

---

## 三、★ 边界一：`PR_GET_SECCOMP` 判据的局限（如实记录）★

### 3.1 判据本身

`prctl(PR_GET_SECCOMP)` 的取值（内核 ABI）：

| 值 | 含义 |
|---|---|
| 0 | 没有过滤器 |
| 1 | `SECCOMP_MODE_STRICT`（只放行 read/write/_exit/sigreturn） |
| 2 | `SECCOMP_MODE_FILTER`（装了 BPF 过滤器） |

**★ 返回 2 只证明"存在某个 seccomp 过滤器"，证明不了"这是 Android 那套需要
中和的白名单"。★** 报告作者已指出这一点，实测把它坐实了。

### 3.2 实测证据：一个**与 Android 毫无关系**的过滤器同样报 2

装一个只有 3 条 BPF 指令、**只对 `chmod` 返回 ENOSYS** 的过滤器：

```
装过滤器前 PR_GET_SECCOMP = 2
装过滤器后 PR_GET_SECCOMP = 2   ← 与 Android 毫无关系的过滤器也是这个值
对照：chmod 被这条过滤器拒绝 -> rc=-1 errno=38 (Function not implemented)
```

（顺带踩到一个坑：`chmod(...)` 与 `errno` 若写成同一个 `printf` 的两个实参，
C 未规定求值顺序，实测会把 `errno` 印成调用前的旧值 `-1`。先调用、再取
`errno` 才对。这个坑已写进探针脚本的注释。）

### 3.3 两类误判，方向相反

| 误判方向 | 会不会发生 | 后果 |
|---|---|---|
| **误跳过**（有白名单却说没有） | **不会** —— 门 ③ 只对 `0`/`1` 跳过，而 Android 白名单一定让 `PR_GET_SECCOMP` 读到 2 | — |
| **误执行**（过滤器不是白名单却说"有"） | **会发生**，且无法从返回值区分 | 补丁照打 |

### 3.4 为什么仍然接受这个不精确的判据

因为"误执行"一侧有**站点表自身的逐字节校验**兜底，"误跳过"一侧没有：

- **误执行** → `patch_one()` 先比对原指令是否 `svc #0`。非 Android 的过滤器
  **不会改变 libc 的字节**，所以校验照样通过、补丁照样打上；语义上把这两个
  调用变成"成功 / `ENOSYS`"。而这正是内核在过滤器下**本来就会给**的结果
  （§1.3 实测两个号都返回 `-38`），不制造新的不一致。风险是"多做了一件没必要的
  事 + 一次可写代码页窗口"，**不是崩溃**。
- **误跳过** → 在真机上必然死于 159（Bad system call），而且**无法挽救**
  （seccomp 以 `KILL_PROCESS` 处理，不投递信号；参考实现记录里 SIGSYS 处理器
  「实测一次都没被调用」）。**真机是主战场，这一侧不能赌。**

所以门控方向定为"**宁可多跑一次 livepatch，不可在 Android 上误跳过**"：

```
只有明确读到"没有过滤器"（0 / 1）才跳过；
prctl 调用失败（返回 -1，例如极老内核不认 PR_GET_SECCOMP）时**不跳过**，
照常打补丁 —— 未知一律按"可能有过滤器"处理。
```

这条"未知不跳过"有独立断言覆盖（§4.1 场景 4c）。

### 3.5 站点表的"校验失败即跳过"够不够？

**够兜住一类，兜不住另一类，而兜不住的那类不需要兜：**

- **兜得住**："该地址上不是 `svc #0`"——换编译器、换 glibc 导致布局漂移时，
  `patch_one` 返回 0，`hits` 不增加，不会打错位置。
- **兜不住**："过滤器不是白名单、而站点确实是 `svc`"——这一类**不需要**兜，
  理由见 §3.4（打上去的语义与内核本来会给的一致，不制造新不一致）。
- **需要额外兜的是**："换 glibc 版本让偏移整体漂移 → 校验全失败 → 补丁一条都没
  打 → 而进程照常启动、一句话都不说"。这是**静默失效**，由门 ④ 的运行期版本
  断言负责，见下一节。

---

## 四、版本断言的实现与实测输出（报告 P2-4.1）

### 4.1 实现

```c
#define LP_SITE_LIBC_VERSION "2.39"     /* 与站点表成对，改表必须改这里 */

ver = gnu_get_libc_version();           /* 直接调用，不经 dlsym */
if (ver == NULL)          → WARN + 跳过（读不到 = 偏移不可信）
if (strcmp(ver, "2.39"))  → WARN + 跳过
```

用 `gnu_get_libc_version()` 而不是 `confstr(_CS_GNU_LIBC_VERSION)`：前者返回裸
版本号（`"2.39"`），后者返回 `"glibc 2.39"` 还要再剥前缀。两者实测：

```
confstr(_CS_GNU_LIBC_VERSION) ret=11 buf="glibc 2.39"
gnu_get_libc_version() = "2.39"
```

**★ 必须用直接调用、不能用 `dlsym` ★** —— 本项目已有两处记载：本环境里
`dlsym(RTLD_NEXT)` 拿到的 libc 地址不可靠（外层做了活体代码补丁），跳进去会
SIGSEGV。`gnu_get_libc_version` 由链接器在加载期解析，没有这个问题。

### 4.2 实测告警输出（逐字）

版本不符（站点表 2.39，当前 2.40）：

```
[bxroot] WARN: livepatch: 站点表是给 glibc 2.39 写的，当前是 glibc 2.40，偏移不可信 → livepatch 已跳过
```

版本读不出来：

```
[bxroot] WARN: livepatch: 站点表是给 glibc 2.39 写的，但读不到当前 glibc 版本（gnu_get_libc_version 返回空）→ livepatch 已跳过
```

两次告警都**没有**触发 `mprotect`（见下表 `mprotect=0`）。

### 4.3 门控全场景实测（驱动**真实** `livepatch.c`）

手法：在测试程序里用替身接管 `prctl` / `gnu_get_libc_version` / `mprotect`，
把"环境"做成可编程的，并**数 `mprotect` 调用次数**。

| 场景 | 注入的环境 | `rc` | `skip` | `mprotect` | 判定 |
|---|---|---|---|---|---|
| 1 | `PR_GET_SECCOMP=0`（无过滤器） | 2 | 2 | **0** | ✅ 跳过，未碰代码页 |
| 2 | `PR_GET_SECCOMP=1`（STRICT） | 2 | 2 | **0** | ✅ 跳过，未碰代码页 |
| 3 | `BXROOT_NO_LIVEPATCH=1` + 有过滤器 | 1 | 1 | **0** | ✅ 跳过，未碰代码页 |
| 4 | 有过滤器 + 版本 2.40 | 3 | 3 | **0** | ✅ 跳过 + 告警 |
| 4b | 有过滤器 + 版本读不出 | 3 | 3 | **0** | ✅ 跳过 + 告警 |
| 4c | **`prctl` 失败**（未知） | **0** | **0** | 1 | ✅ **未跳过**，`hits=2` |
| 5 | 有过滤器 + 版本 2.39（**Android 场景**） | **0** | **0** | 1 | ✅ **行为与修复前完全一致** |

**★ `mprotect=0` 是本节最硬的一条 ★** —— 它直接证明危险路径被挡在门外，
而不是"门控只是返回了个好看的数字"。

场景 5 是 P0 守恒项（"有过滤器时行为必须完全不变"）的断言：

```
[PASS] ★ rc=0（与修复前一致：返回 0 = 至少一个站点打上）
[PASS] ★ hits=2（与修复前一致）
[PASS] ★ applied=1
[PASS] ★ skip_reason=NONE（没被门控误跳过）
[PASS] ★ site[0]=mov x0,#0（补丁内容一字未改）
[PASS] ★ site[1]=mov x0,#0（补丁内容一字未改）
```

### 4.4 端到端：真机路径实测（最有说服力的一条）

用**真实构建产物** `build/libbxroot-runtime.so`，经官方 bridge/linker 在容器里
跑一个只做 `pthread_create` 的探针：

```
[bxroot] livepatch: 已中和 2 个站点
[bxroot] proc: 已修复 glibc 线程链表未初始化 (pd=0x733f77b8c0 list=0x733f77b980)
pthread_create rc=0
join 完成 r=42
PTHREAD-OK
rc=0
```

**能力未受损**：门控放行 → 2 个站点中和 → `pthread_create` 正常。
（`pthread_create` 正是 livepatch 存在的唯一理由；门控若误跳过，这里会是 159。）

集成状态下各访问器的读数：

| 场景 | `has_seccomp()` | `applied()` | `hits()` | `skip_reason()` | `libc_base()` |
|---|---|---|---|---|---|
| 默认（本容器） | 1 | 0 | 0 | 0（未跳过） | `0x7a0b4ca000` |
| `BXROOT_NO_LIVEPATCH=1` | 1 | 0 | 0 | **1** | **`0x0`** |

★ `libc_base()=0x0` 是"门控真的提前返回了"的旁证 ★ —— 它连
`/proc/self/maps` 都还没读。

> `applied()=0` 而 `skip_reason()=0` 在默认场景下不矛盾：本容器的活体 libc
> **已被外层 runtime 改写成 `mov x0,#0`**，`patch_one` 逐字节校验发现"不是
> `svc`"，于是 `hits=0`。这正是站点表校验机制在按设计工作。

---

## 五、回归结果

### 5.1 全量回归（我的工作副本）

```
sh test/RUN_ALL.sh
```

第 1 轮（`21:08:14` 启动）与第 2 轮（`21:10` 后启动）的结论一致：

| 项 | 结果 |
|---|---|
| l2s 运行时 / l2s×fakeroot 协同 / fakeroot 纯逻辑 | ✅ PASS |
| 系统调用参数位置 / rename-link 双路径 / 身份 syscall 伪装 | ✅ PASS |
| crash 崩溃处理器 / D4 进程管理 / 运行时构建（23/23 符号导出） | ✅ PASS |
| proot CLI 兼容 / 上游 proot 选项表覆盖 / 路径形态回归（7 用例） | ✅ PASS |
| l2s 端到端 / wait 家族 / dl 家族 / system-popen / pthread_create / shebang / 降权族 | ✅ PASS |
| 编译告警门禁 | 见 §5.2（第 1、2 轮为红，**已由同事修复，现为绿**） |

### 5.2 编译告警：`livepatch.c` 始终零告警

第 1 轮全量回归时编译告警门禁报红，红点是 `src/runtime/preload.c:4201`：

```
⚠️  src/runtime/livepatch.c            0 条      ← 本次改动，零告警
❌ 共 1 条告警，涉及: src/runtime/preload.c
     src/runtime/preload.c:4201:24: warning: the comparison will always evaluate
       as 'true' for the address of 'dlvsym' will never be NULL [-Waddress]
```

**那一条不是我引入的**，三条独立证据：

1. **告警在 `preload.c`**，而任务书明确要求我**不要动**该文件的 `dlsym` /
   `ldso_service_*` 区域 —— `4201` 行正在 `dlsym` 函数内（另一位同事在改）。
2. **告警门禁对每个文件独立编译**（`for f in $UNITS`，各自一条 `gcc`），
   所以 `livepatch.c` 的改动在原理上不可能影响 `preload.c` 的告警。
3. **我只改了 2 个文件**（按 mtime 核对）：`src/runtime/livepatch.c`、
   `src/runtime/livepatch.h`。`preload.c` 的 mtime 停在 `20:59:27`，早于我开始。

**当前状态**：同事已修掉 `preload.c` 那条告警，门禁现在是**全绿**：

```
✅ src/runtime/preload.c              0 条
✅ src/runtime/livepatch.c            0 条
   ...（11 个编译单元）
✅ 零告警（检查了 11 个编译单元）
```

所以我**没有**去动 `preload.c` —— 那会与同事的改动冲突，且问题已自行消解。

### 5.3 独立副本上的全量回归：**19 通过 / 0 失败**

在这一点上有一份**比我自己那轮更强的证据**。集成方在
`/root/bxroot-cleanci-ULiDNV/repo` 做了一份**全新副本**并跑了全量回归。
经核对，该副本里的 `livepatch.c` 与我的版本**逐字节相同**：

```sh
diff -q /root/bxroot-cleanci-ULiDNV/repo/src/runtime/livepatch.c \
        src/runtime/livepatch.c
→ （无差异）
```

且其构建产物确实含本次门控（符号 + 告警字符串都在）：

```
nm -D --defined-only build/libbxroot-runtime.so → bxroot_livepatch_has_seccomp /
    skip_reason / site_libc_version 等 7 个符号齐全
strings → "BXROOT_NO_LIVEPATCH"、"[bxroot] livepatch: BXROOT_NO_LIVEPATCH="
```

回归结果（`/root/bxroot-ci-evidence/run_all_clean.log`）：

```
▶️  编译告警门禁         ✅ rc=0  ✅ 零告警（检查了 11 个编译单元）
▶️  路径形态回归         ✅ rc=0  7 个用例
▶️  运行时构建           ✅ rc=0  ✅ D4 进程管理符号全部导出（23/23）
▶️  pthread_create 栈    ⏭️  rc=2  环境不满足（找不到官方 runtime，跳过）
   ...（其余各项 RESULT: PASS）
  通过 19 / 失败 0
  ✅ 全部通过
EXIT=0
```

**要点**：在一个**与我的工作副本隔离的干净树**上、用**同一份代码**、跑完整回归，
结果是 **0 失败** —— 这同时排除了"我的工作副本里有别人未提交的中间状态"
这一整类怀疑。唯一的 `⏭️` 是环境不满足（缺官方 runtime 对照物），不是缺陷。

> 我自己那轮（第 3 轮）在我写文档时仍在跑 `D4 进程管理`：该子项的 gcc 正以
> `R` 状态持续消耗 CPU（`utime` 从 143643 涨到 210667 ticks），**是慢不是死**。
> 原因是容器里同时有**另一份全量回归**在跑（8 核，两个 `cc1` 并行），
> 加上本容器 gcc 的间歇性 ICE 重试，`test_proc` 那个编译单元被拖得很长。
> 判定依据是上面那份独立副本的 0 失败结果，以及这里可观测的 CPU 推进。

### 5.4 关于"路径形态回归"那次报红：是**并发编辑**，不是回归

第 1 轮全量回归时路径形态回归报红：

```
❌ bxroot 侧有 1 个用例失败：
     [FAIL] T06 经绝对符号链接 open -- No such file or directory
```

查明原因是**测试脚本在回归进行中被并发编辑**：

```
test/RUN_PATH_FORMS.sh 的 mtime = 21:08:44
我第一次 RUN_ALL 的启动时间    = 21:08:14
```

即回归跑到一半时文件被换掉了。用当前版本重跑：

```
ℹ️  已知限制 1 项（不是本次回归）：
     [KNOWNLIMIT] T06 经绝对符号链接 open -- ...
✅ 路径形态回归通过（7 个用例），另有 1 项已知限制（见上）
RESULT: PASS
```

新版脚本已把 `T06` 正确识别为**已知架构限制**（`KNOWNLIMIT`，内核解析链接目标，
LD_PRELOAD 感知不到），旧版把它算成 `fail`。**这不是我的改动的责任**，
但值得记一笔：**并行度高时，回归结果要连带核对被测文件的 mtime**。

### 5.5 两次失败小结

`RUN_ALL.sh` 在任务书里被描述为"当前 20 项全绿"，我的实测与之有出入，
但**两次偏差都已定位且都不是本次改动引入的**：

| 现象 | 根因 | 现状 |
|---|---|---|
| 编译告警门禁红（`preload.c:4201`） | 他人改动区域的**既有**告警 | 同事已修，**现为绿** |
| 路径形态回归红（`T06`） | 测试脚本**在回归进行中被并发编辑** | 用新脚本重跑 **PASS** |

另：`test/RUN_ALL.sh` 我**未做任何修改**（按任务书要求，交由集成方处理）。

---

## 六、踩过的坑（留给后人）

1. **`chmod(...)` 与 `errno` 写在同一个 `printf` 里会印出旧 `errno`。**
   C 未规定实参求值顺序。先调用、再取 `errno`。（§3.2）
2. **本容器的活体 libc 是"已被改过"的。** 活体内存比对显示两个站点都已是
   `0xd2800000`（外层 proroot 打的）。想验证本仓库的成功路径，必须先把站点
   **还原**成 `svc #0` —— 否则会得到误导性的 `hits=0`。
   磁盘文件与活体内存**不一致**是本环境的常态，不是异常。
3. **现象 A（SIGSEGV）在本容器复现不出来，不代表它不存在。** 本容器恰好
   "外层已把代码页改可写"，写入路径是通的。真机受限环境另说。
4. **`/tmp` 下 `LD_PRELOAD` 的 `.so` 会 `Permission denied`。** 集成验证要把
   探针与 `.so` 放进工作区目录，并注意 bridge 是 **ptrace/双视角**架构 ——
   传给 `--preload` 的必须是**内核视角**路径
   （`/data/data/com.dsh.client/files/linux/ubuntu/...`），不是翻译后视角。
5. **`-Wl,--unresolved-symbols=ignore-all` 会把重定位表搞坏**（`reloc:
   unsupported type 0`）。要验证 `LD_PRELOAD` 的访问器，正确做法是把 `.so`
   链接成依赖（`-l:rt.so` + `-Wl,-rpath,$ORIGIN`）。

---

## 七、遗留问题

1. **`MOV_X0_ENOSYS` 目前没有任何站点在用**（两条站点都是 `MOV_X0_0`）。
   文件头原注释论证"rseq 必须返回 ENOSYS"，与实现不一致。本轮**只加门控、
   未改补丁内容**（避免动到真机行为）。实测佐证：外层 runtime 在活体 libc 上
   也把 rseq 站点改成了 `mov x0,#0`，且 dsh/node 在该补丁下正常运行 ——
   所以 `MOV_X0_0` 这条路是走得通的。建议后续单独起一轮，用
   `docs/官方seccomp补丁分析.md` 的方法重新评估 rseq 的返回值语义。
2. **门 ③ 判不出过滤器的种类**（§3），这是 `PR_GET_SECCOMP` 的固有局限，
   非本修复能解决。若将来需要精确判据，可考虑：探测站点对应的系统调用在
   当前过滤器下**实际**的返回（直发 `svc` 并捕获 SIGSYS / 观察 `ENOSYS`），
   代价是引入"探测本身可能被杀"的风险，需要 `fork` 隔离 —— 明显更重，
   本轮不做。
3. **`LP_SITE_LIBC_VERSION` 与站点表是手工同步的两个副本。** 目前靠注释
   （"改表必须改这里"）约束。若将来站点表变大，值得加一个编译期断言把
   版本串与偏移表绑在一起。
4. **编译告警门禁当前为红**（`preload.c:4201`，他人改动区域），需集成时处理。

---

## 八、改动清单

| 文件 | 改动 |
|---|---|
| `src/runtime/livepatch.c` | 加门控（env 硬开关 / 架构 / seccomp / 版本断言）；`g_applied` 语义修正；`skip_reason` 记录；新增访问器与诊断输出 |
| `src/runtime/livepatch.h` | 新增 `LP_SKIP_*` 常量、`bxroot_livepatch_skip_reason()`、`bxroot_livepatch_site_libc_version()`、`bxroot_livepatch_has_seccomp()`；补充接口语义注释 |
| `docs/livepatch门控修复.md` | 本文档 |
| `docs/raw/livepatch门控探针.sh` | 可复跑的原始证据探针（`sh` 直接跑，退出码 0 = 所有环境断言仍成立） |

**未改动**：`src/runtime/preload.c`（含 `dlsym` / `ldso_service_*`）、
`test/RUN_ALL.sh`、以及任何其它文件。
