# 裸 syscall 身份伪造：修复 + 机制更正

> 状态：**第 1 部分（读身份 174..177）已修并有回归覆盖**；
> 第 2 部分（降权族）**已调查、未动手**，结论与建议见 §5。
>
> ⚠️ **本报告更正了原任务描述里的两处机制判断，两处都以实测为准**
> （见 §2、§3）。结论是：任务的前提「官方在裸 syscall 层也伪造」**不成立**，
> 而真正的缺口比原描述**小一半**（只有 `syscall()` 符号层，不含 `svc` 层）。

---

## 一、三层实测对照表

探针同时读四层：

| 层 | 读法 | 说明 |
|---|---|---|
| `status` | `/proc/self/status` 的 `Uid:` 行 | 内核真值，没有任何一层会改它 |
| `libc` | `getuid()` 等 libc 符号 | LD_PRELOAD 符号钩子的作用面 |
| `sym` | `syscall(174)` —— **libc 的 `syscall()` 符号** | libuv / 静态程序走的路径，`syscall_guard.c` 的作用面 |
| `svc` | 内联汇编 `svc #0` | 不经任何 libc 代码，只有内核能拦 |

**关键手法**：`svc` 列有两种写法，必须区分 ——
1. **静态内联 `svc`**（编译进探针二进制）：可被加载期指令补丁改写；
2. **运行时 JIT 生成的 `svc`**（写进 mmap 出来的可执行页）：**任何
   LD_PRELOAD / 符号劫持 / 加载期补丁都够不着**，给出硬件层的判决性观测。

下面的"JITsvc"列即第 2 种。

### 1.1 身份读取（fakeroot 开启）

| 侧 | status | libc `getuid()` | sym `syscall(174)` | svc（静态） | **JITsvc** |
|---|---|---|---|---|---|
| 无 runtime（纯 ldso） | 10655 | 10655 | 10655 | 10655 | 10655 |
| **官方** | 10655 | **0** | **0** | **10655** | **10655** |
| **bxroot 修前** | 10655 | **0** | **10655** ❌ | 10655 | 10655 |
| **bxroot 修后** | 10655 | **0** | **0** ✅ | **10655** | **10655** |

修后 **sym 列与官方逐字一致**。原始输出见 §6.1。

### 1.2 官方 getuid 的四个身份入口是否一致

| 侧 | libc `getuid/geteuid/getgid/getegid` | sym `174/175/176/177` |
|---|---|---|
| 官方 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| bxroot 修前 | 0 / 0 / 0 / 0 | **10655 × 4** ❌ |
| bxroot 修后 | 0 / 0 / 0 / 0 | **0 / 0 / 0 / 0** ✅ |

### 1.3 修后仍未对齐的地方（逐条登记，均在 §5 有分析）

| 项 | 官方 | bxroot 修后 | 性质 |
|---|---|---|---|
| `syscall(148)` `getresuid` | 0 / 0 / 0 | **10655 / 10655 / 10655** | 本轮未覆盖（缺口 B） |
| `syscall(150)` `getresgid` | 0 / 0 / 0 | **10655 / 10655 / 10655** | 同上 |
| `syscall(158)` `getgroups` | 1（零组） | **6（真实组表）** | 未覆盖（缺口 B） |
| **JITsvc `getuid`** | **10655** | **10655** | **两侧一致，不是缺口** |
| `setuid/setgid/setgroups/...` | 假装成功（0） | -1 / errno=38 ENOSYS | 缺口 C（§5） |

---

## 二、★ 更正一：官方**不**在 `svc` 层伪造身份 —— "特权转发层"解读是错的

任务描述引用的反汇编结论（`syscall(174)` 被转发到 `0x8740`）**方向是对的，
但层数判断是错的**。判决实验：

```sh
# 运行时 JIT 生成的 svc，加载期补丁够不着
JITsvc : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
```

**官方侧也是 10655。** 两侧都如此（修前修后都一样，因为这一层压根不受影响）。

补充两条独立证据：

1. **seccomp 没介入身份号**。用 SIGSYS 处理器逐号观测，官方侧
   `svc(174)` 的 `si_syscall = -1`（未投递 SIGSYS），说明内核**直接放行了
   这个调用**并返回真值 —— 不是被 TRAP 后改写。
   对照：`svc(425 io_uring_setup)` 两侧都 `si_syscall = 425`（确实被 TRAP）。
2. **内核在身份上是"自己人"**。本进程的 uid 就是 10655，内核认为它就
   应该看到 10655。要在硬件 syscall 层伪造，唯一手段是 seccomp
   （动作只有 `ALLOW/ERRNO/KILL/TRAP/LOG`，**不能伪造任意返回值**）
   或 ptrace。本栈里两者都没做。

**所以正确的表述是**：官方把身份伪造覆盖到了 **`syscall()` 符号层**，
覆盖范围 = `libc 符号 + syscall() 符号`；真·`svc` 在两侧都不伪造。
原文档 `docs/身份伪造只在符号层.md` 里那句「连裸 syscall 都被改写」，
如果把"裸 syscall"理解为 `svc #0`，就是**过度推断**；它实际指的是
`syscall(174)`。

### 这带来两个实际结论

- **修复目标可以精确化**：不需要、也不可能去伪造 `svc` 层；
  只要对齐 `syscall()` 符号层就与官方一致。本修复正是这么做的。
- **原文档 §2 的机制描述应从"返回值改写 vs 特权转发"更正为**：
  官方用内部转发层、bxroot 用"调用后改写返回值"，**机制不同但外部
  可观测行为一致**（在 `syscall()` 符号层逐字一致）。

---

## 三、★ 更正二：官方**确实**让降权族"假装成功"，但那一层够不着

任务描述里那条实测（官方 `setgroups(0,NULL) rc=0`、
**`raw syscall(159) rc=0`**）我**完全复现**了：

| 侧 | libc `setgroups(0,NULL)` | sym `syscall(159,0,NULL)` |
|---|---|---|
| 官方 | rc=0 | **rc=0** |
| bxroot 修前/修后 | rc=-1 / errno=38 | **rc=-1 / errno=38** |

（完整 9 个 setter × 2 层 × 3 侧的矩阵见 §6.3，与任务描述给的列表
**逐项一致**，`setfsuid/setfsgid` 也在内。）

**机制判定（与任务描述一致，但补上了判决性证据）**：这是**用户态模拟**，
不是更宽的 seccomp 过滤器。我用 JIT svc 逐号 + SIGSYS 观测把这件事坐实了：

| syscall | 官方 | bxroot | 是否投递 SIGSYS（官方侧） |
|---|---|---|---|
| `144 setgid` | **rc=0** | rc=-38 | **是**（`si_syscall=144`） |
| `143 setregid` | **rc=0** | rc=-38 | **是** |
| `146 setuid` | **rc=0** | rc=-38 | **是** |
| `145 setreuid` | **rc=0** | rc=-38 | **是** |
| `149 setresgid` | **rc=0** | rc=-38 | **是** |
| `159 setgroups` | **rc=0** | rc=-38 | **是** |
| `151 setfsuid` | **rc=0** | rc=-38 | **是** |
| `152 setfsgid` | **rc=0** | rc=-38 | **是** |
| `147 setresuid` | rc=-1 | rc=-1 | 否（内核直接 EPERM） |
| `174..177` 读身份 | 10655 | 10655 | 否 |

**读法**：官方侧这些号**全部被 seccomp TRAP**（投递 SIGSYS），却返回 0 ——
说明官方的 SIGSYS 处理器**接管并改写了 x0**，把内核的 EPERM/ENOSYS
换成了成功。（`147 setresuid` 两侧都是 -1/EPERM，因为内核在 seccomp
之前就对它做了权限检查，没有 TRAP 可接。）

**所以任务描述里"最可能是 SECCOMP_RET_TRAP + 官方在 SIGSYS 处理器里
改写 x0"的猜测，实测证实了。** 而 bxroot 的 `sigsys.c` 的既定策略是
**统一回 ENOSYS**（`sigsys.c:156-163`，为的是让 libuv 回退 epoll），
所以降权族在 bxroot 下统一变成 errno=38。

> ⚠️ **这里有一个真实性副作用，必须写清**：官方让这些调用返回 0，
> 但**内核实际没有改变任何身份**。程序会以为自己已经降权，
> 后续以"已降权"的心智模型运行，而它实际仍是原 uid。
> 官方就是这么做的，所以为了兼容要跟 —— 但这**不是"正确",
> 是"与官方一致"**。详见 §5。

---

## 四、修法与判别力验证

### 4.1 改了什么（3 个文件，均为定点改动）

| 文件 | 改动 |
|---|---|
| `src/runtime/preload.c` | **纯追加**（文件末尾）：导出 `int bxroot_fakeroot_ids(unsigned int *uid, unsigned int *gid)`，返回 `g_fakeroot_on` 并通过出参给出伪造身份。既有逻辑一行未动 |
| `src/runtime/syscall_guard.c` | ① 加 `__attribute__((weak)) int bxroot_fakeroot_ids(...)` 前向声明（与既有 `l2s_rt_patch_statx_buf` 同一约定）；② 在 `long ret = raw_syscall6(...)` **返回之后**、`return ret` 之前，按 `number` 精确分派 174/175/176/177 改写 `ret` |
| `test/test_id_syscall_guard.c` | 新建（37 用例） |
| `test/RUN_ID_SYSCALL.sh` | 新建运行器（编译参数只有一份） |
| `test/RUN_ALL.sh` | 只加了 1 行 `run_step` + 2 行注释（判据未动） |

**门控条件**（一条都不能少，均写在代码注释里）：`ret >= 0`（保留失败语义）、
`number` 逐个 `case` 而非范围判断（避免把邻近的 172 getpid / 178 gettid
卷进来）、`bxroot_fakeroot_ids != NULL`（weak 未链接时跳过）、
返回非 0（未启用时原样透传）。

**为什么不硬编码"假身份 = 0"**：假身份是 fakeroot 层的判据
（`fakeroot_state_set_enabled` 还支持 `setresuid` 之后变化）。
在 guard 里写死 0 等于把同一套规则写两处 —— 本项目在 statx 的
`stx_mode` 宽度、fakeroot 的初始化顺序上都踩过这种漂移。

### 4.2 ★ 测试的判别力：伪造值取 12345，不是 0

这是本测试**唯一**的设计要点。若判据写成 `syscall(174) == 0`：

- 本容器跑着**外层 proroot**，它把静态 `svc` 的 getuid 也改写成 0；
- 于是"改之前"就已经是绿的 —— **一个恒真的测试**。

这正是本项目记录过的事故类型（"这套回归声称能防的那个具体缺陷，
它防不住"）。所以桩返回真值**绝不可能取到**的 **12345/54321**，
判据写成"与桩值比"：

```
fakeroot 关 → 结果**绝不能**是伪造值（否则等于永远在伪装）
fakeroot 开 → 结果**必须**等于伪造值
```

### 4.3 改前红 / 改后绿（同一份测试源码，只换被测的 `syscall_guard.c`）

**改前**（用 `/tmp/bxroot-git` 镜像重建的 `syscall_guard.c`）：

```sh
gcc -std=c11 -O1 -Wall -Wextra -D_GNU_SOURCE= -I/root/idfix/before-tree/src/runtime \
  /root/idfix/test_id_syscall_guard.c /root/idfix/before-tree/src/runtime/syscall_guard.c \
  -o /root/idfix/t-before && /root/idfix/t-before
```

```
  [FAIL] getuid 被改写为伪造 uid  syscall(174)=10655 期望 12345
  [FAIL] geteuid 被改写为伪造 uid  syscall(175)=10655 期望 12345
  [FAIL] getgid 被改写为伪造 gid  syscall(176)=10655 期望 54321
  [FAIL] getegid 被改写为伪造 gid  syscall(177)=10655 期望 54321
  [FAIL] 连续 64 轮改写稳定
  [FAIL] 反复切换开关每次都正确  关=10655/10655 开=10655/10655
------------------------------------------------------
用例 37，失败 6
RESULT: FAIL —— 裸 syscall 层的身份伪装契约被破坏
退出码=1
```

**改后**（工作副本）：`sh test/RUN_ID_SYSCALL.sh` →

```
------------------------------------------------------
用例 37，失败 0
RESULT: PASS
退出码=0
```

**红的 6 条全部落在身份改写上，其余 31 条（负向判据、路径翻译回归、
NULL 边界）改前改后都是绿** —— 说明测试精确指向被测缺陷，没有靠
"到处变红"来伪装判别力。

### 4.4 负向判据（防止"多改"）

`syscall_guard.c` 有两次明确记录的致命事故（`case 36` 把 dirfd 当路径、
`case 260` 把 wait4 当 linkat 写坏 `wstatus`），都是"把不相干的调用卷进来"。
所以测试同时钉住：

- `syscall(172)` getpid：fakeroot 开/关下**都**不变；
- `syscall(178)` gettid（紧邻 177，最容易被顺手卷进来）：不变；
- 174..177/148/150/172/178 **不得**进入路径参数表；
- `symlinkat(36)` 的 a1 仍未被当成路径（历史事故防回归）；
- 身份改写路径**一次都不碰**翻译桩；
- `statx(291)`/`newfstatat(79)` 路径翻译仍照常工作；
- `statx` 的 `a4=NULL` 时返回 EFAULT 且不崩溃、仍只翻译 a1；
- **反向对照**：关掉翻译桩后同一调用必须失败 —— 证明上面那条不是恒真。

### 4.5 一个 gcc/环境级坑（让测试"看起来在测、其实没测"）

第一版把翻译桩与计数器放在**同一个编译单元**里，结果：

```
桩确实被调用了（stderr 能打印出来），而 main 读到的 g_seen_n 仍是 0
```

于是断言"桩被调 0 次"**恒真**，测试白写。根因是外层 proroot 对 libc
做的**活体代码补丁**（本仓库多处记录过"dlsym 拿到的地址不可靠"）。
**结论：跨"真实调用边界"传递的观测值一律 `volatile`。**
这条已写进测试文件头注释。

---

## 五、降权族：调查结论（**未动手**，等决策）

### 5.1 官方到底让哪些"假装成功"——实测表

| syscall | 官方 libc | 官方 `syscall()` 符号 | 官方 JITsvc | 被 seccomp TRAP |
|---|---|---|---|---|
| `setuid(146)` | 0 | 0 | 0 | 是 |
| `setgid(144)` | 0 | 0 | 0 | 是 |
| `setreuid(145)` | 0 | 0 | 0 | 是 |
| `setregid(143)` | 0 | 0 | 0 | 是 |
| `setresuid(147)` | 0 | 0 | **-1** | 否 |
| `setresgid(149)` | 0 | 0 | 0 | 是 |
| `setgroups(159)` | 0（含 `setgroups(1,{999})`） | 0 | 0 | 是 |
| `setfsuid(151)` | 0（返回旧值） | **999** | 0 | 是 |
| `setfsgid(152)` | 0（返回旧值） | **999** | 0 | 是 |

**全部 9 个官方都"假装成功"**，包括 `setgroups(1,{999})`（非空组表）。

### 5.2 有没有官方也拒绝的？

**没有。** 9 个 setter 在官方侧全部返回成功。唯一"不一致"的是
`147 setresuid` 的 JITsvc 列（-1）—— 那是因为内核在 seccomp 之前就
对它做了权限检查，没有 TRAP 可接，属于**内核行为**而非官方选择。

### 5.3 `-0`（change-id）与这些的关系

- `-0` / `--root-id` → `cfg->fakeroot = 1`（`launcher.c:333`）。
- `-i 0:0` / `--change-id 0:0` → **等价于 `-0`**；
  **其它取值直接报错未实现**（`launcher.c:420-438`：
  `错误: -i/--change-id 只支持 "0:0"（等价于 -0）。`）。
- 所以"降权族要不要假装成功"**与本项目现有的 `--change-id` 无关** ——
  它只支持 0:0。它影响的只是**客户程序自己主动调降权**的场景。

### 5.4 我的建议：**不要做**（三条理由，按强度排序）

1. **副作用是真实的，且方向危险。** 让 `setgid`/`setgroups` 返回 0
   而不真正改身份，程序会进入"我已降权"的分支 —— 典型是
   `chage`/`passwd`/`su` 这类工具：它们会**跳过**后续的权限检查，
   却仍然以 root 身份执行。官方就是这么做的（`chage -l root` 能输出），
   所以这是**"与官方一致"而非"正确"**。跟进它等于把这个安全语义
   也一起继承，需要有意识的决定。
2. **实现位置会碰红线。** 唯一的做法是在 `sigsys.c` 的 SIGSYS 处理器里
   按号改写 `x0`。但 `sigsys.c` 的现有策略是**统一回 ENOSYS**
   （`sigsys.c:156-163`），那是让 libuv 回退 epoll 的**关键契约**
   —— 一旦引入"按号改成成功"的分支，就等于把"哪些号回 ENOSYS、
   哪些号回成功"变成一张新表。本项目在"号码表"上已经出过两次致命
   事故，而这张表会更难测（要覆盖全部被 TRAP 的 80+ 个号）。
   任务也明确要求**不要动 `syscall_guard.c` 的拦截策略**；
   而 `sigsys.c` 同样是全局导出符号面。
3. **收益不明确。** 修前 `chage` 的失败链是"raw 层看到非 root →
   尝试降权 → 撞 seccomp"。**第 1 部分修完后，raw 层已经看到 root
   （`syscall(174)=0`）**，程序的自检结果已与官方一致，
   "因为自检非 root 而去降权"这条链已经断了。
   §5.5 给了一个可判定的验收方法。

### 5.5 如果仍要做，建议的验收方法（先测后改）

用真实受害者命令做**两侧对照**，而不是看单个 syscall 的返回值：

```sh
# 官方侧
PROROOT_ROOTFS=... PROROOT_TMP_DIR=... bridge --preload <官方runtime> \
    <rootfs>/usr/bin/chage -l root
# bxroot 侧（同样的 argv）
BXROOT_ROOTFS=... BXROOT_TMP_DIR=... BXROOT_FAKEROOT=1 bridge --preload <bxroot runtime> \
    <rootfs>/usr/bin/chage -l root
```

判据：**两侧输出逐字一致**才算需要跟；若 bxroot 在我们**没做**
降权族改动的情况下已经与官方一致，那就不该做（理由 3）。

### 5.6 若要做，最小实现草案（仅供评估，未实现）

在 `sigsys.c` 的处理器里，**在既有的 ENOSYS 回退之前**插入一个小表：

```
被 TRAP 且 number ∈ {143,144,145,146,149,151,152,159,147?}
  → x0 = 0（成功），且 setfsuid/setfsgid 例外：x0 = 当前 fs 的旧值
  → 其余号：维持现有 ENOSYS 策略（**契约不变**）
```

风险点：`setfsuid/setfsgid` 的返回值语义是"**旧的** fs uid/gid"而非 0，
照抄 `x0=0` 会让调用方拿到错误的旧值；`setgroups` 还要考虑
`getgroups` 的一致性（缺口 B）。**这三条必须先有测试再动手。**

---

## 六、原始输出

### 6.1 端到端三层对照（修前 / 修后 / 官方）

```sh
. /root/idfix/run.sh
run_side before libbxroot-BEFORE.so "$STAGE_LOAD/probe2" read   # 修前（git 镜像重建）
run_side bx     libbxroot-runtime.so  "$STAGE_LOAD/probe2" read   # 修后
run_side off    libofficial-runtime.so "$STAGE_LOAD/probe2" read  # 官方
```

```
########## 修前（libbxroot-BEFORE.so）##########
=== op=read ===
  Uid:	10655	10655	10655	10655
  libc : getuid=0 geteuid=0 getgid=0 getegid=0
  sym  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  svc  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  libc : getresuid rc=0 r=0 e=0 s=0
  libc : getresgid rc=0 r=0 e=0 s=0
  sym  : getresuid rc=0 r=10655 e=10655 s=10655 errno=0
  sym  : getresgid rc=0 r=10655 e=10655 s=10655 errno=0
  svc  : getresuid rc=0 r=10655 e=10655 s=10655
  libc : getgroups(0,NULL)=0

########## 修后（libbxroot-runtime.so）##########
=== op=read ===
  Uid:	10655	10655	10655	10655
  libc : getuid=0 geteuid=0 getgid=0 getegid=0
  sym  : getuid=0 geteuid=0 getgid=0 getegid=0
  svc  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  libc : getresuid rc=0 r=0 e=0 s=0
  libc : getresgid rc=0 r=0 e=0 s=0
  sym  : getresuid rc=0 r=10655 e=10655 s=10655 errno=0
  sym  : getresgid rc=0 r=10655 e=10655 s=10655 errno=0
  svc  : getresuid rc=0 r=10655 e=10655 s=10655
  libc : getgroups(0,NULL)=0

########## 官方（libofficial-runtime.so）##########
=== op=read ===
  Uid:	10655	10655	10655	10655
  libc : getuid=0 geteuid=0 getgid=0 getegid=0
  sym  : getuid=0 geteuid=0 getgid=0 getegid=0
  svc  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  libc : getresuid rc=0 r=0 e=0 s=0
  libc : getresgid rc=0 r=0 e=0 s=0
  sym  : getresuid rc=0 r=0 e=0 s=0 errno=0
  sym  : getresgid rc=0 r=0 e=0 s=0 errno=0
  svc  : getresuid rc=0 r=10655 e=10655 s=10655
  libc : getgroups(0,NULL)=1
```

> ⚠️ **环境变量两侧分开设**（这个坑任务描述已提醒过，我确认它真实存在）：
> bxroot 侧 `BXROOT_ROOTFS/BXROOT_TMP_DIR/BXROOT_FAKEROOT=1`，
> 官方侧 `PROROOT_ROOTFS/PROROOT_TMP_DIR`。官方 runtime 里 `BXROOT_`
> 字符串出现 0 次，喂错前缀会被静默忽略，跑出来的不是对照实验。

> ⚠️ **无 runtime 基线也要跑**（任务描述没提，但会决定结论）：
> 纯 `proroot-ldso` 下 `libc/sym/svc` 三层**全是 10655** ——
> 说明伪造完全是 runtime 做的，与 ldso 无关。少了这一列就无法排除
> "外层 proroot 在帮忙"。

### 6.2 判决性实验：JIT svc（官方侧也读真值）

```sh
run_side off libofficial-runtime.so "$STAGE_LOAD/probe4" all
```

```
=== probe4 op=all ===
  JITsvc : getuid=10655 geteuid=10655 getgid=10655 getegid=10655   <- 加载后生成的 svc，加载期补丁够不着
  JITsvc : getresuid rc=0 r=10655 e=10655 s=10655
  JITsvc : getresgid rc=0 r=10655 e=10655 s=10655
  ...
  SIGSYS : svc(174) rc=10655 errno=0 捕获到的 si_syscall=-1 (无 SIGSYS -> 无 seccomp 介入)
  SIGSYS : svc(425 io_uring_setup) rc=0 errno=0 si_syscall=425 (有 seccomp TRAP)
```

bxroot 侧逐字相同（除 setter 族，见 §6.3）。

### 6.3 降权族：三方矩阵（原始）

```sh
for s in before bx off; do run_side $s <pre> "$STAGE_LOAD/probe2" setters; done
```

```
--- before ---
    libc setuid(999)   rc=-1 errno=38 (Function not implemented) 后 getuid=0
    libc setgid(999)   rc=-1 errno=38 (Function not implemented) 后 getgid=0
    libc setgroups(0,NULL) rc=-1 errno=38 (Function not implemented)
    sym  syscall(146,999) rc=-1 errno=38 (Function not implemented) 后 sym174=10655
    sym  syscall(144,999) rc=-1 errno=38 (Function not implemented) 后 sym176=10655
    sym  syscall(159,0,NULL) rc=-1 errno=38 (Function not implemented)
--- bx ---
    libc setuid(999)   rc=-1 errno=38 (Function not implemented) 后 getuid=0
    libc setgid(999)   rc=-1 errno=38 (Function not implemented) 后 getgid=0
    libc setgroups(0,NULL) rc=-1 errno=38 (Function not implemented)
    sym  syscall(146,999) rc=-1 errno=38 (Function not implemented) 后 sym174=0
    sym  syscall(144,999) rc=-1 errno=38 (Function not implemented) 后 sym176=0
    sym  syscall(159,0,NULL) rc=-1 errno=38 (Function not implemented)
--- off ---
    libc setuid(999)   rc=0 errno=0 (Success) 后 getuid=999
    libc setgid(999)   rc=0 errno=0 (Success) 后 getgid=999
    libc setgroups(0,NULL) rc=0 errno=0 (Success)
    sym  syscall(146,999) rc=0 errno=0 (Success) 后 sym174=999
    sym  syscall(144,999) rc=0 errno=0 (Success) 后 sym176=999
    sym  syscall(159,0,NULL) rc=0 errno=0 (Success)
```

**注意 `before` 与 `bx` 的 `sym174` 差异**：`before` 是 10655（真值），
`bx` 是 0（伪造值）—— 这正是本次修复的效果，且它**穿透到了降权族探针**
里（因为探针在 `syscall(146)` 失败后回读身份）。

### 6.4 回归与门禁

```sh
sh test/RUN_ALL.sh --quick
```

```
  ✅ 编译告警门禁       ✅ 零告警（检查了 11 个编译单元）
  ✅ l2s 运行时            RESULT: PASS
  ✅ l2s×fakeroot 协同     RESULT: PASS
  ✅ fakeroot 纯逻辑       RESULT: PASS
  ✅ 系统调用参数位置 RESULT: PASS
  ✅ rename/link 双路径    RESULT: PASS
  ✅ 身份 syscall 伪装    RESULT: PASS      ← 本次新增
  ✅ crash 崩溃处理器    RESULT: PASS
  ✅ D4 进程管理             断言门禁：通过
  ✅ 运行时构建          ✅ D4 进程管理符号全部导出（复用产物核对）
  ✅ proot CLI 兼容         RESULT: PASS
  ✅ l2s 端到端契约      RESULT: PASS
  ✅ wait 家族钩子           ✅ waitpid/wait4/wait3/waitid 均已导出
------------------------------------------------------
  通过 13 / 失败 0
  ✅ 全部通过
```

**修前基线是 12/12**（同一条命令，改动前实测）→ 现在是 **13/13**：
新增项计入，**既有 12 项一项都没红**。

```sh
sh test/RUN_WARN_GATE.sh
```

```
✅ src/runtime/preload.c              0 条
✅ src/runtime/syscall_guard.c        0 条
✅ src/runtime/sigsys.c               0 条
✅ src/runtime/crash.c                0 条
✅ src/runtime/livepatch.c            0 条
✅ src/runtime/fakeroot.c             0 条
✅ src/l2s/l2s.c                      0 条
✅ src/l2s/l2s-runtime.c              0 条
✅ src/launcher/launcher.c            0 条
✅ src/bridge/bridge.c                0 条
✅ src/proc/proc.c                    0 条
---------------------------------------------------------------------
✅ 零告警（检查了 11 个编译单元）
```

### 6.5 构建

```sh
sh BUILD_RUNTIME.sh
```

```
== 构建 libbxroot-runtime.so ==
   ✅ 链接成功（-O2，第 6 次尝试）        ← 本容器 gcc 13.3.0 有已知间歇性 ICE，脚本自带重试
   大小: 229288 字节
   导出符号（nm -D --defined-only）: 353
   ✅ D4 进程管理符号全部导出（23/23，含 waitpid/wait4/wait3/waitid）
```

新符号已进入**动态符号表**（这是 LD_PRELOAD 能否用的唯一判据）：

```sh
nm -D --defined-only build/libbxroot-runtime.so | awk '{print $3}' | grep -x bxroot_fakeroot_ids
```

```
bxroot_fakeroot_ids
```

> ⚠️ **关于并发编辑**：本次任务期间**另一个 agent 正在改同一个
> `src/runtime/preload.c`**（在我追加之后又新增了 `dlerror` /
> `dl_iterate_phdr` 两块，文件从 6157 行涨到 6512 行）。
> 我的改动是用 `edit` 做的**定点追加**，位于文件**最末尾**，与那两块
> 互不重叠；上面 §6.4 / 本节的数字都是**在对方改动落地之后重跑**的。
> 若后续还有人动这个文件，请注意 `bxroot_fakeroot_ids` 必须留在
> `g_fakeroot_on` / `g_fakeroot_state` 的**作用域之后** —— 这两个是
> `static`，声明在文件中部（约 130-140 行），函数体放在文件末尾是
> 为了拿到它们，不是随意摆放。

### 6.6 最终三方端到端确认（并发编辑落地后重跑）

```sh
. /root/idfix/run.sh
for s in before bx off; do run_side $s <pre> "$STAGE_LOAD/probe2" read; done
```

```
--- before ---
  libc : getuid=0 geteuid=0 getgid=0 getegid=0
  sym  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  svc  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  sym  : getresuid rc=0 r=10655 e=10655 s=10655 errno=0
--- bx ---
  libc : getuid=0 geteuid=0 getgid=0 getegid=0
  sym  : getuid=0 geteuid=0 getgid=0 getegid=0          ← ✅ 与官方逐字一致
  svc  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  sym  : getresuid rc=0 r=10655 e=10655 s=10655 errno=0  ← 缺口 B
--- off ---
  libc : getuid=0 geteuid=0 getgid=0 getegid=0
  sym  : getuid=0 geteuid=0 getgid=0 getegid=0
  svc  : getuid=10655 geteuid=10655 getgid=10655 getegid=10655
  sym  : getresuid rc=0 r=0 e=0 s=0 errno=0
```

### 6.7 端到端 dsh 仍正常

```sh
sh test/RUN_E2E.sh --version
```

```
node[1]: pthread_create: Invalid argument
0.1.5-rc.2
退出码=0
```

> `pthread_create: Invalid argument` 是**既有现象**，与本次改动无关 ——
> 修前产物上跑同一条命令输出**逐字相同**（已在 `before-tree` 上复核）。

---

## 七、与预期不符之处（汇总）

| # | 预期 | 实测 | 影响 |
|---|---|---|---|
| 1 | 官方在**裸 syscall 层**也伪造（`svc` 层） | 官方 **JITsvc 也是 10655**。伪造覆盖到 `syscall()` 符号层为止 | **修复目标精确化**：无需也无法伪造 `svc` 层；`syscall()` 符号层对齐即与官方一致 |
| 2 | bxroot `syscall(174)` 泄露 10655（描述为"raw"） | 属实，但它泄露的是 **`syscall()` 符号层**，不是 `svc` 层（`svc` 层两层都泄露） | 修复点选在 `syscall_guard.c` 是**正确**的 |
| 3 | ——（描述未提） | 容器自身 `svc(174)` 读到 **0**，而同进程 `syscall(174)` 读到 **10655**：外层 proroot 对静态内联 svc 与 libc `syscall()` **分别处理** | 测试的"真值基准"**不能用裸 svc**，判据必须收敛成"不等于伪造值"（已改） |
| 4 | ——（描述未提） | 无 runtime 时三层**全是 10655** | 伪造完全是 runtime 行为，与 ldso 无关。少了这条基线无法排除"外层在帮忙" |
| 5 | `setresuid(147)` 与其它 setter 同类 | 官方 JITsvc 侧 `147` 返回 **-1**（未被 TRAP），其余 8 个都返回 0 | 若要做降权族，**不能一刀切**，`147` 要单独判断 |
| 6 | `setfsuid/setfsgid` 返回旧值 | 官方 **libc** 侧返回 0，**`syscall()` 侧返回 999** | 两条路返回值语义不同；照抄 `x0=0` 会错 |
| 7 | ——（描述未提） | gcc 把"桩内自增 / main 读取"当两个对象，桩被调用而计数器读 0 → 断言恒真 | 观测值一律 `volatile`（已改） |
| 8 | `getresuid` 是否要处理"由你判断" | 官方**已覆盖**（sym 列 0/0/0），bxroot **未覆盖**（10655） | 这是一个**真实且确认**的缺口，见缺口 B |

---

## 八、缺口登记（尚未修，均有测试边界钉住）

| 缺口 | 内容 | 官方 | bxroot | 建议 |
|---|---|---|---|---|
| **A** | `svc #0` 真·裸层 | 不伪造 | 不伪造 | **不是缺口，是两侧一致**。不要试图修 |
| **B** | `148/150`（getresuid/getresgid）、`158`（getgroups） | 已覆盖 | 未覆盖 | **建议下一个任务做**：风险与 174..177 同级（`syscall_guard.c` 里加 3 个 case + 一次指针写回），收益确定（官方已覆盖，且 dpkg/postinst 大量用 `getresuid`） |
| **C** | 降权族 9 个 setter | 假装成功 | ENOSYS | **建议先不做**，理由见 §5.4；若要做，先按 §5.5 做受害者命令的两侧对照 |

**缺口 B 的实现要点（供下个任务参考）**：`148/150` 的 `a0/a1/a2` 是
三个 `uid_t*`，需要**判空后逐个写回**（客户允许传 NULL，内核语义是
"不关心这一项"）—— 这正是本项目在 `statx` 的 `a4=NULL` 上踩过的
同一类坑，已在 `test/test_id_syscall_guard.c` 里留了 NULL 边界的写法
可直接照抄。`158 getgroups` 更麻烦：长度与内容必须自洽
（`size==0` 返回个数、`size<n` 返回 EINVAL），且要与
`preload.c` 的 `getgroups` 钩子返回**同一个**组表，否则又是一处漂移。
