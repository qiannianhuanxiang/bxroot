# 裸 syscall 身份伪造：修复 + 机制更正

> 状态：**第 1 部分（读身份 174..177）已修并有回归覆盖**；
> 第 2 部分（降权族）**已调查、未动手** —— 缺口**已实测确认真实存在**
> （`chage` 两侧不一致），取舍分析与实现评估见 §5。
>
> ⚠️ **本报告更正了原任务描述里的两处机制判断，两处都以实测为准**
> （见 §2、§3）。结论是：任务的前提「官方在裸 syscall 层也伪造」**不成立**，
> 而真正的缺口比原描述**小一半**（只有 `syscall()` 符号层，不含 `svc` 层）。
>
> ⚠️ **报告自身也经过一次更正**：初版 §5.4 的理由 3（"收益不明确"）
> 被上级 agent 的实测**推翻**，我复现并进一步定位到"`chage` 只需 2 个号"。
> 原始措辞与被推翻的证据都保留在 §5.4，以免后人重犯同一推断。

---

## 一、四层实测对照表

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
| `setuid/setgid/setgroups/...` | 假装成功（0） | -1 / errno=38 ENOSYS | 缺口 C（§5）—— 已实测确认 `chage` 两侧不一致 |

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

## 五、降权族：调查结论（**未动手**；缺口已实测确认真实存在）

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

### 5.4 ★ 更正：理由 3 被实测推翻 —— 缺口是**真实存在**的

> **本节经过一次更正。** 初版写的理由 3「收益不明确，第 1 部分修完后
> `chage` 的链已断」是**错的**，且我当时把它标注为"我未能验证"。
> 上级 agent 按 §5.5 的方法实测后给出反例，我**独立复现并进一步定位**，
> 结论如下。**原始措辞与推翻它的证据都保留**，以免后人重犯同一推断。

#### 5.4.1 实测：两侧确实不一致（我独立复现）

```sh
. /root/idfix/chage/run.sh          # 两侧同样 argv，退出码单独取（不经管道）
OUT=$(run_off libofficial-runtime.so 2>&1); RC=$?     # 官方
OUT=$(run_bx  libbxroot-runtime.so  2>&1); RC=$?      # bxroot（已含本轮 174..177 修复）
```

```
##### 官方 #####
Last password change					: Aug 05, 2025
Password expires					: never
...
chage 真实退出码 = 0

##### bxroot（修后，本轮已修 174..177）#####
chage: failed to drop privileges (Function not implemented)
chage 真实退出码 = 1
```

#### 5.4.2 为什么理由 3 是错的（机制层面）

我原来的推断是「raw 层看到 root → 自检通过 → 跳过降权」。**这个推断
预设了"先自检再决定"**，而 glibc/PAM 的 drop-privileges 路径是
**无条件调用** `setreuid`/`setregid`/`setgroups` —— 与 `getuid()` 取什么
值**无关**。所以修好 174..177 **不影响**这条链。

这不是新知识：本项目 `docs/` 里另一个 agent 早已记下「glibc 的
drop privileges 会无条件调 `setgroups`，与 `getuid()` 取值无关」，
上级当时也转发过这句话。**我读过它，却没有把它落实到"理由 3 是否成立"
的判断上** —— 这是本报告最该记住的教训：**引用了结论不等于检验了结论**。

#### 5.4.3 ★ 进一步定位：`chage` 只需要 **两个**号（这条是新的，不在上级的实测里）

用 `BXROOT_SIGSYS_LOG=1` 追踪 `chage` 实际撞到的号，得到**逐步扩大的
受控实验**（在 `/root/idfix/setter-exp` 的一份**临时副本**上做，
本工作副本的 `sigsys.c` **未被改动**）：

| `BXROOT_EXP_SET`（假装成功的号） | `chage -l root` 退出码 |
|---|---|
| `（空，即现状：全 ENOSYS）` | **1** ❌ |
| `143` | **1** ❌ |
| **`143,145`** | **0** ✅ |
| `143,145,159` | 0 ✅ |
| `143,145,159,144` | 0 ✅ |
| `143,145,159,144,146,149,151,152` | 0 ✅ |

```
--- BXROOT_EXP_SET='' ---
chage: failed to drop privileges (Function not implemented)
退出码=1
--- BXROOT_EXP_SET='143' ---
chage: failed to drop privileges (Function not implemented)
退出码=1
--- BXROOT_EXP_SET='143,145' ---
Last password change					: Aug 05, 2025
Password expires					: never
退出码=0
```

`chage` 的输出与官方**逐字一致**：

```sh
diff /root/idfix/chage/out_off.txt /root/idfix/chage/out_exp.txt
```

```
✅ 逐字一致
```

**代价比 §5.6 草案预估的**小得多**：不是"9 个 setter 的号码表"，
而是 **`{143, 145}` 两个号**就能让 `chage` 完全对齐。

**但这不等于"只做两个号就够"** —— 见 5.4.4 的反面证据。

#### 5.4.4 ★ 反面证据：最小集合是**按工具**变化的，不是恒定的

| 工具 | 官方 | bxroot 现状 | bxroot + 仅 `{143,145}` | 阻塞原因 |
|---|---|---|---|---|
| `chage -l root` | rc=0 ✅ | rc=1 ❌ | **rc=0 ✅ 逐字一致** | setter 族 |
| `chage -l nosuchuser` | 报 "does not exist in /etc/passwd" | "failed to drop privileges" | — | **先降权再查库**，故连报错都不同 |
| `passwd -S root` | rc=0 `root L 2025-08-05 …` | rc=1 ❌ | **rc=1 ❌ 未修好** | **不是 setter 族**（零 SIGSYS 命中） |
| `su -S` | 参数错 rc=1 | 相同 | 相同 | 与本议题无关 |

**`passwd` 的失败是另一个缺陷**，与降权族无关 —— 它**一次 SIGSYS 都没撞**：

```
##### passwd 现状 + SIGSYS 日志 #####
[bxroot] sigsys 模拟层已安装
passwd: user 'root' does not exist          ← 没有任何 "模拟 syscall" 行

##### passwd 实验组(143,145) + SIGSYS 日志 #####
[bxroot] sigsys 模拟层已安装
passwd: user 'root' does not exist          ← 补了 setter 也没用
```

定位到用户库查询这一层：

```sh
getent passwd root
```

```
--- off : root:x:0:0:root:/root:/bin/bash     ✅
--- bx : （空）                                ❌
```

`id` 也是同类（两侧都输出 `uid=0(root) gid=0 groups=0`，但 bxroot 少了
`(root)` 的组名反查）。**这是一个独立缺口，不应混进降权族里。**

#### 5.4.5 更正后的结论

- **理由 1 和 2 仍然成立**（副作用真实且方向危险；实现位置会碰
  `sigsys.c` 的 ENOSYS 契约）。它们才是真正的顾虑。
- **理由 3 撤销**：缺口**真实存在**，`chage` 两侧不一致是硬证据。
- **结论从"建议不做"改为**：
  **技术上确实有缺口，且代价比预估小（`chage` 只需 2 个号）；
  是否做取决于对理由 1/2 的取舍，而不是"收益不明确"。**
- 不要把这个建议建立在一个已被推翻的论据上 —— 这正是本节更正的用意。

### 5.5 验收方法（已实测有效，可复现）

用真实受害者命令做**两侧对照**，而不是看单个 syscall 的返回值：

```sh
# 官方侧
PROROOT_ROOTFS=... PROROOT_TMP_DIR=... bridge --preload <官方runtime> \
    --argv0 chage <rootfs>/usr/bin/chage -l root
# bxroot 侧（同样的 argv）
BXROOT_ROOTFS=... BXROOT_TMP_DIR=... BXROOT_FAKEROOT=1 bridge --preload <bxroot runtime> \
    --argv0 chage <rootfs>/usr/bin/chage -l root
```

判据：**两侧退出码与输出逐字一致**。

> ★ **两个操作细节**（都会让结论失真）：
> 1. **退出码必须单独取，不要经管道** —— `cmd | head` 拿到的是 `head`
>    的退出码，会把 `rc=1` 显示成 `rc=0`。
> 2. **要判"是否真的被阻塞"，看 `BXROOT_SIGSYS_LOG=1` 的命中行**，
>    不要只看报错文本 —— `chage -l nosuchuser` 两侧都"报错"，
>    但错误内容与成因完全不同（一个是查库失败，一个是降权失败）。

### 5.6 若要实现：最小改动面、最坏情况、必须先有的测试（**未实现**）

#### 5.6.1 最小改动面

**一个函数、一处插入**，不改任何现有策略分支：

```c
/* src/runtime/sigsys.c —— 改这个函数，其余一行不动 */
static int emulate_errno(long sc)
{
    (void)sc;
    return ENOSYS;          /* 现状 */
}
```

改成"查一张小表，表内返回 0，表外维持 ENOSYS"。表内**候选**：

| 号 | 名称 | 表内取值 | 依据 |
|---|---|---|---|
| 143 | `setregid` | 0 | 实测 `chage` 需要 |
| 145 | `setreuid` | 0 | 实测 `chage` 需要 |
| 144 | `setgid` | 0 | 官方返回 0；尚未实测到受害者 |
| 146 | `setuid` | 0 | 官方返回 0；尚未实测到受害者 |
| 149 | `setresgid` | 0 | 官方返回 0；尚未实测到受害者 |
| 159 | `setgroups` | 0 | **风险最高**，见 5.6.2 |
| 151/152 | `setfsuid`/`setfsgid` | **旧值，不是 0** | 官方 libc 侧返 0、`syscall()` 侧返 999 |
| 147 | `setresuid` | **不进表** | 实测**未被 TRAP**（内核直接 EPERM），本函数根本收不到它 |

**最小可行集是 `{143,145}`**（`chage` 的实测充分必要集）；
其余号要不要加，取决于能否为每个号找到受害者并两侧对照。

#### 5.6.2 最坏情况（按严重度）

1. **安全语义被静默放宽（最重要）**。返回 0 而不真改身份 → 程序进入
   "已降权"分支。若某个 setuid 工具因此**跳过**了后续的权限检查，
   却仍以原（root）身份执行，那是**行为上的提权**。
   官方已经在这么做，所以跟进 = 继承同一个语义 —— 必须是有意识的选择，
   而不是"为了对齐而对齐"。
2. **`setgroups` 的返回值与 `getgroups` 必须自洽**。若 `setgroups` 假装
   成功而 `getgroups`（`syscall(158)`，**当前未覆盖**，返回真实 6 个组）
   仍报旧组表，客户会看到自相矛盾的状态。这正是缺口 B 与缺口 C 的
   **耦合点** —— 单独做 C 而不做 B，会制造一个新的不一致。
3. **`setfsuid/setfsgid` 返回旧值**。`x0=0` 会让调用方（典型是
   `setfsuid(uid)` 之后读返回值判断"我成功了吗"）拿到错误结论；
   正确值是"**改动前**的 fs uid/gid"，而这个值在 SEQUENCE 模式下
   需要跟踪状态。
4. **与 `sigsys.c` 的 ENOSYS 契约耦合**。`ENOSYS` 是 libuv 回退 epoll 的
   信号。改动必须保证**只有表内号**走成功分支，表外**逐字不变**；
   否则 `io_uring_setup(425)` 等回退路径会被破坏（实测那会让 node
   直接 abort）。
5. **号码表本身的漂移风险**。本项目在 `syscall_guard.c` 的号码表上已出过
   两次致命事故（36 把 dirfd 当路径、260 把 wait4 当 linkat）。
   本表虽小，但同样必须**逐个 `case` 列出**、不得写范围判断。

#### 5.6.3 必须先有的测试（按顺序，缺一不可）

1. **`sigsys.c` 的 ENOSYS 契约回归**：表内号返回 0，**表外每个号仍返回
   ENOSYS**。已有 `test/RUN_WAIT_TESTS.sh` / crash 测试覆盖部分；需要补一条
   直接断言 `emulate_errno()` 行为的用例（可参照
   `test/test_id_syscall_guard.c` 的"负向判据"写法：用一个**真值取不到**
   的期望值，避免恒真）。
2. **`chage -l root` 两侧逐字对照**（§5.5），且必须**同时**断言
   `rc` 与**完整输出**（只比 rc 会漏掉"输出不同但都返回 0"的情况）。
3. **`setfsuid/setfsgid` 返回旧值**的专项用例（这是唯一返回非 0 的号）。
4. **`setgroups` 与 `getgroups` 的自洽性**用例 —— **依赖缺口 B 先做**。
5. **`io_uring_setup(425)` 仍回 ENOSYS**（防"表写宽了"）—— 这一条
   必须有，否则 node 会以退出码 159 静默死掉。

#### 5.6.4 建议的执行顺序

```
① 缺口 B（148/150/158）先做 —— 它是 ③ 的前置，且风险最低（与已完成的 174..177 同级）
② 补 sigsys 契约测试（5.6.3 的 1、5）
③ 只加 {143,145}，用 chage 验收
④ 再谈其余号（每个号都要先找到受害者并两侧对照）
```

**不要跳过 ① 直接做 ③** —— 那会让 `setgroups`(假装成功) 与
`getgroups`(真实组表) 互相矛盾，制造一个比现在更难查的缺陷。

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

### 6.8 降权族：`chage` 两侧对照（§5.4 的原始输出）

```sh
. /root/idfix/chage/run.sh
OUT=$(run_off libofficial-runtime.so 2>&1); RC=$?    # 官方
OUT=$(run_bx  libbxroot-runtime.so  2>&1); RC=$?     # bxroot（已含 174..177 修复）
```

```
##### 官方 #####
Last password change					: Aug 05, 2025
Password expires					: never
Password inactive					: never
Account expires						: never
Minimum number of days between password change		: 0
Maximum number of days between password change		: 99999
Number of days of warning before password expires	: 7
chage 真实退出码 = 0

##### bxroot（修后，本轮已修 174..177）#####
chage: failed to drop privileges (Function not implemented)
chage 真实退出码 = 1
```

### 6.9 受控实验：找出 `chage` 的**充分必要**阻塞集

在一个**临时副本**（`/root/idfix/setter-exp`）上把 `emulate_errno()`
改成可配置（表内返回 0、表外维持 ENOSYS），工作副本的 `sigsys.c` 未动。

```sh
for SET in "" "143" "143,145" "143,145,159" ...; do
  BXROOT_EXP_SET="$SET" ... --preload libbxroot-exp.so ... chage -l root
done
```

```
--- BXROOT_EXP_SET='' ---
chage: failed to drop privileges (Function not implemented)
退出码=1
--- BXROOT_EXP_SET='143' ---
chage: failed to drop privileges (Function not implemented)
退出码=1
--- BXROOT_EXP_SET='143,145' ---
Last password change					: Aug 05, 2025
Password expires					: never
退出码=0
--- BXROOT_EXP_SET='143,145,159' ---
Last password change					: Aug 05, 2025
Password expires					: never
退出码=0
```

**充分必要集 = `{143 setregid, 145 setreuid}`**（144/146/149/151/152/159 加了
不会更好，不加也不影响 `chage`）。

输出与官方逐字一致：

```sh
diff /root/idfix/chage/out_off.txt /root/idfix/chage/out_exp.txt
```

```
✅ 逐字一致
```

### 6.10 缺口 D 的原始证据（`passwd` / `getent`）

```
##### passwd 现状 + SIGSYS 日志 #####
[bxroot] sigsys 模拟层已安装
passwd: user 'root' does not exist          ← 无任何 "模拟 syscall" 行

##### passwd 实验组(143,145) + SIGSYS 日志 #####
[bxroot] sigsys 模拟层已安装
passwd: user 'root' does not exist          ← 补了 setter 也没用
```

```
--- off : root:x:0:0:root:/root:/bin/bash
--- bx : （空）
```

```
--- id (off) : uid=0(root) gid=0(root) groups=0(root)
--- id (bx)  : uid=0(root) gid=0 groups=0
```

`passwd -S root`：官方 `root L 2025-08-05 0 99999 7 -1` rc=0；
bxroot `passwd: user 'root' does not exist` rc=1。**两侧差异与 setter 无关。**

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
| 9 | **降权族"收益不明确，链已断"**（我自己初版的理由 3） | **被推翻**：修完 174..177 后 `chage` **仍然** rc=1，官方 rc=0。glibc 的降权是**无条件调用**，与 `getuid()` 无关 | 缺口 C **真实存在**。§5.4 已更正，教训是"引用了结论 ≠ 检验了结论" |
| 10 | ——（描述未提） | `chage` 的阻塞集**恰好是 `{143 setregid, 145 setreuid}` 两个号**（逐步扩大的受控实验） | 缺口 C 的代价比预想**小得多**：不是 9 个号的表 |
| 11 | `passwd`/`su` 与 `chage` 同类 | `passwd -S root` 的失败**零 SIGSYS 命中**，是**用户库查询**缺陷（`getent passwd root` 返回空） | 新缺口 **D**，与 B/C 修复路径完全不同，不可混做 |

---

## 八、缺口登记（尚未修，均有测试边界钉住）

| 缺口 | 内容 | 官方 | bxroot | 建议 |
|---|---|---|---|---|
| **A** | `svc #0` 真·裸层 | 不伪造 | 不伪造 | **不是缺口，是两侧一致**。不要试图修 |
| **B** | `148/150`（getresuid/getresgid）、`158`（getgroups） | 已覆盖 | 未覆盖 | **下一个任务做**（本轮明确不做：并发 agent 太多）。实现要点见 §8.1 |
| **C** | 降权族 setter | 假装成功 | ENOSYS | 缺口**真实存在**（`chage` 两侧不一致，§5.4.1）；是否做取决于 §5.4.5 的取舍。实现评估见 §5.6 |
| **D** | **用户/组库查询**（`getent passwd`、`passwd -S`、`id` 的组名反查） | 正常 | 空/失败 | **本轮新发现**，与 B/C 都无关，见 §8.2 |

### 8.1 缺口 B 的完整实现要点（留给下一轮）

**改动面**：`src/runtime/syscall_guard.c` 一处（`return ret` 之前的同一个
`switch`），`src/runtime/preload.c` 的 `bxroot_fakeroot_ids()` **需要扩展**
（当前只给 uid/gid 两个值，不够用）。

#### 8.1.1 接口扩展（必须先做，否则 B 做不了）

`148/150` 一次要写**三个**值（real/effective/saved），而当前入口只有
两个出参。且 `getresuid` 的三个值**不是**同一个数 —— 它们来自
`fakeroot_state` 的 `ruid/euid/suid`（`getresgid` 取
`rgid/egid/sgid`），**在 `setresuid(-1,1000,-1)` 之后会各不相同**。

所以 **不要**把 `bxroot_fakeroot_ids` 改成给三个 uid 就完事（那会让
`getgid` 也跟着拿 uid 的值）—— 正确做法是**再加一个独立入口**：

```c
/* preload.c 追加（与现有入口并列，不改动它） */
int bxroot_fakeroot_res_ids(unsigned int *ruid, unsigned int *euid,
                           unsigned int *suid, unsigned int *rgid,
                           unsigned int *egid, unsigned int *sgid);
```

返回 0=未启用 / 1=已启用并已写满六个出参。**判据仍用 `g_fakeroot_on`**
（与 `getuid` 钩子同源，理由见 §4.1 的注释）。

#### 8.1.2 `syscall_guard.c` 的三个新 case

```c
case 148:   /* getresuid(uid_t *r, uid_t *e, uid_t *s) */
case 150:   /* getresgid(gid_t *r, gid_t *e, gid_t *s) */
```

**四条硬性注意**（每条都有前车之鉴）：

1. **每个指针都要单独判空**。客户可以传 NULL 表示"这一项不关心"
   （内核语义），`getresuid(&r, NULL, &s)` 是合法的。**三个参数分别判**，
   不能"有一个 NULL 就整体跳过" —— 内核的语义是逐项写。
   这正是本项目在 `statx` 的 `a4=NULL` 上踩过的同一类坑
   （见 §4.4 的负向判据写法，可直接照抄）。
2. **写回的是 `uid_t`（4 字节），不是 `long`**。`raw_syscall6` 的
   `a0/a1/a2` 是 `long`（8 字节），**必须 `(int *)` 而非 `(long *)` 解引用**
   —— 写成 `long *` 会写坏相邻 4 字节。这是"参数宽度"类缺陷，
   本项目在 statx 的 `stx_mode` 宽度上出过同款。
3. **`ret == 0` 才写回**。失败时内核没写缓冲，改它就是碰运气
   （与 statx 补丁的门控一致）。
4. **`number` 逐个 `case`**，不写范围。

#### 8.1.3 `158 getgroups` —— 明显更难，建议单独一轮

| 难点 | 说明 |
|---|---|
| 返回值双重语义 | `size==0` 时返回**组数**且不写缓冲；`size<n` 时返回 -1/EINVAL；否则写 `size` 个元素并返回 `n` |
| 长度必须自洽 | 组表长度来自 `fakeroot_state.ngroups`，必须与 `preload.c` 的 `getgroups` 钩子返回**同一个**表 |
| 元素宽度 | `gid_t`（4 字节），同上第 2 条 |
| 缓冲大小由客户给 | 必须在**写入前**校验 `size >= n`，否则越界写 |

**★ 必须与 `preload.c` 的 `getgroups` 钩子同源**（`fakeroot_state.groups`
+ `ngroups`），**不要**在 guard 里另建一份组表 —— 那就是 §4.1 反复警告的
"同一套规则写两处"。当前实测：`libc getgroups(0,NULL)` 在 fakeroot 下返回
**0**（`g_fakeroot_on` 分支，`ngroups` 为 0），而 `syscall(158)` 返回
**6**（真实组表）—— 这个矛盾本身就是缺口 B 的一部分。

#### 8.1.4 缺口 B 必须先有的测试

1. `syscall(148)`/`syscall(150)` 在 fakeroot 开/关下分别返回伪造值/真值；
2. **三个指针的 NULL 组合**（`(NULL,NULL,NULL)`、`(&r,NULL,NULL)` 等）
   都不能崩溃、且只写非 NULL 的那几个；
3. **宽度**：在缓冲区**前后各放哨兵**，断言只被改写了 4 字节；
4. `syscall(158)` 的 `size==0` / `size<n` / `size>=n` 三种分支；
5. `syscall(158)` 与 `libc getgroups` 返回**同一个**表（自洽性）；
6. **负向**：`172/178/174..177` 仍不受影响（防"加 148/150 时把邻近号卷进来"）。

### 8.2 ★ 缺口 D：用户/组库查询（本轮新发现）

**这不是降权族，也不是身份读取**，是一个独立缺陷。最初是在分析
`passwd -S root` 为何失败时发现的 —— 它**一次 SIGSYS 都没撞**，
排除了 setter 族，继续追才定位到这里。

```sh
getent passwd root
```

```
--- 官方 : root:x:0:0:root:/root:/bin/bash
--- bxroot: （空）
```

```sh
id
```

```
--- 官方 : uid=0(root) gid=0(root) groups=0(root)
--- bxroot: uid=0(root) gid=0 groups=0        ← 注册名/组名反查缺失
```

**受害命令**：`passwd -S root`（官方 rc=0 输出 `root L 2025-08-05 …`，
bxroot rc=1 报 `passwd: user 'root' does not exist`）。

**方向（未定位到根因，仅记录观测）**：`getent`/`passwd` 走的是
NSS 路径（`/etc/nsswitch.conf` → `files` → 读 `/etc/passwd`），
或 `getpwuid`/`getpwnam` 的符号路径。`id` 能拿到 uid/gid 却拿不到
名字，说明 **`getpwuid`/`getgrgid` 这一族在 bxroot 下返回了空**。

**为什么单列**：它与缺口 B/C 的修复路径**完全不同**（B/C 在
`syscall_guard.c` + `sigsys.c`，D 大概率在 `preload.c` 的 NSS 符号
或 `/etc/passwd` 的路径翻译上），混在一起做会互相干扰判断。
**下一轮应该先单独定位 D 的根因**，再决定它与 B 的先后。
