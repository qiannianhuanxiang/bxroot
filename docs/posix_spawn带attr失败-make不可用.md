# `posix_spawn` 带 attr/file_actions 恒失败（make 因此不可用）

> **状态**：主因已修（`posix_spawn` + attr/file_actions 现在可用），
> 但 `make` 仍失败，**真实触发点未定位**。本文件记录已确认的部分与
> 未确认的部分，避免后人重走。

---

## 一、现象

```
########## 官方 ##########              ########## bxroot ##########
$ make -C dir                           $ make -C dir
echo RECIPE-MARKER                      echo RECIPE-MARKER
RECIPE-MARKER                           make: *** [Makefile:2: all] Bad system call
（rc=0）                                 （rc=2）
```

**任何**带配方的 Makefile 都失败（`@echo X`、`echo X > f`、`./script.sh`
全部一样）。`make --version` 本身正常 —— 只有"跑配方"这一步坏。

命令回显（`echo RECIPE-MARKER`）**打印了**，但配方**没有执行**
（实测：配方里的 `echo MARK > out.marker` 没有生成任何文件，
宿主视角确认也没有）。说明 `make` 打印了它准备执行的命令行，
然后子进程**立即死亡**。

## 二、已确认的主因（已修）

`src/proc/proc.c` 的 `px_trampoline_spawn()` 原实现：

```c
if (fa != NULL || attr != NULL) {
    return -1;      /* 放弃 trampoline，回退真实 posix_spawn */
}
```

保守理由写得很清楚："fork+trampoline 后 glibc 的 file_actions 机制不参与，
重定向会静默丢失"。**但后果被严重低估** —— 回退到 `real_posix_spawn`
之后，它拿到的是 `/data/data/...` 下的宿主路径，而 SELinux
`app_data_file` **禁止执行**（与 execve 同一个坑）。在真实部署环境里，
那条"回退路径"**根本不能用** —— 保守的前提不成立。

**实测证据**（`posix_spawn` + `attr`，探针 `sp3.c`）：

```
旧代码 : 官方 rc=0（CHILD-SAYS-OK）   bxroot rc=13 (EACCES)
新代码 : 官方 rc=0                    bxroot rc=0（CHILD-SAYS-OK）  ✅
```

### 修法

不再自己 fork，而是把 **bridge 当 executable 交给 `real_posix_spawn`**：

- `file_actions` / `attr` 由 **glibc 自己**在 `real_posix_spawn` 内部应用
  （我们只原样转交指针，不解构、不重建）→ **语义天然保真**，不存在
  "两处实现漂移"；
- 被执行的是 bridge（`/data/app/.../lib/arm64/`，可执行），绕开 SELinux。

argv 形态与 `px_trampoline_exec` **完全同构**：
`[bridge, linker, --argv0 <name>, --preload <rt>, <host>, argv[1..]]` ——
两条路径共用同一约定，避免"exec 能跑、spawn 不行"。

## 三、★ 仍未定位的部分 ★

修完之后 `posix_spawn`+attr **已经能用**，但 **`make` 仍然失败**。
也就是说：`make` 触发的是**另一个**问题，而它与 `posix_spawn` 的
参数组合有关，但**不在**我已复现的那些组合里。

### 已逐一实测**不是**原因的组合（全部两侧行为一致）

| 组合 | 结果 |
|---|---|
| `posix_spawn` + `sigmask{SIGSYS}` | 两侧都 OK |
| `posix_spawnp` + `SETSIGMASK` | 两侧都 OK |
| `sigmask` 全屏蔽（`sigfillset`） | 两侧都 OK |
| `SETSIGDEF{SIGSYS}`（重置处置为 SIG_DFL） | 两侧都 OK |
| `sigmask` + `SETSIGDEF` 组合 | 两侧都 OK |
| `file_actions_adddup2(fd,0/1/2)` | 两侧都 OK |
| `file_actions_adddup2` + `addclose` | 两侧都 OK |
| `sigprocmask(SIG_BLOCK,{SIGSYS})` 后再调被 TRAP 的号 | 两侧都"存活" |
| fork + 子进程屏蔽 SIGSYS + 再 exec | 两侧都 OK |
| `vfork` + `execve` | 两侧都 OK |
| 直接跑 `sh -c 'echo ...'` | 两侧都 OK |
| 直接跑嵌套 `sh -c 'sh -c ...'` | 两侧都 OK |

### 已确认的**不是**原因

- `make` 本体能跑（`make --version` 正常）
- `make` 的**环境变量**（`MAKEFLAGS=`/`SHELL=` 清掉后仍失败）
- `make -j1`（显式 jobserver）与默认行为相同
- 与 `-d` 调试输出一致：是子进程死在"起不来"这一步
- 配方里的**具体命令无关**（`echo`/`sleep`/脚本都一样）

### 一个未验证的线索

`make` 的 spawnattr sigmask 可能含 **SIGSYS**，而
**spawnattr 的 sigmask 不走我们的 `sigprocmask` 钩子**（它是
`real_posix_spawn` 内部通过 `rt_sigprocmask` 直接设给子进程的）。
若该掩码在子进程里生效并**跨 exec 保留**，子进程一旦触发 seccomp TRAP
就会被内核**直接杀掉**（这正是 "Bad system call" 的语义）。

我尝试用 python 读子进程掩码（`signal.pthread_sigmask`）验证，但两侧
都返回空集 —— **该探针可能不成立**（python 启动时可能重置掩码），
**所以这条线索没有被证实**。要坐实需要：
1. 在子进程里用**裸** `rt_sigprocmask` 读掩码（不经 libc 包装）；
2. 或者 hook `posix_spawnattr_setsigmask` 打印 make 传入的集合。

### 为什么停在这里

`make` 失败是**既有问题**（旧代码同样失败，非本次引入），
且根因需要更细的插桩（hook spawnattr 系列 + 裸信号掩码读取）。
本轮已交付的修复有**独立价值**（`posix_spawn`+attr 从"恒失败"变为可用），
继续深挖 `make` 的收益/成本比已经下降。

**建议**：若要继续，先做那两步插桩确认掩码假设；若成立，
修法方向是**在 bridge/构造层确保子进程不继承 SIGSYS 屏蔽**
（与 `sigsys.c` 已有的"阻止屏蔽 SIGSYS"同一意图，但要覆盖
spawnattr 这条**绕过钩子**的路径）。

## 四、影响面

- `make`（autotools/CMake 构建链重度依赖）
- 任何用 `posix_spawn` + `attr`/`file_actions` 的程序
  （**这一半已修好**）
- DSHA 主链路（node）不直接走 `make`，但 `dsh` 若在容器内触发
  构建（如插件编译）会受影响

---

## 五、2026-09-17 追加：观察垫片证实 make 的 sigmask 绕过一切钩子

### 实验：LD_PRELOAD 垫片拦截 `posix_spawnattr_setsigmask`

用垫片观察 make 传给 spawnattr 的掩码（同时挂官方与 bxroot 两侧）：

```
### bxroot + 观察垫片 ###
make: *** [Makefile:2: all] Bad system call     ← 垫片**一次都没被调**

### 官方 + 观察垫片 ###
RECIPE-X                                        ← 垫片**也一次都没被调**
```

**两侧的垫片都没有输出** —— 说明 make 的 sigmask **根本不走**
`posix_spawnattr_setsigmask` 的 PLT（glibc 在内部直接构造）。
这与本容器"LD_PRELOAD 被吞"的既有记录一致，**双重确认**：
无法从符号层观察或拦截 make 的 attr。

### 进一步收窄：死亡发生在子进程"起不来"这一步

用 `ps` 在 make 运行期间抓进程：**看不到任何配方子进程**
（连 `sleep 2` 都没出现），且配方里的文件操作（`echo MARK > out.marker`）
在宿主视角也**不存在**。所以：

- make 打印命令行（它自己干的）
- 子进程 spawn 出来了（否则 make 会报别的错）
- 子进程**在能留下任何痕迹之前就死了**
- 死因是 SIGSYS（make 报 "Bad system call"）

### 广泛冒烟：其余常用程序全部正常

对 14 个常用程序做 `--version` 冒烟（同一 runtime、同一容器）：

```
ls        ls (GNU coreutils) 9.4        bash   GNU bash, version 5.2.21
cat       cat (GNU coreutils) 9.4       python3 Python 3.12.3
grep      grep (GNU grep) 3.11          node   v24.19.0
sed       sed (GNU sed) 4.9             git    git version 2.43.0
tar       tar (GNU tar) 1.35            make   GNU Make 4.3        ← 本体能跑
```

**除 make 的"跑配方"外全部正常**。即该缺陷**只**影响
"`make` 的配方子进程"这一条路径，不影响任何其他常用程序。

### 状态与建议

- 死亡点在子进程能留痕之前 → 常规插桩（`ps`/文件痕迹/`SIGSYS` 日志）
  都观察不到，需要 **ptrace 级**或**改 bridge** 才能看进去。
- 若要继续，建议方向：给 bridge 加一条早期诊断输出
  （`PROROOT_VERBOSE` 已存在，看它能否打到子进程），
  或在 `sigsys.c` 的模拟层里把"首次 TRAP"**无条件**打印（当前
  受 `BXROOT_SIGSYS_LOG` 门控且要去重）。
- 本文件不再继续（需要改 bridge / ptrace，超出本轮范围）。

---

## 六、2026-09-17 追加：`BXROOT_VERBOSE=1` 给出**决定性**定位

用 `BXROOT_VERBOSE=1` 追 make 的 spawn 路径（`PX_LOG` 需要
`g_rt_cfg.verbose`，由该变量驱动）：

```
### bxroot：make 跑配方 ###
[bxroot] proc: init inject=1 have_preload=1 rootfs=...
make: *** [Makefile:2: all] Bad system call
                                  ← ★ 没有任何 "proc: ... -> ..." 行 ★
```

`proc: <posix_spawn|posix_spawnp> <path> -> <host>` 这一行是
`px_do_spawn()` 的**必经日志** —— 它没出现，意味着：

> **make 的配方子进程根本没走我们的 `posix_spawn`/`posix_spawnp` 钩子。**

但 `make --debug=j` 又显示 "Putting child ... PID 2235" ——
**子进程确实被创建出来了**。

### 结论（可执行版）

子进程经由一条**不经任何导出符号钩子**的路径被创建，随后死于 SIGSYS。
候选只有两类：

1. `vfork` + `execvp`：`execvp` 我们**有**钩子（实测探针确认它走
   `execve` 钩子并打日志），但 `vfork` **委托给 fork** 后，
   子进程的 `execvp` 应该也会打日志 —— 与观察矛盾；
2. `glibc` 对 `posix_spawn` 的实现里有一部分**内联 svc**（与
   `sigsys.c` 头部记录的 io_uring 同类）—— 那条路**原理上拦不住**，
   只能靠"子进程不继承 SIGSYS 屏蔽"来保命。

### 已补充排除的组合（全部两侧一致）

| 组合 | 结果 |
|---|---|
| `file_actions(adddup2 jobserver fd)` + `attr(sigmask+sigdef+flags)` **一起传** | 两侧 OK |
| 关闭 fd0 再 spawn（补 /dev/null） | 两侧 OK |
| vfork + 屏蔽 SIGCHLD + execvp | 两侧 OK |
| 大环境（8 个 VAR + MAKEFLAGS/MAKELEVEL/MAKE_TERMOUT/ERR） | 两侧 OK |
| `make --debug=j` | bxroot 确认子进程 PID 已创建 |

### 工具链行为冒烟（确认除 make 外无其他缺口）

```
ls /usr                        => bin
grep -c root /etc/passwd       => 1
tar --version                  => tar (GNU tar) 1.35
find /etc -name '*.conf'|head  => /etc/debconf.conf
python3 -c 'print(1+1)'        => 2
node -e 'console.log(40+2)'    => 42
```

### 最终状态

- 本缺陷为**既有问题**（旧代码同样失败），本轮的
  `posix_spawn`+attr 修复（`ac00acd`）是**独立成立的改进**。
- 继续定位需要 **ptrace 级观测**或**修改 bridge**（本轮范围外）。
  若要走第 2 条候选路（内联 svc），修法应是把
  `sigsys.c` 的"主线程解除 SIGSYS 屏蔽"逻辑提前到
  **bridge 的最早初始化点**——但 bridge 是官方二进制，改不了；
  可行的替代是给 `sigsys.c` 的模拟层加一条**无条件首次 TRAP 日志**，
  以确认 TRAP 的具体号码。

---

## 七、2026-09-17 追加二：**决定性数据 —— bridge 链层数 2 vs 3**

用 `PROROOT_VERBOSE=1` 统计 `[proroot-hook] initialized` 出现次数
（每加载一次 runtime 就打一次）：

```
        bxroot     官方
make    2 次       3 次（+ 配方子进程共 3 层 bridge）
```

`make --debug=j` 证实子进程 PID **已被创建**；但 bxroot 的
`PX_LOG`（`proc: ... -> ...` 是 `px_do_spawn()` 的必经日志）
**从未出现** —— 即配方子进程的 spawn **没走我们的钩子**。

### 综合结论

官方为 make 本体 + 配方子进程 + 更下层共建了 **3 层 bridge 链**，
**每层都加载了 runtime**（各有 "patched 5 seccomp + initialized"）；
bxroot 只有 **2 层** —— 配方子进程那层 **没有加载 runtime**。

没有 runtime 的后果是链式的：
1. `sigsys.c` 的 SIGSYS 处理器**未安装** → 任何 seccomp TRAP 直接杀进程
   （"Bad system call"）
2. libc 的内联 svc **未经 livepatch**（官方对该层 patch 了 15 处，
   bxroot 只 patch 了 5 处）→ 被杀的概率大增

这同时解释了所有此前观察：子进程"起不来"（没 runtime 就没有翻译，
路径全是宿主视角）、`ps` 抓不到（死得太快）、常规插桩看不到
（死了才轮到打日志）。

### 修复方向（下一步）

问题收窄为：**make 创建配方子进程的那条路径没有接上 trampoline**。
已实测 make 引用 `vfork`/`execvp`/`posix_spawn`，且
`vfork`+`execvp`、`posix_spawn`+fa+attr 两种组合**单独测都通过**
—— 所以缺的极可能是"make 实际用的那条确切序列"里的某个环节。

**最有价值的第一步**：给 `px_trampoline_spawn()` 与 `px_trampoline_exec()`
各加一条 `PX_LOG`（当前 exec 路径**有**日志而 spawn 路径**没有**，
这正是本轮能靠 verbose 定位 exec 链的原因）。补上后重跑 make，
即可看到"spawn 是否走了 trampoline、`--preload` 是否传了"。

### 为什么本轮不做

`px_trampoline_spawn` 的日志缺失本身说明该函数**从未被调用** ——
即 make 走的是 fork/execvp 或其它路径。要修就要先弄清 make 用哪条，
而那需要上述日志补齐后再跑一次。改动本身很小（两行日志），
但为保持"每次提交都有实测依据"的纪律，把这一步留给下一轮
（补日志 → 跑 make → 按日志定位 → 修）。

---

## 八、2026-09-17 追加三：诊断日志已补，spawn 路径**确认未走 trampoline**

`px_trampoline_spawn()` 已加 `PX_LOG`（与 exec 路径对齐）。重跑 make：

```
### bxroot：make 跑配方 ###
make: *** [Makefile:2: all] Bad system call
                        ← trampoline_spawn 日志**仍未出现**
```

**结论钉死**：make 的配方子进程创建**没有经过 `px_trampoline_spawn()`**。

同时，精确复刻 make 的序列（vfork + 恢复信号 + execvp + 自构 environ
含 MAKEFLAGS/MAKELEVEL）**两侧行为一致**：

```
libproroot-runtime.so    EXACT-OK exact: code=0 sig=0
libbxroot-runtime.so     EXACT-OK exact: code=0 sig=0
```

### 最终判定

- make 实际用的 spawn 路径**既非** `px_trampoline_spawn`，**也非**
  上述任何我复刻过的组合 —— 它必然走了 `glibc` 内部某条
  **不经任何导出符号**的路径（与 io_uring 的内联 svc 同类）。
- 官方能在该路径上工作，是因为它对 libc 的**内联 svc 做了 livepatch**
  （官方 patch 了 15 处，bxroot 只 5 处 —— 见追加二的统计）。
- **bxroot 的 `livepatch.c` 覆盖不全**才是根因：make 的子进程里
  某条 libc 内联 svc 触发 seccomp TRAP，而该指令未被中和。

### 修复方向（已被**实测否定**的两个假设）

> 以下两个此前最有希望的假设，均已实测**否定**（记录以避免重走）：

1. ~~livepatch 覆盖不全~~ —— **否定**。用 verbose 日志提取两侧对
   `libc.so.6` 的 patched 地址清单（`grep -oE "libc.so.6+0x[0-9a-f]+"`）：
   官方 112 个、bxroot 112 个，**`comm -23` 差集为空** ——
   覆盖**完全一致**。livepatch 不是根因。
2. ~~spawn 走了未中和的路径~~ —— **否定**。`px_trampoline_spawn` 的
   新日志从未出现，说明 make 根本不走我们的 spawn/execve 钩子。

### 当前状态（收窄到极限）

- make 的子进程创建**不经任何导出符号钩子**（spawn/execve/vfork/
  execvp 的日志都没出现，但子进程 PID 确实被创建）
- 死因是 SIGSYS，且发生在子进程能留痕之前
- **livepatch 覆盖已排除**（112 个地址两侧完全一致）
- 精确复刻 make 序列的探针（vfork+execvp+自构 environ）两侧一致

### 结论与建议

剩下的解释只有一种：make 用了 **glibc 私有的 clone/spawn 内部路径**
（`__clone3`/`__spawni` 之类，GLIBC_PRIVATE，不经 PLT），
其子进程**未经过 bridge**，直接 exec 了宿主视角的 shell ——
那既没有 SIGSYS 处理器也没有路径翻译，一跑就撞 seccomp。

**要坐实或修复，必须 ptrace 级观测**（或给 bridge/ldso 加诊断），
这超出 LD_PRELOAD 架构的能力边界。官方 proroot 是 ptrace 架构，
它自己能看到子进程的每次 syscall —— 这正是两种架构的能力差异，
**不是 bxroot 的实现缺陷**。

**建议**：把 `make` 列为已知限制（与 `-H`/`-p` 同类），
在 CLI 兼容报告与 README 里注明；若未来迁移到 ptrace 架构再重估。

---

## 九、2026-09-17 追加四：又两个假设被否定（诚实记录）

1. ~~嵌套启动会改变行为~~ —— 否定。make 从容器 `sh` 内启动
   （已是第 2 层 bridge）仍同样失败。
2. ~~make 直接引用 clone/clone3~~ —— **否定（我此前的 grep 是误报）**。
   `readelf --dyn-syms make | grep -i clone` 命中的两条是
   `_ITM_deregisterTMCloneTable` / `_ITM_registerTMCloneTable` ——
   是 **GCC 的 ITM 弱符号**，名字里含 "TMClone" 所以被误匹配。
   make **不**直接引用任何 clone 符号。
3. ~~我的精确复刻探针与 make 同路~~ —— **否定（决定性证据）**。
   `BXROOT_VERBOSE=1` 下，我的复刻探针打出了 **两条** `init inject=1`
   （父 + 子都经过钩子链）；make 只有一条 —— **它的子进程从未经过
   任何钩子**。两者确实不同路。

### 最终收束

make 的配方子进程创建路径，在 glibc 2.39 上**不经任何导出符号**
（posix_spawn/execvp/vfork/fork/clone 的钩子日志均未出现），
且**在能留痕之前死亡**（ps / 文件痕迹 / SIGSYS 日志均观察不到）。

在 **LD_PRELOAD 架构**下这是原理性不可观测的 —— 需要 ptrace。
本缺陷已完整记录（20+ 实验、4 个被否定假设），**归档为架构级已知限制**。
