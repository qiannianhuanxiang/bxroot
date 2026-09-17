# getpid 伪造缺陷（fakeroot 下硬编码返回 1）

**日期**：2026-09-17
**缺陷位置**：`src/runtime/preload.c` 原 `:5407-5419`（`getpid` 钩子）
**修法**：**直接删除该钩子**（选项 a），并删除配套的 `real_getpid` 静态指针与其初始化
**影响面**：`BXROOT_FAKEROOT=1` 下的**全部**进程

---

## 0. 一句话结论

`getpid` 钩子在 fakeroot 下把返回值硬编码为 `1`，而官方 proroot/proot
**从不导出、也从不修改** `getpid`。这不是洁癖问题：它使 `$$`（= `getpid()`）
在容器内**全部退化为 1**，`D=/tmp/build-$$` 这类并发去重手段彻底失效，
并发构建（`portage`/`dpkg`/`npm`）会互相删对方的中间文件。

**并且它还是第二个缺陷的根因**：`crash.c` 的崩溃重抛走
`kill(getpid(), sig)`，拿到 `1` 后被 D4 白名单当成「容器外进程」**拒绝**，
重抛静默失败。两处同源，一并修复。

---

## 1. 三条证据

### 证据 1：官方明确写着自己不改 getpid

`/tmp/proot-research/termux-proot/src/extension/fake_id0/sendmsg.c:164-165`
（fake_id0 就是 proot 的 fakeroot 扩展）原文：

```c
				/* Set uid and gid of SCM_CREDENTIALS to ones that proot really has.
				 * Pid is not changed as we don't fiddle with getpid()  */
				ucred->uid = getuid();
				ucred->gid = getgid();
```

「Pid is not changed as we don't fiddle with getpid()」——
官方唯一会碰到 pid 的地方（`SCM_CREDENTIALS`）都刻意绕开了它。
fakeroot 只伪装 **uid/gid**，与 pid 是两件不相干的事。

全树搜索也确认官方**没有**任何 `getpid` 钩子：

```sh
$ grep -rn "getpid" /tmp/proot-research/termux-proot/src/ | head -20
src/cli/cli.c:468:	tracee->pid = getpid();
src/execve/enter.c:520:	status = readlink_proc_pid_fd(getpid(), fd, path);
src/extension/fake_id0/sendmsg.c:165:  ... * Pid is not changed as we don't fiddle with getpid()  */
src/path/temp.c:275:	name = talloc_asprintf(context, "%s/%s-%d-XXXXXX", temp_directory, prefix, getpid());
src/tracee/event.c:126:		kill(getpid(), SIGSTOP);
```

出现的四处**全是 proot 自己进程内部**的正常使用（取自己的 pid 建临时文件名、
`SIGSTOP` 自己），没有一处是「替 tracee 伪造一个假 pid」。

### 证据 2：官方 runtime 根本不导出 getpid

用 `nm -D --defined-only` 去版本号后 `sort -u` 核对两份动态符号表。
**本次修复后重新实测**（原始输出见 §5.3）：

```
官方 work/parity/off/libproroot-runtime.so : （不导出 getpid）
bxroot build/libbxroot-runtime.so          : （不导出 getpid）   ← 修复后

修复前：
$ nm -D --defined-only build/libbxroot-runtime.so | ... | grep -x getpid
getpid                                                          ← 唯一的偏离
```

官方 runtime 的 `pid` 相关导出只有 `pidfd_send_signal` 与
`proroot_is_proc_pid_exe`（内部辅助），**没有任何 getpid 家族符号**：

```sh
$ nm -D --defined-only work/parity/off/libproroot-runtime.so | awk '{print $3}' \
    | sed 's/@.*//' | sort -u | grep -x -E 'getpid|getppid|getpgrp|getsid'
（无输出）
```

顺带核对：bxroot 也**不**导出 `getppid`/`getpgrp`/`getsid`/`gettid` ——
即 `getpid` 是**唯一**被滥用的 pid 家族符号，修复它就把这一类偏离清零了。

### 证据 3：同一个探针，两侧行为不同

探针 `probe.sh`：

```sh
echo "PID=$$"
sh -c 'mkdir -p /tmp/pidprobe-$$; echo "CHILD_A pid=$$ dir=/tmp/pidprobe-$$"' &
A=$!
sh -c 'mkdir -p /tmp/pidprobe-$$; echo "CHILD_B pid=$$ dir=/tmp/pidprobe-$$"' &
B=$!
wait "$A" "$B"
echo "DIRS=$(ls -d /tmp/pidprobe-* 2>/dev/null | wc -l)"
```

（`$$` 在 dash 里就是 `getpid()` 的结果，所以这个探针测的正是本缺陷。）

修复前实测：

```
官方 : PID=10664  CHILD_A pid=10665  CHILD_B pid=10666  DIRS=2
bxroot: PID=1     CHILD_A pid=1      CHILD_B pid=1      DIRS=1   ← 撞车
```

完整三方对照见 §5.2。

---

## 2. 真实危害

shell 里 `$$` 是**进程唯一性**的常规手段，脚本普遍用它做临时路径去重：

```sh
D=/tmp/build-$$        # 并发跑就会撞
mkdir -p "$D"
```

bxroot 下所有并发进程的 `$$` 全是 `1` → **全部撞进同一个 `/tmp/build-1`**，
互相删对方的中间文件。这不是理论推演，上面的 `DIRS=1` 就是实测：

- 两个子进程都认为自己是 `1`，`mkdir -p /tmp/pidprobe-1` 第二次是 no-op
  （`-p` 不报错，所以**没有任何错误信息**）；
- 于是两个进程共用同一个「私有」目录，后一个的清理会删掉前一个的产物。

这正是「有些并发构建会莫名其妙地失败」的一类根因，且**现象离原因极远**：
没有报错、没有崩溃、只是偶发地缺文件。DSHA 生产环境里的
`portage` / `dpkg` / `npm` 都会 fork 并发，全在这个射程内。

---

## 3. 依赖链调查（本次任务的重点）

要回答的问题是：**这个钩子当初为什么存在？删除它会破坏什么？**

### 3.1 钩子的来历：不是设计，是误加

追溯到 git 镜像里钩子**首次**出现的提交：

```sh
$ cd /tmp/bxroot-git && git log --oneline --all -S "pid_t getpid(void)" -- src/runtime/preload.c
829844a feat: 路径翻译运行时核心
64d20d6 add: src/runtime/preload.c
```

在 `64d20d6` 里它与 `getuid`/`getgid`/`geteuid`/`getegid` 是**同一批**加进来的，
注释只有一行 `/* 伪装为 root 进程 */`。也就是说它是「fakeroot 就该伪装身份，
那 pid 也一起伪装吧」的**顺手推断**，而不是任何功能的需求推导。

`src/runtime/fakeroot.h:6` 留下了这条思路的原文：

> 克隆版只钩了 getuid/getgid/geteuid/getegid/**getpid** 五个函数。这不够：

这句是在说「5 个钩子不够，要加 stat 补丁 + chown 记账」——
但它默认接受了 `getpid` 属于 fakeroot 的钩子集合。
**这正是误加的源头**：uid/gid 与 pid 被混为一谈。官方证明了两者无关（证据 1）。

### 3.2 全仓搜索：谁调用 getpid

搜索范围覆盖 `src/proc/proc.c`、`src/l2s/`、`src/launcher/`、`src/runtime/`、
`src/bridge/`、`test/`、`docs/`。

以**函数调用**形式出现的（排除 `syscall(SYS_getpid)` 与注释）：

| 位置 | 用途 | 需要真 pid 吗 |
|---|---|---|
| `src/runtime/crash.c:372` | `kill(getpid(), sig)` 重抛信号 | **需要** ← 见 3.3 |
| `src/bridge/bridge.c:51` | socket 路径 `/tmp/.bxroot-bridge-%d.sock` | **需要** |

两者都**需要真实 pid**，删除钩子对它们**只有好处**。

关键的对照：**D4 进程管理层根本不走这个钩子**。`src/proc/proc.c` 一律用
裸系统调用取自身 pid，刻意绕开 libc 包装：

```c
static pid_t px_self_pid(void)          /* proc.c:2805 */
{
    if (g_cached_self_pid <= 0) {
        g_cached_self_pid = (pid_t)syscall(SYS_getpid);   /* ← 裸 syscall */
        ...
static pid_t px_real_getpid(void) { return (pid_t)syscall(SYS_getpid); }  /* proc.c:2821 */
```

`px_runtime_kill_on_exit` 同样如此（`proc.c:4594`、`4650` 都是
`syscall(SYS_getpid)`）。**所以 D4 从未依赖这个钩子，删除它不影响 D4 的正确性。**

### 3.3 ★ 第二个缺陷：crash.c 才是真正的受害方 ★

`crash.c:340-372` 的注释解释了为什么重抛必须用 `kill(getpid(), sig)`：

```c
    /*
     *   2. 用 kill(getpid(), sig) 而不是 raise() —— raise() 同样不保证安全；
     */
    {
        struct sigaction dfl;
        ...
        sigaction(sig, &dfl, NULL);
    }
    kill(getpid(), sig);
```

`crash.c` 与 `preload.c` 编进**同一个** `libbxroot-runtime.so`
（`BUILD_RUNTIME.sh:76`），并且该 .so 同时导出 `getpid` 和 `kill`
（已用 `nm -D` 核对）。于是这两个调用**都**走 bxroot 自己的钩子：

1. `getpid()` → fakeroot 下返回 `1`；
2. `kill(1, sig)` → 进 D4 的 `px_check_kill`。`1` 不在账本里
   （没有任何代码把 pid 1 登记进账本），也不是自己的父进程
   → **`PROC_KILL_DENY`**；
3. 重抛失败，`kill()` 返回 `-1/EPERM`，**静默**（返回值没被检查）。

修复前实测原始输出（`BXROOT_VERBOSE=1`）：

```
[bxroot] SIGSEGV pc=0x0000007f15167808 lr=0x0000007f151677fc fault=0x0000000000000000 code=1
[bxroot] backtrace (fp chain):
[bxroot] 提示：fault 地址未映射（SEGV_MAPERR），跳过内存窗口
[bxroot] proc: kill(1, 11) 被拒绝（容器外进程）      ← 重抛被自己的白名单拒绝
```

退出码仍是 `139`（`_exit(128+sig)` 兜底），所以**从外部完全看不出来**：
现象是「core dump 不产生 / 崩溃退出路径与官方不同」，而日志里那句
「被拒绝」很容易被当成正常的越界防护。这是一个被安全层**误伤**的
合法自杀操作 —— 而它误伤的原因，正是 `getpid()` 返回了假 pid。

### 3.4 `docs/P0-3-D4集成报告.md:51-52` 那句话怎么读

原文（该文档**只读不动**，此处仅引用）：

```c
+    /* 把自己记进账本：否则 kill(getpid()) 会被自己的白名单拒绝
+     *（getpid 在 fakeroot 下被伪装成 1，这个自伤场景是常态） */
+    px_runtime_register_self();
```

**结论：这不是依赖，是规避。** 逐点说明：

1. **没有代码判断 `getpid() == 1`。** 全仓扫描 `src/runtime/`、`src/l2s/`、
   `src/proc/proc.c`、`src/launcher/` 里所有带 `pid` 的 `== 1` / `!= 1`
   比较，**结果为空**。
2. 那句话是在**描述现象**（"被伪装成 1"）并据此加了
   `px_runtime_register_self()` 作为**补丁绕过** —— 让 `kill(1, ...)`
   因为「1 在账本里」而被放行。这是绕开错误行为，不是依赖错误行为。
3. 那句话自称「自伤场景是常态」，但它**说反了因果**：
   `kill(getpid())` 之所以会自伤，**正是因为** getpid 被伪造。
   getpid 一修，这个「常态」就消失了。
4. 因此 `px_runtime_register_self()` **保留不动**：真实 pid 下把自己记进
   账本**依然正确**（本就是应有行为），删除它对本轮缺陷零收益、只有回归风险。
   仅把注释里那句已失真的描述更正掉（见 §4）。

> 关于「依赖一个错误行为本身就是 bug」这个判断：本次调查的结论是
> **依赖并不存在**，存在的是一处**规避型补丁 + 一句失真的注释**。
> 规避补丁在真实 pid 下无害（可保留），失真的注释必须改（否则会误导
> 后来者以为 `getpid()==1` 是设计的一部分，从而"修复"时把它加回来）。

### 3.5 删除不破坏任何东西 —— 逐项核对

| 潜在依赖方 | 实际取的 pid 来源 | 删除钩子后 |
|---|---|---|
| D4 `px_self_pid` / `PX_SYSOPS` | `syscall(SYS_getpid)`（绕开钩子） | ✅ 无影响 |
| D4 kill-on-exit（`g_kox_owner`） | `syscall(SYS_getpid)` | ✅ 无影响 |
| `crash.c` 重抛 | `kill(getpid(), sig)` → 需要真 pid | ✅ **修好了** |
| `bridge.c` socket 路径 | `getpid()` → 需要真 pid | ✅ **修好了** |
| `px_runtime_register_self()` | `px_self_pid()`（裸 syscall） | ✅ 保留，仍然正确 |
| 任何 `getpid() == 1` 判据 | —— | ✅ **不存在** |
| 零告警门禁（`-Wunused`） | —— | ✅ 同步删掉 `real_getpid`，见 §4 |

**没有发现任何真实功能依赖 `getpid() == 1`。**

---

## 4. 修法选择理由

三个候选：

| 选项 | 做法 | 评价 |
|---|---|---|
| **(a) 删除钩子** | 与官方逐符号一致 | ✅ **采用** |
| (b) 保留钩子但返回真 pid | 语义与 (a) 相同 | 可用，但更差，见下 |
| (c) 其它（如只在非 fakeroot 伪装） | —— | 不改「fakeroot 与 pid 无关」这一事实，方向就错了 |

**(a) 与 (b) 语义完全等价**（都返回真实 pid），但 (a) 更强，三条理由：

1. **与官方逐符号一致** —— 这正是本项目 `work/parity` 的目标本身。
   官方不导出，bxroot 也不导出，`nm -D` 对照即可回归（§5.3）。
2. **没有调用开销** —— `getpid` 是热路径（shell、libuv、进程管理都会走）。
   (b) 每次调用都要过 `ensure_real_functions()` 再间接转发一次。
3. **消灭整类缺陷** —— 钩子没了，就没有任何分支可能再把它改回 `1`。
   留一个"只做原样转发"的钩子，等于给下一个人留了个改错的地方。
   本缺陷的成因恰恰就是"顺手加了个钩子"（§3.1），(a) 从结构上杜绝复发。

**配套改动（零告警门禁要求）**：删除钩子后，`real_getpid` 静态指针
（原 `:178`）与它在 `ensure_real_functions()` 里的初始化（原 `:1038`）
就成了未使用变量，会触发本仓库的 `-Wall -Wextra` 零告警门禁，
**一并删除**。

**注释处理**：在新位置留了一段长注释，写明官方行为、原来错在哪、
为什么这样改、以及删除它不破坏什么 —— 目的是让后来者不会"顺手加回来"。
同时更正了 `constructor()` 里那句已失真的注释（§3.4）。

**`px_runtime_register_self()` 保留不动**，理由见 §3.4 第 4 点。

---

## 5. 实测验证

所有指令均逐字执行，输出为原始粘贴。

### 5.1 构建

```sh
$ cd /root/proroot-work/agents/rename-bxroot && sh BUILD_RUNTIME.sh
== 构建 libbxroot-runtime.so ==
   编译器     : gcc (13)
   proc.c     : /root/proroot-work/agents/rename-bxroot/src/proc/proc.c
   起始优化   : -O2
   gcc ICE（-O2 第 1 次），重试
   gcc ICE（-O2 第 2 次），重试
   ✅ 链接成功（-O2，第 3 次尝试）
   产物: /root/proroot-work/agents/rename-bxroot/build/libbxroot-runtime.so
   大小: 228864 字节
   导出符号（nm -D --defined-only）: 350
   ✅ D4 进程管理符号全部导出（23/23，含 waitpid/wait4/wait3/waitid）
```

（`-O2` 前两次是容器已知的 gcc 间歇性 ICE，第 3 次成功，与 `BUILD_RUNTIME.sh`
的设计一致；**构建零告警**，说明删除 `real_getpid` 后没有 `-Wunused` 问题。）

### 5.2 对照实验一：`$$` 去重（缺陷本体）

同一探针，同一跑法，三方对照：

```sh
$ sh /root/pidfix/run_probe.sh official.so
========== 官方 libproroot-runtime.so ==========
PID=16973
CHILD_A pid=16974 dir=/tmp/pidprobe-16974
CHILD_B pid=16975 dir=/tmp/pidprobe-16975
DIRS=2

$ sh /root/pidfix/run_probe.sh bxroot-before.so
========== bxroot（修复前）==========
PID=1
CHILD_A pid=1 dir=/tmp/pidprobe-1
CHILD_B pid=1 dir=/tmp/pidprobe-1
DIRS=1

$ sh /root/pidfix/run_probe.sh bxroot-after.so
========== bxroot（修复后）==========
PID=17087
CHILD_A pid=17089 dir=/tmp/pidprobe-17089
CHILD_B pid=17090 dir=/tmp/pidprobe-17090
DIRS=2
```

**修复后与官方逐项一致**：每进程拿到自己的真实 pid，两个并发子进程的
`$$` 目录**不再碰撞**（`DIRS=2`）。

### 5.3 对照实验二：导出符号

```sh
$ nm -D build/libbxroot-runtime.so | grep getpid
                 U getpid@GLIBC_2.17
```

⚠️ 注意读法：`U` = **未定义（undefined）**，即"本库**引用** libc 的 getpid"
—— 这正是修复的目标状态：不再**定义/导出** getpid，只按需调用 libc 的。
修复前这里是 `T getpid`（`T` = 已定义并导出）。

```sh
$ for lib in work/parity/off/libproroot-runtime.so build/libbxroot-runtime.so; do
      printf '%-46s : ' "$lib"
      r=$(nm -D --defined-only "$lib" | awk '{print $3}' | sed 's/@.*//' | sort -u | grep -x getpid)
      echo "${r:-（不导出 getpid）}"
  done
work/parity/off/libproroot-runtime.so          : （不导出 getpid）
build/libbxroot-runtime.so                     : （不导出 getpid）
```

**两侧逐符号一致。**

### 5.4 对照实验三：D4 自伤保护（第二个缺陷）

探针只用 `kill(pid, 0)`（0 号信号 = 纯存在性探测，**不投递任何信号**，
绝对不会杀掉任何进程）：

```sh
$ sh /root/pidfix/run_bin.sh bxroot-before.so /root/pidfix/pidprobe
[bxroot] proc: kill(1, 0) 被拒绝（容器外进程）
PROBE real_pid=11683 getpid()=1
PROBE kill(getpid(),0)  rc=-1 errno=1(Operation not permitted)     ← 自伤保护是坏的
PROBE kill(realpid,0)   rc=0 errno=0(Success)

$ sh /root/pidfix/run_bin.sh bxroot-after.so /root/pidfix/pidprobe
PROBE real_pid=17235 getpid()=17235
PROBE kill(getpid(),0)  rc=0 errno=0(Success)                      ← 修好了
PROBE kill(realpid,0)   rc=0 errno=0(Success)

$ sh /root/pidfix/run_bin.sh official.so /root/pidfix/pidprobe
PROBE real_pid=17377 getpid()=17377
PROBE kill(getpid(),0)  rc=0 errno=0(Success)                      ← 官方基线
PROBE kill(realpid,0)   rc=0 errno=0(Success)
```

**修复后 bxroot 与官方逐行一致。** 这直接证伪了
`docs/P0-3-D4集成报告.md` 里"把 pid 1 记进账本所以自伤场景已覆盖"的说法：
`px_runtime_register_self()` 登记的是**真实 pid**，它救不了 `kill(1, ...)`。

### 5.5 对照实验四：崩溃重抛

```sh
$ sh /root/pidfix/run_bin.sh bxroot-before.so /root/pidfix/crashtest
CRASH probe: real work then deref NULL
[bxroot] SIGSEGV pc=0x0000007f15167808 lr=0x0000007f151677fc fault=0x0000000000000000 code=1
[bxroot] backtrace (fp chain):
[bxroot] 提示：fault 地址未映射（SEGV_MAPERR），跳过内存窗口
[bxroot] proc: kill(1, 11) 被拒绝（容器外进程）      ← 重抛失败

$ sh /root/pidfix/run_bin.sh bxroot-after.so /root/pidfix/crashtest
CRASH probe: real work then deref NULL
[bxroot] SIGSEGV pc=0x00000075f8013808 lr=0x00000075f80137fc fault=0x0000000000000000 code=1
（"kill(1, 11) 被拒绝" 已消失 → 重抛成功）

$ sh /root/pidfix/run_bin.sh official.so /root/pidfix/crashtest
CRASH probe: real work then deref NULL
[proroot] SIGSEGV pc=0x74c3c9f808 lr=0x74c3c9f7fc fault=(nil) code=1
```

退出码三方均为 `139`（`128+SIGSEGV`），与 `RUN_CRASH_TESTS.sh` 的 T4 契约一致。

### 5.6 回归：`sh test/RUN_ALL.sh --quick`

| 时刻 | 结果 |
|---|---|
| 修复**前**（基线） | **12 通过 / 0 失败** |
| 修复**后** | **12 通过 / 0 失败** |

修复后原始输出（尾部汇总）：

```
======================================================
 回归汇总
======================================================
  ✅ 编译告警门禁       ✅ 零告警（检查了 11 个编译单元）
  ✅ l2s 运行时            RESULT: PASS
  ✅ l2s×fakeroot 协同     RESULT: PASS
  ✅ fakeroot 纯逻辑       RESULT: PASS
  ✅ 系统调用参数位置 RESULT: PASS
  ✅ rename/link 双路径    RESULT: PASS
  ✅ crash 崩溃处理器    RESULT: PASS
  ✅ D4 进程管理             断言门禁：通过
  ✅ 运行时构建          ✅ D4 进程管理符号全部导出
  ✅ proot CLI 兼容         RESULT: PASS
  ✅ l2s 端到端契约      RESULT: PASS
  ✅ wait 家族钩子           ✅ waitpid/wait4/wait3/waitid 均已导出
------------------------------------------------------
  通过 12 / 失败 0
  ✅ 全部通过
```

单独复核 `test/RUN_WAIT_TESTS.sh`（任务点名关注项）：

```
- W12 ★长跑不退化★：30 轮 fork+waitpid 后账本无残留 LIVE
    ✅ 30 轮全部「wait 完即 REAPED」
    ✅ ★残留 LIVE 条目 = 1（应 ≤1，仅自身）
    ✅ REAPED 条目 ≥30（40），说明回收确实落在账本上
----------------------------------------
cases:  14  (0 failed)
checks: 52  (0 failed)
RESULT: PASS
== 符号门禁 ==
   ✅ waitpid/wait4/wait3/waitid 均已导出
```

特别说明 `crash 崩溃处理器` 与 `D4 进程管理` 两项：修复前它们就是绿的，
修复后依然绿 —— 因为 `RUN_CRASH_TESTS.sh` 是**独立编译 `crash.c`** 的
单元级测试（不加载 fakeroot 运行时），**从未覆盖**本缺陷暴露的那条路径。
这是测试覆盖的真实盲区：**缺陷在测试全绿的情况下存在**。端到端探针
（§5.4/§5.5）才是暴露它的手段。

### 5.7 汇总表

| 检查项 | 官方 | bxroot 修复前 | bxroot 修复后 |
|---|---|---|---|
| `nm -D` 导出 `getpid` | 否 | **是** ❌ | 否 ✅ |
| `$$`（主进程） | 16973 | **1** ❌ | 17087 ✅ |
| 并发子进程 `$$` 是否碰撞 | 否（2 个目录） | **是**（1 个目录）❌ | 否（2 个目录）✅ |
| `kill(getpid(), 0)` | rc=0 | **rc=-1 EPERM** ❌ | rc=0 ✅ |
| 崩溃重抛 `kill(getpid(), sig)` | 成功 | **被拒绝** ❌ | 成功 ✅ |
| 崩溃退出码 | 139 | 139 | 139 |
| `RUN_ALL.sh --quick` | — | 12/12 | 12/12 |
| 构建零告警 | — | ✅ | ✅ |

---

## 6. 对原始分析的两点修正

委派方的分析基本正确，两处以实测为准予以更正/加强：

1. **「官方其实也伪造 getpid」—— 不成立，已用两份二进制实证。**
   官方 runtime 的动态符号表里没有任何 getpid 家族符号（§1 证据 2、§5.3），
   源码注释也明说不改（§1 证据 1）。原判断成立。

2. **「如果真有依赖，那是第二个缺陷」—— 依赖不存在，但第二个缺陷确实存在，
   只是形态不同。**
   没有**代码判据**依赖 `getpid() == 1`（§3.4 第 1 点，全仓扫描为空）。
   真正存在的是两个**被这个假 pid 损害**的调用点：
   - `crash.c:372` 的 `kill(getpid(), sig)` —— 被 D4 白名单**拒绝**，
     重抛静默失败（§3.3、§5.5）；
   - `bridge.c:51` 的 socket 路径 —— 所有进程抢同一个
     `/tmp/.bxroot-bridge-1.sock`。
   `docs/P0-3-D4集成报告.md:51-52` 那句不是依赖，而是一个
   **规避型补丁的注释**，且它**说反了因果**：`kill(getpid())` 会自伤
   正是因为 getpid 被伪造（§3.4 第 3 点）。该规避补丁在真实 pid 下无害，
   故保留；只更正了失真注释。

   除此之外还有一点值得记下：**修复前 `crash.c` 的重抛是坏的，而
   `crash 崩溃处理器` 这项回归一直是绿的** —— 因为它是独立编译 `crash.c`
   的单元测试，不加载 fakeroot 运行时，从未覆盖这条路径。
   「测试全绿」在这里不构成「功能正常」的证据。

---

## 7. 改动清单

**仅两个文件**（均在允许范围内）：

1. `src/runtime/preload.c`
   - 删除 `getpid` 钩子实现（原 `:5407-5419`），原位留下说明性长注释；
   - 删除 `static pid_t (*real_getpid)(void)` 声明（原 `:178`）——
     否则触发零告警门禁的未使用变量告警；
   - 删除 `ensure_real_functions()` 里的 `real_getpid = ...` 初始化（原 `:1038`）；
   - 更正 `constructor()` 里那句已失真的注释（原 `:6006`），
     说明"自伤场景是常态"**正是本缺陷的症状**，而该登记补丁仍然保留。
   - **未触碰** `audit_*` 桩家族（另一 agent 的并行改动），已核对：修改前后
     `grep -c "audit_"` 均为 19，`audit_open`/`audit_close`/`audit_log_*`
     定义完好。

2. `docs/getpid伪造缺陷.md`（本文件，新建）

**未改动**：`src/l2s/`、`src/proc/proc.c`、`src/launcher/launcher.c`、
`test/RUN_ALL.sh`、`test/RUN_WARN_GATE.sh`、`BUILD_RUNTIME.sh`，
以及 `docs/P0-3-D4集成报告.md` 等已有文档（只引用，不修改）。
