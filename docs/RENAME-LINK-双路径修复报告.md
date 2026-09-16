# renameat / renameat2 / linkat 第二路径参数翻译 —— 修复报告

工作副本：`/root/proroot-work/agents/rename-bxroot`（未触碰 `/tmp/bxroot-git`）
报告日期：本轮会话

---

## 一、任务是什么

`renameat` / `renameat2` / `linkat` 的**第二个路径参数**（newpath / newlinkpath，
位于 a3）此前没有做路径翻译。跨目录重命名、建硬链接时，目标路径落到宿主真实
命名空间而非 guest 命名空间。

---

## 二、实测出了什么（这一节是本次修复的核心）

硬约束要求"每个断言都要实测验证"。我按这个要求做了逐参数取证，
结果**推翻了两处既有代码里的结论**，其中一处是静默数据损坏级缺陷。

### 2.1 参数位置：全部实测确认

用返回值 / errno / 真实文件系统效果取证，**不靠记忆**：

| 编号 | 调用 | 实测方法 | 结果 |
|---|---|---|---|
| 276 | `renameat2` | `(AT_FDCWD,src,AT_FDCWD,dst,0)` | r=0，dst 出现且内容=src 原内容、src 消失 → **a3 是被写入的目标名** |
| 276 | 同上 | a2 = 伪 dirfd `999999` | `EBADF(9)`（若 a2 是路径指针应为 `EFAULT(14)`）→ **a2 是 dirfd** |
| 276 | 同上 | a2 = 真目录 fd，a3 = `"c_in_sub"` | r=0，文件落在**该目录内** → **a3 相对 a2 解析** |
| 276 | 同上 | a0 = 真目录 fd，a1 = `"d_src"` | r=0 → **a1 相对 a0 解析** |
| 276 | 同上 | a4 = `RENAME_NOREPLACE(1)` 且目标已存在 | `EEXIST(17)`；改 0 则成功 → **a4 是 flags** |
| 38 | `renameat` | 同 ①②③ | 结论一致 |
| 37 | `linkat` | `(AT_FDCWD,A,AT_FDCWD,B,0)` | r=0，**A 与 B 的 st_ino 相同、st_nlink 都是 2** → 真硬链接，**a3 是第二个路径** |
| 37 | 同上 | a2 = 伪 dirfd | 不给 `EFAULT` → **a2 是 dirfd** |
| 36 | `symlinkat` | `("tgt", 999999, "rel-l")` | `EBADF` → **a1 是 dirfd**（复跑确认历史结论） |
| 36 | 同上 | `("tgt", <文件fd>, "rel-l")` | `ENOTDIR` → a1 被当目录 fd |
| 36 | 同上 | `("tgt", AT_FDCWD, NULL)` | `EFAULT` |
| 全族 | NULL 路径 | 各调用 a1=NULL / a3=NULL | 统一 `EFAULT` |

**a0 / a2 确认是 dirfd，绝不能当路径解引用。** 传 `AT_FDCWD` 时走相对路径逻辑。

### 2.2 ★ 发现一：表里的 `case 260` 是错的 —— 260 的真身是 `wait4`

`syscall_guard.c` 原表把 **260 当作 linkat** 并翻译其 a1。实测行为判决：

```
fork 一个 _exit(42) 的子进程，然后
syscall(260, pid, &wstatus, 0, NULL)
  → 返回 pid，wstatus 被内核写入，WIFEXITED=1、WEXITSTATUS=42
```

只有 `wait4` 会写 wstatus，**所以 260 是 wait4**（asm-generic 编号）。
本机 `SYS_linkat == 37`。原注释里那句"260 linkat → EPERM（存在）"是把
"随便发一个号得到 EPERM"当成了存在性证据 —— 那个推论无效。

**后果不是"少翻译一条"，而是主动制造静默数据错写**，机制值得记录：

- `wait4` 的 a1 是 `int *wstatus`。
- guard 的 `looks_like_guest_abs_path()` 只看**首字节**是不是 `/`。
- 而 `wait4` 是在**发起调用之前**检查 a1 的 —— 所以危险条件是
  **调用前**缓冲区首字节已是 `/`（调用方复用/未初始化栈变量时很常见）。
- 实测复现：把 wstatus 预置为 `0x0000002f`（首字节 `'/'`）后调用，
  未修版本中内核把退出状态**写进了 guard 的临时缓冲**，
  调用方那个 wstatus 永远保持 `0x2f` 不被写入 → `WTERMSIG` 读到 47 而非实际信号。

这正是"猜参数位置比不翻译更危险"的第二种后果：非路径参数被当路径，
不只是崩溃一条路，还可能是**静默的数据错写**。

### 2.3 ★ 发现二：`SYS_linkat` 是 37，而 guard 完全没列这个号

原表列的是 260（错的），**真正的 37 从未被列入**。也就是说：
走裸 `syscall()` 的 `linkat` 形态此前**完全没有路径翻译** ——
不只是 newpath 漏翻，oldpath 也没翻。本次一并覆盖。

### 2.4 侧记：环境取证时踩到的两个坑（都已固化进测试）

1. **本容器存在外层 proroot 的用户态路径翻译**，它工作在 glibc 符号层；
   而 guard 的转发是**裸 svc**（这是它存在的理由 —— 避免递归回 libc 的
   `syscall()`）。两者可能落在**不同的命名空间视图**里。实测：
   `glibc mkdir("/tmp/x")` 成功，而裸 svc `newfstatat("/tmp/x")` 报 ENOENT。
   因此测试内部**不能混用**两种调用方式，否则夹具与断言不自洽
   （我第一版就踩了这个，全红且看起来像代码缺陷）。
2. **符号链接必须用 `AT_SYMLINK_NOFOLLOW` 判断存在性**。
   `symlinkat` 建出 `l -> "TGT"`（TGT 不存在）后：
   `fstatat(l)` → ENOENT（看着像没建成），
   `fstatat(l, NOFOLLOW)` → 0，`readlinkat(l)` → "TGT"。

---

## 三、改了什么

### 3.1 `src/runtime/syscall_guard.c`（主要改动）

**接口升级：`path_arg_index()` → `path_arg_mask()`，返回路径参数位掩码。**

旧接口返回 `int`（只能表达 a0 或 a1），这带来两个后果，本次一并解决：

1. `renameat`/`renameat2`/`linkat` 有**两个**路径参数（a1、a3），旧接口只
   表达得了一个 → newpath 长久漏翻（本次任务要修的缺口）。
2. `symlinkat` 的 linkpath 在 **a2**，旧接口完全表达不了 → 当初只能选择
   "整条不列入"（也就是"创建符号链接"在裸 syscall 形态下一直没翻译，
   而 l2s 层大量依赖它）。

新的表（每一行都有实测依据，见 §2）：

```c
case 291:  return 1u << 1;                  /* statx      */
case 79:   return 1u << 1;                  /* newfstatat */
case 78:   return 1u << 1;                  /* readlinkat */
case 48:   return 1u << 1;                  /* faccessat  */
case 56:   return 1u << 1;                  /* openat     */
case 35:   return 1u << 1;                  /* unlinkat   */
case 34:   return 1u << 1;                  /* mkdirat    */
case 221:  return 1u << 0;                  /* execve     */
case 439:  return 1u << 1;                  /* faccessat2 */
case 281:  return 1u << 1;                  /* execveat   */
case 276:  return (1u << 1) | (1u << 3);    /* renameat2: oldpath + newpath  ★新增 a3 */
case 38:   return (1u << 1) | (1u << 3);    /* renameat:  oldpath + newpath  ★新增 a3 */
case 37:   return (1u << 1) | (1u << 3);    /* linkat: oldpath + newlinkpath ★新增整条 */
case 36:   return 1u << 2;                  /* symlinkat: 只翻 linkpath(a2)  ★从"不列入"改为列入 */
default:   return 0;
```

- **`case 260` 已删除**（它是 wait4，见 §2.2）。
- `symlinkat` 的 **a0（target）刻意不翻**：它是**链接内容**不是待解析路径，
  翻了客户 `readlink` 就会看到宿主路径、泄漏翻译层内部布局。
  这与 `preload.c` 的 symlinkat 钩子**逐字同语义**。
- `a0`/`a2`（dirfd）**绝不出现在掩码里**。

**翻译分支改为按掩码循环**，按下标回写：

```c
pmask = path_arg_mask(number);
if (pmask != 0) {
    for (i = 0; i < 6; i++) {
        if (!(pmask & (1u << i))) continue;
        pth = (const char *)(uintptr_t)*args[i];
        if (*args[i] == 0) { errno = EFAULT; return -1; }   /* NULL 安全 */
        if (looks_like_guest_abs_path(pth)) { ...翻译... *args[i] = ...; }
    }
}
```

**NULL 安全（硬约束 3）**：所有路径参数显式判空 → `errno = EFAULT`、返回 -1。
虽然下面的 `looks_like_guest_abs_path()` 对 NULL 恰好返回 0（也会透传给内核、
内核同样给 EFAULT），但仍显式判一次，理由写在代码注释里：不要把正确性寄托在
"被调用函数恰好返回 0"这个隐式契约上；而且对**双路径**调用，若 a1 为 NULL
而 a3 是有效 guest 路径，透传会让 a3 不被翻译、客户拿到 ENOENT 而非 EFAULT，
**errno 就与原生不一致**。提前返回复刻了内核"先解 oldpath、遇 NULL 立即
EFAULT"的顺序（已实测）。

**未删除任何现有功能**（硬约束 4）：io_uring 拦截、诊断输出、缓冲池轮转
与原子取号、重入守卫等全部原样保留；只把路径表与翻译分支的表达能力扩展了。

### 3.2 `src/runtime/preload.c` —— **未改动**

已逐条核对，四个钩子**本来就正确处理了两个路径**：

- `linkat`：`translate_path(oldpath)` + `translate_path(newpath)` ✅
- `renameat`：两个都翻 ✅
- `renameat2`：两个都翻 ✅
- `symlinkat`：只翻 `linkpath`、`target` 原样 ✅（与新 guard 语义一致）

按"改动要最小化"的要求，**一行都没动**。

### 3.3 `test/RUN_ALL.sh` —— 新增第 5b 步

把新测试接入回归（不改动其他步骤）。

---

## 四、怎么验证的

### 4.1 新增测试 `test/test_rename_link_argpos.c`（54 用例，全绿）

**真能区分"翻译了"与"没翻译"** —— 这是本测试的设计重点：

- **自带一个翻译桩**，并与 `syscall_guard.c` **一起编译**，于是在**同一个
  进程内**观察并驱动 guard 的翻译层。
- **指针身份断言**（最硬的证据）：桩记录每次收到的指针，据此断言被当路径
  解引用的寄存器**恰好**是 a1 与 a3（renameat 族）、**恰好**是 a2
  （symlinkat），且**永不含 AT_FDCWD**。翻错了能直接指出是哪个寄存器。
- **效果断言**：`syscall(276, AT_FDCWD, "/g/src", AT_FDCWD, "/g/dst", 0)`
  只有在 a1 与 a3 **都被翻译**时才成功、文件才真的落到 `<base>/dst`；
  a3 漏翻则内核收到 `new="/g/dst"`、调用失败、文件原地不动。
- **反向对照**（证明用例不是恒真）：关掉翻译桩后同一调用**必须失败**、
  文件必须留在原处；重新打开后立即成功。
- **dirfd 防护**：桩对 `< 4096` 的"指针"（含 NULL 与 AT_FDCWD=-100）
  **拒绝解引用**，只置错误标志。这样一旦退回"把 dirfd 当路径"的老 bug，
  测试报出可读的 FAIL，而不是以 SIGSEGV 静默收场。
- **NULL 安全**：7 个用例覆盖 a1/a3/a2=NULL → EFAULT，并断言 NULL 未被
  送进翻译层（不会解引用）。
- **260 判别用例**：见下。

#### ★ 判别力矩阵（防止"假绿"）

写完测试后我把源码**故意改回旧行为**，验证测试确实会红：

| 被测版本 | 结果 |
|---|---|
| ① 已修版（当前源码） | **54 用例 0 失败 / PASS** |
| ② 未修 a3（只翻 oldpath） | **10 失败 / FAIL** ✅ 抓得住 |
| ③ 未修 260（把 wait4 当 linkat） | **2 失败 / FAIL** ✅ 抓得住 |
| ④ 两者都错 | **10 失败 / FAIL** ✅ |

这一步抓出了我自己的一个**假安全**缺陷：第一版 260 用例
（子进程被信号 47 杀、status 初值 0）**测不出 260 的 bug** ——
因为 guard 在调用**前**读首字节，那时 status=0 不是 `/`。
实测"未修 260"的版本照样全绿。我据此加了**判别性用例**：
先把 wstatus 置为 `0x0000002f`（首字节 `/`），再用必然成功的 wait，
断言 wstatus 仍被正确写入。加上之后，未修版本立刻变红（矩阵第 ③ 行）。

同一轮还发现翻译桩第一版写成"只认 `/g/` 前缀，其余返回 0"，
而这**掩盖了 260 事故** —— 真实 `translate_path` 会把任何以 `/` 开头的
字符串当绝对路径翻译。桩必须**与被替代的东西同语义**，
否则测试给出虚假的安全感。已改为忠实实现。

### 4.2 全量回归

```
sh test/RUN_ALL.sh --quick
→ 通过 10 / 失败 0  ✅ 全部通过
   编译告警门禁 / l2s 运行时 / l2s×fakeroot / fakeroot 纯逻辑
   系统调用参数位置 / rename/link 双路径 / crash / D4 / 运行时构建 / wait 家族
```

（任务描述说 --quick 会有 8 项。实际现在有 10 项：其中一项是我新增的
第 5b 步，另一项是期间别的代理也往 RUN_ALL 里加了内容。
**跳过的是"运行时构建"之外的构建步骤，符合 --quick 语义。**）

### 4.3 构建

```
sh BUILD_RUNTIME.sh
→ ✅ 链接成功（-O2，第 1 次尝试）
   产物 build/libbxroot-runtime.so，227304 字节，337 个导出符号
   ✅ D4 进程管理符号全部导出
```

### 4.4 零告警（硬约束 5）

```
sh test/RUN_WARN_GATE.sh
→ ✅ 零告警（检查了 11 个编译单元）
   syscall_guard.c 0 条
```

新测试文件本身也在 `-Wall -Wextra` 下 **0 告警**。

### 4.5 环境适配（重要，供后续维护者参考）

测试**不假设** `/tmp` 可用。它先探测一个"裸 svc 可写、且自洽、
且支持符号链接"的 base 目录（候选：`$BXARG_BASE` → `$TMPDIR` → `/tmp`
→ 容器 tmp → `/data/local/tmp` → `/sdcard/Download` → cwd），
之后**所有**夹具创建与结果核对都走裸 svc，调用方式自洽。

实测本机的目录能力差异（这解释了为什么必须探测）：

| 目录 | 裸 svc 写 | 硬链接 | 符号链接 |
|---|---|---|---|
| `/tmp` `/root` `/data/local/tmp` | ✗（外层只允许经它自己的翻译层写） | — | — |
| `/sdcard/Download`（FUSE） | ✓ | ✗ EACCES | ✗ EACCES |
| `<app 私有>/files/linux/tmp` | ✓ | ✗ EACCES | ✓ |

**硬链接在本机所有目录都不可用**（Android SELinux 禁止 `link(2)`）——
这正是 l2s 层存在的理由。因此 `linkat` 的"效果类"断言（同 inode / nlink=2）
在不可用时**降级为跳过**，而**参数位置类**断言仍然硬验
（用"伪 dirfd 不给 EFAULT"这一判据，不依赖文件系统是否允许建链）。
这样测试在普通 CI 的 `/tmp` 与真机受限环境里都能给出可信结论，
不会把环境能力差异误报成代码缺陷。

### 4.6 环境干扰说明

期间环境的 `/tmp` 曾一度被并发操作改成 `000`（我已恢复为 `1777`），
并且外层 proroot 的拦截行为在会话中途发生变化，导致我最初几轮探针
结论不稳定。这是**环境问题不是代码问题** —— 我用"重跑此前已通过的探针"
（探针1 始终稳定给出同一组正确结论）确认了这一点，
并据此把测试改成不依赖环境稳定性（§4.5）。

---

## 五、还有什么没解决

1. **未做真机端到端验证。** 任务说明已指出外层 proot 会吞掉 `LD_PRELOAD`
   注入，可信手段是逻辑单元测试 / 编译检查 / 反汇编 / 真实 fs 操作 /
   显式 `ld.so --preload`。我做的是前四类。**`ld.so --preload` 形式的
   端到端验证我没做** —— 建议在有 pristine 环境时补一次，
   用真实的 `/g/...` guest 路径跑一遍 rename/link。

2. **`openat2`(437) 仍未覆盖**（原注释称本内核 ENOSYS）。本轮未复核，
   属既有状态，未改动。

3. **`linkat` 的 `AT_EMPTY_PATH` 语义未特殊处理。** `linkat(fd, "", ...,
   AT_EMPTY_PATH)` 是合法用法（空路径 + fd 指代文件）。当前实现里空串
   首字节不是 `/`，会被透传、不翻译 —— 行为正确（空路径本就不该翻译），
   但没有专门测试锁定。已实测本机该用法返回 EINVAL，无法构造有效用例。

4. **`renameat2` 的 `RENAME_EXCHANGE`(2) / `RENAME_WHITEOUT`(4) 未单独测试。**
   它们的路径语义与 flags=0 相同（同样两个路径），翻译逻辑一致，
   但未逐 flag 验证。

5. **并发代理造成的冲突风险。** `test/RUN_ALL.sh` 与 `src/proc/proc.c`
   在我工作期间被**其他代理**修改过（`proc.c` 一度出现 `PX_LOG` 未声明
   告警，使回归两次报红，几分钟后自行恢复）。我的改动只落在
   `src/runtime/syscall_guard.c`、`test/test_rename_link_argpos.c`、
   `test/RUN_ALL.sh`（仅新增第 5b 步）三个文件上，与它们无重叠，
   但**合入前建议再跑一次全量回归确认无相互覆盖**。
   `preload.c` 我**一字未动**（符合"最小化改动"要求，
   且它本来就正确处理了两个路径）。

---

## 六、交付物

| 文件 | 说明 |
|---|---|
| `src/runtime/syscall_guard.c` | 路径参数位掩码 + 双路径翻译 + NULL 安全 + 修正 260→wait4 + linkat(37) 入表 + symlinkat 只翻 a2 |
| `test/test_rename_link_argpos.c` | 新增，54 用例，含忠实翻译桩、指针身份断言、反向对照、260 判别用例、能力自适应 |
| `test/RUN_ALL.sh` | 新增第 5b 步接入回归（其余未动） |

所有注释、文档、提交说明均为中文。
