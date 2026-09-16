# linker 接口适配分析 —— `dlsym(RTLD_NEXT)` 假设的实测否定

> 任务：验证「bxroot 下 `px_dlsym` 返回野地址 ⇒ 子进程 SIGSEGV」这一假设，并做修复。
>
> **结论先行：该假设不成立。实测 `px_dlsym` 返回的是合法高地址。**
> 真正的根因是**内核态真实 uid 差异**（官方 = 0，bxroot = 10655），
> 导致 `execve` 被内核/SELinux 判 `EACCES(13)`；官方 runtime 内部走
> `trampoline` 重新进入特权上下文 exec，bxroot 完全没有这一层。
>
> 所有结论均附可复跑命令与原始输出。**本文刻意区分「实测」与「未能定位」。**

---

## 0. 环境与复现基线

```sh
cd /root/proroot-work/agents/rename-bxroot
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
STAGE_LOAD="$ROOTFS/tmp/bxroot-e2e"
export BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" BXROOT_WORKDIR="/" \
       BXROOT_GUEST_EXE="/usr/local/bin/node" BXROOT_FAKEROOT=1
timeout 150 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 node \
  --preload "$STAGE_LOAD/libbxroot-runtime.so" "$ROOTFS/usr/local/bin/node" "$STAGE_LOAD/probe2.js"
```

**严格对照原则**：同 bridge、同 linker、同 exe，**只换 `--preload`**。
对照组 `liboff-runtime.so` = 官方 `libproroot-runtime.so` 的副本。

### 0.1 ★ 取证过程中的两处环境污染（影响结论可信度，必须记录）★

1. **SIGSEGV 基线产物已被覆盖。**
   `/tmp/bxroot-e2e/libbxroot-runtime.so` 的 mtime 从报告中的 17:43
   变成了 **18:18:13**，md5 `f924a5b2be8ed87f3ce0c664e21412f7`。
   即 **`signal=SIGSEGV` 的原始二进制已不存在**，事后重跑该文件得到的是
   `status=null`（无 SIGSEGV）。因此**「修复前 SIGSEGV → 修复后 status=0」
   这一对照在本轮无法用该文件复现**，只能用「原始 `px_dlsym` 语义 + 源码重建」
   的方式做等价对照（见 §2）。

2. **`/tmp` 是共享且被并发写的。**
   `BUILD_RUNTIME.sh` 硬编码 `LOG=/tmp/bxroot-runtime-cc.err`，多个 agent
   并发构建时会互相覆盖该日志，造成 **ICE 被误判成「非 ICE 真错误」**。
   本报告 §6 有实例。

---

## 1. 第一步：`px_dlsym` 返回值实测 —— **合法，不是野地址**

### 1.1 做法

把 `src/proc/proc.c` 的 `px_dlsym` **还原成修复前的原始实现**
（只用 `dlsym(RTLD_NEXT, …)`），在其后插入 `fprintf`：

```c
/* ===== 诊断：完全复刻修复前的原始实现（只用 dlsym(RTLD_NEXT)）===== */
p = dlsym(RTLD_NEXT, name);
fprintf(stderr, "[ORIGDIAG] %-26s dlsym(RTLD_NEXT)=%p  dlerror=%s\n",
        name, p, dlerror() ? dlerror() : "(null)");
fflush(stderr);
```

> 注意：`LOG`/`PX_LOG` 宏受 `BXROOT_VERBOSE` 运行期门控，且 `PX_LOG` 的定义
> 位于 `#if !PX_PURE_LOGIC` 钩子层内，直接用 `fprintf(stderr, …)` 最省事。

### 1.2 原始输出

```
$ ./run_cases.sh libbxroot-orig.so cspawn4 /tmp/bxroot-e2e/cspawn4
=== 变体对照 ===
[ORIGDIAG] posix_spawn                dlsym(RTLD_NEXT)=0x7c02b181c0  dlerror=(null)
posix_spawn  /bin/true + environ           rc=13  Permission denied
...
```

再换一个探针（`uidfix` 会依次解析 `fork` / `execve`）：

```
[ORIGDIAG] fork                       dlsym(RTLD_NEXT)=0x7a31103a10  dlerror=(null)
[ORIGDIAG] execve                     dlsym(RTLD_NEXT)=0x7a310ffcc0  dlerror=(null)
```

### 1.3 判据结论

| 符号 | `px_dlsym` 实测值 | 合法高地址？ |
|---|---|---|
| `posix_spawn` | `0x7c02b181c0` | ✅ 是 |
| `fork` | `0x7a31103a10` | ✅ 是 |
| `execve` | `0x7a310ffcc0` | ✅ 是 |

对照官方 runtime 下 `dlsym(RTLD_NEXT, …)` 的同名符号：

```
posix_spawn -> 0x7d6e4ae10c      execve -> 0x7d6e4a2fec      fork -> 0x7d6e4911a0
```

数值不同（不同进程 ASLR），但**同处 libc 映射区间 `0x7x…`**，
偏移量级一致（`posix_spawn` 都在 libc + 0x…181c0 附近）。

**判定：`px_dlsym` 返回的是合法高地址，不是 NULL、不是 `0xffffffff…`、
不是 0/1 小数值。核心假设不成立。**

---

## 2. 为什么「`dlsym(RTLD_NEXT)` 恒 NULL」这个观察是真的，却不是根因

### 2.1 观察本身可复现（但它是探针假象）

用**主程序**探针 `dlsymprobe`（复刻提问方的 C 探针）：

```
=== dlsym(RTLD_NEXT, ...) 解析结果 ===
  posix_spawn    -> (nil)
  posix_spawnp   -> (nil)
  execve         -> (nil)
  fork           -> (nil)
  waitpid        -> (nil)
  malloc         -> (nil)
  open           -> (nil)
  readlink       -> (nil)
```

官方 runtime 下同一探针全部非 NULL。**这一段观察属实。**

### 2.2 ★ 但「谁在调用」决定结果 ★

在 `.so` **内部**（`bxroot_real_symbol` 里）打印同一个 `dlsym(RTLD_NEXT, …)`：

```
[RSDIAG] bxroot_real_symbol(open                  ) RTLD_NEXT=0x70d84c6680
[RSDIAG] bxroot_real_symbol(openat                ) RTLD_NEXT=0x70d84c6860
[RSDIAG] bxroot_real_symbol(stat                  ) RTLD_NEXT=0x70d84c7400
[RSDIAG] bxroot_real_symbol(newfstatat            ) RTLD_NEXT=(nil)
```

**在 .so 内部是非 NULL 的。**

**结论**：`dlsym(RTLD_NEXT, …)` 在**主程序**里恒 nil，在**我们自己的 .so 内部**
正常。原因是搜索起点（caller 的 link_map）不同 —— 主程序后面没有 libc，
而我们 .so 后面有。所以「恒 NULL」是**探针位置造成的假象**，
不能推广成「bxroot 下 `dlsym` 不可用」。

### 2.3 顺带否定另一个担心：`dlopen` 回退**不会**自递归

`preload.c` 导出了自己的 `dlopen`（`nm -D` 可见 `T dlopen`），
而 `bxroot_real_symbol` 的回退会调 `dlopen("libc.so.6", RTLD_LAZY)`。
静态推理会得出「我们自己的 `dlopen` 调用解析回自己 → 无限递归」。

**实测否定**（加了嵌套深度计数）：

```
[DLDIAG] 进入我们的 dlopen("libc.so.6") 嵌套深度=0 fn=(nil)
[RSDIAG] bxroot_real_symbol(dlopen                ) RTLD_NEXT=0x70d8467490
[DLDIAG] 退出 dlopen -> 0x70d8f40f30
```

嵌套深度始终为 0，一次进入一次退出，**`dlopen` 句柄正常返回**。
→ `dlopen` 回退路径是安全的，可以保留。

---

## 3. 真正的根因：内核态 uid 差异（实测）

### 3.1 最小判别探针

```c
printf("libc: uid=%d | 内核: uid=%d\n", (int)getuid(), (int)syscall(SYS_getuid));
```

> 关键：`getuid()` 会被 bxroot 的 fakeroot 层伪装成 0，
> **必须用裸 `syscall(SYS_getuid)` 读内核真值**。

### 3.2 原始输出（只换 `--preload`）

```
$ ./run_cases.sh liboff-runtime.so uidcheck /tmp/bxroot-e2e/uidcheck
libc:  uid=0 euid=0 gid=0 egid=0
内核:  uid=0 euid=0 gid=0 egid=0

$ ./run_cases.sh libbxroot-snap.so uidcheck /tmp/bxroot-e2e/uidcheck
libc:  uid=0 euid=0 gid=0 egid=0
内核:  uid=10655 euid=10655 gid=10655 egid=10655

$ ./uidcheck          # 容器内无 runtime
libc:  uid=0 euid=0 gid=0 egid=0
内核:  uid=0 euid=0 gid=0 egid=0
```

**同一个 bridge、同一个 linker、同一个 exe，只换 `--preload`，
内核里的真实 uid 从 0 变成 10655（app uid）。**

### 3.3 用「只有 uid 0 能 exec 的文件」做终局判定

```sh
cp $ROOTFS/bin/true /root/rename-bxroot/execonly/rootonly-exec
chown 0:0 execonly/rootonly-exec && chmod 0700 execonly/rootonly-exec
```

```
--- 官方 ---
  exec(0700 root 文件) -> ✅ 成功(root)   [libc uid=0 syscall uid=0]
--- bxroot ---
  子: errno=13 (Permission denied)
  exec(0700 root 文件) -> ❌ 被拒(非root)   [libc uid=0 syscall uid=10655]
--- 容器内无 runtime ---
  exec(0700 root 文件) -> ✅ 成功(root)   [libc uid=0 syscall uid=0]
```

**铁证：bxroot 是真的没有 root 权限。**

### 3.4 旁证：bxroot 无法自救

```
裸 syscall setresuid(0,0,0) -> -1 errno=1 (Operation not permitted)
裸 syscall setresgid(0,0,0) -> -1 errno=38 (Function not implemented)
```

### 3.5 这解释了全部现象

| 现象 | 旧假设（野指针）能否解释 | uid 差异能否解释 |
|---|---|---|
| `posix_spawn` 恒 **EACCES(13)** | ❌ 说不通（那是 POSIX 错误码，野指针会是 SIGSEGV 或无返回） | ✅ EACCES 正是权限不足 |
| `spawnSync -> signal=null status=null error=EACCES errno=-13` | ❌ | ✅ |
| `open()`/`stat()`/`access(X_OK)` 全 OK，**只有 execve 失败** | ❌ | ✅ open 走钩子/rootfs 内文件，execve 要内核查权限 |
| 父进程一切正常 | ✅ | ✅ |
| 子进程 SIGSEGV（**未能复现**，见 §0.1） | 声称能解释 | 未复现，不下结论 |

**关键逻辑**：`ENOSYS(38)` 才是「`real_posix_spawn == NULL`」的特征码。
实测拿到的是 `EACCES(13)`，说明 **`real_posix_spawn` 非空、且被真正调用了**
—— 这与 §1 的地址实测完全自洽。

---

## 4. 官方 runtime 是怎么做到的：trampoline（bxroot 缺这一层）

### 4.1 exec 机制矩阵

```
--- 官方 ---
身份: libc uid=0 euid=0 gid=0 | 裸syscall uid=0 gid=0
  0 裸syscall execve(host)                -> ❌ 失败
  1 libc execve(host)                      -> ✅ OK
  2 裸 execveat(fd,AT_EMPTY_PATH)         -> ❌ 失败
  3 裸 execve(/proc/self/fd/N)            -> ❌ 失败
  4 libc fexecve(fd)                       -> ❌ 失败
```

**官方 runtime 下，裸 `syscall(SYS_execve, 宿主路径)` 同样 EACCES**，
但 **libc `execve()` 却 OK**。且官方进程的内核 uid 明明是 0。

→ 说明官方 libc `execve` **不是**直接转发给内核 `execve`，
而是走了另一条机制。

### 4.2 符号级证据

```
$ nm /root/proroot-work/backup/libproroot-runtime.so | grep -i trampoline
000000000001d328 t build_trampoline_exec_argv
0000000000007fdc t execve_trampoline
000000000001db10 t get_child_trampoline_env
000000000000743c t setresuid_trampoline
...（约 40 个 *_trampoline）

$ strings -a libproroot-runtime.so | grep -i trampoline
PROROOT_TRAMPOLINE_PATH
PROROOT_TRAMPOLINE_ARGV_OFFSET
execve trampoline:
trampoline exec failed
```

结合官方 runtime 对 `execve`（`0x1afec`）的反汇编，可看到它构造
`snprintf` 参数串后**经 trampoline 重新进入特权上下文**再 exec。

### 4.3 环境对照：两边都有 `PROROOT_TRAMPOLINE_PATH`

```
--- 官方 ---   PROROOT_TRAMPOLINE_PATH=.../libproroot-bridge.so
--- bxroot ---  PROROOT_TRAMPOLINE_PATH=.../libproroot-bridge.so   ← 同样存在
```

两边环境变量**一摸一样**（连 `PROROOT_CFG_FD`、`PROROOT_ESCAPE_FD=3` 都相同），
**唯一区别是 runtime 是否使用它**。

### 4.4 bxroot 侧现状

```sh
$ grep -rn "PROROOT_TRAMPOLINE" src/
# 无任何命中
```

bxroot 全仓库**没有任何 trampoline 处理**（`px_xlate_trampoline` 是
proc.c 里一个**同名但无关**的路径翻译回调）。

### 4.5 已排除的机制（负结果，避免后人重复踩）

- **不是 seccomp 差异**：`/proc/self/status` 里 `Seccomp: 2`、`NoNewPrivs: 0`、
  `CapEff: 0`、`Uid: 10655` 在官方/bxroot/无 runtime 三种情况下**完全相同**。
  `PROROOT_NO_SECCOMP=1` 对结果无影响。
- **不是单纯的 setuid 丢失**：手动 `setresuid(0,0,0)` 被 EPERM 拒绝，
  **bxroot 进程无法通过调用 API 自救**，必须以特权身份被启动。
- **`PROROOT_TRAMPOLINE_PATH` 指向不存在的路径时官方仍能 spawn**：
  说明该环境变量的存在性本身不是充要条件（可能官方通过 `PROROOT_ESCAPE_FD`
  持有 `PROROOT_CFG_FD` 里的配置，或该探针路径未触发 trampoline 分支）。
  **具体触发条件未能定位。**

---

## 5. 修复建议（未实施验证，仅基于实测证据的方向）

> **本轮只做到根因定位，未做代码修复。** 原因见 §6。

1. **主体**：让子进程通过 `PROROOT_TRAMPOLINE_PATH`（= bridge.so）
   重新进入特权上下文 exec —— 即适配官方 linker 的 `execve_trampoline` /
   `build_trampoline_exec_argv` 协议。这是**唯一**与实测一致的修复方向。
2. **不要**把精力放在 `dlsym` 回退上：实测 `px_dlsym` 本来就能拿到正确地址，
   换回退不改变 EACCES。
3. 若短期要可用：确认 DSHA 是否能以特权（root/Shizuku）身份启动 bxroot runtime，
   使内核 uid 真正为 0。

---

## 6. 回归与门禁

### 6.1 告警门禁 ✅

```
$ sh test/RUN_WARN_GATE.sh
✅ src/runtime/preload.c              0 条
✅ src/runtime/proc/proc.c            0 条
（共 11 个编译单元）
✅ 零告警（检查了 11 个编译单元）
```

### 6.2 `sh test/RUN_ALL.sh` —— 9 通过 / 1 失败

```
  ✅ 编译告警门禁       ✅ 零告警（检查了 11 个编译单元）
  ✅ l2s 运行时            RESULT: PASS
  ✅ l2s×fakeroot 协同     RESULT: PASS
  ✅ fakeroot 纯逻辑       RESULT: PASS
  ✅ 系统调用参数位置 RESULT: PASS
  ✅ rename/link 双路径    RESULT: PASS
  ✅ crash 崩溃处理器    RESULT: PASS
  ✅ D4 进程管理             断言门禁：通过
  ❌ 运行时构建          rc=1 --- 编译器输出 ---
  ✅ wait 家族钩子           ✅ waitpid/wait4/wait3/waitid 均已导出
------------------------------------------------------
  通过 9 / 失败 1
```

**唯一的失败是「运行时构建」，且不是本次改动引起的**，有两个独立原因：

1. **gcc ICE 率已超出重试上限。** `BUILD_RUNTIME.sh` 每级优化最多重试 10 次；
   实测 `proc.c`（`px_merge_preload` @1214）**连续 10 次全部 ICE**，
   第 11 次才成功：
   ```
   ❌ -O2 编译失败（非 ICE，是真错误）
   --- 编译器输出 ---      ← 空的！
   ```
   我手动执行同一条 gcc 命令，拿到真实原因：
   ```
   during RTL pass: reload
   src/proc/proc.c: In function 'px_merge_preload':
   src/proc/proc.c:1214:1: internal compiler error: Segmentation fault
   ```
2. **并发写共享日志导致误判。** `BUILD_RUNTIME.sh` 的
   `LOG=/tmp/bxroot-runtime-cc.err` 是硬编码共享路径。多 agent 同时构建时
   日志被覆盖，`grep -q 'internal compiler error' "$LOG"` 读到空文件，
   于是把 ICE **误判为「非 ICE 真错误」并直接放弃重试**。

**建议**（小改动、独立价值）：
- `BUILD_RUNTIME.sh` 把 `LOG` 改为 `mktemp` 或带 `$$` 的唯一路径；
- 把每级重试次数从 10 提到 ≥30（本容器 ICE 率已明显劣化）。

### 6.3 交付探针状态（当前源码，实测）

| 探针 | 官方 | bxroot（当前源码） |
|---|---|---|
| `uidcheck` | 内核 uid=0 | 内核 uid=10655 |
| `exec400`（0700 root 文件） | ✅ 成功 | ❌ EACCES |
| `cspawn4` 四变体 | rc=0 ×4 | rc=13 ×4 |
| `probe2.js` spawnSync | status=0 | status=null / error=EACCES |

---

## 7. 明确「未定位」的部分

诚实划界，避免后人被本文误导：

- ❌ **未能复现 `signal=SIGSEGV`**：基线产物已被覆盖（§0.1）。
  SIGSEGV 是否与 execve EACCES 同源，**本文没有证据**，不下结论。
- ❌ **未能确定 trampoline 的精确触发条件**：`PROROOT_TRAMPOLINE_PATH`
  被指向不存在的路径时官方仍能 spawn（见 §4.5），说明还有别的控制位
  （疑与 `PROROOT_ESCAPE_FD=3` / `PROROOT_CFG_FD` 有关）。**需要进一步逆向。**
- ❌ **未能定位「官方 runtime 为何内核 uid=0 而 bxroot 不是」的上游机制**：
  两者由**同一个 bridge** 启动，差异必然在 runtime 初始化阶段。已知
  bxroot 侧 grep 不到任何 `setresuid(0,0,0)` 之类的提权调用，
  但官方侧对应实现（`setresuid_trampoline` 的调用方）**未深入逆向**。
- ⚠️ **`open()` 行为仍有未解释的差异**：官方 `open(/bin/true)` 返回 fd=6
  且 errno=22（残留值），bxroot 返回 fd=11 且 errno=0。不影响主结论，但未深究。

---

## 附录 A：原始复现脚本

`/root/rename-bxroot/evidence/run_cases.sh`：

```sh
#!/bin/sh
# 统一复现脚本：同一 bridge/linker/exe，只换 --preload
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
STAGE_LOAD="$ROOTFS/tmp/bxroot-e2e"
RT="$1"; EXE="$2"; GUEST="$3"; shift 3
BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" BXROOT_WORKDIR="/" \
BXROOT_GUEST_EXE="$GUEST" BXROOT_FAKEROOT=1 "$@" \
timeout 120 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 "$(basename "$GUEST")" \
  --preload "$STAGE_LOAD/$RT" "$STAGE_LOAD/$EXE"
```

原始输出全文：`/root/rename-bxroot/evidence/RAW.txt`

## 附录 B：本轮用到的探针源码（均在 `/root/rename-bxroot/`）

| 探针 | 用途 |
|---|---|
| `uidcheck.c` | 打印 libc vs 内核 uid（本报告的核心判别器） |
| `exec400.c` | exec 一个 0700 root 文件，判定真实特权 |
| `cspawn2.c` / `cspawn4.c` | 复刻提问方的 spawn 变体探针 |
| `dlsymprobe`（提问方） | 主程序视角的 `dlsym` |
| `rawspawn.c` | 同一进程内「钩子路径」vs「裸 libc 路径」对照 |
| `why.c` | exec 机制矩阵（execve / execveat / /proc/self/fd / fexecve） |
| `xlate.c` / `envprobe.c` / `statusprobe.c` | 路径翻译、环境、内核状态对照 |

**注**：`orig/`、`diag/`、`rdiag/` 三个目录是插桩用的源码副本，
构建产物在 `/root/rename-bxroot/out/`，**均未进入仓库 `src/`**。

---

*报告时间：2026-09-16 18:5x UTC*
*所有命令均在真机容器内实跑，输出为原样粘贴（仅去掉 ASLR 随机高位带来的无关差异说明）。*
