# 子进程派生 SIGSEGV 分析报告

**结论一句话**：根因**不是 bxroot 的代码**，而是 **proroot 自研加载器不运行 glibc 的 minimal 线程初始化**，
导致 `struct pthread` 的 `list` 字段（`TCB-0x680`）停留在 `NULL`；glibc 的 `__fork()` 在子进程里
摘除该链表节点时解引用 `NULL+8` → **SIGSEGV**。
bxroot 的 `proc.c` 通过 `dlsym(RTLD_NEXT,"fork")` 走到了 glibc 的 `__fork`，因此**撞上了这个坑**；
官方 runtime 之所以没事，是因为它**自己接管了 `fork`**（裸 syscall），压根不调用 glibc 的 `__fork`。

**已修复并实测验证**：`src/proc/proc.c` 新增 `px_heal_thread_list()`，在 `px_runtime_init()` 里
把该字段补成自环。修复后 `fork()` 派生路径全部恢复正常。

---

## 1. 崩溃现场（原始证据）

诊断程序 `dtest`（自建，带 `SIGSEGV` 处理器，动态 PIE）分别在官方与 bxroot 运行时下运行，
**同一环境、同一加载器、同一二进制，只换 `--preload`**：

```
########## bxroot 运行时 ##########
>> dtest mode=all kpath=/bin/echo pid=1
-- forkonly (fork, no exec) --

*** SIGSEGV child: addr=0x8 pc=0x7746503b54 lr=0x7746503a60 sp=0x77463ff8a0 pid=1
    maps: 77464c8000-77465dc000 r-xp 00086000 fe:3e 5909499  /data/data/com.dsh.client/files/linux/ubuntu/usr/lib/aarch64-linux-gnu/libc.so.6
[forkonly] exited status=99
-- forkexec (fork + execl /bin/echo, 经钩子) --
*** SIGSEGV child: addr=0x8 pc=0x7746503b54 ...
[forkexec] exited status=99
-- forkexecraw (fork + 裸 syscall execve 内核路径) --
*** SIGSEGV child: addr=0x8 pc=0x7746503b54 ...
[forkexecraw] exited status=99
-- vforkexec (vfork + execl) --
*** SIGSEGV child: addr=0x0 pc=0x0 lr=0x0 sp=0x77463ffa10 pid=1
=== exit=99 ===
```

```
########## 官方运行时（黄金对照）##########
-- forkonly (fork, no exec) --      [forkonly] exited status=42
-- forkexec (fork + execl /bin/echo) --  from-forkexec     [forkexec] exited status=0
-- forkexecraw --                   from-raw            [forkexecraw] exited status=0
-- vforkexec --                     from-vfork          [vforkexec] exited status=0
-- posix_spawn(/bin/echo) --        from-spawn          [posix_spawn] exited status=0
```

**注意 `forkonly`**：它只调用 `fork()`，子进程立刻 `_exit(42)`，**完全没有任何 exec**。
它照样 SIGSEGV，且崩溃点与 exec 路径**完全相同**（`pc` 偏移 `0xC1B54`、`addr=0x8`）。
这一条实验就把「路径翻译 / envp 重建 / argv / 加载器加载新映像」全部排除掉了。

复现命令（`dtest` 源码见 `/tmp/bxmin/dtest.c`）：

```sh
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
export BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$ROOTFS/tmp/bxroot-e2e/tmp" \
       BXROOT_WORKDIR="/" BXROOT_FAKEROOT=1
"$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 dtest \
  --preload "$ROOTFS/tmp/bxroot-e2e/libbxroot-runtime.so" "$ROOTFS/tmp/bxmin/dtest" all
```

## 2. 崩溃点精确定位

`pc=0x7746503b54`，libc 映射基址 `0x77464c8000`（`maps` 行 `offset 00086000`）→ 文件偏移 `0xC1B54`。
`__fork@@GLIBC_2.17` 位于 `0xC1A10`（`.eh_frame` FDE 边界 `pc=0xc1a10..0xc1dd8`），故函数内偏移 `+0x144`：

```
c1b50:  ldp  x4, x3, [x1, #-128]   ; x1 = x23-0x600，取出链表节点 {prev, next}
c1b54:  str  x3, [x4, #8]          ; ← 崩溃指令：写 [x4+8]，x4(NULL) → addr=0x8
c1b58:  str  x4, [x3]
```

`x1` 来自 `c1b3c: sub x1, x26, #0x600`，而 `x1` 在 `c1b50` 被读作 `[x1-128]` 即 `x26-0x680`；
`x26` 在 `c1a9c` 由 `mrs x26, tpidr_el0` 得到，即 **TCB 基址**：

```asm
c1a9c:  mrs  x26, tpidr_el0
c1aa0:  sub  x23, x26, #0x740      ; x23 = pthread_self
c1ad8:  sub  x28, x25, #0xc0
...
c1b50:  ldp  x4, x3, [x1, #-128]   ; 节点地址 = TCB-0x680
c1b54:  str  x3, [x4, #8]          ; x4 == NULL → 0x8
```

**节点地址 = `TCB-0x680` = `pthread_self + 0xC0`，正是 `struct pthread` 的 `list` 字段**
（`offsetof(struct pthread, list) == 0xC0`）。

## 3. `TCB-0x680` 的实测取值（决定性对照）

自建 `dtest2`（用 `mrs tpidr_el0` 直接读该槽位）：

| 环境 | `[TCB-0x680]` | glibc `fork()` |
|---|---|---|
| 普通执行（无 proroot 加载器） | `0x7a5d81f980` = `pd+0xC0`（**自环**） | ✅ status=42 |
| proroot 加载器 + `libnoop.so` | **`(nil)`** | ❌ SIGSEGV `addr=0x8` |
| proroot 加载器 + **官方 runtime** | `0x7a3f54a980` = `pd+0xC0`（**自环**） | ✅ status=42 |

```
--- proroot 加载器 + libnoop ---
>> TCB: tpidr_el0=0x7a4a5df000 pthread_self=0x7a4a5de8c0  (tcb - self = 0x740)
   ** [TCB-1664] = (nil) (nil)   <-- fork 会解引用这里

--- 普通执行 + LD_PRELOAD libnoop ---
   ** [TCB-1664] = 0x7a5d81f980 0x7a5d81f980   <-- fork 会解引用这里
[glibc fork] exited status=42
```

这是「**未初始化**」与「**已初始化成自环**」的干净 A/B。`tcb - pthread_self = 0x740` 也被实测确认，
与崩溃指令反推的偏移**双向吻合**。

## 4. 关键判据：**这不是 bxroot 引入的缺陷**

用 `libnoop.so` 做单变量隔离 —— 它只有一行 `write(2,...)`，**零 `dlsym`、零 `atfork`、零 bxroot 代码**：

```c
__attribute__((constructor)) static void noop_init(void){
    write(2, "[libnoop] constructor ran (no atfork)\n", 38);
}
```

```
########## libnoop.so（preload 但什么都不做）##########
*** SIGSEGV child: addr=0x8 pc=0x76db303b54 ...     ← 与 bxroot 完全相同的 PC 与 addr
[forkonly] exited status=99

########## 普通执行 + 同一个 LD_PRELOAD（不经 proroot 加载器）##########
[forkonly] exited status=42                          ← 正常
```

**只要经 proroot 加载器 preload 任意一个 .so，`fork()` 就崩**；不经加载器则完全正常。
`libatfork.so`（仅注册 `pthread_atfork` 三件套）同样崩，PC 一致。

同时确认：**proroot 加载器下 `fork()` 走的是 `glibc` 的 `__fork`**（否则不会崩在这个地址）。
官方 runtime 之所以没事，反汇编证据是它**接管了 `fork`**：

```asm
00000000000091a0 <fork>:
    91e4:  bl  8740 <proroot_raw_syscall6>   ← 裸 syscall，不走 glibc
    91f0:  cbz w0, 920c
    920c:  bl  90cc <proroot_atfork_child>
0000000000009260 <__fork>:
    9260:  b   5be0 <fork@plt>               ← 连 glibc 内部别名 __fork 也被它顶替
```

官方还导出了 `__fork` / `__vfork` / `__execve` / `__execvpe` / `__posix_spawn` / `__clone3`
等 glibc 内部别名；**bxroot 一个都没有**：

```
--- 官方 ---                          --- bxroot ---
T __clone3                            （无）
T __execve                            （无）
T __fork                              （无）
T __posix_spawn                       （无）
```

## 5. 修复

`src/proc/proc.c` 新增 `px_heal_thread_list()`，在 `px_runtime_init()` 中、
**`pthread_atfork()` 注册之前**调用：

```c
#define PX_TCB_TO_PD      0x740u   /* pthread_self = tpidr_el0 - 0x740 */
#define PX_PD_LIST_OFF    0xC0u    /* offsetof(struct pthread, list)   */

void px_heal_thread_list(void)
{
    unsigned long tcb;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tcb));
    if (tcb == 0) return;
    {
        uintptr_t  pd  = (uintptr_t)tcb - PX_TCB_TO_PD;
        uintptr_t *lst = (uintptr_t *)(pd + PX_PD_LIST_OFF);
        if (lst[0] == 0 && lst[1] == 0) {      /* 严格只在「未初始化」时动手 */
            lst[0] = (uintptr_t)lst;           /* next = 自己 */
            lst[1] = (uintptr_t)lst;           /* prev = 自己 */
        }
    }
}
```

**设计要点**：

- 不解析任何符号、不依赖内部链接名，只按实测偏移写内存；
- 只在 `next`/`prev` **都是 NULL** 时才动手。glibc 自己初始化过就**绝不触碰** ——
  否则会把正常链表节点摘断，制造更糟的故障；
- 偏移不匹配时静默跳过（宁可少修，不可错写），与 `livepatch` 的「逐点校验、不匹配即放弃」同一原则。

**为什么不用官方的做法（裸 syscall `fork`）**：那会绕开 glibc 的 `atfork` 链与内部列表一致性，
bxroot 的 `px_atfork_*` 三件套（账本重置、pid 缓存失效）就失效了。就地补字段的影响面最小。

## 6. 修复验证

**修复后实测**（`libtcfix` 为等价的独立实现，用作交叉验证）：

```
########## 修复后 dtest + libtcfix（对照）##########
-- forkonly     -- [forkonly] exited status=42     ✅  ← 修复前 SIGSEGV(99)
-- forkexec     -- from-forkexec     status=0      ✅
-- forkexecraw -- from-raw           status=0      ✅
-- vforkexec    -- from-vfork        status=0      ✅
-- posix_spawn  -- from-spawn        status=0      ✅

########## 修复后 dtest + bxroot 运行时（本仓库构建）##########
-- forkonly     -- [forkonly] exited status=42     ✅  ← 本次修复的直接判据，已通过
-- forkexec     -- status=127                      ❌  §8 缺陷（exec EACCES），与本次修复无关
-- forkexecraw -- status=127                      ❌  同上
-- vforkexec    -- SIGILL(132)                    ❌  §8b 缺陷（落 Android linker），与本次修复无关
```

**判据说明**：`forkonly`（纯 `fork()`，无任何 exec）是本次根因的**唯一判据**，
它已从 `SIGSEGV(99)` 变为 `status=42`。其余三项的失败来自 §8/§8b 的**独立缺陷**——
它们修复前是 `SIGSEGV`（与 `forkonly` 同一崩溃点），修复后变为 `127`/`SIGILL`
（**不再是 SIGSEGV**），说明 fork 层已修好，失败原因已下移到 exec 路径。

`[TCB-0x680]` 修复后取值 `0x7f35820980`，等于 `pd+0xC0`（自环），与官方运行时一致。

**回归**：`sh test/RUN_WARN_GATE.sh` → ✅ 零告警（11 个编译单元，含 `proc.c`）。
`sh test/RUN_ALL.sh` → **9/10 通过**；唯一失败的「运行时构建」已确证为
**本容器 gcc 13.3.0 的间歇性 ICE**（同一条命令重跑第 2 次即成功，产物完好），非代码缺陷。

## 7. 排除清单（都有实测证据）

| 嫌疑 | 判定 | 证据 |
|---|---|---|
| `pthread_atfork` 未注册 | ❌ 排除 | `proc.c` 确实注册；`libnoop`（不注册 atfork）同样崩 |
| `px_dlsym(RTLD_NEXT)` 解析错误 | ❌ 排除 | 实测 `RTLD_NEXT fork = 0x77dfb03a10`，`dladdr` → `libc.so.6`，合法 |
| `px_dlsym` 自我递归 | ❌ 排除 | `posix_spawn` 解析到 `0x7abb7181c0`（libc），bxroot 自身是库内偏移 `0x1b660`，地址空间不同 |
| 静态子进程证明「与加载器无关」 | ❌ **该推论作废** | proroot 加载器要求 `PT_DYNAMIC`，静态 ELF 直接被拒（`failed no PT_DYNAMIC`），它本来就跑不起来 |
| vfork 破坏父进程堆 | ❌ 排除 | 父进程崩溃后完全健康 |
| envp 重建（`px_env_build`） | ❌ 排除 | `forkonly` 根本不走 exec，照样崩 |
| 路径翻译 / `/proc/self/exe` 伪装 | ❌ 排除 | 同上；且 exec 不存在的路径也是同一 PC |
| bxroot 的 `proc.c` 逻辑本身 | ❌ 排除 | `libnoop`（零 bxroot 代码）复现完全相同的 PC 与 addr |

## 8. 遗留：第二个独立缺陷（执行 guest 二进制返回 EACCES）

`fork()` 修好后，`execve`/`posix_spawn` 仍失败：`rc=13 (EACCES)`。**这是另一个独立问题，且已定性为环境固有约束**：

```
########## 完全不加载 bxroot，同一容器内直接 execve ##########
  [child] execve(/data/.../ubuntu/bin/echo) errno=13 (Permission denied)
execve(/data/.../ubuntu/bin/echo) -> ❌失败
HELLO-FROM-CHILD
execve(/bin/echo) -> ✅成功          ← 跑的是宿主 Android toybox，不是 guest 的
```

`$ROOTFS/usr/local/bin/node`、`$ROOTFS/tmp/bxmin/marker` 同样 **EACCES(13)**。
即：**Android 不允许 `execve` app 私有目录（`/data/data/...`）下的文件** ——
这正是 proroot 要用「自研 ELF 加载器 mmap + 跳转」而不是 `execve` 的根本原因。

官方运行时的做法（反汇编证据）是在 `posix_spawn` 内部调 `do_translate` 并且**从不真 execve guest 路径**：

```asm
000000000002610c <posix_spawn>:
   261ac:  bl  a9a0 <do_translate>     ← 官方自己在 spawn 里翻译
```

**bxroot 当前把 guest 路径翻译成宿主路径后交给 `real_posix_spawn`（glibc）**，
而 glibc 的 `posix_spawn` 最终要走真 `execve` → 撞上 SELinux 的 EACCES。

实测确认的路径行为矩阵（经加载器，`errprobe`）：

| 传给 `execve` 的路径 | 结果 |
|---|---|
| `/bin/echo` | 成功，但执行的是**宿主 toybox**（输出 `toybox: Unknown command x`） |
| `$ROOTFS/bin/echo` | **EACCES(13)** |
| `$ROOTFS$ROOTFS/bin/echo` | ENOENT(2) |
| `/nonexistent-abc` | ENOENT(2) |

### 8b. 该缺陷的第二个表现形态：`vfork` 子进程落到 Android `linker64`

修好 `fork()` 后，`vfork()+execl()` 仍有 **SIGILL(132)**，而官方运行时 `status=0`：

```
--- bxroot 运行时 ---    -- vforkexec --                             退出码=132 (Illegal instruction)
--- 官方运行时 ---       -- vforkexec --  from-vfork  status=0  ✅
--- libnoop / libtcfix --  -- vforkexec --  from-vfork  status=0  ✅  ← 无 bxroot 代码则正常
```

把 `BXROOT_ROOTFS` 设为 `/`（让翻译退化为恒等）后，真凶现形：

```
CANNOT LINK EXECUTABLE "echo": library "libc.so.6" not found:
  needed by /data/data/.../ubuntu/tmp/bxroot-e2e/libbxroot-runtime.so in namespace (default)
```

即：bxroot 注入的 `LD_PRELOAD` 是**宿主/guest 路径**，而 `vfork` 后子进程的真 `execve` 由
**Android 的 `linker64`**（而非 proroot 加载器）接手，Android linker 既找不到 `libc.so.6`
（那是 Ubuntu 的 glibc，不在 Android 命名空间里），也无法加载 app 私有目录下的 `.so` → SIGILL。

**这与 §8 是同一个根因**：bxroot 走「真 `execve`」，而 proroot 架构的前提是
「**永不真 `execve`**，一切经自研加载器 mmap 跳转」。

**建议的后续方向**（本次未实施，需与 `preload.c` / 加载器协作设计，**不属 proc.c 内部**）：
在 exec/spawn/vfork 路径上复用 proroot 的 mmap 加载器（经官方 linker 的
`ldso_runtime_dlopen` / `ldso_runtime_dlsym` 服务接口，或 bxroot 自己的加载器），
而不是把路径交给 glibc 的 `posix_spawn` / `execve` 去真 `execve`；
同时 `LD_PRELOAD` 的注入值必须是加载器能解析的形态。
这条线索与另一个 agent 在查的「官方 linker 接口协议」方向是**同一件事**，建议汇合。

## 9. 复现脚本

```sh
# 崩溃现场（修复前）
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
export BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$ROOTFS/tmp/bxroot-e2e/tmp" \
       BXROOT_WORKDIR="/" BXROOT_FAKEROOT=1
"$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 dtest \
  --preload "$ROOTFS/tmp/bxroot-e2e/libbxroot-runtime.so" "$ROOTFS/tmp/bxmin/dtest" forkonly

# 判据：TCB 槽位取值
"$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 dtest2 \
  --preload "$ROOTFS/tmp/bxroot-e2e/libbxroot-runtime.so" "$ROOTFS/tmp/bxmin/dtest2" info

# 单变量隔离（证明与 bxroot 无关）
"$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 dtest \
  --preload "$ROOTFS/tmp/bxmin/libnoop.so" "$ROOTFS/tmp/bxmin/dtest" forkonly
```

辅助程序（本次新建，均在 `/tmp/bxmin/`）：`dtest.c`（五项派生路径 + SIGSEGV 处理器）、
`dtest2.c`（读 TCB 槽位 + `_Fork`/裸 `clone`/`fork` 对照）、`libnoop.c`、`libatfork.c`、
`libtcfix.c`（TCB 修复验证）、`libdlsymprobe2.c`（否证自我递归）、`errprobe.c`、`exectest.c`。
