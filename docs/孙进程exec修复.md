# 孙进程 exec 修复报告

> 任务：让孙进程（以及更深层级）的 exec 也能正确工作。
>
> **结论：已定位并修复。** 根因有**两个**，彼此独立、都必须修：
>
> 1. **`px_runtime_build_env()` 把 `envp == NULL` 当空环境传下去** ——
>    注释承诺的「兜底到 `environ`」在代码里**根本不存在**，于是
>    `execv`/`execvp`/`execl*` 家族（不传 envp）的子进程只拿到 4 条
>    强制变量，`PROROOT_TRAMPOLINE_PATH` 也在丢失之列。
> 2. **trampoline 的 argv 少传 `--argv0` / `--preload`** —— linker 收不到
>    `--preload` 就不装运行时库，子进程只有 bridge+linker、**没有任何钩子**。
>
> 修好这两个之后孙进程 exec 立刻跑通，但暴露出**第三个**（既有的、
> 被掩盖的）缺陷：`vfork` 子进程里的任何堆分配都会破坏父进程的堆。
> 该缺陷与 bxroot 的具体实现无关（极简 preload 库不触发，官方 runtime
> 也不触发），但**必须由我们这一层消除**，否则 dash 的 `vfork+exec`
> 优化路径必崩。已改为把 `vfork` 委托给 `fork`。
>
> **实测结果**：6 条验收标准**全部通过**；`RUN_ALL.sh` 11/11；
> 告警门禁零告警；深度 2/3/4 全部 `status=0`。

---

## 0. 摘要（先看这张表）

| # | 缺陷 | 层 | 证据强度 | 状态 |
|---|---|---|---|---|
| 1 | `envp==NULL` 未兜底到 `environ` | `proc.c` 钩子层 | 带 pid 的原始输出 | ✅ 已修 |
| 2 | trampoline argv 缺 `--argv0`/`--preload` | `proc.c` `px_trampoline_exec` | 与官方 cmdline 逐项对照 | ✅ 已修 |
| 3 | `vfork` 子进程分配破坏父进程堆 | 环境级（非 bxroot 独有） | 受控探针阶梯实验 | ✅ 已绕开（vfork→fork） |

**我在本轮推翻的既有说法**（诚实起见列清楚）：

| 曾经的说法 | 出处 | 实测判定 |
|---|---|---|
| 「trampoline 路径下 `LD_PRELOAD` 不需要处理」 | 前一个 agent | ✅ **成立**（这点他是对的，见 §4） |
| 「trampoline 只在顶层生效，子进程里钩子没接上」 | 任务书 | ⚠️ **表述需修正**：不是「钩子没接上」，而是**运行时库压根没被加载**（§3） |
| 「子进程 envp 里 `PROROOT_TRAMPOLINE_PATH` 在不在？」 | 任务书方向 1 | ✅ **正中要害** —— 修复前**不在**（§2） |
| 「`px_trampoline_exec` 里有只在顶层为真的前置条件」 | 任务书方向 3 | ❌ **否定**：early-return 逻辑本身正确，是它的**输入**（getenv）为空 |

---

## 1. 复现基线（修复前）

```sh
cd /root/proroot-work/agents/rename-bxroot
cp build/libbxroot-runtime.so /tmp/bxroot-e2e/libbxroot-runtime.so
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
STAGE_LOAD="$ROOTFS/tmp/bxroot-e2e"
export BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" BXROOT_WORKDIR="/" \
       BXROOT_FAKEROOT=1 BXROOT_GUEST_EXE=/usr/local/bin/node
timeout 150 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 node \
  --preload "$STAGE_LOAD/libbxroot-runtime.so" "$ROOTFS/usr/local/bin/node" "$STAGE_LOAD/probe14.js"
```

原始输出（修复前）：

```
A) sh -c 'echo ok':  status=0 out="ok\n"
B) sh -c '/bin/echo direct': status=1 out=""
   stderr="CANNOT LINK EXECUTABLE \"/bin/echo\": library \"libc.so.6\" not found: needed by
           /data/data/com.dsh.client/files/linux/ubuntu/tmp/bxroot-e2e/libbxroot-runtime.so
           in namespace (default)\n"
```

`sh test/RUN_E2E.sh --selftest` 原始输出（修复前）：

```
=== 子进程派生 ===
CANNOT LINK EXECUTABLE "/bin/echo": library "libc.so.6" not found: ...
  ❌ execSync /bin/echo: Command failed: /bin/echo ok
/data/data/com.dsh.client/files/linux/ubuntu/bin/sh: 1: /usr/bin/id: not found
  ❌ execSync /usr/bin/id -u: Command failed: /usr/bin/id -u
结果: 6 通过 / 2 失败
```

---

## 2. 根因 1：`envp == NULL` 的兜底**只写在注释里**

### 2.1 定位过程（带 pid 的诊断）

在 `px_runtime_build_env()` 里加临时诊断（`BXROOT_GC_DIAG` 门控）：

```c
fprintf(stderr, "[GC-DIAG pid=%d] build_env: in=%p n_in=%zu\n",
        (int)getpid(), (const void *)envp, nin);
rc = px_env_build((const char *const *)envp, &pol, out, NULL);
fprintf(stderr, "[GC-DIAG pid=%d] build_env: rc=%d n_out=%zu\n",
        (int)getpid(), rc, nout);
```

跑 `cp.spawnSync("/bin/sh", ["-c", "echo HELLO_FROM_CHILD"])`，原始输出：

```
node[1]: pthread_create: Invalid argument
pid=1 顶层 env 条目=69
status=0 out="HELLO_FROM_CHILD\n"
err="[GC-DIAG pid=1] build_env: in=(nil) n_in=0
     [GC-DIAG pid=1] build_env: rc=0 n_out=4"
```

**`in=(nil) n_in=0` → `n_out=4`**：输入是空，输出只有 4 条（正好是
`LD_PRELOAD` / `BXROOT_ROOTFS` / `PROROOT_ROOTFS` / `BXROOT_LD_PRELOAD`
四个强制条目）。

### 2.2 子进程环境对照（`sh -c set`）

修复前，子进程 `sh` 的 `set` 实测：

```
BXROOT_LD_PRELOAD='...'
BXROOT_ROOTFS='...'
LD_PRELOAD='...'
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
PROROOT_ROOTFS='...'
PWD='...'                       ← dash 自己设的
```

子进程 `child-set-lines=14`（真实变量 5 条），而顶层 node 是
`env 条目数=68`、其中 `PROROOT|BXROOT` 相关 17 条。

### 2.3 代码缺陷本体

`proc.c` 原第 2688 行：

```c
int rc = px_env_build((const char *const *)envp, &pol, out, NULL);
```

而它上方第 2679 行的注释白纸黑字写着：

> `envp == NULL` 时用 environ。
> …纯逻辑层不兜底是刻意的（要能测「空环境」），**兜底责任在这一层**。

`px_env_build` 里是 `if (in_envp != NULL) { ... }` —— 传 NULL 就是
**空环境**。纯逻辑层这个语义是**对的**（`test_proc.c` 的 C1 用例
`px_env_build(NULL, ...)` → `out.n == 2` 正钉着它，不能改）。
**兜底代码在钩子层根本不存在。**

### 2.4 为什么这条比「用户变量丢失」严重得多

丢的不只是用户变量 —— `PROROOT_TRAMPOLINE_PATH` 与
`PROROOT_LINKER_PATH` 也在其中，而 `px_trampoline_exec` /
`px_trampoline_spawn` 正是靠它们判断「要不要走 bridge」：

```c
if (tramp == NULL || tramp[0] == '\0' || linker == NULL || linker[0] == '\0') {
    return -1;          /* ← 这里直接放弃 trampoline */
}
```

于是子进程退化成「直接 execve 翻译后的宿主路径」，而 guest 文件在
`/data/data`（SELinux `app_data_file`，内核禁止执行）→ 必然失败。

**修复**（`proc.c`）：

```c
const char *const *src = (envp != NULL) ? (const char *const *)envp
                                        : (const char *const *)environ;
int rc = px_env_build(src, &pol, out, NULL);
```

修复后同一探针：子进程 `child-set-lines=76`，`PROROOT_TRAMPOLINE_PATH`
等全部到位。

### 2.5 修复 1 之后孙进程**仍然失败** —— 说明还有第二个根因

```
B) sh -c '/bin/echo direct': status=1 out=""
   stderr="CANNOT LINK EXECUTABLE ..."     ← 症状完全相同
```

---

## 3. 根因 2：trampoline 没传 `--preload`，子进程**没有钩子**

### 3.1 子进程 maps：运行时库根本不在

让子进程 `sh` 读自己的 `/proc/self/maps`（修复前）：

```
MAP: ... libproroot-bridge.so
MAP: ... libc.so.6
MAP: ... libproroot-linker.so
--- end maps ---
```

**`libbxroot-runtime.so` 不在里面。** 对照顶层 node 的 maps，它是有的：

```
7c647a4000-7c647c9000 r-xp ... /data/.../tmp/bxroot-e2e/libbxroot-runtime.so
```

### 3.2 官方 runtime 同场景对照（决定性证据）

同一台机器、同一 bridge、同一 linker，**只换 runtime**，让子进程
`sh` 打印自己的 `/proc/self/cmdline`：

**官方 runtime（成功，`B) status=0 out="direct\n"`）**：

```
子进程 sh cmdline (status=0):
    /data/app/.../lib/arm64/libproroot-bridge.so
    /data/app/.../lib/arm64/libproroot-linker.so
    --argv0
    /bin/sh
    --preload
    /data/app/.../lib/arm64/libproroot-runtime.so
    /data/data/.../ubuntu/usr/bin/dash
    -c
    tr "\0" "\n" < /proc/self/cmdline
```

**本实现（失败，`status=1`）**：

```
子进程 sh cmdline (status=1):
  (空)
子进程 stderr="CANNOT LINK EXECUTABLE \"tr\": library \"libc.so.6\" not found:
               needed by .../libbxroot-runtime.so in namespace (default)"
```

差的就是 **`--argv0 <name>` 与 `--preload <runtime>`** 这两组选项。

官方 runtime 的子进程 maps 里也**确实有** runtime：

```
MAP: 7781688000-77816cb000 r-xp ... libproroot-runtime.so     ← 官方有
```

### 3.3 代码缺陷本体

`px_trampoline_exec` 原来构造的是 `[bridge, linker] + 原 argv`：

```c
nv[n++] = tramp_path;
nv[n++] = (char *)(uintptr_t)linker;
for (i = 0; argv[i] != NULL && n < PX_ARGV_MAX + 2; i++) nv[n++] = argv[i];
```

函数头注释还把它写成了「设计」：

> `argv = [bridge, linker, (原 argv[0..]), NULL]`
> `envp 原样（官方另注 PROROOT_TRAMPOLINE_ARGV_OFFSET，此处从简）`

—— 「从简」掉的恰恰是**让孙进程能工作的全部**。

**为什么顶层能跑而孙进程不能**：顶层那次是启动器（`RUN_E2E.sh`）
直接调 bridge 并**完整传了** `--argv0`/`--preload`；而孙进程这次是
**我们**在 `px_trampoline_exec` 里拼的 argv，少了两项 → linker 不装
runtime → 孙进程裸奔 → 它再 exec 外部程序时落到 Android linker，
而 `LD_PRELOAD` 指向 glibc 库 → `CANNOT LINK EXECUTABLE`。

### 3.4 手工验证修复形态（先验证再改码）

```sh
timeout 90 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
  --argv0 /bin/sh --preload "$RT" "$ROOTFS/usr/bin/dash" -c '/bin/echo direct'
```

原始输出：

```
direct
rc=0
```

### 3.5 修复

`px_trampoline_exec` 补齐官方形态，并把 `host`（翻译后的宿主 exe）
与 `argv0`（guest 眼里的程序名）都接上；实参从 `argv[1]` 起接
（`argv[0]` 已由 `--argv0` 表达、`host` 已单独占一项，从头接会把
程序名重复成第一个实参）。新增签名参数：

```c
static int px_trampoline_exec(const char *host, char *const argv[],
                              char *const *envp, const char *argv0,
                              const char *preload);
```

调用点（`px_do_execve`）：

```c
px_trampoline_exec(host, final_argv, final_env, guest,
                   getenv("BXROOT_LD_PRELOAD"))
```

拿不到 `preload` 时**返回 -1 放弃 trampoline**（「装上钩子」正是走
trampoline 的全部意义，装不上就没必要进 bridge）；拿不到 `argv0`
时**不发** `--argv0`（宁可让 linker 用默认值，也不要传空名字）。
`px_trampoline_spawn` 同步接上 `host`/`argv0`/`preload`。

修复后：`B) status=0 out="direct\n"`。

---

## 4. 关于 `LD_PRELOAD` 是否需要处理（重新实测确认）

**前一个 agent 的结论成立，我复核后确认**：trampoline 路径下
**不需要**额外处理 `LD_PRELOAD`。

理由（本轮实测）：孙进程 `sh` 的环境里 `LD_PRELOAD` **本来就在**
（由根因 1 修复后的 env 注入保证），而**真正把 runtime 装进内存的是
linker 的 `--preload` 选项**，不是 `LD_PRELOAD`：

- 修复前：`LD_PRELOAD` 有值，但 runtime **不在** maps 里（§3.1）；
- 修复后：runtime 在 maps 里，孙进程钩子生效。

也就是说 `LD_PRELOAD` 在该链路里是**冗余的**（它甚至会造成误导 ——
根因 2 的报错信息就是 Android linker 拿它去解析 glibc 库名）。
**不要**因为「报错里提到了 `LD_PRELOAD`」就去动它。

---

## 5. 根因 3：`vfork` 子进程分配破坏父进程堆（既有缺陷，被前两个掩盖）

修好 §2 §3 后 exec 成功了，但退出码是 `signal=SIGSEGV` 而非 0。
这是一个**独立**的、此前被 `CANNOT LINK EXECUTABLE` 掩盖的缺陷。

### 5.1 受控复现（最小化）

`vf2.c`（`vfork()` 后子进程 `execve("/bin/true")`）原始输出：

```
bxroot  fork   : rc=0    [vf2] PARENT: before vfork|[vf2] PARENT: resumed child=9630|...|PARENT: survived
bxroot  vfork  : rc=139  [vf2] PARENT: before vfork|[vf2] CHILD: alive, about to execve /bin/true||SIGSEGV
官方  vfork  : rc=0    ...|PARENT: resumed|PARENT: survived
```

崩溃转储（`crash.c` 打的）：

```
[bxroot] SIGSEGV pc=0x0000007a825e3b58 lr=0x0000007a825e3b58 fault=0x0000007a825e3b58 code=2
```

**pc == lr == fault**，且该地址落在**栈**上（非可执行匿名映射）——
返回地址被写坏。

### 5.2 阶梯实验：与 bxroot 的实现无关

同一探针只换 `--preload` 的库：

```
① 无 --preload（纯 bridge+linker） : rc=0    PARENT: resumed|PARENT: survived
② --preload 极简 libnoop.so        : rc=0    PARENT: resumed|PARENT: survived
③ --preload 官方 runtime            : rc=0    PARENT: resumed|PARENT: survived
④ --preload bxroot runtime          : rc=139  SIGSEGV
```

进一步：**纯转发** vfork 钩子（`libt8.so`，只 `dlsym`+forward）也复现
rc=139；而把 vfork 实现成调用 glibc `fork` 的垫片（`libt10.so`）→ **rc=0**。

### 5.3 精确到「分配」这一步

`vf8.c`（`vfork()` 后子进程只做一次 `malloc` 再 `_exit`）：

```
libnoop.so             child_alloc=0 : rc=0    PARENT survived
libnoop.so             child_alloc=1 : rc=0    PARENT survived
libbxroot-runtime.so   child_alloc=0 : rc=0    PARENT survived
libbxroot-runtime.so   child_alloc=1 : rc=139  SIGSEGV
```

`vf6.c`（子进程分别做不同的事）：

```
noexec     : rc=0    PARENT survived          ← 只 _exit
malloc     : rc=135  SIGBUS                   ← 只 malloc
execfail   : rc=139  SIGSEGV                  ← execve 到不存在的路径
exectrue   : rc=139  SIGSEGV                  ← execve /bin/true
```

**结论：vfork 子进程里的任何堆分配都会破坏父进程的堆。**
`execve` 之所以也触发，是因为我们的 exec 钩子要构建 envp/argv（分配）。

### 5.4 排除的替代解释（负结果，都有实测）

- ❌ **不是构造函数内容**：把 `preload.c` 构造函数的每一步
  （`init_config` / `init_l2s` / `init_fakeroot` / `bxroot_sigsys_install` /
  `bxroot_livepatch_apply` / `px_runtime_init` / `px_runtime_register_self` /
  `bxroot_crash_install`）**逐个**关、以及**全部同时**关，仍然 rc=139。
  （注：该临时门控已完全还原，`preload.c` 最终无我的改动。）
- ❌ **不是 TCB 线程链表修复**：只做 `px_heal_thread_list` 的等价操作
  （`libt1.so`）→ rc=0。
- ❌ **不是 `pthread_atfork`**：只注册 atfork（`libt2.so`）→ rc=0；
  在 atfork 的 child 回调里分配（`libt3.so`）→ rc=0。
- ❌ **不是库体积/布局**：把极简库用 padding 撑到 266 KB（比 bxroot 还大，
  `libt6.so`）→ rc=0。
- ❌ **不是 `syscall` 符号插入**：只导出 `syscall`（`libt5.so`）→ rc=0。
- ❌ **不是普通 ld.so 环境**：`LD_PRELOAD=<bxroot> ./vf8 malloc`（不走
  bridge/linker）→ rc=0。必须**经 proroot 自研加载器**才复现。

### 5.5 修复策略与「为什么可以这么修」

既然「vfork 子进程里分配」是环境级的雷，而我们**无法约束调用方**
（dash/libuv/各种库）的 vfork 子进程不分配 —— 尤其 dash 对简单命令
正是用 `vfork+exec` —— 唯一能由我们这一层消除风险的办法就是
**不让 vfork 真的以 vfork 语义发生**：

```c
pid_t vfork(void)
{
    g_rt_stats.vfork_calls++;
    /* ... 根因说明 ... */
    return fork();
}
```

**合法性**：POSIX 允许 vfork 被实现为 fork —— fork 的语义是 vfork 的
**严格超集**（vfork 只保证「子进程先跑、父进程挂起」；fork 给了完整的
地址空间隔离）。依赖 vfork 省内存的程序只是少省一点内存，行为完全合法。

**顺带收益**：这**彻底消除**了 `vfork()` 原注释里自己承认的未完成项
（「vfork + 账本表将满 → 破坏父进程堆」）—— 不再有共享堆的 vfork
子进程，账本在 fork 子进程里分配是安全的。那条「标记为未完成」的
技术债随之关闭。

**实测**：`vf2 vfork` → rc=0；`dash -c '/bin/true; echo B'` → rc=0。

---

## 6. 验收标准实测结果（6/6 全部通过）

### 验收 1：`spawnSync("/bin/sh", ["-c", "/bin/echo direct"])`

```
✅ spawnSync('/bin/sh',['-c','/bin/echo direct']) = "status=0 out=\"direct\\n\""
```

### 验收 2：`execSync("/bin/echo ok")`

```
✅ execSync('/bin/echo ok') = "ok"
```

### 验收 3：`sh test/RUN_E2E.sh --selftest` 的「子进程派生」两项

```
=== 子进程派生 ===
  ✅ execSync /bin/echo: ok
  ✅ execSync /usr/bin/id -u: 0
...
结果: 8 通过 / 0 失败
```

（修复前：`6 通过 / 2 失败`）

### 验收 4：`cspawn4` 不回归

```
posix_spawn  guest + environ              rc=0   OK
     子进程 status=0 sig=0
posix_spawn  host  + environ              rc=0   OK
     子进程 status=0 sig=0
posix_spawn  guest + 空环境            rc=0   OK
     子进程 status=0 sig=0
posix_spawn  argv[0]=NULL                 rc=0   OK
     子进程 status=0 sig=0
✅ 4/4 rc=0 (4/4 通过)
```

> 注：原 `cspawn4` 探针被 `RUN_E2E.sh` 开头的 `rm -rf /tmp/bxroot-e2e`
> 删掉了（该目录是共享的，已丢过多次）。此处按
> `docs/linker接口适配分析.md` §6.3 记载的 4 个变体**重建**为
> `cspawn4.c`，变体与文档一致。

### 验收 5：`spawnSync("/bin/echo", ["ok"])` 不回归

```
✅ spawnSync('/bin/echo',['ok']) = "signal=null status=0 out=\"ok\\n\""
```

### 验收 6：官方对照仍正常

```
--- 官方 runtime / probe14 ---
A) sh -c 'echo ok':  status=0 out="ok\n"
B) sh -c '/bin/echo direct': status=0 out="direct\n"
--- 官方 runtime / cspawn4 ---
✅ 4/4 rc=0 (4/4 通过)
```

### 附加：更深层级与周边路径（13/13，连跑 3 轮稳定）

```
=== 更深层级（孙进程及以下）===
  ✅ 深度2 sh->echo = "status=0 sig=null out=\"L2\\n\""
  ✅ 深度3 sh->sh->echo = "status=0 sig=null out=\"L3\\n\""
  ✅ 深度4 sh->sh->sh->echo = "status=0 sig=null out=\"L4\\n\""
=== 其它路径 ===
  ✅ sh -c 'echo builtin'（不 exec） = "0:\"builtin\\n\""
  ✅ sh -c '/bin/true; echo B' = "status=0 out=\"B\\n\""
  ✅ sh -c 'exit 7'（退出码透传） = 7
  ✅ 管道 sh -c 'echo X | cat' = "status=0 out=\"X\\n\""
  ✅ PATH 搜索 /bin/echo via execSync = "viaPath"
  ✅ execSync('id -u') 走 PATH = "0"
  ✅ 子进程继承完整环境（条目数>50） = true
结果: 13 通过 / 0 失败
```

### 附加：全量回归与告警门禁

```
 通过 11 / 失败 0
  ✅ 全部通过

✅ 零告警（检查了 11 个编译单元）
```

---

## 7. 改动清单

**只改了 `src/proc/proc.c`**（diff：+202 / −55 行）。

| 位置 | 改动 |
|---|---|
| `px_runtime_build_env()` | `envp == NULL` → 真的兜底到 `environ`（**根因 1**） |
| `px_trampoline_exec()` | 签名加 `argv0`/`preload`；argv 补齐 `--argv0`/`--preload`/`host`；实参从 `argv[1]` 起（**根因 2**） |
| `px_trampoline_spawn()` | 同步接上 `host`/`argv0`/`preload` |
| `px_do_execve()` 调用点 | 传 `guest`（guest argv0）与 `getenv("BXROOT_LD_PRELOAD")` |
| `px_do_spawn()` 调用点 | 传 `host`/`argv[0]`/`BXROOT_LD_PRELOAD` |
| `vfork()` | 委托给 `fork()`（**根因 3**）；删除不再使用的 `real_vfork` |

**约束遵守情况**：

- ✅ 未改禁改文件：`syscall_guard.c` / `fakeroot.c` / `RUN_WARN_GATE.sh` /
  `BUILD_RUNTIME.sh` / `launcher.c` / `RUN_ALL.sh`
  （`preload.c` 的差异是**另一个 agent** 的 `bxroot_next_symbol` 改动，
  我插入的临时诊断门控已**完全还原**并核对）
- ✅ `px_heal_thread_list` 保留（`proc.c:2265/2273/2518`）
- ✅ trampoline 的 `/proc/self/root` 前缀处理保留（`proc.c:3169`）
- ✅ 零告警
- ✅ 未做任何 git 操作
- ✅ 未删任何探针/原有测试

---

## 8. 给后续维护者的提醒（踩过的坑）

1. **`RUN_E2E.sh` 开头有 `rm -rf /tmp/bxroot-e2e`** —— 那是个共享目录，
   跑一次 E2E 就会删掉别人放在那里的探针。本轮探针因此丢过一次。
   建议把探针放独立目录（我用 `/root/grandchild/probes/`）。
2. **`BUILD_RUNTIME.sh` 用固定日志路径** `/tmp/bxroot-runtime-cc.err` ——
   **两个 agent 同时构建会互相清空日志**，症状是「编译失败但编译器输出为空」。
   本轮遇到过两次，重试即可。建议日志带 `$$` 或用 `mktemp`。
3. **`[NEXT]` / `[DLADDR]` 前缀的 stderr 输出**来自另一个 agent 正在
   `preload.c` 里调试的 `bxroot_next_symbol`（**非**本轮改动的产物，
   也不影响功能）。看输出时注意过滤。
4. **不要用「日志里出现 `CANNOT LINK EXECUTABLE` 提到 `LD_PRELOAD`」
   去推断需要在 `LD_PRELOAD` 上做处理** —— 那个报错是 §3 的症状，
   真因是 linker 没拿到 `--preload`（见 §4）。

---

*报告时间：2026-09-16 20:3x UTC*
*所有命令均在真机容器内实跑，输出为原样粘贴（仅去掉 ASLR 随机高位差异）。*
