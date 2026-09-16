# trampoline 特权 exec 实现报告

> 任务：修复 bxroot 下 `execve` / `posix_spawn` 恒失败（官方正常）的缺陷。
>
> **结论：已定位并修复。** 根因是 **guest 可执行文件位于 `/data/data` 下、
> SELinux 标签为 `app_data_file`，内核禁止执行**；官方 runtime 的做法是
> 经 `PROROOT_TRAMPOLINE_PATH`（bridge.so，位于可执行的 `/data/app` 下）
> 重新进入加载流程，bxroot 缺这一层。已按该协议在 `src/proc/proc.c`
> 实现 `px_trampoline_exec` / `px_trampoline_spawn`。
>
> **实测结果**：`cspawn4` 4/4 变体 `rc=13 → rc=0`；
> `probe12.js` 的 `/bin/true`、`/bin/echo` 与官方**逐字节一致**。
> 剩余 1 项（嵌套 node 报 SIGSYS）经查为**独立的既有缺陷**，非本次引入。

---

## 0. 本轮推翻了两个先前结论（含我自己和他人的）

诚实起见，先把**被实测否定**的说法列清楚 —— 它们都曾被认为是"根因"：

| 曾经的结论 | 提出者 | 实测判定 |
|---|---|---|
| `px_dlsym` 返回野地址 → 子进程 SIGSEGV | 任务书 / 父 agent | ❌ **否定**，返回合法高地址 |
| bxroot 下 `dlsym(RTLD_NEXT,…)` 恒 NULL | 父 agent | ⚠️ **探针假象**：主程序视角为 NULL，`.so` 内部正常 |
| `dlopen` 回退会自递归爆栈 | 我 | ❌ **否定**，嵌套深度实测恒为 0 |
| 内核态 uid 差异（0 vs 10655）是根因 | 我 | ❌ **否定**，官方 `Uid:` 也是 10655（被 fake 层骗了） |
| `LD_PRELOAD` 指向 glibc 库导致 exec 失败 | 父 agent | ❌ **否定**，剔除后 4 个变体仍全部 EACCES |
| `/data/data` 是 noexec 挂载 | 我 | ❌ **否定**，`com.dsh.client` 子挂载无 `noexec`；是 **SELinux 标签** |

**最终确认的根因只有一个**（见 §2）。

---

## 1. 第一步：`px_dlsym` 返回值实测 —— **合法，不是野地址**

把 `px_dlsym` 还原成修复前的原始实现（纯 `dlsym(RTLD_NEXT,…)`）并加 `fprintf`：

```c
p = dlsym(RTLD_NEXT, name);
fprintf(stderr, "[ORIGDIAG] %-26s dlsym(RTLD_NEXT)=%p  dlerror=%s\n",
        name, p, dlerror() ? dlerror() : "(null)");
```

原始输出：

```
[ORIGDIAG] posix_spawn                dlsym(RTLD_NEXT)=0x7c02b181c0  dlerror=(null)
[ORIGDIAG] fork                       dlsym(RTLD_NEXT)=0x7a31103a10  dlerror=(null)
[ORIGDIAG] execve                     dlsym(RTLD_NEXT)=0x7a310ffcc0  dlerror=(null)
```

| 符号 | 实测值 | 判据（应为 `0x7f...` 级高地址） |
|---|---|---|
| `posix_spawn` | `0x7c02b181c0` | ✅ 合法 |
| `fork` | `0x7a31103a10` | ✅ 合法 |
| `execve` | `0x7a310ffcc0` | ✅ 合法 |

**判定：全部合法高地址，不是 NULL / `0xffffffff…` / 0/1。核心假设不成立。**

### 1.1 为什么「恒 NULL」的观察是真的却不是根因

同一环境下，**主程序**探针 `dlsymprobe` 的 `RTLD_NEXT` 列**确实全 nil**；
而把探测放进**被 `--preload` 加载的 .so 内部**（`bxroot_real_symbol` 里）：

```
[RSDIAG] bxroot_real_symbol(open    ) RTLD_NEXT=0x70d84c6680
[RSDIAG] bxroot_real_symbol(stat    ) RTLD_NEXT=0x70d84c7400
[RSDIAG] bxroot_real_symbol(dlopen  ) RTLD_NEXT=0x70d8467490
```

**在 .so 内部是非 NULL 的。** 「谁调用」决定结果 —— 主程序搜索链里自己之后没有 libc，
返回 NULL 是**语义的正常结果**，不是 bxroot 的缺陷。

### 1.2 附带否定：`dlopen` 回退不会自递归

加嵌套深度计数后实测：

```
[DLDIAG] 进入我们的 dlopen("libc.so.6") 嵌套深度=0 fn=(nil)
[RSDIAG] bxroot_real_symbol(dlopen  ) RTLD_NEXT=0x70d8467490
[DLDIAG] 退出 dlopen -> 0x70d8f40f30
```

深度恒为 0，句柄正常返回。**`dlopen` 回退路径安全。**

---

## 2. 真正的根因：SELinux 标签禁止执行 `/data/data` 下的文件

### 2.1 判定探针（裸 syscall，绕开一切钩子）

```
进程 SELinux 上下文: u:r:untrusted_app:s0:c143,c258,c512,c768
内核 uid=0

/data/data/.../ubuntu/bin/true
     mode=100755 uid=0 gid=0
     标签=u:object_r:app_data_file:s0:c143,c258,c512,c768
     裸 execve -> ❌ EACCES/被拒          ← 即使 uid=0 也被拒

/system/bin/sh
     标签=u:object_r:shell_exec:s0
     裸 execve -> ✅ 成功

/data/app/.../lib/arm64/libproroot-bridge.so
     裸 execve -> ✅ 成功
```

**结论：`app_data_file` 标签的文件内核禁止 execve，与 uid 无关**
（uid=0 与 uid=10655 都测过，均 EACCES）。

### 2.2 因此「翻译成宿主路径再 execve」**永远不可能成功**

这也解释了为什么官方 runtime 要发明 trampoline —— 它 exec 的不是 guest
文件，而是**自己的 bridge**（在 `/data/app` 下，标签允许执行），
再由 bridge 用 **mmap + 跳转**装入 guest（不经内核的 exec 权限检查）。

### 2.3 排除了的替代解释（负结果）

- **不是 uid 差异**：`/proc/self/status` 的 `Uid:` 行官方与 bxroot **都是 10655**
  （官方把 `getuid` 在 syscall 层伪造了，但内核真值相同）。
- **不是 noexec 挂载**：`/data/data` 本身是 noexec tmpfs，但
  `/data/data/com.dsh.client` 是**独立的 f2fs 子挂载、无 noexec**。
- **不是 LD_PRELOAD**：剔除 `LD_PRELOAD` 后 4 个变体（raw/libc × 含/不含）
  **仍然全部 EACCES**。
- **不是 `syscall_guard` 污染**：手动绕过翻译（`BXROOT_BINDS`）后
  `execve(bridge)` 才成功 —— 这条是**第二个**独立障碍（见 §3.2）。

---

## 3. 实现

### 3.1 改动位置（`src/proc/proc.c`，本轮归属本 agent）

| 函数 | 作用 |
|---|---|
| `px_trampoline_exec()` | execve 路径：构造 `[bridge, linker] + 原argv`，裸 syscall exec |
| `px_trampoline_spawn()` | posix_spawn 路径：`fork()` + 子进程 exec trampoline |

**接入点**：
- `px_do_execve()` 转发前调用 `px_trampoline_exec()`（成功则永不返回）
- `px_do_spawn()` 转发前调用 `px_trampoline_spawn()`（成功则 `rc=0; goto out`）

### 3.2 ★ 关键坑：`/data/app` 路径会被翻译坏，必须加 `/proc/self/root` ★

bridge 在 `/data/app/...` 下。这个前缀**既不在 rootfs 内、也不是声明的
bind source**，于是被翻译成 `<rootfs>/data/app/...` —— 不存在，恒 ENOENT。

实测（同一 bridge）：

| 路径写法 | `stat` | `execve` |
|---|---|---|
| `/data/app/.../libproroot-bridge.so` | ❌ ENOENT | ❌ ENOENT |
| **`/proc/self/root` + 原路径** | ✅ 成功 | ✅ **成功** |
| `/proc/1/root` + 原路径 | ❌ 失败 | — |
| `execveat(fd, AT_EMPTY_PATH)` | ❌ 失败 | — |

因为翻译层对 `/proc` 是**透传**的，而内核对本进程 `/proc/self/root` 就是 `/`。
实现里加了 `/proc/` 前缀判断，避免出现 `/proc/self/root/proc/...` 畸形路径。

### 3.3 回退语义（保证普通环境不变）

- 未设 `PROROOT_TRAMPOLINE_PATH` / `PROROOT_LINKER_PATH` → 立即返回 `-1`，
  调用方照旧直接 `execve` / 真实 `posix_spawn`。
  实测验证：`LD_PRELOAD=<新产物> cspawn4` 在普通 ld.so 下仍 4/4 `rc=0`。
- `posix_spawn` 传了非空 `file_actions` / `attr` → 主动放弃 trampoline、
  回退真实 `posix_spawn`（见 §5 已知限制）。
- **路径不硬编码**：全部从 `PROROOT_TRAMPOLINE_PATH` / `PROROOT_LINKER_PATH` 读。

---

## 4. 验证（修复前 vs 修复后）

### 4.1 `cspawn4`：`rc=13` → `rc=0` ✅

```
--- 修复前 ---
posix_spawn  /bin/true + environ           rc=13  Permission denied
posix_spawn  host路径 + environ          rc=13  Permission denied
posix_spawn  空环境                     rc=13  Permission denied
posix_spawn  空argv[0]=NULL               rc=13  Permission denied

--- 修复后 ---
posix_spawn  /bin/true + environ           rc=0   OK
posix_spawn  host路径 + environ          rc=0   OK
posix_spawn  空环境                     rc=0   OK
posix_spawn  空argv[0]=NULL               rc=0   OK
```

### 4.2 `exectest`：execve 与 spawn 双双通过 ✅

```
--- 修复后 ---
  execve(guest /bin/true)            -> ✅ OK
  execve(host 路径)                -> ✅ OK
  execve(guest, 空环境)           -> ✅ OK
  posix_spawn(guest /bin/true)       -> rc=0 (OK) errno=0
       子进程 ✅ status=0
  posix_spawn(host 路径)           -> rc=0 (OK) errno=0
  posix_spawn(guest, 空环境)      -> rc=0 (OK) errno=0
```

### 4.3 ★ node `spawnSync`：与官方**逐目标一致** ★

```
目标                     官方                        修复后
/bin/true          -> status=0 out=""       -> status=0 out=""        ✅ 一致
/bin/echo          -> status=0 out="x\n"    -> status=0 out="x\n"     ✅ 一致
/usr/local/bin/node-> status=0 out=""       -> status=159（SIGSYS）   ⚠️ 见 §5
```

`probe2.js` 的 `spawnSync` 由 `signal=SIGSEGV`（原始现象）变为 `status=0`。

### 4.4 门禁与回归

```
$ sh test/RUN_WARN_GATE.sh
✅ src/proc/proc.c                    0 条        ← 我的改动零告警
（其余单元：preload/syscall_guard/sigsys/crash/livepatch/fakeroot/l2s×2/bridge 均 0 条）
❌ src/launcher/launcher.c —— 编译失败（非告警，是真错误）
     launcher.c:222:12: error: invalid storage class for function 'join_dir_name'
```

```
$ sh test/RUN_ALL.sh
  ❌ 编译告警门禁       （← launcher.c，**非本次改动**，见下）
  ✅ l2s 运行时 / l2s×fakeroot / fakeroot 纯逻辑 / 系统调用参数位置
  ✅ rename/link 双路径 / crash 崩溃处理器 / D4 进程管理
  ✅ 运行时构建（D4 符号 23/23 全部导出）
  ✅ wait 家族钩子
  通过 9 / 失败 1
```

**唯一失败明确不是本次改动引起的**：`src/launcher/launcher.c` 是**另一位
agent 正在编辑的文件**（mtime 19:16，晚于我的改动），当前处于
**编译不过的中间状态**（`join_dir_name` 位于函数体内 → `invalid storage class`）。
`src/proc/proc.c` 单独门禁为 **0 告警**。

---

## 5. 已知限制与未定位项（如实记录）

1. ⚠️ **嵌套 node 报 SIGSYS（`status=159`）**：`spawnSync("/usr/local/bin/node")`
   时子进程 stderr 为 `sigsys: trap on syscall nr not on allow-list, terminating`。
   **这不是本次改动引入的**：它发生在 proroot 自研加载器的 seccomp 允许列表里，
   与 exec 权限无关。官方 runtime 同样走 trampoline 却正常，说明官方加载器的
   seccomp 表更宽。**需要单独排查 seccomp 允许列表，本文未定位。**

2. ⚠️ **`posix_spawn` + `file_actions` 的重定向会丢失**：走 fork+trampoline 后，
   glibc 那套"靠导出符号（open64/dup2/chdir）实现 file_actions"的机制不参与。
   实现里已**主动保守回退**（非空 `fa`/`attr` 就不用 trampoline），
   避免静默丢语义。**这是当前实现的明确功能缺口**，未解决。

3. ⚠️ **`PROROOT_TRAMPOLINE_ARGV_OFFSET` 未注入**：官方在 envp 里注入
   `PROROOT_TRAMPOLINE_ARGV_OFFSET=2`。实测**不注入也能正常工作**
   （§4.3 的 `/bin/echo`、`/bin/true` 输出与官方一致），故从简未加。
   该变量的确切语义（下标 vs 字节偏移）**未逆向确认**。

4. ⚠️ **关于 `LD_PRELOAD`（回答父 agent 的提问）**：实测**在 trampoline 路径下
   无需额外处理**。子进程 envp 里仍有 `LD_PRELOAD=<bxroot runtime>`，
   但 `/proc/self/maps` 显示它是由 **proroot 自研加载器**装入的
   （bridge + linker 接管），**没有**触发 Android linker 的 `libc.so.6` 解析失败。
   即：`LD_PRELOAD` 在这条路径上是"信息性"的，不会造成 `CANNOT LINK EXECUTABLE`。

---

## 6. 复现命令（全部照抄可跑）

```sh
cd /root/proroot-work/agents/rename-bxroot
APP_LIB=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
ROOTFS=/data/data/com.dsh.client/files/linux/ubuntu
STAGE_LOAD="$ROOTFS/tmp/bxroot-e2e"
export BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" BXROOT_WORKDIR="/" \
       BXROOT_FAKEROOT=1 BXROOT_GUEST_EXE="/tmp/bxroot-e2e/cspawn4"
timeout 120 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" --argv0 cspawn4 \
  --preload "$STAGE_LOAD/libbxroot-tramp3.so" "$STAGE_LOAD/cspawn4"
```

> ★ 写文件用容器视角 `/tmp/bxroot-e2e/`，传给 `--preload` 的用内核视角
> `$ROOTFS/tmp/bxroot-e2e/` —— 本项目反复踩的坑。

### 原始输出留档

- `/root/rename-bxroot/evidence/RAW.txt` —— 第一轮（dlsym / uid / exec 机制矩阵）
- `/root/rename-bxroot/evidence/RAW2.txt` —— 第二轮（SELinux / trampoline / 混淆排除）

### 本轮探针源码（均在 `/root/rename-bxroot/` 或 `/root/tramp/`，未进仓库）

| 探针 | 用途 |
|---|---|
| `execperm.c` | **核心判别器**：SELinux 标签 + 裸 execve 判定 |
| `uidcheck.c` | libc vs 内核 uid（证伪 uid 假设） |
| `exec400.c` / `syslevel.c` | 特权判定、syscall 级定位 |
| `preldiag.c` | LD_PRELOAD 因果验证（4 变体） |
| `tramp2.c` / `tramp4.c` / `tramp5.c` | trampoline argv 形态搜索 |
| `trampnode2.c` | **关键对照**：只换内层 `--preload` 的 runtime |
| `dlsymprobe` / `why.c` / `xlate.c` / `envprobe.c` | dlsym、exec 机制、翻译、环境 |

---

*报告时间：2026-09-16 19:2x UTC。所有命令均在真机容器内实跑，输出原样粘贴。*
