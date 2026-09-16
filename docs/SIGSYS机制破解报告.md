# proroot-ldso SIGSYS 白名单与官方 syscall 接管机制（破解报告）

> 本轮研究目标：让 bxroot 能独立启动 dsh。
> **结论：机制已 100% 破解；bxroot 已实现关键的一层并验证有效；
> 但 node/libuv 仍有一条绕过路径未封堵。**

---

## 一、加载器的 SIGSYS 白名单（已完整反汇编）

`libproroot-linker.so` 是 **static-pie 可执行文件**（不是共享库），
它自己安装 SIGSYS 处理器。相关字符串连续排在 `.rodata` 偏移
`0xd930–0xda70`（该文件 `.rodata` 的 vaddr 与文件偏移相同）。

### 判定逻辑（`0x8944–0x8990`，逐条解码）

```asm
8944:  cmp  w0, #0x1          ; si_code == SYS_SECCOMP(1) ?
8948:  b.ne 89fc              ; 否则 → "sigsys: unexpected si_code, terminating"
894c:  ldr  w21, [x1, #24]    ; w21 = si_syscall
8950:  sub  w0, w21, #0x63    ; syscall - 99
8954:  cmp  w0, #0x1
8958:  b.ls 89bc              ; (syscall-99) <= 1 → 放行
895c–8990: 打印 "sigsys: trap on syscall nr not on allow-list, terminating"
           → 终止进程
89bc:  （放行路径）
89c0:  ldrb w0, [x0, #3632]   ; 日志开关
89d8:  "allowed" 标签
89e0:  mov  x0, #0xffffffffffffffda   ; -38 = -ENOSYS
89e4:  str  x0, [x22, #184]           ; ucontext->uc_mcontext.regs[0]
89e8:  ... ret
```

**白名单是硬编码的：只有系统调用 99 和 100。**
（aarch64 上是 `set_robust_list` 与 `get_robust_list`。）

⇒ **`io_uring_setup`(425) 永远不在白名单里**，所以走加载器的处理器必然终止。

### 相关环境变量（加载器读取）

| 变量 | 用途 |
|---|---|
| `PROROOT_LDSO_DEBUG=` | 加载器调试 |
| `PROROOT_SIGSYS_LOG_HOST_PATH=` | 把 SIGSYS 事件写到指定文件 |
| `PROROOT_TRACE_DLOPEN=1` | 跟踪 dlopen |
| `PROROOT_ROOTFS=` | 根文件系统路径 |

---

## 二、官方 runtime 的真正解法：**接管 `syscall` 符号**

### 决定性证据

`libproroot-runtime.so` 的 `.dynsym` 里有：

```
171: 000000000001082c  188 FUNC GLOBAL DEFAULT 11 syscall
```

**它导出了一个 188 字节的 `syscall` 函数。** 实测确认符号归属：

| 配置 | `dlsym(RTLD_DEFAULT,"syscall")` 指向 |
|---|---|
| 有官方运行时 | `libproroot-runtime.so` |
| 无官方运行时 | `libc.so.6` |

### 官方实现的反汇编（`0x1082c`，188 字节）

```asm
1082c: sub  sp, sp, #0xb0
10830: mov  w7, #0xfffffff8
10834: add  x8, sp, #0x80
...
10854: mov  x22, x0            ; 保存系统调用号
1085c: mov  x23, x1            ; 保存参数 0
...
10878: stp  x1, x2, [sp, #128] ; 参数入栈
1087c: stp  x3, x4, [sp, #144]
10880: stp  x5, x6, [sp, #160]
10884: bl   e0a0               ; ← 转交内部核心
10888: mov  x19, x0            ; 保存返回值
1088c: bl   6180 <__errno_location@plt>
10890: ldr  w3, [x0]           ; 读 errno
108a8: adrp x0, 34000
108b8: add  x0, x0, #0x788     ; ← 某个格式化串/表
108bc: bl   9030               ; ← 真正的判定+转发核心
108c0: tbnz x19, #63, 108c8    ; 返回值为负？
108c4: str  wzr, [x20]         ; 成功则清零 errno
108cc: mov  x0, x19
108e4: ret
```

**关键：它是一个完整的 syscall 包装器**，把调用号与 6 个参数转交给内部核心
（`bl 9030`），由核心决定拦截还是转发。

### 对照实验（证明它就是解法）

```
正常              rc=0     node -e 'console.log(1)' 成功
PROROOT_NO_PATCH=1  rc=159   ← 关掉后官方自己也崩
```

**官方跑得通，靠的就是这一层。**（注：`PROROOT_NO_PATCH` 影响的不止
seccomp 补丁，还包括 path/brk 补丁，因此 159 也可能来自其他补丁的缺失；
但 `syscall` 符号接管的存在与归属是实测确证的。）

---

## 三、bxroot 的实现与验证

新增 `src/runtime/syscall_guard.c`：

- 导出 `long syscall(long number, ...)`，与 glibc 签名一致
- 对 `io_uring_setup`(425) / `io_uring_enter`(426) / `io_uring_register`(427)
  直接返回 `ENOSYS`，**不发出 svc**
- 其余调用用**裸 `svc` 内联汇编**转发（不能调 libc 的 `syscall()`，会递归）

### 验证结果（最小复现）

程序只做一件事：`syscall(425, 8, NULL)`

| 配置 | 结果 |
|---|---|
| 无 bxroot | ❌ `sigsys: trap on syscall nr not on allow-list, terminating`（进程死） |
| **有 bxroot** | ✅ **`-1 errno=38 (ENOSYS)`，程序正常继续** |

**这一层完全有效。**

### 但 node 仍死 —— 存在第二条路径

追踪日志（`BXROOT_SCG=1`）：

```
[bxroot] syscall_guard: 转发 90    ← chmod，正常转发
...（11 次）
[bxroot] syscall_guard: 拦截 425 -> ENOSYS   ← 我们成功拦到了！
（此后无任何输出，进程死于 159）
```

⇒ **我们的拦截生效了，但 libuv 还有另一条不经 `syscall()` 符号的路径
发出了 425。**

---

## 四、已排除的假设（避免重复劳动）

| 假设 | 排除依据 |
|---|---|
| 我的处理器没装上 | 实测 `who.so` 确认 handler 指向 `libbxroot-runtime.so` 且 `flags=0x4`(SA_SIGINFO) |
| 处理器被加载器抢走 | `constructor(65535)` 最后安装后，不再出现加载器的 `not on allow-list` 消息 |
| `struct sigaction` 布局错误 | **确实踩过这个坑**（见下），已修 |
| `SA_NODEFER` 导致重入失败 | 设了 `SA_NODEFER` 后仍 159，且处理器只被调用 1 次 |
| 在 `syscall()` 层拦截对 node 无效 | 部分无效 —— 确实拦到了 425，但 node 另有路径 |
| 425 是硬编码常量 | node 与 libc 里搜 `mov x8/w8,#425` 均 **0 命中**，说明是寄存器传递 |
| `dlsym(RTLD_NEXT,…)` 可用 | **不可用** —— 该环境里会 SIGSEGV，故障地址呈 `0xffffffff…` 伪地址形态 |

---

## 五、本轮踩到的三个真实 bug（都已修）

### 5.1 `struct sigaction` 布局：glibc 与内核不同

| 字段 | glibc（152 字节） | 内核（asm-generic） |
|---|---|---|
| handler | 0 | 0 |
| **flags** | **136** | **8** |
| restorer | 144 | 16 |
| mask | 8 | 24 |

我原先直接调 `rt_sigaction` 传 glibc 结构体，实测：

```
裸 rt_sigaction(glibc结构) = -1 errno=22(EINVAL)
读回 flags=0x0   SA_SIGINFO=0        ← 处理器从未装上
```

**修法**：改用 glibc 导出的 `__libc_sigaction`（`GLIBC_PRIVATE`，内部做布局转换）。
修好后立刻能看到 `sigsys 模拟层已安装` 与 `模拟 syscall 425 -> ENOSYS` 日志。

（相反，`sigset_t` 在内核与 glibc 里都是 128 字节位图，布局**一致**，
所以 `rt_sigprocmask` 可用裸调用 —— 不要一概而论。）

### 5.2 `pthread_sigmask` 钩子有害

早期版本拦截 `pthread_sigmask`/`sigprocmask` 强行剔除 SIGSYS 屏蔽位。
用最小复现验证发现：**加载器本来就保护 SIGSYS**
（`pthread_sigmask(SIG_BLOCK,{SIGSYS})` 返回 0 但实际没屏蔽）。
我们的干预破坏了 node `PlatformInit` 的返回码/掩码一致性假设，
导致 `Assertion failed: (err) == (0)` → abort（rc=134）。已移除。

### 5.3 路径视角陷阱（踩了三次）

同一份文件有两个名字，不同操作分别只认其中一个：

| 操作 | 只认 | 给错的后果 |
|---|---|---|
| `mkdir` / `cp` | 容器视角 `/tmp/x` | 给 `$ROOTFS/tmp/x` → **返回 0 却不创建**（静默失败） |
| `--preload` | 内核视角 `$ROOTFS/tmp/x` | 给 `/tmp/x` → `deps: failed to preload … rc=2` |
| shell 的 `test -f` / `ls` / `strings` / `file` | 容器视角 | 看不到 `/data/app/…`，报"不存在" |
| `exec` | 内核视角 | 同样路径却能正常运行 |

实测 `/tmp` 与 `$ROOTFS/tmp` inode 相同（5899539）。

**衍生的一个方法论错误**：我最初搜 `allow-list` 字符串时用了
`/data/app/…` 路径，`strings` 静默返回空，我据此误判"该字符串不存在"，
浪费了一轮。**必须用 `/proc/<pid>/root` 前缀访问官方库。**
（注意：`/proc/self/root` 不行 —— self 是 proroot 的客户，其 root 已被翻译。）

---

## 六、官方与加载器的私有接口（bxroot 拿不到的能力）

| 方向 | 符号 |
|---|---|
| 加载器导出 | `ldso_runtime_dlopen`、`ldso_runtime_dlsym`、`ldso_runtime_dlsym_addr_of` |
| 运行时消费 | `ldso_service_dlsym`、`ldso_service_dlsym_global`、`ldso_service_dlsym_next_from`、`ldso_service_find_object_by_addr`、`ldso_service_find_object_by_handle`、`ldso_service_dl_iterate_phdr` |

官方通过加载器解析符号，因此能拿到 libc 的**可靠地址**。这是它做
活体补丁与符号接管的基础设施。

---

## 七、下一步

1. **找到 io_uring 的第二条发起路径**（已派子代理专项分析）
   - 怀疑是 libuv 静态链接后直接 `svc`，或 `bl` 到内部地址不经 PLT
   - 若是内联 `svc`，需要在加载时做代码补丁（官方 `dynamic-patched` 那条路）
2. 若第二条路径是内联 `svc`，则 bxroot 需要实现**最小化的运行时指令补丁**：
   定位 `svc` 前的系统调用号来源，把 425 的路径短路。
   —— 这正是官方 `[proroot-hook] dynamic-patched %s+0x%lx svc mov+0x%lx`
   与 `shared-x8 skip %s+0x%lx (movz feeds 2+ svc)` 在做的事。
3. 在能跑事件循环后，用 pnpm 验证 l2s 的 `st_nlink` 契约实际效果。

---

## 八、实验闭环：425 被成功拦截，但进程仍死

### 环形缓冲的决定性证据

在 `syscall` 拦截层加入环形缓冲（记录最近 64 个调用号）后：

```
[bxroot]   最近调用号(旧→新): 90 90 90 90 90 90 90 90 90 90 90 425
[bxroot] syscall_guard: 拦截 425 -> ENOSYS
（此后进程立即死亡，再无任何系统调用经过本层）
```

同时装 SIGSYS 观察层做对照：

| 配置 | SIGSYS 处理器被调用次数 | 结果 |
|---|---:|---|
| 仅观察层 | **1**（sc=425，由 `SECCOMP_RET_TRAP` 投递） | rc=159 |
| **我们的拦截层** | **0**（425 从未发出 `svc`） | rc=159 |

**我们的拦截完全生效**（425 没有发出去，观察层一次都没被调用），
但进程依然死亡，且**之后没有任何系统调用经过本层**。

### 排除项

| 假设 | 排除依据 |
|---|---|
| node 有内联 `svc` | **`node` 中 4 字节对齐的 `svc #0` = 0 处**（先前搜到的 35 处均为数据区假阳性，地址全部非 4 字节对齐） |
| node 调用 libc 的 `syscall()` | 调用者地址经 `dladdr` 解析确属 node，**我们已拦到**，说明这条路已封堵 |
| 425 是硬编码常量 | node 与 libc 中搜 `mov x8/w8,#425` 均 0 命中 |
| libuv 静态链接后自设 x8 | node 的 `libuv` 符号已 strip 但字符串存在；然而无对齐 `svc`，故不自设 x8 |

### 结论

⇒ 致命调用来自 **libc/libpthread 内部的直接 `svc`**。这些调用
**不经 PLT、不经 `syscall()` 符号**，因此 `LD_PRELOAD` 层（无论导出
`syscall` 还是别的）**在原理上无法拦截**。

这正是官方必须做**活体代码补丁**（`mprotect` + `memcpy` 改写指令）的
根本原因 —— 也是 `[proroot-hook] dynamic-patched %s+0x%lx svc mov+0x%lx`
那条日志的含义。

### 附带发现：libuv 拿到 ENOSYS 后没有安全回退

按 libuv 源码，`uv__io_uring_setup` 返回 `ENOSYS` 时应回退到 epoll。
但实测进程在拦截后立即死亡，说明该版本在**工作线程场景**下的回退路径
本身会触发另一次被禁调用（或其他 libc 内部路径）。

**这一点需要子代理的进一步分析确认，我不下最终结论。**

---

## 九、对 bxroot 的可操作结论

### 已确认可行的部分

1. **`syscall` 符号接管层有效** —— 最小复现程序验证：
   `syscall(425, 8, NULL)` 在无拦截时进程死，有拦截时返回
   `-1 errno=38(ENOSYS)` 且程序正常继续。
   **这一层应当保留**，它封堵了所有经 `syscall()` 的路径。

2. **用户态 SIGSYS 处理器路线不可行** —— 完整对照实验证明处理器
   被调用、返回 ENOSYS，进程仍死。不要再在这条路上投入。

### 唯一剩余的可行路线

**实现最小化的运行时指令补丁**：在客户程序加载后，扫描 libc/libpthread
的 `.text`，把发起"被禁系统调用"的 `svc` 指令就地改写。

这与官方做法一致，但**必须极其克制**，理由：
- 活体补丁正是官方 issue #22/#23 的来源
- bxroot 的架构优势（用 glibc 原生 ld.so）会因补丁而削弱

**建议的最小实现范围**：只针对 libc 的 `syscall()` 内部那一条 `svc`
（`libc.so.6` 偏移 `0xe9764`，已从官方补丁后的对比中定位），
以及 libpthread 中调用 `io_uring` 的路径（待子代理确认具体位置）。

**在此之前，bxroot 独立跑 dsh 仍不可行** —— 应如实记录为已知限制，
而不是用"双运行时"的方式掩盖（双运行时下 bxroot 会被官方完全架空，
那不能算 bxroot 的成果）。
