# bxroot 端到端试跑报告（Ubuntu 容器内）

> 实验日期：本轮会话
> 实验位置：Android 设备容器 `/data/data/com.dsh.client/files/linux/ubuntu`
> 结论摘要：**bxroot 能被官方加载器加载并真实执行钩子；但无法独立跑起 dsh，
> 缺的是 seccomp/SIGSYS 白名单这一层。**

---

## 一、最重要的更正：此前"双运行时跑通"的结论是错的

先前我把「官方运行时 + bxroot 同时 preload」下的成功当成了 bxroot 的功劳。
**这是误判**，必须纠正：

| 配置 | `BXROOT_VERBOSE=1` 的 `translate:` 日志条数 | 实际是谁在干活 |
|---|---:|---|
| 官方运行时 + bxroot | **0 条** | **官方**（bxroot 被完全架空） |
| 仅 bxroot | 大量 | **bxroot** |

判定方法：用 `-DBXROOT_VERBOSE=1` 编译（注意 `LOG` 宏受**编译期**开关控制，
运行期设 `BXROOT_VERBOSE=1` 环境变量是无效的，这本身也踩过一次坑）。

机制：官方运行时的符号优先级更高，先处理掉所有路径操作，bxroot 的钩子
一条都收不到。**双加载模式下"测试通过"证明的是官方在干活。**

→ 教训：**多注入层的测试，必须验证每一层是否真的被调用**，不能只看最终结果。

---

## 二、官方 proroot 的真实注入机制（实测）

```
libproroot-bridge.so  libproroot-linker.so --argv0 <name> \
    --preload <runtime> <guest-exe> [args...]
```

- **不用 `LD_PRELOAD`**：`/proc/<pid>/environ` 里 `LD_PRELOAD` 为空。
  用 `LD_PRELOAD=… /bin/true` 完全无效（`ld.so` 不会加载它）。
- `libproroot-linker.so` 是**自研 ELF 加载器**（接受 `--argv0/--preload`），
  `bridge` 是外层宿主加载器，`stub-loader` 作为 `PT_INTERP`。
- 加载器向运行时提供**私有符号服务**，这是 bxroot 拿不到的能力：

  | 方向 | 符号 |
  |---|---|
  | 加载器导出 | `ldso_runtime_dlopen`、`ldso_runtime_dlsym`、`ldso_runtime_dlsym_addr_of` |
  | 运行时消费 | `ldso_service_dlsym`、`ldso_service_dlsym_global`、`ldso_service_dlsym_next_from`、`ldso_service_find_object_by_addr`、`ldso_service_find_object_by_handle`、`ldso_service_dl_iterate_phdr` |

  官方运行时**通过加载器解析符号**，所以能拿到 libc 函数的可靠地址。
  我们的 `dlsym(RTLD_NEXT, …)` 在该环境下**不可靠**：实测调用会 SIGSEGV，
  故障地址呈 `0xffffffff……` 符号扩展伪地址形态（外层做了活体代码补丁）。

---

## 三、bxroot 独立运行的真实边界（实测）

命令：仅 `--preload <bxroot>`，不带官方运行时。

| 命令 | 退出码 | 结果 |
|---|---:|---|
| `/bin/true` | 0 | ✅ |
| `node --version` | 0 | ✅ `v24.19.0` |
| `node -e 'console.log(1)'` | **159** | ❌ |
| `dsh --version` | **159** | ❌ |
| `dsh --help` | **159** | ❌ |

`159 = 128 + 31 = SIGSYS`。报错文本：

```
sigsys: trap on syscall nr not on allow-list, terminating
```

### 这句话不是 bxroot 打印的

**实测：完全不加任何 `--preload` 时同样如此**（`node -e` → 159）。
所以它是 `proroot-ldso`（自研加载器）自己的 SIGSYS 白名单机制。

### 机制（已用最小实验证实）

1. Android app 沙箱给进程装了 seccomp 过滤器
   （`/proc/self/status`：`Seccomp: 2`，`Seccomp_filters: 1`）。
2. 它 TRAP 掉 `io_uring_setup`(425)。**直接调用时返回 ENOSYS，不致命**
   （已用独立程序验证）。
3. 但 libuv 在**工作线程**里发起该调用，而 seccomp 以
   `SECCOMP_RET_TRAP` 拦截时，若 SIGSYS **被屏蔽**，内核**直接杀进程** ——
   无法捕获、无法抢救，就是 159。
4. `node --version` 不启动事件循环，所以能过；一旦跑事件循环就死。

用最小复现程序验证了第 3 条：同一线程内 `pthread_sigmask(SIG_BLOCK,{SIGSYS})`
后调用被拦系统调用 → 进程立即终止。

### 官方为什么能跑

官方运行时有 **2624 字节**的 SIGSYS 模拟层
（`proroot_sigsys_emulate` 1468B / `sigsys_log_append` 488B /
`proroot_sigsys_handler` 408B）。这是它"第三层"架构的真实用途。

---

## 四、本轮在 bxroot 上做的实事

### 4.1 修复了一个静默失效（P0）

`l2s_rt_patch_stat` / `l2s_rt_patch_statx` **在生产代码里零调用** ——
实现完整、单测 119 条全绿，但 `objdump` 里 `bl …@plt` 计数为 0。
后果：`ln a b` 成功，但 `stat()` 报 `st_nlink=1`，pnpm 据此认为未链接，
退化成完整复制（正是 DSHA 被迫用 `package-import-method=copy` 的根因）。

**修复**：在 7 个 stat 家族钩子（`stat`/`stat64`/`newfstatat`/
`newfstatat64`/`lstat`/`lstat64`/`__xstat`/`__lxstat`/`__xstat64`/
`__lxstat64`）+ `statx` 的真实调用成功分支后接线。

验证：`l2s_rt_patch_stat` 的 `bl` 调用点 **0 → 10**，
`l2s_rt_patch_statx` **0 → 1**。

### 4.2 新增 sigsys.c（seccomp/SIGSYS 兼容层）

实现了 SIGSYS 处理器 + 被拦调用模拟（返回可回退的 ENOSYS）。
**但它不足以解决问题** —— 因为拦截发生在 proroot-ldso 自己的白名单层，
在 SIGSYS 信号送达我们之前进程就已终止。

**结论：这一层只有在不经 proroot-ldso 的环境（真机直跑）才可能生效，
或者在加载器的白名单里注册。当前状态下它不解决问题，但代码保留，
因为它本身是正确的，且是将来接入的正确位置。**

### 4.3 移除了一处有害代码

sigsys.c 早期版本拦截 `pthread_sigmask`/`sigprocmask` 强行剔除 SIGSYS
屏蔽位。**实测有害**：最小复现显示 `pthread_sigmask(SIG_BLOCK,{SIGSYS})`
在官方加载器下**本来就返回 0 且不真正屏蔽**（加载器已保护），
我们的干预破坏了 node `PlatformInit` 的返回码/掩码一致性假设，
导致 `Assertion failed: (err) == (0)` → abort（rc=134）。

---

## 五、路径视角陷阱（踩了三次，值得单列）

**同一份文件有两个名字**，不同操作分别只认其中一个：

| 操作 | 只认 | 给错会怎样 |
|---|---|---|
| `mkdir` / `cp` | **容器视角** `/tmp/x` | 给 `$ROOTFS/tmp/x` → **返回 0 但不创建**（静默失败） |
| `--preload` | **内核视角** `$ROOTFS/tmp/x` | 给 `/tmp/x` → `deps: failed to preload … rc=2` |
| shell 的 `test -f` / `ls` | **容器视角** | 看不到 `/data/app/…`，报"不存在" |
| `exec` | **内核视角** | 同样路径却能正常运行 |

实测 `/tmp` 与 `$ROOTFS/tmp` inode 相同（5899539），是同一目录。

`APP_LIB` 因此必须用内核视图路径，且**不能用 `[ -f ]` 校验** ——
"[ -f ] 说不存在"与"exec 能跑"可以同时成立。

---

## 六、可复现的试跑方式

见 `test/RUN_E2E.sh`（含 `--selftest` 自检模式）。

自检结果（仅 bxroot 模式下 `node --version` 可用；完整自检需要 SIGSYS 缺口修复后才有意义）：

```
=== 路径翻译 ===
  ✅ 读 rootfs 的 /etc/hostname: localhost.localdomain
  ✅ readdir('/') 项数: 20
  ✅ stat('/') 是目录: true
=== fakeroot 身份 ===
  ✅ getuid(): 0
  ✅ getgid(): 0
=== 子进程派生 ===
  ✅ execSync /bin/echo: ok
  ✅ execSync /usr/bin/id -u: 0
结果: 8 通过 / 0 失败
```

（该组数据采集于双运行时配置下，故反映的是官方+dxroot 的合力；
bxroot 独立通过的是路径翻译与 fakeroot 部分，事件循环受限。）

---

## 七、下一步（按优先级）

1. **接入加载器白名单**（P0，决定 bxroot 能否独立跑 dsh）
   需要弄清 `proroot-ldso` 如何决定白名单，以及运行时能否注册。
   备选：让 bxroot 提供 `ldso_service_*` 的消费者实现以复用加载器能力。
2. **重测 l2s 契约**（在能跑事件循环之后，用 pnpm 验证 st_nlink 行为）
3. **D4 进程管理集成**（P0-3 子代理已交付，`INTEGRATION.md` 三步补丁）
4. **waitpid 家族**（P0-3 指出的账本泄漏，引用数第一）
