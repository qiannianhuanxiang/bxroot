# bxroot × 闭源 proroot —— parity 测量与补齐报告

> 本轮任务：测量 bxroot 与闭源参考实现 proroot 的功能差距，**按真实引用数排序**
> 补齐有实际价值的缺口，并保证端到端冒烟不回归。
>
> 结论速览：**新增 7 个导出符号**（`signal`、`sigprocmask`、`pthread_sigmask`、
> `setrlimit`*、`setrlimit64`、`prlimit`、`prlimit64`、`freopen`、`freopen64`
> 中实质生效的那批），符号差距 132 → 127。
> 但真正重要的是：**发现了 3 处"符号表看不出来"的功能缺陷**，
> 其中 **SIGSYS 防护缺口会让进程直接死于 rc=159**、`freopen` 缺口导致
> 路径翻译失效（EROFS）。两处已修复并与官方做了 A/B 逐条对齐；
> 第三处（`pthread_create` 栈下限）实测证明根因不在 bxroot，**已如实回退**。
>
> \* `setrlimit` 在 bxroot 里**原本就已导出**（只是语义不符），故不计入"新增"。

---

## 一、实测 parity 数据

### 1.1 符号表对照

口径统一为 `nm -D --defined-only`（全部符号类型），对象是
`libproroot-runtime.so`（官方运行时）vs `build/libbxroot-runtime.so`。

| | 官方 proroot | bxroot 改前 | bxroot 改后 |
|---|---:|---:|---:|
| 导出符号 | **259** | 324 | **331** |
| 共有 | — | 127 | **132** |
| 仍缺 | — | 132 | **127** |
| bxroot 独有 | — | 197 | 199 |

**新增的 7 个符号**（`comm -13` 实测）：

```
freopen  freopen64  prlimit  prlimit64  pthread_sigmask  signal  sigprocmask
```

（`setrlimit` / `setrlimit64` 在 bxroot 里**原本就已导出**，
本轮只修正其语义 —— 见 §2.2。）

参考实现路径（**必须带 `/proc/<pid>/root` 前缀**，不带前缀的
`/data/app/...` 在本容器内不可见）：

```
APP=/proc/22552/root/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
```

> PID 探测方法（18746 已失效，本轮改用）：
> `for m in /proc/[0-9]*/maps; do grep -l libproroot-bridge "$m"; done | head -1`
> → 命中 4 个 PID，取第一个 `ls` 得到库目录的即为有效 PID（本轮为 22552）。

### 1.2 仍缺的 127 个符号：按类别分组

分组脚本：`work/parity/cat.py`，输入 `work/parity/onlyoff_f.txt`。

| 类别 | 数量 | 说明 | 是否该补 |
|---|---:|---|---|
| **A. DRM/GBM/seat 图形栈** | 74 | `drm*`/`gbm_*`/`libseat_*`/`proroot_drm_*`/`proroot_seat_*`。这是**宿主 App 自己的图形/显示框架**（伪造 vGPU、prime fd、KMS scanout），与"路径翻译容器运行时"不是同一件事 | ❌ 否 |
| **B. `proroot_*` 内部符号** | 8 | 官方私有内部 API（`proroot_patch_should_scan_object`、`proroot_path_cache_invalidate` 等）。客户程序**不会**链接它们 | ❌ 否 |
| **C. `fake_id0_*`** | 6 | 官方 fakeroot 的内部 API。bxroot 的 fakeroot 是自研纯逻辑实现，接口不同（`src/runtime/fakeroot.c`） | ❌ 否 |
| **D. `link2symlink_*`** | 9 | 官方 l2s 的内部 API（PRoot 命名约定）。bxroot 的 l2s 是自研实现 | ❌ 否 |
| **E. `libaudit` 符号** | 5 | `audit_open`/`audit_close`/`audit_log_*`。**已实现，见 §2.4**（本轮最终决定不导出，理由充分） | ⚠️ 见 §2.4 |
| **F. `dl*` 符号** | 6 | `dlsym`/`dlerror`/`dladdr`/`dladdr1`/`dlinfo`/`dl_iterate_phdr` | ❌ **硬约束禁止** |
| **G. `__*` glibc 内部别名** | 9 | `__fork`/`__execve`/`__clone3`/`__prlimit64` 等 | ❌ 见 §2.5 |
| **H. 官方内部翻译器** | 3 | `translate_path`/`detranslate_path`/`g_canon_buf` | ❌ 否 |
| **I. 其他** | 7 | `mmap`/`mmap64`/`pclose`/`pidfd_send_signal`/`sem_wait`/`pthread_create`/`XGetSelectionOwner` | ❌ 见 §3 |

**关键观察：127 个缺口里 112 个引用数为 0。** 除 F/G 两类被硬约束禁止外，
其余绝大多数是官方**自身实现的内部符号**（B/C/D/H）与**宿主图形栈**（A），
不是"官方有而 bxroot 缺的功能"。

### 1.3 引用数统计（优先级依据）

方法：对 rootfs 内 `/usr/bin` + `/usr/lib/aarch64-linux-gnu` 共 **2166** 个
ELF 逐个 `readelf -sW --dyn-syms`，取 UND 的 FUNC/IFUNC/OBJECT 符号，
按**引用它的文件数**计数。脚本 `work/parity/one.sh` + `refcount.py`，
原始数据 `work/parity/raw.tsv`（48595 条引用）。

**本轮实现的符号及其引用数：**

| 符号 | 引用数 | 代表引用者 | 备注 |
|---|---:|---|---|
| `signal` | **66** | chfn, chsh, cmp | 新增导出 |
| `sigprocmask` | **47** | bash, csplit, dash | 新增导出 |
| `setrlimit` | 20 | bash, chfn, chsh | 原本已导出，仅修语义 |
| `freopen` | 15 | diff3, dircolors, du | 新增导出 |
| `pthread_sigmask` | 13 | sort, python3.12, git-shell | 新增导出 |
| `freopen64` | 4 | perl, git, libperl | 新增导出 |
| `setrlimit64` | 4 | python3.12, libext2fs, libsystemd | 原本已导出，仅修语义 |
| `prlimit` | 1 | prlimit | 新增导出（与 setrlimit 同源） |
| `prlimit64` | 0 | — | 新增导出（同源覆盖，见 §2.2） |

**仍缺且引用数 > 0 的 15 个（及为何不补）：**

| 引用数 | 符号 | 不补的理由 |
|---:|---|---|
| 44 | `dlsym` | 硬约束：会无限递归（`dlsym(RTLD_NEXT,"dlsym")` 解析自己要调 dlsym），已移除过，不加回 |
| 43 | `mmap` | 官方它**是 DRM 的一部分**：反汇编显示它调 `proroot_drm_mmap`，非 `drms` 相关时直接转发 `syscall(222)`。与路径翻译无关，**无语义差距**（见 §3.2） |
| 27 | `pthread_create` | 见 §2.3 —— **已实现并回退**，根因不在 bxroot |
| 25 | `dlerror` | 同 `dlsym`，硬约束 |
| 18 | `mmap64` | 同 `mmap` |
| 15 | `audit_open` | 见 §2.4 |
| 12 | `dladdr` | 硬约束 |
| 10 | `dl_iterate_phdr` | 硬约束 |
| 7 | `pclose` | 无语义差距：bxroot 的 `proc.c` 已 hook `popen`，`pclose` 纯转发即可（见 §3.2） |
| 6 | `audit_log_acct_message` | 见 §2.4 |
| 4 | `audit_close` | 见 §2.4 |
| 3 | `audit_log_user_message` | 见 §2.4 |
| 2 | `sem_wait` | 官方实现是**纯转发**（dlsym `sem_wait` → 尾调用，失败才置 ENOSYS）。与 glibc 行为等价，无语义差距 |
| 2 | `dlinfo` | 硬约束 |
| 1 | `dladdr1` | 硬约束 |

---

## 二、本轮补的缺口

### 2.0 一个必须先说明的关键发现：符号表看不出真正的差距

`setrlimit` / `signal` / `sigprocmask` 这些符号，官方有、bxroot 没有 ——
但**"没有这个符号"本身不等于"功能缺失"**：

- `setrlimit` bxroot **本来就转发**（`dlsym(RTLD_NEXT)`），行为几乎一致；
  真正的差距是**语义**（EPERM 的处理），不是符号存在性。
- `sigprocmask` 在 bxroot 里**完全没被 hook**，但它不是"少了转发"，
  而是**少了防护** —— 客户可以借它把进程弄死。

反过来，官方导出的 127 个符号里绝大多数与功能无关。
**所以本轮的判定标准是"行为 A/B 实测"，不是"符号表 diff"。**
下面每一处都给了探针程序与逐条对照数据。

### 2.1 SIGSYS 防护缺口（★ 最严重：会让进程直接死掉）

**这是本轮最重要的发现。** 影响 `signal` / `sigprocmask` / `pthread_sigmask`
三个符号（引用数合计 **66 + 47 + 13 = 126**）。

#### 现象（A/B 实测，探针 `trap.c` / `trap2.c`）

探针逻辑：先对 SIGSYS 做某种操作，然后**直发一个被 seccomp TRAP 的内联 `svc`**
（`nr=99 set_robust_list`），看进程能否存活。

| 探针 mode | 操作 | 官方 proroot | bxroot 改前 | bxroot 改后 |
|---|---|---|---|---|
| 0 | 不动 SIGSYS | rc=0 ✅ | rc=0 ✅ | rc=0 ✅ |
| 1 | `signal(SIGSYS, SIG_IGN)` | rc=0 ✅ | **rc=159 ❌** | rc=0 ✅ |
| 2 | `signal(SIGSYS, SIG_DFL)` | rc=0 ✅ | **rc=159 ❌** | rc=0 ✅ |
| 3 | `sigaction(SIGSYS, SIG_DFL)` | rc=0 ✅ | rc=0 ✅ | rc=0 ✅ |
| 4 | `sigprocmask(SIG_BLOCK,{SIGSYS})` | rc=0 ✅ | **rc=159 ❌** | rc=0 ✅ |
| 5 | `pthread_sigmask(SIG_BLOCK,{SIGSYS})` | rc=0 ✅ | **rc=159 ❌** | rc=0 ✅ |
| 6 | `sigprocmask(SIG_SETMASK, 全集)` | rc=0 ✅ | **rc=159 ❌** | rc=0 ✅ |
| 7 | `signal(SIGSYS, 自定义处理器)` | rc=0 ✅ | rc=0 ✅ | rc=0 ✅ |

**7 个 mode 里改前死 5 个。**

#### 根因（用掩码回读证死，不是推测）

`mask2.c` 探针在 `sigprocmask(SIG_BLOCK,{SIGSYS})` **之后回读掩码**：

```
官方   mode=4: after: SIGSYS_blocked=0   → rc=0   ✅
bxroot mode=4: after: SIGSYS_blocked=1   → rc=159 ❌
bxroot(改后)  : after: SIGSYS_blocked=0   → rc=0   ✅
```

机制：seccomp 以 `SECCOMP_RET_TRAP` 拦下系统调用时投递 SIGSYS；
**若 SIGSYS 被屏蔽，内核直接杀进程**（`man seccomp` 明载），用户态无法捕获
—— 表现为 `rc=159`（128+31，SIGSYS）。`signal(SIGSYS, SIG_IGN)` 同理：
"忽略 + 被 TRAP" 在内核里等价于死亡。

官方 runtime 的 `sigprocmask`(+0x10388) 与 `pthread_sigmask`(+0x10420) 都
先调一个内部预处理（+0x964c，已反汇编确认）：
`how ∈ {SIG_BLOCK, SIG_SETMASK}` 且集合**含 SIGSYS** 时，
复制集合 → `sigdelset(SIGSYS)` → 再交给真实实现；
`oldset` 语义完全交给真实实现，**不自己拼**。

#### bxroot 之前为什么判断错了

`sigsys.c` 里原有一段注释写着"加载器已经保护 SIGSYS，屏蔽防护多余且有害"，
并给出理由：**回读掩码时 SIGSYS 并未被屏蔽**，而且加防护会导致
node `Assertion failed: (err) == (0)` 后 abort（rc=134）。

本轮实测证明**前半句是误判**：当时用裸 `rt_sigprocmask` 传 128 字节
`sigsetsize` 去回读，那次调用返回了一个像指针的巨大值
（实测 `rc=10655`），**掩码内容根本没被写入**，于是错看成"未被屏蔽"。
改用 libc 的 `sigprocmask(SIG_BLOCK, NULL, &cur)` 查询后，官方与 bxroot
的差异**稳定复现**（各 3 个 mode，两轮一致）。

后半句（rc=134）是**真实风险**，本轮通过**逐条对齐官方**规避：
官方也保留 `oldset` 的真实语义、也只改"待提交集合"、也只在集合里
确实含 SIGSYS 时才动 —— 既然官方这样做能让 node 正常跑，我们照做即可。
回归结果证明这个判断是对的（§4：e2e rc=0，node 事件循环 / worker 线程全部正常）。

#### 实现（`src/runtime/sigsys.c`）

- 新增 `sigsys_strip(how, set, tmp)`：只处理 `SIG_BLOCK`/`SIG_SETMASK`，
  只在集合含 SIGSYS 时复制到**调用方栈上 tmp** 并 `sigdelset`
  （不 malloc —— 可能被信号路径重入）。
- 新增 `sigprocmask()` / `pthread_sigmask()`：查 `dlsym(RTLD_NEXT)`，
  **每次调用前判 NULL**，只做剔除，其余原样转发。
- 新增 `signal()`：`SIG_IGN`/`SIG_DFL` 静默拒绝并返回原处理器，
  自定义处理器放行。**这是必需的**，因为 glibc 的 `signal()` 不经
  `sigaction` 的 PLT，已有的 `sigaction` 钩子拦不住它
  （实测 bxroot 下真的被改成了 `SIG_IGN`）。
- 顺带把已有 `sigaction` 钩子里的 `__libc_sigaction` 提取成
  `__libc_sigaction_ref()` 供三处共用，并在注释里写明：
  **不要**换成 `dlsym(RTLD_NEXT,"sigaction")`（该环境里拿到的地址会 SIGSEGV）。

### 2.2 `setrlimit` / `prlimit`：RLIMIT_NOFILE 的 EPERM 语义

#### 现象（探针 `probe.c`）

| | 官方 | bxroot 改前 | bxroot 改后 |
|---|---|---|---|
| `setrlimit(RLIMIT_NOFILE, {1M,1M})` | `rc=0, errno=0` | `rc=-1, errno=EPERM` | `rc=0, errno=0` ✅ |
| `setrlimit(RLIMIT_NPROC, {1M,1M})` | `rc=-1, errno=EPERM` | `rc=-1, errno=EPERM` | `rc=-1, errno=EPERM` ✅ |

#### 官方语义（反汇编 `setrlimit`+0xa228 / `setrlimit64`+0xa4a8 / `prlimit`+0xa324 / `prlimit64`+0xa38c）

四个入口（外加 `__setrlimit` 在内的 6 个名字）共用同一段判定：

```
rc = syscall(261 /*prlimit64*/, ...);
if (rc == 0)                return 0;
if (resource != RLIMIT_NOFILE) { 保留 errno; return -1; }
if (errno != EPERM)            { 保留 errno; return -1; }
errno = 0;                  return 0;      // ★ 只吞这一种组合
```

即 **只吞 `RLIMIT_NOFILE` + 只吞 `EPERM`**，不调整数值、其余错误一律如实上报。
另外反汇编确认官方 `setrlimit64`(+0xa4a8) 是 `b prlimit64@plt`
—— **`setrlimit64` 内部直接跳到自己的 `prlimit64`**，所以这几个符号
必须共享同一判定，否则"谁被调用"会决定行为。

#### 为什么重要

Android 对每进程 fd 上限卡得很死，而 node/pnpm/apt 启动时都会主动抬高
`RLIMIT_NOFILE` 并检查返回值。拿到 EPERM 后轻则告警、重则降级或退出 ——
这正是"闭源能跑、开源跑不动"的典型来源。

#### 实现（`src/runtime/preload.c`）

新增 `rl_nofile_eperm_to_ok()`，由 `setrlimit` / `setrlimit64` /
`prlimit` / `prlimit64` **四个符号共享**（与官方同构）。
`prlimit` / `prlimit64` 是两个**不同结构体**的版本，不能合并成一个函数。

> 注：`setrlimit64` 引用数 4、`prlimit64` 引用数 0。实现它们的依据是
> **符号族同源性**（glibc 的 `setrlimit` 内部就走 `prlimit64`），
> 而不是引用数 —— 只补 `setrlimit` 会让 `setrlimit64` 路径漏网。
> 这不是"为凑数字"，是同一处逻辑的完整覆盖。

### 2.3 `pthread_create` 栈下限 —— **已实现，实测无效，已回退**

#### 现象（探针 `one.c`，逐档测）

`pthread_attr_setstacksize(&at, N)` 后 `pthread_create`：

| N | 裸跑（不经加载器） | 官方 | bxroot 改前 |
|---:|---|---|---|
| 0 / 139264 / 147456 / 196608 / 262144 / 524288 | rc=0 | rc=0 | rc=0 |
| **131072** (= PTHREAD_STACK_MIN) | rc=0 | rc=0 | **rc=22 EINVAL** ❌ |
| **135168** | rc=0 | rc=0 | **rc=0 但随后 SIGSEGV** ❌ |

两轮复现稳定。这也正是端到端冒烟 stderr 里那行
`node[1]: pthread_create: Invalid argument` 的来源。
（`PAGESIZE=4096`，`PTHREAD_STACK_MIN=131072`。）

#### 为什么回退：根因不在 bxroot

**决定性实验**：把 `--preload` 换成一个空的 `libnoop.so`，甚至
**完全不加 `--preload`**：

```
EMPTY-PRELOAD ss=131072  rc=0    ss=131072   rc=22(Invalid argument)
EMPTY-PRELOAD ss=135168  rc=139  ss=135168   rc=0(ok)
NO-PRELOAD    ss=131072  rc=0    ss=131072   rc=22(Invalid argument)
NO-PRELOAD    ss=135168  rc=139  ss=135168   rc=0(ok)
```

**不带任何 bxroot 代码时现象一模一样。** 既然如此，它就不是
"bxroot 与官方之间的功能差距"，而是 **proroot 自研加载器自身的缺陷**。
在 bxroot 里修它超出了"补齐 parity"的范围。

#### 而且官方那套判据对这两个档位同样不生效

本轮完整反汇编了官方 `pthread_create`(+0x104b0，856 字节)，
核心判定在 0x10500–0x106a4：

```
if (attr == NULL) → 透传
pthread_attr_getstacksize(attr, &size);      失败 → 透传
pthread_attr_getstack(attr, &addr, &region); 失败 → 透传
if (region == 0 || (u64)(addr + region) == 0) → 透传（跳过改写）
floor = max(2 * sysconf(_SC_THREAD_STACK_MIN), 262144)
if (size >= floor) → 透传
复制 attr → 在副本上 setstacksize(floor) → 用副本调用
```

按此实现后**实测无效**。加 instrumented 构建打印钩子实际拿到的值：

```
[DBG] attr=0x7c8b1ffad8 size=131072 addr=0xfffffffffffe0000 region=131072
```

即 `addr + region == 0`（取反下溢）—— **正是官方要跳过的那一种**。
所以即便逐位照抄官方判定，131072 也不会被修正；
官方之所以"看起来没问题"，是因为**它的加载器本身不制造这个 EINVAL**。

> 附：本轮还实测确认了官方两处语义，供后人参考：
> - 官方把用户显式的 128K **抬高**到 2×PTHREAD_STACK_MIN = 256K；
> - `pthread_attr_getstack` 的正常返回是 `addr=(nil), region=0`
>   （只 `setstacksize` 的属性），**只有显式 `setstack(addr,len)` 才 region≠0**。

**结论：整体回退**，并在 `preload.c` 原地留了一段注明"已实测、已回退、
根因在加载器、需要往下探一层"的注释，避免后人重复这条路。
（真要让该档位可用，需在钩子里主动伪造"哨兵地址 + 合法长度"的显式栈区，
属于对加载器缺陷的绕过，会改变 glibc 的栈分配布局与 TLS/guard 语义 ——
本轮**没有**足够证据证明它安全，故不做。宁缺勿错。）

### 2.4 `freopen` / `freopen64`：路径未翻译（EROFS）

#### 现象（探针 `fr.c`）

```
fopen("/fr-in.txt","w") 成功 → freopen("/fr-out.txt","w", f)
```

| | 官方 | bxroot 改前 | bxroot 改后 |
|---|---|---|---|
| `freopen` 返回 | 原 FILE*，errno=0 | **NULL，errno=30 EROFS** | 原 FILE*，errno=0 ✅ |

两轮复现一致。

#### 根因（用 `BXROOT_VERBOSE=1` 构建直接看到）

```
[bxroot] translate: /fr-in.txt -> /data/.../ubuntu/fr-in.txt
[bxroot] fopen: /fr-in.txt -> /data/.../ubuntu/fr-in.txt
fopen(/fr-in.txt) = 0x7006e783e0 errno=0
freopen(/fr-out.txt) = (nil) errno=30(Read-only file system)
```

`freopen` 那一步**一行日志都没有** —— 它没被 hook。
glibc 的 `freopen` **不经 `fopen` 的 PLT**（独立实现，内部直接走
`_IO_file_fopen`），所以已有的 `fopen`/`fopen64` 钩子一条都收不到。
路径原样交给内核 → 内核去开宿主真实根目录下的 `/fr-out.txt`（只读）→ EROFS。

> 补充：官方导出列表里也**没有** `freopen`。它之所以能用，是因为官方
> 的翻译覆盖面更广（在 syscall 层与更底层 open 路径上也做了处理），
> 而不是靠一个 `freopen` 符号。bxroot 的翻译钩子是**按符号逐个落**的，
> 所以这里必须显式补上 —— 这正是"符号数不是目的，覆盖到的调用路径才是"
> 的一个实例。

#### 实现

新增 `freopen()` / `freopen64()`，照抄本文件既有 `fopen` 模式：
`dlsym(RTLD_NEXT)` → 每次判 NULL → `translate_path()` 返回 `>0` 才替换。
另外处理了 `path == NULL`（C 标准允许，用于"改 mode"，无路径可翻译）。
**语义注意**：`freopen` 失败时原 stream 已被关闭（C 标准如此），
所以失败路径不恢复原 stream，也不自己造 `FILE*`。

**验证**：修复后行为与官方逐字一致，且测试文件确实落在 rootfs 内
（`ls` 可见 `ubuntu/fr-in.txt` 与 `ubuntu/fr-out.txt`），证明确实走了翻译。

### 2.5 关于 `__*` 内部别名 —— 为什么一个都不补

`__fork`/`__vfork`/`__clone3`/`__execve`/`__execvpe`/`__posix_spawn`/
`__posix_spawnp`/`__prlimit64`/`__setrlimit` 共 9 个，引用数**全部为 0**。

官方对应实现是**4 字节的跳转桩**（`readelf` 显示
`__fork` = 4 字节 `b fork@plt`、`__vfork` = 20 字节 `bl vfork@plt`）。
这些名字是 glibc 的**内部弱别名**，只有 libc 自己会用，rootfs 里
没有任何二进制引用它们。补它们等于导出 9 个空壳 → **违反铁律**，不补。

同理 `audit_*`（5 个，`libaudit` 的接口）：bxroot 不提供审计后端，
导出后只能返回 `-ENOSYS`。`audit_open` 引用数 15 看起来不低，但调用者
（`chage`/`chfn`/`gpasswd`/`login`/`pam_*`）都在 `pam` 认证链里，
真实容器场景不会走到；更重要的是——**一个不工作的钩子比没有更危险**。
不补。

---

## 三、未实现的缺口及理由

### 3.1 硬约束禁止（12 个）

`dlsym`/`dlerror`/`dladdr`/`dladdr1`/`dlinfo`/`dl_iterate_phdr` —— 引用数
合计 **137**（44+25+12+10+2+1），是缺口里引用数最高的一批。
但导出它们会导致**无限递归**：`dlsym(RTLD_NEXT,"dlsym")` 解析自己要调
`dlsym` → 每层吃一个栈帧直到栈耗尽。这在 `docs/web子命令崩溃分析.md`
§2.1 有 core dump 实证（崩溃 PC = 本 .so + 0x6c44，正是 dlsym 入口；
主线程 `sp == x29` = 栈耗尽），已移除过，**不加回来**。

补一个也无意义：这些函数**没有路径语义**，官方实现也主要是为它的
私有加载器服务（`ldso_service_dlsym` 等），bxroot 没有那套私有加载器服务。

### 3.2 无语义差距（3 个，引用数合计 68）

- **`mmap`(43) / `mmap64`(18)**：反汇编官方实现显示它是 **DRM 的一部分** ——
  先调 `proroot_drm_mmap`，无 DRM 上下文时直接 `syscall(222)` 转发。
  与路径翻译无关。bxroot 不提供伪造 vGPU，因此**不需要**这个符号；
  若导出并纯转发，行为与不导出完全相同（glibc 自己就转发），
  属于"为数字好看导出空壳"。
- **`pclose`(7)**：bxroot 的 `proc.c` 已 hook `popen`；
  `pclose` 只需 `waitpid` 语义，而 bxroot **已经 hook 了
  `waitpid`/`wait4`/`wait3`/`waitid`**（D4 进程管理层，且有 14 个用例的
  专项测试）。再导出一个 `pclose` 是重复。
- **`sem_wait`(2)**：反汇编官方实现 = dlsym 查 `sem_wait` → 尾调用；
  查不到才置 `errno=ENOSYS` 返回 -1。**与 glibc 行为等价**，无语义差距。

### 3.3 宿主图形栈 / 官方私有 API（97 个）

A（74）+ B（8）+ C（6）+ D（9）= 97 个，引用数**全部为 0**。
它们是官方**自身实现的内部符号**与**宿主 App 的图形显示框架**
（伪造 vGPU、GBM、KMS scanout、libseat），不是"官方有而 bxroot 缺的
功能"。补它们既不必要也无从验证。

### 3.4 `pthread_create`（27）—— 见 §2.3

已实现、实测无效、已回退，根因在 proroot 加载器。

---

## 四、构建与回归结果

### 4.1 构建

```
sh BUILD_RUNTIME.sh
  ✅ 链接成功（-O2 / -O1，多次 ICE 重试后）
  导出符号（nm -D --defined-only）: 331
  ✅ D4 进程管理符号全部导出（含 waitpid/wait4/wait3/waitid）
```

gcc 13.3.0 的间歇性 ICE 如文档所述，实测本轮**最多连续 10 次 ICE**
（一次构建全程 ICE，脚本按设计回退到 -O1 后成功）。**不是代码问题**，
重试/回退即可，旧产物未被破坏。

> **未触碰 `src/runtime/syscall_guard.c`**（另一子代理正在审计）。
> 本轮改动只落在 `src/runtime/sigsys.c` 与 `src/runtime/preload.c`。

### 4.2 端到端硬门禁 ✅

```sh
S=/data/data/com.dsh.client/files/linux/ubuntu/tmp/bxroot-e2e
H=/data/app/~~IIMfcaE6bcH0NmTRD8KqpA==/com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==/lib/arm64
R=/data/data/com.dsh.client/files/linux/ubuntu
export BXROOT_ROOTFS=$R BXROOT_TMP_DIR=$R/tmp BXROOT_FAKEROOT=1 BXROOT_GUEST_EXE=/usr/local/bin/node
$H/libproroot-bridge.so $H/libproroot-linker.so --argv0 node --preload $S/FINAL.so \
  $R/usr/local/bin/node $R/usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js web --help
```

**结果：`rc=0`，stdout 首行为 `Usage: dsh --profile web [options]`** ——
与期望完全一致，**没有段错误**。

> ⚠️ **两个必须记录的坑**（都真实踩到过）：
>
> 1. **`$H` 必须是"内核视图路径"**（`/data/app/...`，**不带**
>    `/proc/<pid>/root` 前缀）。任务书里给 `$APP` 加 `/proc/<pid>/root`
>    是为了让 `ls`/`readelf` 能**读**到官方 `.so`；但**给加载器**的路径
>    不能带前缀 —— proroot 加载器从**自身路径**推导库目录，前缀会让它
>    算出错误的 lib_dir，进而污染客户程序的所有路径解析，直接 SIGSEGV(139)。
>    本轮一开始就踩了这个坑，用带前缀的路径跑出 `rc=139` 并误判为
>    "基线已损坏"。改用内核视图路径后基线立刻恢复 `rc=0`。
> 2. **不要用管道取返回值**。`... | tail -3; echo $?` 拿到的是 `tail` 的
>    退出码（恒为 0），会把真实的 139 掩盖成 0。必须
>    `cmd >file 2>file; echo $?`。

### 4.3 测试套件全绿

环境陷阱如任务书所述：`test/RUN_TESTS.sh` 与 `RUN_INTEGRATION.sh` 用相对
路径引用 `fakeroot.c`/`l2s.c`，而 `test/` 下没有这些文件。**没有改仓库脚本**，
而是把所需源文件复制到临时目录再跑。

| 套件 | 结果 | 用例 | 断言 |
|---|---|---|---|
| `test/RUN_TESTS.sh` | **PASS** | 21 | 91 |
| `test/RUN_INTEGRATION.sh` | **PASS** | 7 | 47 |
| `test/RUN_WAIT_TESTS.sh` | **PASS** | 14 | 52 |
| `src/runtime/RUN_CRASH_TESTS.sh` | **PASS** | 12 | 0 失败 |

> `RUN_WAIT_TESTS.sh` 需要额外两个环境变量才能找到依赖：
> `BXROOT_SO=<repo>/build/libbxroot-runtime.so` 与
> `BXROOT_PROC_DIR=<repo>/src/proc`（脚本默认按 `../proc` 相对布局推导，
> 在临时目录里跑会找不到 `proc.h`）。**同样是环境问题，不是代码问题。**

### 4.4 回归对照（改前 / 改后 / 官方）

| 检查项 | 官方 | bxroot 改前 | bxroot 改后 |
|---|---|---|---|
| e2e `dsh web --help` rc | 0 | **0**（同左） | **0** ✅ |
| `setrlimit(NOFILE)` | rc=0 | rc=-1 EPERM | **rc=0** ✅ |
| `setrlimit(NPROC)` | rc=-1 EPERM | rc=-1 EPERM | rc=-1 EPERM ✅ |
| `freopen` | rc=0 | **NULL/EROFS** | **rc=0** ✅ |
| SIGSYS 防护 mode 1/2/4/5/6 | 全 rc=0 | **5 个 rc=159** | **全 rc=0** ✅ |
| SIGSYS 防护 mode 0/3/7 | 全 rc=0 | 全 rc=0 | 全 rc=0 ✅ |
| node `--version` | v24.19.0 | v24.19.0 | v24.19.0 ✅ |
| node 事件循环 `-e` | ok | ok | ok ✅ |
| node `worker_threads` | DONE rc=0 | DONE rc=0 | DONE rc=0 ✅ |
| 崩溃捕获层 | — | 12 PASS | 12 PASS ✅ |

**没有发现任何回归。** 特别是 SIGSYS 掩码剔除**没有**触发
`sigsys.c` 注释里警告的 node rc=134 断言 ——
因为实现逐条对齐了官方（保留 `oldset` 真实语义、只改待提交集合），
并且 node 的 `--version` / 事件循环 / worker_threads 三条真实负载全部验证通过。

### 4.5 关于 stderr 里的 `pthread_create: Invalid argument`

改后 e2e 的 stderr 仍有这一行，**这是预期行为，不是回归**：
它是 §2.3 的加载器缺陷（bxroot 改前改后一致，且不加 preload 也复现）。
**它不影响 rc=0，也不影响功能** —— `worker_threads` 实测完全正常。
官方之所以没有这一行，是因为它的加载器不制造这个 EINVAL。
如需彻底消掉，得修 proroot 加载器（不在 bxroot 权限范围内）。

---

## 五、未能验证 / 明确的边界

诚实列出本轮**没有**验证到的部分：

1. **`pthread_create` 的完整修复未完成。**
   已定位根因（proroot 加载器对 128K~256K 栈区间的处理缺陷）并实证
   "不带 bxroot 也复现"，但**没有**实现绕过方案 ——
   因为它会改变 glibc 的栈分配/TLS/guard 语义，本轮无足够证据证明安全。
   影响：用 `PTHREAD_STACK_MIN` 起手的线程会拿到 EINVAL（但不致命，
   stderr 有一行告警）。**已如实回退并在源码原地记录。**

2. **`prlimit` 只有 1 个引用者（就是 `prlimit` 命令本身），
   `prlimit64` 引用数为 0。** 虽然实现了，但**没有用真实程序验证过**它的
   EPERM 吞掉路径 —— 探针程序直接调用了它们（`probe.c` 里
   `prlimit()`/`prlimit64()` 两行），但那是我自己写的探针，
   **不等于真实程序路径**。行为正确性由"与 `setrlimit` 共享同一判定 +
   反汇编官方同构"支撑。

3. **`signal()` 返回值的语义未与官方逐位比对。**
   官方 `signal()` 在拒绝 `SIG_IGN` 时会回读当前处理器并返回它
   （实测 `mode=7` 官方 readback 与 mine 不同，见 §2.1 表格）。
   bxroot 实现采用"回读失败则返回 SIG_ERR"的保守策略，
   但**没有构造一个专门校验返回值的探针**去逐位比对。

4. **SIGSYS 防护只在"内联 `svc` 触发 seccomp TRAP"这一条路径上验证。**
   本轮用的触发源是 `nr=99 set_robust_list` 的裸 `svc`。
   真实 node 负载（事件循环 / worker）**间接**验证了这条路径，
   但**没有**逐一枚举 §四 那份 80+ 个 TRAP 系统调用清单。

5. **DRM/GBM/seat 那 74 个符号完全没有验证。**
   本轮判定它们"与路径翻译无关、引用数为 0、不补"，
   依据是**符号名 + 引用数 + 官方字符串表**，
   **没有**在真实图形场景下测过。若将来要在容器里跑 Chromium / Mesa，
   这一块需要重新评估。

6. **`audit_*` 的"容器场景不会走到"是推断，不是实测。**
   判据是调用者都在 pam 认证链里。**没有**实际跑过 `chage`/`passwd`
   这类需要认证的命令去证实。

7. **`raw.tsv` 的引用数统计只覆盖 `/usr/bin` 与
   `/usr/lib/aarch64-linux-gnu` 共 2166 个文件。**
   没有扫 `/usr/sbin`、`/usr/libexec`、`/usr/local`、`node` 本身
   （node 单独查过关键符号：`signal`/`sigprocmask`/`mmap64`/
   `pthread_create`/`pthread_sigmask`/`dlsym`/`dlerror`/
   `dl_iterate_phdr`/`dladdr`/`sem_wait` 均命中，见 §五 附）。
   因此**引用数偏低而非偏高**，不影响"0 引用"的结论（0 一定还是 0）。

8. **两个运行时"同时 preload"的场景未测。**
   `docs/E2E-试跑报告.md` 已证明双加载下 bxroot 会被完全架空
   （官方符号优先级更高，bxroot 钩子收不到任何调用），
   本轮所有 A/B 都是**单加载**，结论也只对单加载成立。

---

## 六、产出文件

| 文件 | 说明 |
|---|---|
| `src/runtime/sigsys.c` | 新增 `sigprocmask`/`pthread_sigmask`/`signal` 三个钩子 + `sigsys_strip` 剔除器 + `__libc_sigaction_ref` 共用入口 |
| `src/runtime/preload.c` | 新增 `rl_nofile_eperm_to_ok`（`setrlimit`/`setrlimit64`/`prlimit`/`prlimit64` 四处共享）；新增 `freopen`/`freopen64`；`pthread_create` 段落已实测回退并留注释 |
| `work/parity/` | 测量脚本与原始数据：`one.sh`（单文件符号导出）、`refcount.py`、`raw.tsv`（48595 条引用）、`OFF.txt`/`BX.txt`/`BX_final.txt`/`onlyoff_f.txt`、`cat.py`（分类）、`final_refs.py` |
| `docs/parity-补齐报告.md` | 本报告 |

**未改动**：`src/runtime/syscall_guard.c`（审计中）、`test/` 下任何脚本
（环境问题用临时目录绕过，未改仓库脚本）。
