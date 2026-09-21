# 缺陷：`make` 在 bxroot 下完全不可用（已修复 · 2026-09-20）

> **状态：已修复。** 根因是**两个独立缺陷叠加**，两个都修掉之后
> `make` 完全可用（含真实 `gcc` 编译 + 链接，5/5 稳定通过）。
>
> | # | 缺陷 | 修复位置 |
> |---|---|---|
> | 1 | `__spawni` 的内联 `svc setresuid/setresgid` 撞 seccomp（`CLONE_CLEAR_SIGHAND` 抹掉了 SIGSYS 处理器） | `src/runtime/livepatch.c` 站点表 |
> | 2 | `eaccess()` 未挂钩 → make 的 PATH 搜索恒 ENOENT | `src/runtime/preload.c` |
>
> 下面保留完整的排查过程（含 11 组被实测排除的假设），因为**两次都
> 差一点走错方向**：第一次把 strace 里包装脚本自己的 helper 误读成
> "外层 runtime 接管"，第二次差点把 `eaccess` 的缺失当成"符号链接
> 架构限制"而放弃。

> **结论**：`make` 的配方子进程**被外层 proroot 的 runtime 接管**，
> 绕过了 bxroot。子进程因此在 `set_robust_list` 上撞到
> `SECCOMP_RET_KILL_PROCESS` —— 那是**信号处理器救不了**的一类拦截，
> 进程直接死。任何用 Makefile 的项目在 bxroot 下都**无法构建**。
>
> **归因明确**：同一 Makefile，无 runtime 与官方 proroot 都成功
> （`rc=0`），bxroot 稳定失败（`rc=2`，3/3）。

---

## 一、现象

```sh
$ cat Makefile
all:
	@/bin/echo ABSOK

$ bxroot-run -- /bin/sh -c 'cd /root/bxr-mk && make'
make: *** [Makefile:2: all] Bad system call          # rc=2

$ /usr/bin/make -C /root/bxr-mk                       # 无 runtime
ABSKO / rc=0                                          ✅

$ <官方 proroot runtime> … make -C /root/bxr-mk
ABSKO / rc=0                                          ✅
```

`make --version`、`make -n`（干跑）都正常 —— **只有"真正跑配方"坏**。

### 1.1 两种失败形态

| 写法 | 现象 |
|---|---|
| `make`（默认） | `make: *** [Makefile:N: all] Bad system call`，rc=2 |
| `make SHELL=/bin/sh` | `make: cc: No such file or directory` / `Error 127` |

第二种是 PATH 解析失败（与
`docs/缺陷-faccessat2被谎报ENOSYS.md` 描述的症状同族，但不是同一根因）。

## 二、根因（证据链，含一次被证伪的中间结论）

### 2.0 ★ 必须先说清楚：一个被证伪的中间结论 ★

本文档初稿把根因写成"配方子进程被外层 runtime 接管"，
依据是 strace 里看到配方子进程的 `--preload` 指向
`libproroot-runtime.so`（外层）而不是 bxroot 的库。

**该结论在"用 `make` 自己起进程"的形态下成立，但它不是全部。**
进一步做直接启动（不经 `tools/bxroot-run` 包装）之后，发现
`make` **仍然失败**，说明还有一层更本质的原因。下面两条都记，
因为它们是**两个不同的可观测现象**。

### 2.1 现象 A（经包装脚本时）：子进程拿到外层 runtime

`tools/bxroot-run` 自身是个 shell 脚本，它内部的 `mkdir`/`cp`/`grep`
等命令由**外层** proroot 启动（`--preload` 指外层 runtime）。这本身无害，
但它会让 strace 里出现大量 `APP/libproroot-runtime.so` 的行，
**容易误读成"bxroot 没生效"**。

判据要看清 `--argv0` 是谁：

```
"--argv0", "make", "--preload", "RF/tmp/bxroot-run-NNNNN/libbxroot-runtime.so"   ← make 拿到了 bxroot ✅
"--argv0", "cp",   "--preload", "APP/libproroot-runtime.so"                       ← 包装脚本自己的 helper，无关
```

### 2.2 现象 B：配方跑完之后 make 才失败

> **2026-09-20 结论**：本节当时的推断（"`fa=1 attr=1` 走 glibc 真实
> posix_spawn 导致防护丢失"）**已被证伪**。真正的原因是
> `__spawni` 的**内联 `svc setresuid/setresgid`** 撞上 seccomp，
> 叠加 `CLONE_CLEAR_SIGHAND` 抹掉 SIGSYS 处理器 —— 详见本文档开头
> 的"已修复"摘要与 `缺陷-faccessat2被谎报ENOSYS.md` 的姊妹篇。
> 保留下面的过程记录，因为**排除法的痕迹本身有价值**。


用最小 Makefile 逐步收窄（recipe 故意用绝对路径，排除 PATH 影响）：

```make
all:
	/bin/echo ONE
	/bin/echo TWO
```

```sh
$ bxroot-run -- /bin/sh -c 'make -C /tmp/mk9'
/bin/echo ONE                  ← ★ 配方确实执行了
make: *** [Makefile:2: all] Bad system call     ← 之后 make 才报错
make: Leaving directory '/tmp/mk9'
```

三个实测要点：

| 观察 | 结论 |
|---|---|
| recipe 的输出**打出来了** | 配方子进程**确实跑起来了**，不是"起不来" |
| 报错来自 `make` 自己（`strerror(SIGSYS)` = "Bad system call"） | 是 **make 报它的子进程**死于 SIGSYS，不是 make 自己被杀 |
| `make -n`（干跑）、`make --version` 正常 | 只有"真的 spawn 配方"这条路坏 |

即：**子进程被创建、执行了配方、然后在退出时死于 SIGSYS**，
`make` 如实把 `SIGSYS` 报成 "Bad system call"。

### 2.3 已排除的假设（逐个实测，都不是原因）

这一节很重要 —— 说明"看起来最像"的几个原因**都被证伪了**：

| 假设 | 实测 | 结论 |
|---|---|---|
| 配方子进程拿到外层 runtime | 加 `BXROOT_VERBOSE=1` 看，`--argv0 make` 那行 preload 的是 **bxroot 的库**（`RF/tmp/bxroot-run-NNNNN/libbxroot-runtime.so`）；strace 里那些 `APP/libproroot-runtime.so` 是**包装脚本自己的 helper 命令**（`cp`/`mkdir`/`grep`），与 make 无关 | ❌ 误读 |
| bxroot 的 `trampoline_spawn` 没被调用 | 日志明确有 `trampoline_spawn host=…/bin/echo … preload=…/libbxroot-runtime.so fa=1 attr=1` | ❌ 它调用了 |
| `setgroups`/`setresgid` 报 ENOSYS | 不加 `BXROOT_FAKEROOT` 时确实 ENOSYS；**加上之后两者都返回 0**，make 依旧失败 | ❌ 不是原因 |
| `faccessat2`(439) | 已单独修好（见 `docs/缺陷-faccessat2被谎报ENOSYS.md`），修完 make 仍失败 | ❌ 另有原因 |
| `set_robust_list`(99) 被 KILL | 宿主上它本来就返回 ENOSYS；单独探针在 bxroot 下行为一致 | ❌ 不是差异点 |
| `vfork` / 连续 `posix_spawn` / `posix_spawn(fa,attr)` | 分别实测：`vfork` ✅、连续 3 次 spawn ✅、带 fa+attr 的 spawn ✅ | ❌ 单点都好 |
| `BXROOT_RAW_SYSCALL=1` / `BXROOT_NO_LIVEPATCH=1` | 两个开关都试过，失败率不变 | ❌ 无关 |
| `POSIX_SPAWN_SETSIGDEF` 把 SIGSYS 重置为 `SIG_DFL` | 构造探针实测：子进程 `rc=0 sig=0`，两侧一致 | ❌ 不是原因 |
| `SIGCHLD` handler + 连续 spawn | 装 handler + 连 spawn 3 次，`SIGCHLD-count=3`，全 `rc=0` | ❌ 不是原因 |
| 输出重定向（管道/文件/dev-null） | 三种都仍是 `Bad system call` | ❌ 无关 |
| recipe 走脚本（`@sh f`、`@/bin/sh f`） | 都 `Bad system call`（连输出都没有） | — 同样失败 |

**手工构造的等价调用全部通过**（同环境、同 runtime）：

```
posix_spawn("/bin/echo", NULL, NULL)              → ECHO-DIRECT-OK ✅
posix_spawn("/bin/sh", "-c /bin/echo X", NULL,NULL) → rc=0 ✅
posix_spawn("/bin/echo", fa, attr)                 → PS3-OK ✅
posix_spawn("/bin/sh","-c 'echo ONE; echo TWO'", fa, attr) → rc=0 ✅
fork() + 子进程 execvp("echo", …)                  → 3/3 ok ✅
直接 sh -c '/bin/echo X'                            → SH-CHILD-OK ✅
手工走 trampoline exec /bin/echo                    → MANUAL-TRAMPOLINE-OK ✅
──────────────────────────────────────────────────────────
make 跑任何配方                                      → Bad system call ❌
```

**结论**：缺陷**不是某个单点调用被拒**，而是 `make` 的
特定子进程生命周期（fork + 信号处置 + 配方 shell + 退出路径）
与 bxroot 之间有一个尚未定位到的交互点。
这比"某个 syscall 被 ENOSYS"更难查，也**尚未修复**。

### 2.4 归因：是 bxroot 侧，不是环境

同一 recipe、同一 bridge/linker，**只换 `--preload` 的 runtime**：

| runtime | 结果 |
|---|---|
| 官方 proroot | `WRAPPER-MAKE-OK` / `make: Leaving directory …` / **rc=0** ✅ |
| bxroot | `make: *** [Makefile:2: all] Bad system call` / **rc=2** ❌ |
| 完全不带 runtime | rc=0 ✅ |

两侧 bridge/linker 完全相同，只有内层 runtime 不同 ——
**责任在 bxroot 侧**，不能用"外层环境如此"解释。

## 三、影响面

| 场景 | 是否受影响 |
|---|---|
| 用 Makefile 的项目（`make`） | ❌ **完全无法构建** |
| 手动 `gcc -c` / `ar` / 链接 | ✅ 正常（本次实测：子代理用这种方式建成了项目） |
| `make -n`（干跑）、`make --version` | ✅ 正常 |
| 其它用 `posix_spawn` 的程序 | ⚠️ 顶层正常（钩子生效），嵌套层见 2.3 |

**这一条对"基于 bxroot 做一个项目"是硬阻断**：绝大多数 C/C++ 项目、
以及大量 Python/Node 项目的构建脚本都走 `make`。

本次子代理能完成项目，**唯一原因是它绕过了 `make`、手敲 `gcc`**。
这个事实必须写清楚，不能记成"构建成功"。
（`gcc` 本身在 guest 里可用且工作正常 —— 实测
`gcc --version`、`gcc -c`、`gcc -o`、`ar` 全部通过。缺的只是 `make`。）

## 四、可尝试的修法方向（未验证）

按证据强弱排序：

1. **让 `sh` 的二次 exec 也走 bxroot。**
   配方子进程拿到外层 runtime，根因是那一层 exec 的
   `LD_PRELOAD` 不含 bxroot。可在 `px_runtime_build_env()` 里确保
   子进程环境的 `LD_PRELOAD` 指向 bxroot 的库（而不是被外层覆盖）。
   *风险*：宿主 shell 按**宿主视角**解析 `LD_PRELOAD`，容器视角路径
   会让它 `CANNOT LINK`（`px_cfg_merge_preload` 的既有注释已记录
   这个两难）。所以这条需要先找到"两个视角都对"的表达方式 ——
   项目此前的结论是**在本题里无解**。

2. **钩住 `posix_spawn` 的 recipe 形态**：让 bxroot 在 spawn 的
   `sh` 时把 `BXROOT_LD_PRELOAD` 一并传下去，使 `sh` 内部的
   `execve` 有据可依。需要确认 `sh` 的 exec 走的是符号还是内联 `svc`。

3. **接受为架构限制并记录**（当前状态）：明确写进
   `docs/已知限制与架构能力边界.md`，并在 README 的"非 Android 环境"
   小节里给出"用 bxroot 构建项目时不要用 make"的指引。

**验证任何修法时的判据**（务必照做，否则会得到假绿）：

```sh
# ① 先删干净所有构建产物 —— 否则 make 会报 "Nothing to be done"，
#    复用宿主构建的二进制，看起来像成功
rm -rf build/ *.o
# ② 断言 make 的退出码
bxroot-run -- /bin/sh -c 'cd proj && make; echo "make-rc=$?"'
# ③ 断言产物是 guest 构建的（比对 mtime/inode，或删除后确实重建）
```

★ 第 ① 步不是洁癖，是必需的 ★ 子代理首次跑就踩了这个坑：
`make clean` 先因 SIGSYS 失败，`make` 于是复用了宿主构建的产物并报
"通过" —— 13/13 的结果**完全无意义**。它是因为 `make clean` 失败
才察觉的。

## 五、复现脚本

```sh
mkdir -p /tmp/mkrepro && cd /tmp/mkrepro
printf 'all:\n\t@/bin/echo ABSOK\n' > Makefile

# 对照（应成功）
/usr/bin/make -C /tmp/mkrepro ; echo "no-runtime rc=$?"

# bxroot（失败）
cd /root/bxroot
./tools/bxroot-run -- /bin/sh -c 'cd /tmp/mkrepro && make; echo "bxroot rc=$?"'
```
