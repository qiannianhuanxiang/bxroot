# 缺陷：`faccessat2`(439) 被谎报 ENOSYS —— SIGSYS 层顶掉了外层仿真器

> **结论**：bxroot 的 SIGSYS 处理器对**所有**被拦系统调用一律回 `ENOSYS`。
> 在 proroot 容器内，外层容器自己也装了一个 SIGSYS 处理器（那是它的
> 系统调用仿真层），而 bxroot **把它顶掉了**。于是外层 seccomp 拦下、
> 本该由外层仿真回来的调用（实测 `faccessat2`=439），被 bxroot 谎报成
> "内核不支持"。
>
> 这是**语义缺陷**，不是架构限制 —— 同一个调用在无 runtime 与官方
> proroot 下都正常工作。

---

## 一、现象

同一个探针二进制（`faccessat2` 直接用裸 syscall）：

| 环境 | `faccessat2(/etc/hostname, F_OK, 0)` |
|---|---|
| 无 runtime（裸容器） | `0` ✅ |
| 官方 proroot runtime | `0` ✅ |
| **bxroot runtime** | **`-1 ENOSYS`** ❌ |

外层日志明确记录它拦了这次调用：

```
[proroot-hook] SIGSYS trapped syscall=439 pc=… x0=3 pid=…
```

也就是说：**外层确实拦了，但它自己的仿真层已经不在位了**。

## 二、根因

### 2.1 外层容器的 SIGSYS 处理器被顶掉

读回 `sigaction(SIGSYS)` 的 flags，三个环境对比：

| 环境 | SIGSYS handler flags |
|---|---|
| 无 runtime | `0x48000004` = `SA_SIGINFO｜SA_ONSTACK｜SA_RESTART｜SA_NODEFER` |
| 官方 proroot | `0x48000004` ← **与外层是同一个**（官方不碰它） |
| **bxroot** | `0x00000004` = 只剩 `SA_SIGINFO` ← **外层那个被替换了** |

`flags` 从 `0x48000004` 掉到 `0x00000004`，说明处理器对象整个换了人。
官方 proroot 之所以能从 seccomp 拦截中存活，正是因为它**保留**了外层
仿真层（它自己也有一份 2624 字节的仿真实现，两者协同）。

### 2.2 为什么"一律回 ENOSYS"在这里是错的

回 `ENOSYS` 只在一种情形下正确：**内核本来就不支持该调用，且调用方
有既定的回退路径**。io_uring 家族（425/426/427）就是设计目标 ——
libuv 见 `ENOSYS` 即退回 epoll，那是它已有的代码路径。

但 `faccessat2` 不同：**内核完全支持它**，只是被外层 seccomp 顺带拦下。
对它回 `ENOSYS` 是在撒谎，而且这个谎会一路传下去：

```sh
$ bxroot-run -- /bin/sh -c 'cd proj && make'
make: cc: No such file or directory          # Error 127
make: *** [Makefile:2: all] Error 127
```

`make` 做 PATH 解析时会去检查候选是否可执行，拿到 `ENOSYS` 就判定
"这个文件不能用"，于是报出一个**与实际原因完全无关**的错误 ——
那个 `cc` 明明存在且可执行。

glibc 的 `faccessat(fd, path, mode, AT_EACCESS)` 内部也走 439，
同样静默改变行为。

## 三、修法

在 SIGSYS 处理器里，对**已知的内核支持但会被拦**的号，改用白名单内的
等价调用重放，而不是回 `ENOSYS`：

```c
if (sc == 439) {   /* faccessat2 */
    u->uc_mcontext.regs[0] = (unsigned long)replay_faccessat2(
        regs[0], regs[1], regs[2], regs[3]);
    return;
}
```

`replay_faccessat2()` 的要点：

1. **`flags != 0` 时仍回 `ENOSYS`。** `faccessat(48)` 表达不了
   `AT_EACCESS` / `AT_SYMLINK_NOFOLLOW` 的语义，硬套会给出错误答案。
   回 `ENOSYS` 才是诚实的（glibc 见 `ENOSYS` 会改用 `stat` 自算）。
2. **用 48 号（`faccessat`）重放** —— 实测它在外层 seccomp 白名单里
   （探针返回 0），且 `flags==0` 时与 `faccessat2` 语义相同。

### 3.1 一个踩过的坑：返回值必须按内核 ABI 编码

第一版写成 `return raw4(...)`，直接透传。结果：

```
raw faccessat (48)  → ENOENT   （正确）
raw faccessat2(439) → EPERM    （错）
```

原因是 `raw4()` 用 **libc 约定**（失败返回 `-1` 并把 `errno` 设好），
而写进 `x0` 的必须是**内核约定**的值（失败 `-errno`）。把 `-1` 塞进
`x0`，guest 的 glibc 解码成 `errno = 1 = EPERM` ——
"文件不存在"就成了"权限不足"。

修法是显式转换：

```c
if (raw4(48, dfd, path, mode, 0) == 0) return 0;
return (long)(-(long)errno);          /* 内核约定：-errno */
```

★ 这条值得单独记 ★ 它不报错、不崩溃，只是**把 errno 换成了另一个
同样合理的值**。`test -f missing` 会从"不存在"变成"没权限"，
shell 的分支判断随之走偏 —— 属于最难发现的一类缺陷。

### 3.2 走过的弯路：链式转交上一任处理器

第一版方案是"保存旧处理器，非白名单号就转交给它"。**这条路走不通**：

```
sigsys: trap on syscall nr not on allow-list, terminating
```

内层 loader 的处理器在"号不在白名单"时直接终止进程，转交过去
反而把能用的路径也弄死了。所以最终选了"自己重放等价调用"。

这也澄清了一件事：**外层仿真层不是靠链式调用就能复用的**，
必须在 bxroot 侧自己给出正确结果。

## 四、验证

### 4.1 修复前后（同一探针）

| 调用 | 修复前 | 修复后 | 宿主基线 |
|---|---|---|---|
| `faccessat2(ok_path, F_OK)` | `-1 ENOSYS` ❌ | `0` ✅ | `0` |
| `faccessat2(bad_path, F_OK)` | `-1 ENOSYS` ❌ | `-1 ENOENT` ✅ | `-1 ENOENT` |
| `faccessat2(path, F_OK, flags≠0)` | `-1 ENOSYS` | `-1 ENOSYS` | `0`（差异已记录、有意为之） |
| `io_uring_setup(425)` | `-1 ENOSYS` | `-1 ENOSYS` ✅ | `-1 ENOSYS` |
| `io_uring_enter(426)` | `-1 ENOSYS` | `-1 ENOSYS` ✅ | `-1 ENOSYS` |
| `io_uring_register(427)` | `-1 ENOSYS` | `-1 ENOSYS` ✅ | `-1 ENOSYS` |

**最后三行是关键**：修法不能把 io_uring 的设计目标一起改掉。
`425/426/427` 在宿主上本来就返回 `ENOSYS`（内核不支持），
bxroot 照旧回 `ENOSYS` —— 行为不变。

### 4.2 回归

`sh test/RUN_ALL.sh`：24 通过 / 1 失败，与修复前一致
（那 1 项是既有的 `RUN_UPSTREAM_CLI.sh` 前置自检失败，用错加载路径，
见 `docs/缺陷-exec名字解析丢失ENOENT.md` 第五节）。
**无新增失败**；告警门禁零告警（曾因遗留的未使用函数被拦下一次，已清除）。

## 五、这条修复**没有**解决 `make`

必须写清楚，避免夸大：修完 `faccessat2` 之后 `make` **仍然失败**，
但失败点已经不同（`strace` 证据）：

```
make 的配方子进程:
  --- SIGSYS {si_syscall=__NR_set_robust_list, si_code=SYS_SECCOMP} ---
  execve("…/libproroot-bridge.so", [..., "--preload", "<外层 runtime>", …])
  +++ exited with 2 +++
```

两个关键事实：

1. 配方子进程 preload 的是**外层 proroot 的 runtime**，不是 bxroot 的 ——
   它整个绕开了 bxroot（`make` 用 `fork` + 子进程内 `execvp`，
   不经 `posix_spawn` 的符号钩子）。
2. 它在 `execve` **之前**就死在 `set_robust_list` 上，而那是
   `SECCOMP_RET_KILL_PROCESS`（不是 `TRAP`）—— **SIGSYS 处理器救不了**，
   属于 `docs/已知限制与架构能力边界.md` 里记的架构级限制。

**A/B 对照**：同一 Makefile，官方 proroot 输出 `MAKE-RECIPE-OK`，
bxroot 报 `Bad system call`。所以 `make` 这条路仍然不可用，
但**根因与本缺陷不同**，不应记在这条头上。

## 六、方法论收获

**"无 runtime / 官方 / bxroot" 三方对照**是本次最有效的定位手段。

单看 bxroot 的行为，`faccessat2 → ENOSYS` 完全可以解释为
"内核/环境不支持"，从而被误判为环境限制而放弃。加上两个对照
（无 runtime、官方 runtime）之后，同一个调用在两侧都正常 ——
**立刻把责任锁定在 bxroot 侧**。

本项目此前已有一条类似教训（`docs/两处控制实验缺陷更正.md`），
这次再次印证：**没有对照的"失败"和没有对照的"成功"一样不可信。**
