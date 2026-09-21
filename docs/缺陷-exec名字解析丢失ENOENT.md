# 缺陷：`exec <名字>` 全部失败 —— trampoline 丢失了 ENOENT

> **结论**：bxroot 在 trampoline 路径上**用一次成功的 `execve` 代替了
> 本该失败的 `execve`**，导致调用方（shell 的名字解析）无法推进 PATH 搜索。
> 表现为 `exec <不带斜杠的名字>` 100% 失败。
>
> 这是**语义回归**，不是性能差异：POSIX 要求 `execve` 对不存在的文件
> 返回 `ENOENT`，而 bxroot 因走 trampoline 把这个返回值丢了。

---

## 一、现象

```sh
$ bxroot-run -- /bin/sh -c 'exec echo E'
proroot-ldso: failure rc=2          # rc=2

$ bxroot-run -- /bin/sh -c 'exec /bin/echo E'    # 加斜杠就正常
E
```

对照矩阵（默认 rootfs，各 12 次）：

| 命令 | 结果 |
|---|---|
| `exec echo E` | ❌ 12/12 失败 |
| `exec true` | ❌ 12/12 失败 |
| `exec cat /etc/hostname` | ❌ 12/12 失败 |
| `exec ls /dev/null` | ❌ 12/12 失败 |
| `exec /bin/echo E` | ✅ 0/12 失败 |
| `cat /etc/hostname`（不带 exec） | ✅ 0/12 失败 |

**判据**：失败与「带不带 `/`」完全相关，与目标程序无关。

## 二、根因

### 2.1 dash 的名字解析靠 execve 的返回值推进

dash 解析 `exec <名字>` 时**不做「先搜索、后 exec 命中的那个」**，
而是**逐个候选目录去 exec**，把 `execve` 返回 `ENOENT` 当作
「这个候选没有，试下一个」的信号。

官方 proroot 下的实测（`strace -f -e trace=execve /bin/dash -c 'exec echo HELLO'`）：

```
execve("RF/usr/local/sbin/echo", ["echo","HELLO"], …) = -1 ENOENT  → 下一候选
execve("RF/usr/local/bin/echo",  ["echo","HELLO"], …) = -1 ENOENT  → 下一候选
execve("RF/usr/sbin/echo",       ["echo","HELLO"], …) = -1 ENOENT  → 下一候选
execve("RF/usr/bin/echo",        ["echo","HELLO"], …) =      0     → 命中
```

（`RF` = rootfs 的宿主视角路径。）

### 2.2 bxroot 的 trampoline 让第一个候选「假成功」

bxroot 的 `px_do_execve` 优先走 `px_trampoline_exec()`，它 exec 的是
**proroot 的 bridge**（`/data/app/.../lib/arm64/libproroot-bridge.so`）——
**那个文件确实存在**。于是：

```
execve(<bridge>, [bridge, linker, --argv0 /usr/local/sbin/echo, …]) = 0
```

`execve` **返回 0（成功）**，dash 认为 `/usr/local/sbin/echo` 找到了，
**搜索就此停止**。真正的失败发生在 bridge 里层，报
`proroot-ldso: failure rc=2` —— 但此时**已经没有任何人能把这句话
翻译成 `ENOENT` 交回给 dash 了**，因为 dash 那一轮 `execve` 早就
「成功」返回了。

### 2.3 为什么这是语义缺陷而不是「实现差异」

`execve` 的返回值是**接口契约**的一部分：

- shell 的名字解析（本例）靠它推进候选列表；
- `python` 的 `subprocess`/`shutil.which` 靠它决定回退；
- 任何「遍历候选路径、按 errno 分流」的代码都依赖它。

bxroot 在普通（非 trampoline）路径上返回真实 errno，一走 trampoline
就返回 0 —— **同一个函数在两条路径上语义不一致**，这正是缺陷的本质。

## 三、修法

在决定进 trampoline **之前**，先判断目标是否**确定不是可执行文件**；
只有「确定不是」时才跳过 trampoline，让下面的真实 `execve` 给出
权威 errno。

```c
int definitive_no = 0;
struct stat tst;

if (stat(host, &tst) != 0) {
    if (errno == ENOENT || errno == ENOTDIR) {
        definitive_no = 1;                        /* 确实不存在 */
    }
} else if (S_ISDIR(tst.st_mode)) {
    definitive_no = 1;                            /* 目录不可 exec */
} else if (S_ISREG(tst.st_mode) && (tst.st_mode & 0111) == 0) {
    definitive_no = 1;                            /* 三个执行位全 0 */
}

if (definitive_no) {
    /* 跳过 trampoline，落到下面的真实 execve */
} else if (px_trampoline_exec(...) == 0) { ... }
```

代码见 `src/proc/proc.c` 的 `px_do_execve()`（trampoline 调用点之前）。

### 3.1 两个关键的保守取舍

**① 只在「确定性否定」时才跳过，不做 `access(X_OK)` 全局探测。**

最初写的是 `access(host, X_OK) != 0` 就跳过。**这个写法是错的**，
真机上会制造比原缺陷更严重的回归：

- guest 可执行文件在 `/data/data/<pkg>/files/...`，SELinux 标签
  `app_data_file` —— **内核禁止执行它**，而 **trampoline 正是为了
  绕过这条限制才存在的**（见 `px_do_execve` 里那段既有注释）；
- 若 `stat()` 本身被策略拒绝（`EACCES`），按 `!= 0` 判就会跳过
  trampoline，把「本来能跑」的环境弄坏。

所以只认 `ENOENT`/`ENOTDIR`/目录/执行位全 0 这四种确凿情形，
其余一律照旧走 trampoline。

**② 判定为「不是可执行文件」时不 `return`，而是继续往下走真实 `execve`。**

内核能给出的 errno 比我们丰富（`EACCES`、`ENOEXEC`、`ELOOP`、
`ETXTBSY` …）。自己在这里 `return ENOENT` 会把这些情形错误地
归一成 `ENOENT`，反而降低保真度。让内核说话。

## 四、验证

### 4.1 修复前后对照（默认 rootfs，各 12 次）

| 命令 | 修复前 | 修复后 |
|---|---|---|
| `exec echo E` | ❌ 12/12 失败 | ✅ 0/12 |
| `exec cat /etc/hostname` | ❌ 12/12 失败 | ✅ 0/12 |
| `exec true` | ❌ 12/12 失败 | ✅ 0/12 |
| `exec ls /dev/null` | ❌ 12/12 失败 | ✅ 0/12 |
| `exec /bin/echo E` | ✅ | ✅ |
| `cat /etc/hostname` | ✅ | ✅ |

### 4.2 真 ENOENT 仍然如实透传

```
$ bxroot-run -- /bin/sh -c 'exec no-such-cmd-xyz'
sh: 1: exec: no-such-cmd-xyz: not found      # rc=127
```

**这一条必须验**：修法的风险是「把该失败的也变成失败得不对」。
如果 `exec` 一个不存在的命令不再返回 127，说明我们把
「搜索推进」修成了「一律报错」。

### 4.3 跨 rootfs 验证

`exec <名字>` 在 Debian 13 rootfs（glibc 2.41）与默认 Ubuntu 24.04
rootfs（glibc 2.39）下均通过 —— 说明修法不依赖特定 glibc 版本。

### 4.4 回归

`sh test/RUN_ALL.sh`：**24 通过 / 1 失败**，与修复前**完全一致**
（那 1 项是既有失败，见下）。无新增失败。

## 五、相关的既有失败（与本修法无关）

`test/RUN_UPSTREAM_CLI.sh` 一直失败，原因是它用**已废弃的
`launcher + LD_PRELOAD` 路径**做前置自检：

```
❌ 前置能力自检失败：launcher -r / -w / /bin/true 退出码 1
CANNOT LINK EXECUTABLE "/bin/true": library "…/libbxroot-runtime.so" not found
```

在 proroot 容器内 `LD_PRELOAD` 被静默吞掉（见
`docs/调查-LD_PRELOAD在proroot容器内失效.md`），这条路径**原理上不可用**。
该测试应改用 `bridge + linker + --argv0 + --preload`
（即 `tools/bxroot-run` 固化的那条路径）。

## 六、顺带产出的工具

`tools/bxroot-run` —— 把「在 proroot 容器内正确启动 bxroot guest」
这件事固化成一个脚本，并且**每次运行都自证注入成功**（grep `inject=1`，
不通过就拒绝继续）。写它的原因是：在容器内 `LD_PRELOAD` 失效，
若用错加载方式，guest 会**正常地**跑在外层 proroot 下，输出看起来
完全合理 —— 这类**假绿**比崩溃更难发现。

## 七、尚未解决：exec 路径下 cat 的偶发 `munmap_chunk`

修完 `exec` 之后暴露出另一个缺陷，**本次未修**：

| rootfs | 形式 | 失败率 |
|---|---|---|
| 默认（Ubuntu 24.04 / glibc 2.39） | 直接 `cat` | 0/15 |
| 默认 | `exec` → `cat` | 0/15 |
| Debian 13（glibc 2.41） | 直接 `cat` | 0/15 |
| Debian 13 | `exec` → `cat` | **13/15** |

- A/B 对照（同一 bridge/linker，只换 `--preload` 的 runtime）：
  **官方 0/10，bxroot 7/10** —— 确认是 bxroot 侧缺陷，非环境。
- 触发点收窄到：**「先 exec 到新进程」+「子程序是 cat 这一类」**。
  `/bin/true`、`/bin/echo`、`/bin/ls`、自建小程序均 0 失败；
  `cat` 与 `dash` 高概率失败。
- 崩溃发生在**输出全部完成之后**（`strace` 显示读到 EOF 并写完 stdout，
  随后 `writev(2, "munmap_chunk(): invalid pointer")` → `tgkill(SIGABRT)`）。
- 与 `--no-check`、cleanup 的 `rm -rf`、`BXROOT_FAKEROOT`、
  `BXROOT_NO_LIVEPATCH`、`BXROOT_NO_CRASH` 均无关
  （逐个开关试验，失败率不降）。
- 已排除：`fadvise64`/`posix_fadvise` 返回值正常；bxroot 未 hook
  `mmap`/`munmap`/`malloc`/`free`；父子进程的 argv/env 完整
  （自建探针打印 argc/envc/内容均正确，堆压力测试通过）。

**影响面**：只影响「resolv 到一个与容器根不同的 rootfs」+「exec」的组合。
默认 rootfs（`--rootfs` 缺省）下 0/20，**不影响常规使用**。

**下一步建议**：拿 `cat` 与自建最小程序的差异做二分。
已知 `cat` 独有的是 `fadvise64(POSIX_FADV_SEQUENTIAL)` +
`mmap(393216)` 大缓冲读，但单独复刻这两步**不复现** ——
说明还需要一个尚未识别的条件。可用 `MALLOC_CHECK_=0` 先绕过
（能消除 abort，但那只掩盖症状，不能当修法）。
