# `posix_spawn` 带 attr/file_actions 恒失败（make 因此不可用）

> **状态**：主因已修（`posix_spawn` + attr/file_actions 现在可用），
> 但 `make` 仍失败，**真实触发点未定位**。本文件记录已确认的部分与
> 未确认的部分，避免后人重走。

---

## 一、现象

```
########## 官方 ##########              ########## bxroot ##########
$ make -C dir                           $ make -C dir
echo RECIPE-MARKER                      echo RECIPE-MARKER
RECIPE-MARKER                           make: *** [Makefile:2: all] Bad system call
（rc=0）                                 （rc=2）
```

**任何**带配方的 Makefile 都失败（`@echo X`、`echo X > f`、`./script.sh`
全部一样）。`make --version` 本身正常 —— 只有"跑配方"这一步坏。

命令回显（`echo RECIPE-MARKER`）**打印了**，但配方**没有执行**
（实测：配方里的 `echo MARK > out.marker` 没有生成任何文件，
宿主视角确认也没有）。说明 `make` 打印了它准备执行的命令行，
然后子进程**立即死亡**。

## 二、已确认的主因（已修）

`src/proc/proc.c` 的 `px_trampoline_spawn()` 原实现：

```c
if (fa != NULL || attr != NULL) {
    return -1;      /* 放弃 trampoline，回退真实 posix_spawn */
}
```

保守理由写得很清楚："fork+trampoline 后 glibc 的 file_actions 机制不参与，
重定向会静默丢失"。**但后果被严重低估** —— 回退到 `real_posix_spawn`
之后，它拿到的是 `/data/data/...` 下的宿主路径，而 SELinux
`app_data_file` **禁止执行**（与 execve 同一个坑）。在真实部署环境里，
那条"回退路径"**根本不能用** —— 保守的前提不成立。

**实测证据**（`posix_spawn` + `attr`，探针 `sp3.c`）：

```
旧代码 : 官方 rc=0（CHILD-SAYS-OK）   bxroot rc=13 (EACCES)
新代码 : 官方 rc=0                    bxroot rc=0（CHILD-SAYS-OK）  ✅
```

### 修法

不再自己 fork，而是把 **bridge 当 executable 交给 `real_posix_spawn`**：

- `file_actions` / `attr` 由 **glibc 自己**在 `real_posix_spawn` 内部应用
  （我们只原样转交指针，不解构、不重建）→ **语义天然保真**，不存在
  "两处实现漂移"；
- 被执行的是 bridge（`/data/app/.../lib/arm64/`，可执行），绕开 SELinux。

argv 形态与 `px_trampoline_exec` **完全同构**：
`[bridge, linker, --argv0 <name>, --preload <rt>, <host>, argv[1..]]` ——
两条路径共用同一约定，避免"exec 能跑、spawn 不行"。

## 三、★ 仍未定位的部分 ★

修完之后 `posix_spawn`+attr **已经能用**，但 **`make` 仍然失败**。
也就是说：`make` 触发的是**另一个**问题，而它与 `posix_spawn` 的
参数组合有关，但**不在**我已复现的那些组合里。

### 已逐一实测**不是**原因的组合（全部两侧行为一致）

| 组合 | 结果 |
|---|---|
| `posix_spawn` + `sigmask{SIGSYS}` | 两侧都 OK |
| `posix_spawnp` + `SETSIGMASK` | 两侧都 OK |
| `sigmask` 全屏蔽（`sigfillset`） | 两侧都 OK |
| `SETSIGDEF{SIGSYS}`（重置处置为 SIG_DFL） | 两侧都 OK |
| `sigmask` + `SETSIGDEF` 组合 | 两侧都 OK |
| `file_actions_adddup2(fd,0/1/2)` | 两侧都 OK |
| `file_actions_adddup2` + `addclose` | 两侧都 OK |
| `sigprocmask(SIG_BLOCK,{SIGSYS})` 后再调被 TRAP 的号 | 两侧都"存活" |
| fork + 子进程屏蔽 SIGSYS + 再 exec | 两侧都 OK |
| `vfork` + `execve` | 两侧都 OK |
| 直接跑 `sh -c 'echo ...'` | 两侧都 OK |
| 直接跑嵌套 `sh -c 'sh -c ...'` | 两侧都 OK |

### 已确认的**不是**原因

- `make` 本体能跑（`make --version` 正常）
- `make` 的**环境变量**（`MAKEFLAGS=`/`SHELL=` 清掉后仍失败）
- `make -j1`（显式 jobserver）与默认行为相同
- 与 `-d` 调试输出一致：是子进程死在"起不来"这一步
- 配方里的**具体命令无关**（`echo`/`sleep`/脚本都一样）

### 一个未验证的线索

`make` 的 spawnattr sigmask 可能含 **SIGSYS**，而
**spawnattr 的 sigmask 不走我们的 `sigprocmask` 钩子**（它是
`real_posix_spawn` 内部通过 `rt_sigprocmask` 直接设给子进程的）。
若该掩码在子进程里生效并**跨 exec 保留**，子进程一旦触发 seccomp TRAP
就会被内核**直接杀掉**（这正是 "Bad system call" 的语义）。

我尝试用 python 读子进程掩码（`signal.pthread_sigmask`）验证，但两侧
都返回空集 —— **该探针可能不成立**（python 启动时可能重置掩码），
**所以这条线索没有被证实**。要坐实需要：
1. 在子进程里用**裸** `rt_sigprocmask` 读掩码（不经 libc 包装）；
2. 或者 hook `posix_spawnattr_setsigmask` 打印 make 传入的集合。

### 为什么停在这里

`make` 失败是**既有问题**（旧代码同样失败，非本次引入），
且根因需要更细的插桩（hook spawnattr 系列 + 裸信号掩码读取）。
本轮已交付的修复有**独立价值**（`posix_spawn`+attr 从"恒失败"变为可用），
继续深挖 `make` 的收益/成本比已经下降。

**建议**：若要继续，先做那两步插桩确认掩码假设；若成立，
修法方向是**在 bridge/构造层确保子进程不继承 SIGSYS 屏蔽**
（与 `sigsys.c` 已有的"阻止屏蔽 SIGSYS"同一意图，但要覆盖
spawnattr 这条**绕过钩子**的路径）。

## 四、影响面

- `make`（autotools/CMake 构建链重度依赖）
- 任何用 `posix_spawn` + `attr`/`file_actions` 的程序
  （**这一半已修好**）
- DSHA 主链路（node）不直接走 `make`，但 `dsh` 若在容器内触发
  构建（如插件编译）会受影响
