# `system()` / `popen()` 全部失败：LD_PRELOAD 注入的是宿主视角路径

> **严重度：高**。它让容器里任何 exec 出来的子进程都起不来 ——
> 影响 `system()`、`popen()`，以及所有依赖它们的工具链。
>
> 缺陷由子代理 d117c724 在调查"高频符号缺口"时**顺带发现**
> （他本来在查 `pclose`，发现真根因不在 `pclose`）。我独立复现并确认。

---

## 一、实测（两侧对照，各用各的环境变量前缀）

探针（`sysprobe.c`）：`system("echo SYSCALL-OK")` + `popen("echo POPEN-OK")`。

```
##### 官方 libproroot-runtime.so #####
SYSCALL-OK
system rc=0 errno=0
popen got: POPEN-OK
pclose rc=0

##### bxroot libbxroot-runtime.so #####
CANNOT LINK EXECUTABLE "sh": library "libc.so.6" not found: needed by
  /data/data/com.dsh.client/files/linux/ubuntu/tmp/sys-16405/libbxroot-runtime.so
  in namespace (default)
system rc=256 errno=13
pclose rc=256
```

| | 官方 | bxroot |
|---|---|---|
| `system()` | `rc=0`，输出 `SYSCALL-OK` | **`rc=256`**，链接器报错 |
| `popen()` | `rc=0`，拿到 `POPEN-OK` | **`rc=256`**，无输出 |

## 二、根因（已定位到具体代码行）

### 2.1 决定性对照：官方**根本不设置 `LD_PRELOAD`**

用 `envprobe`（在容器里打印 `getenv("LD_PRELOAD")`）跑两侧：

```
### 官方 libproroot-runtime.so ###
LD_PRELOAD=(unset)
BXROOT_LD_PRELOAD=(unset)

### bxroot runtime ###
LD_PRELOAD=/data/data/com.dsh.client/files/linux/ubuntu/tmp/lp-30220/libbxroot-runtime.so
BXROOT_LD_PRELOAD=/data/data/com.dsh.client/files/linux/ubuntu/tmp/lp-30220/libbxroot-runtime.so
```

**官方压根不走 `LD_PRELOAD` 这条注入路径。** 它是 ptrace/trampoline 架构
（`--preload` 是 linker 的**加载期**机制，靠 `PROROOT_TRAMPOLINE_*` 转发给
子进程），**不依赖环境变量**传钩子。

所以"注入路径要同时对容器视角和宿主视角有意义"这个矛盾，
**对官方不存在** —— 它不需要解决一个它没有的问题。

> **这改变了修复的性质**：不是"照抄官方做法"，因为 bxroot 是
> **LD_PRELOAD 架构**，它**必须**靠环境变量把钩子传给子进程。
> 这个矛盾是 LD_PRELOAD 架构**自带的**，得自己设计解法。

### 2.2 具体代码路径

`src/proc/proc.c:2378-2399` 的 `px_detect_self_lib()`：

```c
static void px_detect_self_lib(char *dst, size_t cap)
{
    Dl_info info;
    dst[0] = '\0';
    memset(&info, 0, sizeof(info));
    if (dladdr((void *)(uintptr_t)&px_runtime_init, &info) != 0 &&
        info.dli_fname != NULL && info.dli_fname[0] != '\0') {
        px_cfg_str(dst, cap, info.dli_fname);
        if (dst[0] == '/') {
            return;   /* 拿到绝对路径，这就是最优解 */
        }
    }
    ...
}
```

`dladdr()` 返回的是**内核视角**路径。然后 `px_cfg_merge_preload()`
（`proc.c:2407-2460`）把它 `setenv("LD_PRELOAD", ...)` 写进环境。

**问题在于**：`system()` / `popen()` 的子进程是 **glibc 硬编码的宿主世界 `/bin/sh`**
（不是容器内的 shell），它按**宿主视角**解析 `LD_PRELOAD` 里的路径。
那个路径在宿主视角下确实存在，但它 `DT_NEEDED` 的 `libc.so.6`
不在宿主的库搜索路径里 → `CANNOT LINK EXECUTABLE`。

> 这正是本项目反复出现的**双视角陷阱**的又一例，但方向是反的：
> 前面几次都是"该用内核视角却用了容器视角"，这次是
> **"注入给宿主世界子进程的路径，必须是宿主能解析的"**。

### 2.3 一个已排除的方向

报告作者实测：**bxroot 的 `system()` 已经是真接管**（用的是容器内 shell），
但它**同样坏了** —— 证明**坏的是环境变量，不是 shell 路径**。
所以"改用容器内 shell"这条路不解决根因。


## 三、为什么之前没被发现

### 3.1 回归套件只检查符号**存在**，不检查它**能用**

`test/RUN_ALL.sh:337-343` 的"运行时构建"一项：

```sh
for s in fork vfork posix_spawn kill tgkill tkill system popen \
         execve execvp execl waitpid wait4 wait3 waitid; do
    nm -D --defined-only build/libbxroot-runtime.so 2>/dev/null \
        | awk "{print \$3}" | grep -qx "$s" || MISSING="$MISSING $s"
done
```

它 grep 的是 `nm -D` 的**符号表**。`system` / `popen` 确实导出了 ——
所以这一项永远绿，**哪怕它们 100% 不可用**。

> 这是本项目**反复出现的缺陷模式**的又一实例：
> 「能力已实现 ≠ 能力已生效」。
> 前面几例是"钩子写了但没接到"，这一例更极端 ——
> **连"是否生效"的测试都没有，只有"符号是否导出"的检查**。
> 符号导出是必要条件，不是充分条件；把它当充分条件是这类漏检的共同成因。

### 3.2 两处文档记录过风险，但都停在"未验证"

- `docs/P0-3-D4集成报告.md:334`
  > 3. **`system()` / `popen()` 的 guest shell 路径没验证**（proc.c 既有代码，非本次改动）。

  —— 问题**被识别了**，但只写进"未验证项"，没写测试。于是它在后续所有回归里
  都显示为绿色（因为没有任何测试碰它）。

- `docs/parity-补齐报告.md:105`
  > | 7 | `pclose` | 无语义差距：bxroot 的 `proc.c` 已 hook `popen`，`pclose` 纯转发即可 |

  —— 这个判断**基于静态推理而非实测**。实测 `pclose rc=256`，
  与"纯转发即可"的结论矛盾。真实情况是：`pclose` 本身没问题，
  但它依赖的 `popen` 已经坏了，所以静态看"pclose 是纯转发"是对的，
  **却在端到端上表现为失败**。

> **教训**：「已 hook `popen`」不等于「`popen` 能用」。
> **依赖链上游坏了，下游看起来也坏**，而静态审查只看下游。

> **第二条教训**：把风险写进"未验证项"**不等于**处理了它。
> 未验证项会随着回归全绿而逐渐被当成"已确认没问题"——
> 这份文档本身就是证据：它记了风险，然后风险发生了。
> **每一条"未验证"都应该有一个对应的测试，哪怕是最粗糙的那个。**


## 四、状态

**已派子代理 356aa9b8 修复**，要求同时满足三条：
1. `system()`/`popen()` 子进程能起来；
2. 子进程**仍带上运行时**（否则路径翻译丢失 —— 那等于用"关掉功能"换"不报错"）；
3. 容器内直接 exec 的程序不受影响。

并要求他先查清**官方是怎么处理这个矛盾的**（注入路径要同时对容器视角
和宿主视角有意义），以官方做法为依据，而不是自己发明。

## 五、待验证的相邻疑点

- `pclose` 是否需要单独补？子代理 d117c724 的报告把这条列为**不确定项**：
  > `pclose` 单独补是否有用（无实测判据 —— 被更前置的 exec 失败掩盖，需先修 `LD_PRELOAD`）

  这个判断是对的：**必须先修上游**，否则测不出 `pclose` 本身有没有问题。
