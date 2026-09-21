# 修复：绝对目标符号链接（`cc` / `awk` / `c99` 全链展开）

> **状态：已修复。** 本文是 `docs/缺陷-绝对目标符号链接打不开.md`
> 的续篇 —— 那篇的结论是"架构级限制，做不到"。**这个结论只对了一半**：
> 通用情形确实做不到，但**绝大多数实际用到的链接链可以展开掉**。
>
> 修完后 `/usr/bin/cc`、`/usr/bin/c99`、`/usr/bin/awk` 全部可用
> （实测 `/usr/bin` 与 `/etc/alternatives` 下共 **98 条**绝对目标链接）。

---

## 一、为什么"架构级限制"这个结论不完整

前篇的推理是：

```
客户 open("linkabs")
bxroot 翻译成 <rootfs>/tmp/a.txt
内核读到目标是绝对路径 "/tmp/t.txt"
  ★ 用这个未翻译的路径从**真实根**开始找 → ENOENT
```

**每一步都是对的**，结论"bxroot 拦不到内核内部的二次查找"也是对的。
但漏了一个反问：**既然拦不到内核的解析，那能不能在内核之前自己解析掉？**

```
<rootfs>/tmp/a.txt  --readlink-->  "/tmp/t.txt"
                    --翻译-->      "<rootfs>/tmp/t.txt"
                    --再试-->      成功
```

展开之后交给内核的**已经不是符号链接**，内核也就没有二次查找，
缺陷消失。所以正确表述是：

> **内核内部的路径查找无法拦截**（前篇结论正确），
> **但可以在交给内核之前先把链接展开掉**（前篇没想到）。

★ 这条值得记一笔：**"做不到"往往只是"没想到某条路"**。
前篇把"拦不到内核"直接推成了"无解"，少问了一句"那我能不能绕过去"。

## 二、实现要点（三个坑，都是实测踩出来的）

### 2.1 只在**失败之后**才展开（性能）

无条件对每次 `open` 先 `readlink` 会把所有文件操作变成两次 syscall。
所以做成"**先照常调用，失败了再展开重试**"：正常路径零额外开销，
最坏情况只影响本来就会失败的那一次。

### 2.2 相对目标**也要跟**，不能直接放弃

第一版写的是：

```c
if (tgt[0] != '/') return 0;   /* 相对目标内核能解析，不用管 */
```

理由是"相对目标在同一目录内，内核能正确解析"。**只在最后一步成立** ——
若相对链接后面还有链接，内核解析完这一跳会继续解析下一跳，
而下一跳若是绝对目标，又掉回老问题。

实测 `/usr/bin/cc` 的链条：

```
cc            -> /etc/alternatives/cc     (绝对)
              -> /usr/bin/gcc             (绝对)
              -> gcc-13                   (相对) ← 旧实现在此 return 0
              -> aarch64-linux-gnu-gcc-13 (相对, 真文件)
```

旧实现把 `<rootfs>/usr/bin/gcc-13` 当最终结果返回，而它**仍然是链接**。

**对照**：`/usr/bin/awk -> /etc/alternatives/awk -> /usr/bin/gawk`
最后一跳落到**真文件**，所以旧实现"碰巧"能用 ——
这就是"`awk` 行、`cc` 不行"的来源，也是**只看一个样本会得出错误结论**
的典型例子。

修法：相对目标按 `cur` 的 dirname 拼接后**继续跟**。

### 2.3 必须放在 shebang 判断**之前**

`/usr/bin/c99` 的链尾 `/usr/bin/c99-gcc` 是个 **`#! /bin/sh` 脚本**
（不是 ELF）。若先做 shebang 判断，那时 `host` 还指向
`<rootfs>/usr/bin/c99`（一个链接），`px_rewrite_shebang` 读它得到的是
"读不到"的结果 → 判定"不是脚本" → 交给 linker →
`loader: reject .../c99-gcc: bad magic`。

所以在 `px_do_execve` 里，展开动作放在 `px_rewrite_shebang` **之前**，
并且**同时更新 host 与 guest 两个视角**（shebang 会用 guest 做 argv[1]）。

## 三、覆盖面：三条路都要接

| 路径 | 作用 | 修法位置 |
|---|---|---|
| `stat` / `lstat` / `stat64` / `lstat64` / `newfstatat` | **找得到**（PATH 搜索） | `preload.c` 各钩子失败后重试 |
| `open` / `open64` / `openat` / `openat64` | **打得开** | 同上 |
| `access` / `eaccess` / `faccessat` | **可执行判定**（make 用 `eaccess`！） | 同上 |
| `execve` | **跑得起来**（加载阶段） | `proc.c` 的 `px_do_execve` |
| `posix_spawn` / `posix_spawnp` | **make 走的那条路** | `proc.c` 的 `px_do_spawn` |

★ 这三条是**独立的**：修了 `stat` 只解决"找得到"，
`awk` 当时仍然 `proroot-ldso: failure rc=2`，因为**加载阶段**才失败。
只修一条会得到"找到了但打不开"或"打得开但跑不起来"这类半残行为。

### 3.0 ★ 还有第四条路：`posix_spawn`（漏了它 `make` 就还是坏的）★

前三处接完之后，`sh -c 'cc --version'` 已经通过，但 **`make` 仍然失败**。
补上这一条才是 `make` 真正可用的最后一环。

**glibc 的 `posix_spawn` 在内部完成 fork+exec**：真正发出 exec 的是
`__spawni` 里的**内联 svc**，不经过 `execve` 导出符号 ——
所以 `px_do_execve` 里那份展开逻辑**拦不到这条路**。

实测（`make` 跑 `cc -c …`）：

```
dash 为外部命令 fork 一个子进程
  → 该子进程走 glibc posix_spawn
  → clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND)     ← 实测计数 1
  → CLONE_CLEAR_SIGHAND 抹掉 SIGSYS 处理器
  → 子进程带着**未展开的** <rootfs>/usr/bin/cc 去 exec
  → proroot-ldso: failure rc=2  → 子进程 exit 2
  → make: *** [Makefile:N: all] Error 2
```

**对照**：不经 make、直接 `cc -c …` 时 `clone3` 计数为 **0**，
走的是导出符号 `execve`，展开逻辑生效 → 成功。

即"**直接能编译、make 里编译不了**"的全部原因。

**修法**：在**父进程**里（`px_do_spawn`）先把 `host` 展开掉。
子进程拿到的就是真文件，与它有没有 SIGSYS 处理器**无关** ——
从这个角度绕开了 `CLONE_CLEAR_SIGHAND` 造成的能力损失。

修完实测：

```
cc 经 make ：修复前 0/10  →  修复后 6/6
真实项目   ：make（默认 cc）完整构建 + 测试 29/29 通过
```

### 3.1 `AT_SYMLINK_NOFOLLOW` 必须保留原语义

带 `NOFOLLOW` 的调用方明确要求"看链接本身"（`tar`/`rsync` 判断
"这是不是链接"就靠它），**绝不能展开**。实测：

```
$ test -L /usr/bin/cc && echo IS-LINK
IS-LINK          ← lstat 语义未被破坏
$ ls -l /usr/bin/cc
lrwxrwxrwx  /usr/bin/cc -> /etc/alternatives/cc   ← 仍显示为链接
```

## 四、诊断开关

新增 `BXROOT_NO_ABSSYM=1`：置位则不展开。用途是**判定某个现象是否由
本层引入** —— 本次正是靠它证明"隔离泄漏与本修复无关"（见下节）。

```
$ bxroot-run -- /bin/sh -c 'cc --version'                    → OK
$ BXROOT_NO_ABSSYM=1 bxroot-run -- /bin/sh -c 'cc --version'  → sh: cc: not found
```

两行同时成立，才说明"是这条修法让 `cc` 可用"，
而不是别的改动碰巧掩盖了问题。

## 五、验证

### 5.1 修复前后

| 命令 | 修复前 | 修复后 |
|---|---|---|
| `cc --version` | ❌ `sh: cc: not found` (127) | ✅ 打印版本 |
| `c99 --version` | ❌ `loader: reject ... bad magic` | ✅ 打印版本 |
| `awk 'BEGIN{print "AWK"}'` | ❌ 127 / `proroot-ldso: failure` | ✅ `AWK` |
| `cat <绝对链接>` | ❌ ENOENT | ✅ 正确内容 |
| `command -v cc` | ❌ 127 | ✅ `/usr/bin/cc` |
| `test -L /usr/bin/cc` | ✅ `IS-LINK` | ✅ `IS-LINK`（未被破坏） |
| 相对目标链接 | ✅ | ✅（未回归） |

### 5.2 `make` 端到端（默认 `CC`）

```
$ bxroot-run -- /bin/sh -c 'rm -f *.o prog; make && ./prog'
gcc -c -o a.o a.c
gcc -c -o b.o b.c
gcc -o prog a.o b.o
make-rc=0
REAL-MAKE-BUILD-OK
```

★ **必须验"默认 CC"** ★ GNU make 的内建 `CC=cc`（origin=default）
**会让 `CC ?= gcc` 失效** —— 子代理在 guest 里实测
`make` 打印 `CC=[cc] origin=default` 确认了这一点。
所以若 Makefile 只写 `CC ?= gcc`，默认 `make` 仍会走 `cc`，
而 `cc` 恰是绝对链接链 —— 这条缺陷**必然**打到它。
这一条是子代理纠正我的，记在这里。

### 5.3 回归

`sh test/RUN_ALL.sh`：与修复前基线一致（唯一失败项是既有的
`RUN_UPSTREAM_CLI.sh` 用错加载路径）。告警门禁零告警。

## 六、未解决：绝对链接的**命名空间泄漏**（独立缺陷）

修此缺陷时暴露出一条**独立且更严重**的问题，**本次未修**：

```sh
$ bxroot-run -- /bin/sh -c 'wc -c < /etc/hosts'          # 直接读
0                                     ← 容器的（空文件）
$ ln -sf /etc/hosts /tmp/iso/probe
$ bxroot-run -- /bin/sh -c 'wc -c < /tmp/iso/probe'      # 经绝对链接
56                                    ← ★ 外层 Android 的 /system/etc/hosts ★
```

内容比对确认取到的是**外层 Android** 的那一份
（`127.0.0.1 localhost` / `::1 ip6-localhost`）。

**定性**：
- 无 bxroot 时得 `0`（正确），**有 bxroot 时得 `56`** ——
  所以是 bxroot 引入的偏差，不是容器固有；
- **但与本修复无关**：用 `BXROOT_NO_ABSSYM=1` 关掉展开后**仍是 56**，
  且泄漏发生在 `open` **成功**的路径上（本层的重试只在失败时触发）。

**影响**：`/etc/hosts`、`/etc/resolv.conf` 等若被绝对链接引用，
读到的是外层命名空间的内容。本次实测的容器里危害有限
（`/etc/passwd`、`/etc/group` 经此路径读到 0 字节），
但**在真机上这可能构成隔离破坏**，应作为独立缺陷跟进。

**方向**：需要让**内核**按 rootfs 解析链接目标。
`openat2(RESOLVE_IN_ROOT)` 是正确的原语，但本内核不支持
（实测 `ENOSYS`）。其余可选：自己实现完整的分段解析
（`O_PATH|O_NOFOLLOW` 逐段走），成本高但语义正确。

---

## 七、命名空间泄漏的补充证据（2026-09-20 晚）

进一步用**受控探针**确认：泄漏只发生在**链接目标恰好是容器自己的
`/etc/hosts`** 这一类"两侧同名文件"的情形，且**与相对路径无关**。

受控对照（自建文件，容器内外同名同内容）：

```sh
printf 'INNER-CONTENT-1234567890' > /tmp/iso2/real_inner.txt
ln -sfn /tmp/iso2/real_inner.txt /tmp/iso2/link_abs
cat /tmp/iso2/link_abs                 # 无 runtime: INNER-CONTENT...
bxroot-run -- /bin/cat /tmp/iso2/link_abs   # ✅ INNER-CONTENT...（正确）
```

自建文件**正确**，说明绝对链接展开本身没问题。而指向 `/etc/hosts` 的
链接给出 56 字节（外层 Android 的 `/system/etc/hosts`），三方对照：

| 环境 | 读 `/tmp/iso2/lnk2`（→ `/etc/hosts`） |
|---|---|
| 无 runtime | **0** 字节 ✅ |
| 官方 proroot | **0** 字节 ✅ |
| **bxroot** | **56** 字节 ❌ |

**机制已定位到这一点**：`BXROOT_NO_ABSSYM=1`（关掉本层的展开）
**仍然是 56**，且 `strace` 显示 `openat` 在**第一次**就成功返回、本层的
重试分支根本没进 —— 说明解析是**内核/内层加载器**做的，
不是本层的展开逻辑。

**与"自建文件正确"并不矛盾**：自建文件的绝对目标
`/tmp/iso2/real_inner.txt` 在**外层命名空间里恰好也真实存在**
（rootfs 与容器共享同一份文件系统），所以两种解析都指向同一份内容，
看不出差别；而 `/etc/hosts` 在两侧**内容不同**（容器 0 字节 /
外层 56 字节），分歧才显现出来。

★ 这是"**测试用例必须能区分两个命名空间**"的又一实例 ★
若只用自建文件测，会得出"绝对链接完全正确"的错误结论。

**优先级**：本次判为独立缺陷、不阻塞当前目标（默认 rootfs 下
常见路径未观察到危害），但**真机上应视为潜在隔离破坏**，
需要让内核按 rootfs 解析链接目标（`openat2(RESOLVE_IN_ROOT)`
在本内核返回 `ENOSYS`，需另寻实现）。

---

## 八、命名空间泄漏：本次**不修**的决定与理由

第七节记录的现象（绝对链接读到外层命名空间的文件）确认属实，
但**本次决定不修**，理由如下 —— 这些理由都要能被复核，不是托辞。

### 8.1 泄漏**不是**这条链接缺陷的一部分

- 关掉本层的展开（`BXROOT_NO_ABSSYM=1`）后泄漏**依旧**
  （56 字节不变）；
- 泄漏发生在 `open` **成功**的路径上，而本层的重试只在**失败**时触发。

本层的展开逻辑**把目标翻译回 rootfs**（正是它让 `/usr/bin/cc` 能用），
方向上与"泄漏到外层"**相反**。所以两者是独立缺陷。

### 8.2 实际可达面很窄（逐项实测）

| 条件 | 实测 |
|---|---|
| 需要一条**目标为绝对路径**的符号链接 | 容器里天然存在的（`/usr/bin/cc`、`/etc/localtime` 等）目标都**不在**外层命名空间，读不到泄漏 |
| 且该目标名在外层**也存在** | 逐文件核对：`/etc` 下只有 **3 个**（`hosts`/`passwd`/`group`）两侧同名；`resolv.conf`/`hostname`/`shadow`/`os-release`/`nsswitch.conf`/`fstab` 外层**都不存在** → 不泄漏 |
| 且**读**（写不泄漏） | 子代理实测：经同一链接**写**会落到**内层**文件，外层未被触碰 |

即：要触发必须**自己造**一条指向 `/etc/hosts`（或 `passwd`/`group`）
的绝对链接。天然路径下不触发。

### 8.3 修它的代价与风险

正确修法是让**内核**按 rootfs 解析链接目标：

- `openat2(RESOLVE_IN_ROOT)` —— 本内核**不支持**（实测 `ENOSYS`）；
- 自己逐段解析（`O_PATH|O_NOFOLLOW` 走每一段）—— 需要替换 `open`
  家族的核心实现，**风险远大于收益**，且本轮刚在 `open` 家族上
  做了改动，再叠一层大改会显著提高回归概率；
- "先 `O_NOFOLLOW` 探一次再决定" —— 每次 `open` 多一条 `syscall`。
  实测 `readlink` 约 **3.75 µs/op**，`O_NOFOLLOW` 同量级；而 bxroot
  的卖点正是"无额外内核往返"，为一个窄面泄漏给**所有**文件操作
  加一条 syscall，与本项目的性能主张直接冲突。

### 8.4 与项目既有定位一致

bxroot 是**用户态路径翻译**，README 与
`docs/已知限制与架构能力边界.md` 都没有把它定位成安全边界
（既有限制清单里 `df` 那条的"不修"理由之一就是"改变路径翻译的
安全边界，影响面远大于收益"）。本条按同一口径处理。

### 8.5 但**必须留痕**，不能静默

- 已写入 `docs/已知限制与架构能力边界.md` 的同一类别下；
- **真机上应重新评估**：Android 的 `/system/etc/*` 与容器 `/etc/*`
  同名文件更多时，可达面比本容器大；
- 若将来要修，起点是 `open` 家族钩子的**成功分支**（当前只在失败
  分支做处理），判据是"打开后 `readlink` 出来的目标是否仍在 rootfs 内"。
